#!/usr/bin/env python3
"""cpu-steal-monitor: watch CPU steal time on a Linux VPS.

Steal time is CPU time the hypervisor gave to other virtual machines on the same host
while yours was waiting to run. On an overloaded host it makes a quiet server slow.

  sample      run the 5-second sampler (systemd runs this as a service)
  update      roll up minutes, read PHP-FPM logs, write the web dashboard data
  report      build the daily report and email it (or --stdout / --html FILE)
  ticket      print a support-ticket text for your web host
  status      show what is running and the latest numbers
  import-sar  import past steal history from sysstat (sar), if installed
  setup       ask the setup questions, write the config and systemd units
  uninstall   stop and remove the services (--purge also deletes data and config)

Only the Python standard library is used (Python 3.9+). See README.md.
"""
import argparse
import csv
import datetime as dt
import getpass
import glob
import hashlib
import html
import json
import os
import re
import secrets
import shutil
import signal
import smtplib
import socket
import subprocess
import sys
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

try:
    from zoneinfo import ZoneInfo
except ImportError:  # Python < 3.9
    ZoneInfo = None

VERSION = '1.0.0'
NAME = 'cpu-steal-monitor'
CONF = os.environ.get('CSM_CONF', '/etc/cpu-steal-monitor.conf')
DATA = os.environ.get('CSM_DATA', '/var/lib/cpu-steal-monitor')
APP_DIR = os.path.dirname(os.path.abspath(__file__))
UNIT_DIR = '/etc/systemd/system'
HTPASSWD = '/etc/cpu-steal-monitor.htpasswd'
WRAPPER = '/usr/local/bin/cpu-steal-monitor'
INTERVAL = 5
UTC = dt.timezone.utc
MARK = 'Written by cpu-steal-monitor'
REPO_URL = 'https://github.com/kevinjavitz/cpu-steal-monitor'

DEFAULTS = {
    'MAIL_TO': '',
    'MAIL_FROM': '',
    'MAIL_TRANSPORT': 'sendmail',  # sendmail | smtp
    'SENDMAIL': '/usr/sbin/sendmail',
    'SMTP_HOST': '',
    'SMTP_PORT': '587',
    'SMTP_SECURITY': 'starttls',  # starttls | ssl | none
    'SMTP_USER': '',
    'SMTP_PASSWORD': '',
    'REPORT_TIME': '00:30',
    'EXTRA_TZ': '',
    'EXTRA_TZ_LABEL': '',
    'WEB_DIR': '',
    'WEB_URL': '',
    'PHP_SLOWLOG': '',
    'PHP_FPM_LOG': '',
    'PHP_POOL': '',
    'SITE_LABEL': '',
    'HOST_LABEL': '',
    'EPISODE_PCT': '20',
    'RAW_DAYS': '35',
    'KEEP_DAYS': '400',
}

CONF_HELP = """# cpu-steal-monitor settings. One KEY=value per line; the value runs to the end of the line.
# Change them with `cpu-steal-monitor setup` (it keeps what is here as the defaults) or edit by hand.
"""


# ---------------------------------------------------------------- config / files

def load_conf():
    conf = dict(DEFAULTS)
    try:
        with open(CONF) as f:
            for line in f:
                line = line.rstrip('\n')
                if line.strip() and not line.lstrip().startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    conf[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return conf


def save_conf(conf):
    lines = [CONF_HELP]
    for key in DEFAULTS:
        lines.append(f'{key}={conf.get(key, "")}\n')
    write_atomic(CONF, ''.join(lines), mode=0o600)


def write_atomic(path, text, mode=0o644, owner=None):
    tmp = f'{path}.tmp{os.getpid()}'
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    # O_EXCL + O_NOFOLLOW: a symlink planted at the temp name can't redirect the write
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), mode)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
        os.fchmod(f.fileno(), mode)
        if owner:
            try:
                os.fchown(f.fileno(), *owner)
            except OSError:
                pass
    os.replace(tmp, path)


def fqdn():
    try:
        return socket.getfqdn() or socket.gethostname()
    except OSError:
        return 'localhost'


def host_label(conf):
    return conf.get('HOST_LABEL') or socket.gethostname()


def tz_extra(conf):
    name = conf.get('EXTRA_TZ', '')
    if not name or ZoneInfo is None:
        return None, ''
    try:
        tz = ZoneInfo(name)
    except Exception:
        return None, ''
    label = conf.get('EXTRA_TZ_LABEL') or name.split('/')[-1].replace('_', ' ')
    return tz, label


def ncpu():
    return os.cpu_count() or 1


def day_str(t):
    return time.strftime('%Y-%m-%d', time.gmtime(t))


def day_start(day):
    return int(dt.datetime(day.year, day.month, day.day, tzinfo=UTC).timestamp())


def days_between(start, end):
    """UTC dates touched by the epoch range [start, end)."""
    d = dt.datetime.fromtimestamp(start, UTC).date()
    last = dt.datetime.fromtimestamp(max(start, end - 1), UTC).date()
    while d <= last:
        yield d
        d += dt.timedelta(days=1)


# ---------------------------------------------------------------- sampler

def read_cpu():
    with open('/proc/stat') as f:
        fields = f.readline().split()
    # user nice system idle iowait irq softirq steal (guest time is already inside user/nice)
    return [int(x) for x in fields[1:9]]


def cmd_sample(_args):
    """Every 5 s: one raw line per sample, one minute line per finished minute."""
    raw_dir, min_dir = f'{DATA}/raw', f'{DATA}/minutes'
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(min_dir, exist_ok=True)
    state = {'minute': None, 'acc': []}

    def flush_minute():
        acc, minute = state['acc'], state['minute']
        if minute is None or not acc:
            return
        n = len(acc)
        steal = [a[0] for a in acc]
        line = (f'{minute * 60},{n},{sum(steal) / n:.2f},{max(steal):.1f},'
                f'{sum(a[1] for a in acc) / n:.2f},{sum(a[2] for a in acc) / n:.2f}\n')
        with open(f'{min_dir}/{day_str(minute * 60)}.csv', 'a') as out:
            out.write(line)
        state['acc'] = []

    def stop(_sig, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    prev = read_cpu()
    due = time.monotonic()
    try:
        while True:
            due += INTERVAL
            now_mono = time.monotonic()
            if due < now_mono - INTERVAL:  # fell far behind (the host stalled us): resync
                due = now_mono + INTERVAL
            time.sleep(max(0.0, due - now_mono))
            cur = read_cpu()
            delta = [c - p for c, p in zip(cur, prev)]
            prev = cur
            total = sum(delta)
            if total <= 0 or min(delta) < 0:
                continue
            steal = 100.0 * delta[7] / total
            iowait = 100.0 * delta[4] / total
            busy = 100.0 * (delta[0] + delta[1] + delta[2] + delta[5] + delta[6]) / total
            now = time.time()
            with open(f'{raw_dir}/{day_str(now)}.csv', 'a') as out:
                out.write(f'{int(now)},{steal:.1f},{busy:.1f},{iowait:.1f}\n')
            minute = int(now // 60)
            if minute != state['minute']:
                flush_minute()
                state['minute'] = minute
            state['acc'].append((steal, busy, iowait))
    finally:
        flush_minute()


# ---------------------------------------------------------------- reading data

def load_raw(start, end):
    """[(t, steal, busy, iowait)] with start <= t < end."""
    out = []
    for d in days_between(start, end):
        path = f'{DATA}/raw/{d.isoformat()}.csv'
        if not os.path.exists(path):
            continue
        with open(path, newline='') as f:
            for row in csv.reader(f):
                try:
                    t = int(row[0])
                    if start <= t < end:
                        out.append((t, float(row[1]), float(row[2]), float(row[3])))
                except (ValueError, IndexError):
                    continue
    out.sort()
    return out


def load_minutes(start, end):
    """{minute_epoch: [n, steal_avg, steal_max, busy_avg, iowait_avg]}; duplicate minutes are merged."""
    out = {}
    for d in days_between(start, end):
        path = f'{DATA}/minutes/{d.isoformat()}.csv'
        if not os.path.exists(path):
            continue
        with open(path, newline='') as f:
            for row in csv.reader(f):
                try:
                    t, n = int(row[0]), int(row[1])
                    s_avg, s_max, b_avg, w_avg = map(float, row[2:6])
                except (ValueError, IndexError):
                    continue
                if not (start <= t < end) or n <= 0:
                    continue
                if t in out:  # sampler restarted inside this minute
                    o = out[t]
                    m = o[0] + n
                    out[t] = [m, (o[1] * o[0] + s_avg * n) / m, max(o[2], s_max),
                              (o[3] * o[0] + b_avg * n) / m, (o[4] * o[0] + w_avg * n) / m]
                else:
                    out[t] = [n, s_avg, s_max, b_avg, w_avg]
    return out


def load_events(start, end):
    """{'slow': [t...], 'full': [t...]} with start <= t < end."""
    out = {'slow': [], 'full': []}
    for d in days_between(start, end):
        path = f'{DATA}/events/{d.isoformat()}.csv'
        if not os.path.exists(path):
            continue
        with open(path, newline='') as f:
            for row in csv.reader(f):
                try:
                    t, kind = int(row[0]), row[1]
                except (ValueError, IndexError):
                    continue
                if start <= t < end and kind in out:
                    out[kind].append(t)
    for v in out.values():
        v.sort()
    return out


def load_sar():
    try:
        with open(f'{DATA}/sar.json') as f:
            return json.load(f).get('points', [])
    except (OSError, ValueError):
        return []


# ---------------------------------------------------------------- PHP-FPM events

FPM_TIME = re.compile(r'^\[(\d\d)-(\w{3})-(\d{4}) (\d\d):(\d\d):(\d\d)\]')
MONTHS = {m: i for i, m in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), 1)}


def fpm_epoch(line):
    """PHP-FPM writes local server time."""
    m = FPM_TIME.match(line)
    if not m or m.group(2) not in MONTHS:
        return None
    d, mon, y, hh, mm, ss = m.groups()
    return int(dt.datetime(int(y), MONTHS[mon], int(d), int(hh), int(mm), int(ss)).timestamp())


def scan_fpm(conf):
    """Yield (t, kind, key) for slow requests and 'pool full' warnings in the configured logs."""
    pool = conf.get('PHP_POOL', '')
    for pattern in filter(None, (p.strip() for p in conf.get('PHP_SLOWLOG', '').split(','))):
        for path in sorted(glob.glob(pattern)):
            try:
                with open(path, errors='replace') as f:
                    for line in f:
                        if not line.startswith('[') or ' pid ' not in line:
                            continue
                        if pool and f'[pool {pool}]' not in line:
                            continue
                        t = fpm_epoch(line)
                        if t is not None:
                            yield t, 'slow', line.strip()[:120]
            except OSError:
                continue
    for pattern in filter(None, (p.strip() for p in conf.get('PHP_FPM_LOG', '').split(','))):
        for path in sorted(glob.glob(pattern)):
            try:
                with open(path, errors='replace') as f:
                    for line in f:
                        if 'max_children' not in line or not line.startswith('['):
                            continue
                        if pool and f'[pool {pool}]' not in line:
                            continue
                        t = fpm_epoch(line)
                        if t is not None:
                            yield t, 'full', line.strip()[:120]
            except OSError:
                continue


def ingest_events(conf):
    """Copy new PHP-FPM events into DATA/events so their history survives log rotation."""
    state_path = f'{DATA}/events-state.json'
    try:
        with open(state_path) as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    new = {}
    for kind in ('slow', 'full'):
        st = state.get(kind, {'t': 0, 'keys': []})
        last_t, seen = st['t'], set(st['keys'])
        found = [(t, key) for t, k, key in scan_fpm(conf) if k == kind and t >= last_t]
        fresh = [(t, key) for t, key in found if t > last_t or key not in seen]
        for t, _ in fresh:
            new.setdefault(day_str(t), []).append((t, kind))
        if found:
            top = max(t for t, _ in found)
            keys = {key for t, key in found if t == top}
            if top == last_t:
                keys |= seen
            state[kind] = {'t': top, 'keys': sorted(keys)}
    if new:
        os.makedirs(f'{DATA}/events', exist_ok=True)
        for day, rows in new.items():
            with open(f'{DATA}/events/{day}.csv', 'a') as out:
                for t, kind in sorted(rows):
                    out.write(f'{t},{kind}\n')
    write_atomic(state_path, json.dumps(state))
    return sum(len(v) for v in new.values())


# ---------------------------------------------------------------- summaries

def find_episodes(minutes, threshold):
    """Runs of minutes averaging >= threshold; one calmer minute inside a run doesn't end it."""
    eps, cur = [], None
    for m in sorted(minutes):
        avg = minutes[m][1]
        if avg < threshold:
            continue
        if cur and m <= cur['end'] + 120:
            cur['end'] = m
            cur['vals'].append(avg)
            cur['peak'] = max(cur['peak'], minutes[m][2])
        else:
            cur = {'start': m, 'end': m, 'vals': [avg], 'peak': minutes[m][2]}
            eps.append(cur)
    out = []
    for e in eps:
        out.append({'start': e['start'], 'minutes': (e['end'] - e['start']) // 60 + 1,
                    'avg': round(sum(e['vals']) / len(e['vals']), 1),
                    'worst': round(max(e['vals']), 1), 'peak': round(e['peak'], 1)})
    return out


def day_summary(day, conf, force=False):
    """Hourly rows, episodes and totals for one UTC day; cached once the day is over."""
    cache = f'{DATA}/cache/{day.isoformat()}.json'
    sources = [f'{DATA}/minutes/{day.isoformat()}.csv', f'{DATA}/events/{day.isoformat()}.csv']
    newest = max((os.path.getmtime(p) for p in sources if os.path.exists(p)), default=0)
    if not force and os.path.exists(cache) and os.path.getmtime(cache) >= newest:
        try:
            with open(cache) as f:
                return json.load(f)
        except (OSError, ValueError):
            pass
    start = day_start(day)
    minutes = load_minutes(start, start + 86400)
    events = load_events(start, start + 86400)
    threshold = float(conf.get('EPISODE_PCT') or 20)
    hours = []
    for h in range(24):
        lo, hi = start + h * 3600, start + (h + 1) * 3600
        rows = [v for m, v in minutes.items() if lo <= m < hi]
        n = sum(r[0] for r in rows)
        slow = sum(1 for t in events['slow'] if lo <= t < hi)
        full = sum(1 for t in events['full'] if lo <= t < hi)
        if not rows and not slow and not full:
            continue
        # [hour start, minutes with data, avg steal, worst minute, highest 5-s sample, own CPU use,
        #  slow PHP requests, pool full, minutes at or over the episode threshold]
        hours.append([lo, len(rows),
                      round(sum(r[1] * r[0] for r in rows) / n, 2) if n else None,
                      round(max(r[1] for r in rows), 1) if rows else None,
                      round(max(r[2] for r in rows), 1) if rows else None,
                      round(sum(r[3] * r[0] for r in rows) / n, 2) if n else None,
                      slow, full, sum(1 for r in rows if r[1] >= threshold)])
    n_all = sum(v[0] for v in minutes.values())
    summary = {
        'day': day.isoformat(),
        'minutes': len(minutes),
        'avg': round(sum(v[1] * v[0] for v in minutes.values()) / n_all, 2) if n_all else None,
        'worst': round(max(v[1] for v in minutes.values()), 1) if minutes else None,
        'peak': round(max(v[2] for v in minutes.values()), 1) if minutes else None,
        'busy': round(sum(v[3] * v[0] for v in minutes.values()) / n_all, 2) if n_all else None,
        'slow': len(events['slow']), 'full': len(events['full']),
        'hours': hours,
        'episodes': find_episodes(minutes, threshold),
    }
    today = dt.datetime.now(UTC).date()
    if day < today - dt.timedelta(days=1) or force:
        os.makedirs(f'{DATA}/cache', exist_ok=True)
        write_atomic(cache, json.dumps(summary, separators=(',', ':')))
    return summary


def all_days():
    """Every UTC day that has minute or event data, oldest first."""
    days = set()
    for sub in ('minutes', 'events'):
        for p in glob.glob(f'{DATA}/{sub}/????-??-??.csv'):
            try:
                days.add(dt.date.fromisoformat(os.path.basename(p)[:10]))
            except ValueError:
                pass
    return sorted(days)


def percentile(sorted_vals, q):
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * q
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def level_for(mean, longest, worst, threshold):
    # Same rules as verdict() in dashboard.html
    if mean >= 10 or longest >= 5:
        return 'Heavy', 'the host was short of CPU and pages will have been slow.'
    if mean >= 3 or worst >= threshold:
        return 'Watch', 'some steal spikes; expect short slow spells.'
    return 'Low', 'the host gave this server its full CPU.'


def range_stats(conf, start, end):
    """Everything the report and the ticket need for [start, end)."""
    raw = load_raw(start, end)
    minutes = load_minutes(start, end)
    events = load_events(start, end)
    threshold = float(conf.get('EPISODE_PCT') or 20)
    steals = sorted(r[1] for r in raw)
    min_avgs = sorted(v[1] for v in minutes.values())
    n = sum(v[0] for v in minutes.values())
    mean = sum(v[1] * v[0] for v in minutes.values()) / n if n else 0.0
    busy = sum(v[3] * v[0] for v in minutes.values()) / n if n else 0.0
    worst = max(minutes.items(), key=lambda kv: kv[1][1]) if minutes else None
    eps = find_episodes(minutes, threshold)
    longest = max((e['minutes'] for e in eps), default=0)
    expected = max(1, (end - start) // INTERVAL)
    level, sentence = level_for(mean, longest, worst[1][1] if worst else 0, threshold)
    return {
        'start': start, 'end': end, 'raw': raw, 'minutes': minutes, 'events': events,
        'samples': len(raw), 'expected': expected, 'coverage': 100.0 * len(raw) / expected,
        'mean': mean, 'busy': busy, 'median': percentile(steals, 0.5), 'p95': percentile(steals, 0.95),
        'peak': steals[-1] if steals else 0.0, 'worst': worst, 'episodes': eps, 'longest': longest,
        'over': {th: sum(1 for v in min_avgs if v >= th) for th in (10, threshold, 40)},
        'threshold': threshold, 'level': level, 'sentence': sentence,
    }


# ---------------------------------------------------------------- report (email)

COL = {'navy': '#10243D', 'ink': '#242424', 'sub': '#5B5F66', 'line': '#E4E9F0', 'ground': '#F6F8FB',
       'flame': '#F85112', 'amber': '#D99A1E', 'bar': '#2B4A72'}
LEVEL_COL = {'Low': ('#17804B', '#E8F5EE'), 'Watch': ('#965E00', '#FDF3E0'), 'Heavy': ('#B42318', '#FBEAEA')}


class Clock:
    def __init__(self, conf):
        self.tz, self.label = tz_extra(conf)

    def at(self, t, date=False):
        u = dt.datetime.fromtimestamp(t, UTC)
        s = u.strftime('%b %d %H:%M' if date else '%H:%M') + ' UTC'
        if self.tz:
            s += f" ({u.astimezone(self.tz).strftime('%H:%M')} {self.label})"
        return s

    def short(self, t):
        return dt.datetime.fromtimestamp(t, UTC).strftime('%H:%M')

    def local_short(self, t):
        return dt.datetime.fromtimestamp(t, UTC).astimezone(self.tz).strftime('%H:%M') if self.tz else ''


def fmt_minutes(m):
    if m < 60:
        return f'{m} min'
    return f'{m // 60} h {m % 60} min' if m % 60 else f'{m // 60} h'


def email_chart(st, clock, slots=96):
    """A bar chart made of table cells, so it shows in Gmail, Outlook and phone mail apps alike."""
    start, end = st['start'], st['end']
    width = (end - start) / slots
    bars = [None] * slots
    marks = [0] * slots
    for m, v in st['minutes'].items():
        i = min(slots - 1, int((m - start) // width))
        bars[i] = v[1] if bars[i] is None else max(bars[i], v[1])
    for t in st['events']['slow'] + st['events']['full']:
        i = min(slots - 1, int((t - start) // width))
        marks[i] += 1
    top = max([10.0] + [b for b in bars if b is not None])
    top = float(int((top + 4.999) // 5 * 5))
    hpx = 120
    thr = st['threshold']
    cells = []
    for b in bars:
        if b is None:
            cells.append(f'<td width="6" valign="bottom" style="padding:0 1px 0 0;">'
                         f'<div style="height:{hpx}px;background:{COL["ground"]};"></div></td>')
            continue
        h = max(1, int(round(b / top * hpx)))
        colour = COL['flame'] if b >= thr else COL['amber'] if b >= 10 else COL['bar']
        cells.append(f'<td width="6" valign="bottom" style="padding:0 1px 0 0;">'
                     f'<div style="height:{hpx - h}px;font-size:0;line-height:0;"></div>'
                     f'<div style="height:{h}px;background:{colour};font-size:0;line-height:0;"></div></td>')
    mark_cells = ''.join(
        f'<td width="6" style="padding:0 1px 0 0;height:8px;">'
        f'<div style="height:6px;border-radius:3px;background:{COL["flame"] if k else "transparent"};"></div></td>'
        for k in marks)
    # hour labels every 3 hours (one colspan cell per 12 slots for a 24-hour report)
    per = max(1, slots // 8)
    labels, local = [], []
    for i in range(0, slots, per):
        t = start + i * width
        labels.append(f'<td colspan="{per}" style="font:11px Arial,sans-serif;color:{COL["sub"]};padding-top:4px;">'
                      f'{clock.short(t)}</td>')
        if clock.tz:
            local.append(f'<td colspan="{per}" style="font:10px Arial,sans-serif;color:{COL["sub"]};">'
                         f'{clock.local_short(t)}</td>')
    rows = [f'<tr>{"".join(cells)}</tr>']
    if st['events']['slow'] or st['events']['full']:
        rows.append(f'<tr>{mark_cells}</tr>')
    rows.append(f'<tr>{"".join(labels)}</tr>')
    if local:
        rows.append(f'<tr>{"".join(local)}</tr>')
    scale = (f'<div style="font:11px Arial,sans-serif;color:{COL["sub"]};margin:0 0 4px;">'
             f'Steal per 15 minutes (worst minute in each slot), scale 0 to {top:.0f}%</div>')
    return (scale + '<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
            'style="border-collapse:collapse;table-layout:fixed;">' + ''.join(rows) + '</table>')


def build_report(conf, start, end, test=False):
    clock = Clock(conf)
    st = range_stats(conf, start, end)
    worst = st['worst']
    site = conf.get('SITE_LABEL') or 'PHP'
    has_php = bool(conf.get('PHP_SLOWLOG') or conf.get('PHP_FPM_LOG'))
    full_day = end - start >= 23 * 3600
    period = (dt.datetime.fromtimestamp(start, UTC).strftime('%a %b %d, %Y') + ' (UTC day)' if full_day
              else f'{clock.at(start, True)} to {clock.at(end, True)}')
    host = host_label(conf)
    subject = (f"{'TEST: ' if test else ''}{host} CPU steal "
               f"{dt.datetime.fromtimestamp(start, UTC):%b %d}: avg {st['mean']:.1f}%, "
               f"worst minute {worst[1][1] if worst else 0:.0f}% ({st['level']})")

    tiles = [
        ('Average steal', f"{st['mean']:.1f}%", f"about {st['mean'] / 100 * ncpu():.2f} of {ncpu()} vCPUs"),
        ('Worst minute', f"{worst[1][1]:.0f}%" if worst else '-', clock.at(worst[0]) if worst else 'no data'),
        (f"Minutes at {st['threshold']:.0f}% or more", str(st['over'][st['threshold']]),
         f"longest run {fmt_minutes(st['longest'])}" if st['longest'] else 'no episodes'),
    ]
    if has_php:
        tiles.append((f'Slow PHP requests', str(len(st['events']['slow'])),
                      f"{site}; pool full {len(st['events']['full'])} times"))
    else:
        tiles.append(('Own CPU use', f"{st['busy']:.0f}%", 'what this server itself used'))

    # 7-day trend: own data where we have it, sar before that
    last = dt.datetime.fromtimestamp(end - 1, UTC).date()
    sar = load_sar()
    trend = []
    for i in range(6, -1, -1):
        d = last - dt.timedelta(days=i)
        s = day_summary(d, conf)
        if s['minutes']:
            trend.append((d, s['avg'], s['worst'], s['slow'], 'own'))
        else:
            lo = day_start(d)
            pts = [p[1] for p in sar if lo <= p[0] < lo + 86400]
            trend.append((d, sum(pts) / len(pts) if pts else None, max(pts) if pts else None, s['slow'], 'sar'))

    # ---- plain text
    txt = [subject, '', st['level'] + ': ' + st['sentence'], f'Period: {period}', '']
    txt += [f'{k}: {v}, {s}' for k, v, s in tiles]
    if has_php:
        txt.append(f"Own CPU use: {st['busy']:.1f}% (what this server itself used)")
    txt += [f"Samples: {st['samples']:,} of {st['expected']:,} ({st['coverage']:.0f}%)", '']
    txt.append(f"Episodes (1-minute average {st['threshold']:.0f}% or more):")
    for e in st['episodes'][:12] or []:
        txt.append(f"  {clock.at(e['start'])}  {fmt_minutes(e['minutes'])}  avg {e['avg']:.0f}%  worst minute {e['worst']:.0f}%")
    if not st['episodes']:
        txt.append('  none')
    txt += ['', 'Last 7 days: average / worst minute (or worst 10 min from sar) / slow PHP']
    for d, avg, wst, slow, src in trend:
        if avg is None:
            txt.append(f'  {d:%a %b %d}  no data')
        else:
            txt.append(f"  {d:%a %b %d}  {avg:.1f}% / {wst:.0f}%{' (sar)' if src == 'sar' else ''} / {slow}")
    if conf.get('WEB_URL'):
        txt += ['', f"Dashboard: {conf['WEB_URL']}"]
    txt += ['', footer_text(conf)]

    # ---- HTML
    e = html.escape
    fg, tint = LEVEL_COL[st['level']]
    font = 'font-family:Montserrat,Arial,Helvetica,sans-serif;'
    tile_cells = []
    for k, v, s in tiles:
        tile_cells.append(
            f'<td width="50%" valign="top" style="padding:6px;">'
            f'<div style="border:1px solid {COL["line"]};border-radius:12px;padding:12px 14px;">'
            f'<div style="{font}font-size:12px;font-weight:600;color:{COL["sub"]};">{e(k)}</div>'
            f'<div style="{font}font-size:26px;font-weight:800;color:#111111;line-height:1.25;">{e(v)}</div>'
            f'<div style="{font}font-size:12px;color:{COL["sub"]};">{e(s)}</div></div></td>')
    tiles_html = ('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">'
                  f'<tr>{tile_cells[0]}{tile_cells[1]}</tr><tr>{tile_cells[2]}{tile_cells[3]}</tr></table>')
    td = f'style="{font}padding:6px 8px;border-bottom:1px solid {COL["line"]};font-size:13px;color:{COL["ink"]};"'
    tdr = f'style="{font}padding:6px 8px;border-bottom:1px solid {COL["line"]};font-size:13px;color:{COL["ink"]};text-align:right;white-space:nowrap;"'
    th = f'style="{font}padding:6px 8px;background:{COL["navy"]};color:#ffffff;font-size:12px;text-align:left;"'
    thr = f'style="{font}padding:6px 8px;background:{COL["navy"]};color:#ffffff;font-size:12px;text-align:right;"'
    h2 = f'style="{font}font-size:16px;font-weight:700;color:#111111;margin:24px 0 8px;"'
    if st['episodes']:
        top_eps = sorted(st['episodes'], key=lambda x: -x['worst'])[:10]
        ep_rows = ''.join(f'<tr><td {td}>{e(clock.at(x["start"]))}</td><td {tdr}>{fmt_minutes(x["minutes"])}</td>'
                          f'<td {tdr}>{x["avg"]:.0f}%</td><td {tdr}>{x["worst"]:.0f}%</td></tr>'
                          for x in sorted(top_eps, key=lambda x: x['start']))
        episodes_html = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">'
                         f'<tr><th {th}>Started</th><th {thr}>Length</th><th {thr}>Average</th><th {thr}>Worst minute</th></tr>'
                         f'{ep_rows}</table>')
        if len(st['episodes']) > 10:
            episodes_html += f'<div style="{font}font-size:12px;color:{COL["sub"]};margin-top:4px;">The 10 worst of {len(st["episodes"])}.</div>'
    else:
        episodes_html = f'<div style="{font}font-size:13px;color:{COL["sub"]};">None.</div>'
    tmax = max([10.0] + [x[2] for x in trend if x[2] is not None])
    trend_rows = []
    for d, avg, wst, slow, src in trend:
        if avg is None:
            trend_rows.append(f'<tr><td {td}>{d:%a %b %d}</td><td {td} colspan="3">no data</td></tr>')
            continue
        w = max(2, int(140 * wst / tmax))
        colour = COL['flame'] if wst >= st['threshold'] else COL['amber'] if wst >= 10 else COL['bar']
        trend_rows.append(
            f'<tr><td {td}>{d:%a %b %d}</td><td {tdr}>{avg:.1f}%</td>'
            f'<td {td}><div style="width:{w}px;height:10px;border-radius:3px;background:{colour};display:inline-block;"></div>'
            f' <span style="{font}font-size:12px;color:{COL["sub"]};">{wst:.0f}%{" (sar)" if src == "sar" else ""}</span></td>'
            f'<td {tdr}>{slow if has_php else ""}</td></tr>')
    trend_html = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">'
                  f'<tr><th {th}>Day (UTC)</th><th {thr}>Average</th><th {th}>Worst minute</th>'
                  f'<th {thr}>{"Slow PHP" if has_php else ""}</th></tr>{"".join(trend_rows)}</table>')
    link = ''
    if conf.get('WEB_URL'):
        link = (f'<p style="margin:22px 0 0;"><a href="{e(conf["WEB_URL"])}" style="{font}display:inline-block;'
                f'background:{COL["flame"]};color:#ffffff;text-decoration:none;font-weight:700;font-size:14px;'
                f'padding:12px 22px;border-radius:8px;">Open the dashboard</a></p>')
    page = (
        f'<div style="{font}max-width:640px;margin:0 auto;color:{COL["ink"]};">'
        f'<div style="{font}font-size:12px;font-weight:700;color:#C73E0C;letter-spacing:.05em;text-transform:uppercase;">'
        f'{e(host)} &middot; CPU steal</div>'
        f'<h1 style="{font}font-size:22px;font-weight:800;color:#111111;margin:4px 0 2px;">{e(period)}</h1>'
        f'<div style="{font}background:{tint};color:{fg};border-radius:12px;padding:12px 16px;font-size:14px;'
        f'font-weight:700;margin:12px 0 8px;">{e(st["level"])}: {e(st["sentence"])}</div>'
        f'{tiles_html}'
        f'<h2 {h2}>The day at a glance</h2>{email_chart(st, clock)}'
        f'<div style="{font}font-size:12px;color:{COL["sub"]};margin-top:6px;">'
        f'Orange: a minute at {st["threshold"]:.0f}% or more. Amber: 10% or more. '
        + ('Dots under the bars: slow PHP requests or a full PHP pool. ' if (st['events']['slow'] or st['events']['full']) else '')
        + f'Own CPU use averaged {st["busy"]:.0f}%.</div>'
        f'<h2 {h2}>Episodes</h2>{episodes_html}'
        f'<h2 {h2}>Last 7 days</h2>{trend_html}'
        f'{link}'
        f'<p style="{font}font-size:12px;color:{COL["sub"]};line-height:1.5;margin-top:24px;">'
        f'Samples: {st["samples"]:,} of {st["expected"]:,} ({st["coverage"]:.0f}%). {e(footer_text(conf))}</p></div>')
    return subject, '\n'.join(txt), page


def footer_text(conf):
    return (f"Steal is CPU time the host gave to other virtual machines instead of this one. Under about 2% is normal; "
            f"long runs at {float(conf.get('EPISODE_PCT') or 20):.0f}% or more make sites slow. "
            f"Sent by {NAME} {VERSION} ({REPO_URL}). Stop these emails: systemctl disable --now {NAME}-report.timer")


def send_mail(conf, subject, text, page, to=None):
    to = to or conf.get('MAIL_TO')
    if not to:
        raise SystemExit('No email address configured (MAIL_TO). Run: cpu-steal-monitor setup')
    sender = conf.get('MAIL_FROM') or f'{NAME}@{fqdn()}'
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = to
    msg['Date'] = formatdate(localtime=False)
    addr = re.search(r'[\w.+-]+@[\w.-]+', sender)
    envelope = addr.group(0) if addr else sender
    msg['Message-ID'] = make_msgid(domain=envelope.split('@')[-1])
    msg.set_content(text)
    msg.add_alternative('<!doctype html><html><body style="margin:0;padding:16px;background:#ffffff;">'
                        f'{page}</body></html>', subtype='html')
    if conf.get('MAIL_TRANSPORT') == 'smtp':
        port = int(conf.get('SMTP_PORT') or 587)
        sec = conf.get('SMTP_SECURITY') or 'starttls'
        cls = smtplib.SMTP_SSL if sec == 'ssl' else smtplib.SMTP
        with cls(conf['SMTP_HOST'], port, timeout=60) as s:
            if sec == 'starttls':
                s.starttls()
            if conf.get('SMTP_USER'):
                s.login(conf['SMTP_USER'], conf.get('SMTP_PASSWORD', ''))
            s.send_message(msg, from_addr=envelope, to_addrs=[to])
    else:
        sendmail = conf.get('SENDMAIL') or '/usr/sbin/sendmail'
        subprocess.run([sendmail, '-t', '-oi', '-f', envelope], input=msg.as_bytes(), check=True, timeout=60)


def report_range(args):
    now = int(time.time())
    if getattr(args, 'hours', None):
        return now - int(args.hours * 3600), now
    day = dt.date.fromisoformat(args.day) if getattr(args, 'day', None) else (
        dt.datetime.now(UTC) - dt.timedelta(days=1)).date()
    start = day_start(day)
    return start, start + 86400


def cmd_report(args):
    conf = load_conf()
    start, end = report_range(args)
    subject, text, page = build_report(conf, start, end, test=args.test)
    if args.stdout or args.html:
        if args.html:
            with open(args.html, 'w') as f:
                f.write(f'<!doctype html><meta charset="utf-8"><title>{html.escape(subject)}</title>'
                        f'<body style="margin:0;padding:16px;background:#fff">{page}')
        if args.stdout:
            print(text)
        return 0
    send_mail(conf, subject, text, page, to=args.to)
    print(f"Sent to {args.to or conf['MAIL_TO']}: {subject}")
    return 0


# ---------------------------------------------------------------- ticket

def ticket_text(conf, start, end):
    st = range_stats(conf, start, end)
    clock = Clock(conf)
    worst = st['worst']
    lines = [
        'Subject: High CPU steal time on our VPS',
        '',
        'Hello,',
        '',
        f"Our VPS ({host_label(conf)}, {ncpu()} vCPUs) is getting a lot of CPU steal time, which makes our sites slow "
        "even though our own load is low. We measure steal from /proc/stat every 5 seconds.",
        '',
        f"Period: {clock.at(start, True)} to {clock.at(end, True)}",
        f"- Average steal: {st['mean']:.1f}% (about {st['mean'] / 100 * ncpu():.1f} of {ncpu()} vCPUs)",
        f"- 95th percentile of 5-second samples: {st['p95']:.1f}%; highest sample {st['peak']:.1f}%",
        f"- Worst minute: {worst[1][1]:.0f}% at {clock.at(worst[0], True)}" if worst else '- Worst minute: no data',
        f"- Minutes averaging {st['threshold']:.0f}% or more: {st['over'][st['threshold']]}",
        f"- Our own CPU use in the same period: {st['busy']:.1f}% on average",
    ]
    if st['episodes']:
        lines += ['', 'Worst episodes (UTC):']
        for e in sorted(st['episodes'], key=lambda x: -x['worst'])[:10]:
            lines.append(f"- {clock.at(e['start'], True)}: {fmt_minutes(e['minutes'])}, "
                         f"average {e['avg']:.0f}%, worst minute {e['worst']:.0f}%")
    lines += ['', 'Could you check the load on the host node, or move our VPS to a less busy node?', '', 'Thank you.']
    return '\n'.join(lines)


def cmd_ticket(args):
    conf = load_conf()
    if args.since:
        start = int(dt.datetime.fromisoformat(args.since).replace(tzinfo=UTC).timestamp())
        end = int(dt.datetime.fromisoformat(args.until).replace(tzinfo=UTC).timestamp()) if args.until else int(time.time())
    else:
        start, end = report_range(args)
    print(ticket_text(conf, start, end))
    return 0


# ---------------------------------------------------------------- sar import

def cmd_import_sar(_args=None, quiet=False):
    """Read sysstat's daily files (10-minute averages) so the dashboard has history from day one."""
    if not shutil.which('sadf'):
        if not quiet:
            print('sysstat (sadf) is not installed; nothing to import.')
        return 0
    files = sorted(glob.glob('/var/log/sa/sa[0-9][0-9]') + glob.glob('/var/log/sysstat/sa[0-9][0-9]')
                   + glob.glob('/var/log/sysstat/sa[0-9]*[0-9]'))
    points = {}
    for path in files:
        try:
            out = subprocess.run(['sadf', '-d', path, '--', '-u'], capture_output=True, text=True, timeout=60,
                                 env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        header = None
        for line in out.splitlines():
            if line.startswith('#'):
                header = [h.strip() for h in line.lstrip('# ').split(';')]
                continue
            p = line.split(';')
            if not header or len(p) != len(header):
                continue
            row = dict(zip(header, p))
            try:
                interval = int(row['interval'])
                stamp = row['timestamp']
                if row.get('CPU') not in ('-1', 'all') or not (300 <= interval <= 3600):
                    continue
                steal, idle = float(row['%steal']), float(row['%idle'])
                iowait = float(row.get('%iowait', 0))
            except (KeyError, ValueError):
                continue
            ts = stamp.replace(' UTC', '')
            try:
                t = dt.datetime.strptime(ts[:19], '%Y-%m-%d %H:%M:%S').replace(tzinfo=UTC)
            except ValueError:
                continue
            points[int(t.timestamp())] = [int(t.timestamp()), round(steal, 2), round(100 - idle - steal - iowait, 2)]
    old = {p[0]: p for p in load_sar()}
    old.update(points)
    merged = sorted(old.values())
    os.makedirs(DATA, exist_ok=True)
    write_atomic(f'{DATA}/sar.json', json.dumps({'points': merged}, separators=(',', ':')))
    if not quiet:
        print(f'Imported {len(points)} sar points ({len(merged)} kept).')
    return 0


# ---------------------------------------------------------------- update (rollups + web data)

def web_owner(web_dir):
    try:
        s = os.stat(web_dir)
        return s.st_uid, s.st_gid
    except OSError:
        return None


def write_web(conf, changed_days):
    web = conf.get('WEB_DIR')
    if not web:
        return
    tpl = os.path.join(APP_DIR, 'dashboard.html')
    with open(tpl) as f:
        files = {'index.html': f.read()}
    days = all_days()
    hours, episodes, daylist = [], [], []
    for d in days:
        s = day_summary(d, conf)
        hours.extend(s['hours'])
        episodes.extend(s['episodes'])
        daylist.append([d.isoformat(), s['avg'], s['worst'], s['busy'], s['slow'], s['full'], s['minutes']])
    for d in changed_days:
        start = day_start(d)
        minutes = load_minutes(start, start + 86400)
        events = load_events(start, start + 86400)
        rows = [[(m - start) // 60, round(v[1], 1), round(v[2], 1), round(v[3], 1)] for m, v in sorted(minutes.items())]
        body = {'day': d.isoformat(), 'start': start, 'm': rows,
                'slow': [t - start for t in events['slow']], 'full': [t - start for t in events['full']]}
        files[f'data/day/{d.isoformat()}.json'] = json.dumps(body, separators=(',', ':'))
    tz, label = tz_extra(conf)
    meta = {
        'host': host_label(conf), 'ncpu': ncpu(), 'generated': int(time.time()), 'version': VERSION,
        'threshold': float(conf.get('EPISODE_PCT') or 20), 'extraTz': conf.get('EXTRA_TZ', '') if tz else '',
        'extraTzLabel': label, 'site': conf.get('SITE_LABEL', ''),
        'php': bool(conf.get('PHP_SLOWLOG') or conf.get('PHP_FPM_LOG')),
        'days': daylist, 'repo': REPO_URL,
    }
    files['data/meta.json'] = json.dumps(meta, separators=(',', ':'))
    files['data/hours.json'] = json.dumps({'h': hours}, separators=(',', ':'))
    files['data/episodes.json'] = json.dumps({'e': episodes}, separators=(',', ':'))
    files['data/sar.json'] = json.dumps({'points': load_sar()}, separators=(',', ':'))
    as_owner(web, lambda: put_web_files(web, files, {d.isoformat() for d in days}))


def as_owner(web, job):
    """Run job() as the user who owns the dashboard folder. Root never writes inside a folder
    that another user controls, so a symlink planted there can't turn into a root write."""
    owner = web_owner(web)
    if os.geteuid() != 0 or not owner or owner[0] == 0:
        return job()
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            os.setgroups([])
            os.setgid(owner[1])
            os.setuid(owner[0])
            job()
            code = 0
        except BaseException as exc:  # report and leave the child; never fall back to root
            print(f'dashboard write failed: {exc}', file=sys.stderr)
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    if status:
        raise SystemExit('Could not write the dashboard files (see the error above).')


def put_web_files(web, files, keep):
    os.makedirs(f'{web}/data/day', exist_ok=True)
    for rel, body in files.items():
        path = f'{web}/{rel}'
        if rel == 'index.html' and os.path.isfile(path):
            with open(path) as f:
                if f.read() == body:
                    continue
        write_atomic(path, body)
    for p in glob.glob(f'{web}/data/day/*.json'):
        if os.path.basename(p)[:10] not in keep:
            os.remove(p)


def prune(conf):
    now = time.time()
    raw_days = int(conf.get('RAW_DAYS') or 35)
    keep_days = int(conf.get('KEEP_DAYS') or 400)
    for sub, days in (('raw', raw_days), ('minutes', keep_days), ('events', keep_days), ('cache', keep_days)):
        for p in glob.glob(f'{DATA}/{sub}/*.*'):
            try:
                if os.path.getmtime(p) < now - days * 86400:
                    os.remove(p)
            except OSError:
                pass


def cmd_update(args=None):
    conf = load_conf()
    os.makedirs(DATA, exist_ok=True)
    ingest_events(conf)
    today = dt.datetime.now(UTC).date()
    web = conf.get('WEB_DIR')
    rebuild = getattr(args, 'all', False) or bool(web and not glob.glob(f'{web}/data/day/*.json'))
    recent = today - dt.timedelta(days=1)
    changed = all_days() if rebuild else [d for d in all_days() if d >= recent]
    for d in changed:
        day_summary(d, conf, force=d < recent)
    write_web(conf, changed)
    prune(conf)
    return 0


# ---------------------------------------------------------------- status

def cmd_status(_args):
    conf = load_conf()
    print(f'{NAME} {VERSION}')
    for unit in (f'{NAME}.service', f'{NAME}-update.timer', f'{NAME}-report.timer'):
        state = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True).stdout.strip() \
            if shutil.which('systemctl') else 'n/a'
        print(f'  {unit:34} {state}')
    now = int(time.time())
    raw = load_raw(now - 600, now + 10)
    if raw:
        last = raw[-1]
        print(f'  last sample {now - last[0]} s ago: steal {last[1]:.1f}%, own CPU use {last[2]:.1f}%')
        print(f'  last 10 minutes: average steal {sum(r[1] for r in raw) / len(raw):.1f}%, highest {max(r[1] for r in raw):.1f}%')
    else:
        print('  no samples in the last 10 minutes')
    st = range_stats(conf, now - 86400, now)
    print(f"  last 24 hours: average {st['mean']:.1f}%, worst minute "
          f"{st['worst'][1][1] if st['worst'] else 0:.0f}%, episodes {len(st['episodes'])} ({st['level']})")
    print(f"  email: {conf.get('MAIL_TO') or 'off'}; dashboard: {conf.get('WEB_URL') or conf.get('WEB_DIR') or 'off'}")
    return 0


# ---------------------------------------------------------------- setup / uninstall

def tty_input(prompt):
    if sys.stdin.isatty():
        return input(prompt)
    try:
        with open('/dev/tty', 'r+') as tty:
            tty.write(prompt)
            tty.flush()
            return tty.readline().rstrip('\n')
    except OSError:
        return ''


def ask(prompt, default='', yes=False):
    if yes:
        return default
    shown = f' [{default}]' if default else ''
    value = tty_input(f'{prompt}{shown}: ').strip()
    return value or default


def ask_yes(prompt, default=True, yes=False):
    if yes:
        return default
    value = tty_input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not value else value.startswith('y')


def apr1(password, salt=None):
    """Apache's $apr1$ MD5 password hash (works for Apache and nginx basic auth)."""
    itoa = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    salt = salt or ''.join(secrets.choice(itoa) for _ in range(8))
    pw, magic = password.encode(), b'$apr1$'
    s = salt.encode()
    alt = hashlib.md5(pw + s + pw).digest()
    ctx = pw + magic + s
    ctx += (alt * (len(pw) // 16 + 1))[:len(pw)]
    i = len(pw)
    while i:
        ctx += b'\x00' if i & 1 else pw[:1]
        i >>= 1
    final = hashlib.md5(ctx).digest()
    for i in range(1000):
        c = (pw if i & 1 else final) + (s if i % 3 else b'') + (pw if i % 7 else b'') + (final if i & 1 else pw)
        final = hashlib.md5(c).digest()

    def b64(v, n):
        out = ''
        while n > 0:
            out += itoa[v & 0x3f]
            v >>= 6
            n -= 1
        return out
    f = final
    h = (b64((f[0] << 16) | (f[6] << 8) | f[12], 4) + b64((f[1] << 16) | (f[7] << 8) | f[13], 4)
         + b64((f[2] << 16) | (f[8] << 8) | f[14], 4) + b64((f[3] << 16) | (f[9] << 8) | f[15], 4)
         + b64((f[4] << 16) | (f[10] << 8) | f[5], 4) + b64(f[11], 2))
    return f'$apr1${salt}${h}'


def detect_paths(patterns):
    found = []
    for p in patterns:
        found += glob.glob(p)
    return sorted(set(found))


def web_server():
    names = subprocess.run(['ps', '-eo', 'comm'], capture_output=True, text=True).stdout.split()
    if any(n in ('httpd', 'apache2', 'lshttpd', 'litespeed') for n in names):
        return 'apache'
    if 'nginx' in names:
        return 'nginx'
    return ''


def unit_files(conf, py):
    app = os.path.join(APP_DIR, 'cpu_steal_monitor.py')
    run = f'{py} -I {app}'
    hh, mm = (conf.get('REPORT_TIME') or '00:30').split(':')
    return {
        f'{NAME}.service': f"""[Unit]
Description=CPU steal monitor: sample /proc/stat every 5 seconds
After=local-fs.target

[Service]
ExecStart={run} sample
Restart=always
RestartSec=10
Nice=10
MemoryMax=64M
CPUQuota=10%

[Install]
WantedBy=multi-user.target
""",
        f'{NAME}-update.service': f"""[Unit]
Description=CPU steal monitor: roll up data and refresh the dashboard

[Service]
Type=oneshot
ExecStart={run} update
Nice=15
IOSchedulingClass=idle
MemoryMax=256M
TimeoutStartSec=240
""",
        f'{NAME}-update.timer': f"""[Unit]
Description=CPU steal monitor: refresh every 5 minutes

[Timer]
OnCalendar=*:0/5
AccuracySec=30s

[Install]
WantedBy=timers.target
""",
        f'{NAME}-report.service': f"""[Unit]
Description=CPU steal monitor: daily email report

[Service]
Type=oneshot
ExecStart={run} report
Nice=15
MemoryMax=256M
TimeoutStartSec=300
""",
        f'{NAME}-report.timer': f"""[Unit]
Description=CPU steal monitor: daily email report at {hh}:{mm} (server time)

[Timer]
OnCalendar=*-*-* {int(hh):02d}:{int(mm):02d}:00
Persistent=true

[Install]
WantedBy=timers.target
""",
    }


def systemctl(*args):
    return subprocess.run(['systemctl', *args], capture_output=True, text=True)


def cmd_setup(args):
    if os.geteuid() != 0 and not os.environ.get('CSM_TEST'):
        raise SystemExit('Run setup as root (sudo cpu-steal-monitor setup).')
    conf = load_conf()
    yes = args.yes
    print(f'\n{NAME} {VERSION} setup. Press Enter to keep the value in [brackets].\n')
    virt = subprocess.run(['systemd-detect-virt'], capture_output=True, text=True).stdout.strip() \
        if shutil.which('systemd-detect-virt') else ''
    if virt in ('lxc', 'lxc-libvirt', 'openvz', 'docker', 'podman', 'wsl'):
        print(f'Note: this looks like a container ({virt}). Containers usually show 0% steal; '
              'the numbers are only meaningful on a full virtual machine (KVM, Xen, VMware, Hyper-V).\n')

    # 1. email
    if args.no_email:
        conf['MAIL_TO'] = ''
    elif args.email is not None:
        conf['MAIL_TO'] = args.email
    else:
        conf['MAIL_TO'] = ask('Email address for the daily report (leave empty for no email)', conf['MAIL_TO'], yes)
    if conf['MAIL_TO']:
        if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', conf['MAIL_TO']):
            raise SystemExit(f"That doesn't look like an email address: {conf['MAIL_TO']}")
        conf['REPORT_TIME'] = args.report_time or ask('Send it at what time each day (HH:MM, server time)',
                                                      conf['REPORT_TIME'] or '00:30', yes)
        if not re.fullmatch(r'([01]?\d|2[0-3]):[0-5]\d', conf['REPORT_TIME']):
            raise SystemExit('The report time must look like 07:30.')
        conf['MAIL_FROM'] = args.mail_from or ask('Send from this address', conf['MAIL_FROM'] or f'{NAME}@{fqdn()}', yes)
        if args.smtp_host:
            conf.update(MAIL_TRANSPORT='smtp', SMTP_HOST=args.smtp_host, SMTP_PORT=str(args.smtp_port or 587),
                        SMTP_SECURITY=args.smtp_security or 'starttls', SMTP_USER=args.smtp_user or '',
                        SMTP_PASSWORD=args.smtp_password or '')
        elif args.sendmail or (shutil.which('sendmail') or os.path.exists('/usr/sbin/sendmail')):
            path = args.sendmail or shutil.which('sendmail') or '/usr/sbin/sendmail'
            if args.sendmail or ask_yes(f'Send with the local mail server ({path})?', True, yes):
                conf.update(MAIL_TRANSPORT='sendmail', SENDMAIL=path)
            else:
                ask_smtp(conf, yes)
        else:
            print('No local sendmail found, so the report goes out through an SMTP server.')
            ask_smtp(conf, yes)
    if args.tz is not None:
        conf['EXTRA_TZ'] = args.tz
    elif not yes:
        conf['EXTRA_TZ'] = ask('Also show times in this time zone (e.g. America/New_York, empty for UTC only)',
                               conf['EXTRA_TZ'], yes)
    if conf['EXTRA_TZ'] and ZoneInfo is not None:
        try:
            ZoneInfo(conf['EXTRA_TZ'])
        except Exception:
            raise SystemExit(f"Unknown time zone: {conf['EXTRA_TZ']}")
    if args.tz_label is not None:
        conf['EXTRA_TZ_LABEL'] = args.tz_label

    # 2. dashboard
    if args.no_web:
        conf['WEB_DIR'] = conf['WEB_URL'] = ''
    elif args.web_dir is not None:
        conf['WEB_DIR'] = args.web_dir.rstrip('/')
        conf['WEB_URL'] = args.web_url or conf['WEB_URL']
    elif not yes:
        conf['WEB_DIR'] = ask('Web dashboard: a folder inside a website to publish it to '
                              '(e.g. /var/www/html/cpu-steal, empty to skip)', conf['WEB_DIR']).rstrip('/')
        if conf['WEB_DIR']:
            conf['WEB_URL'] = ask("That folder's address in a browser (for the email link)", conf['WEB_URL'])
    password_note = ''
    if conf['WEB_DIR']:
        if not os.path.isdir(conf['WEB_DIR']):
            os.makedirs(conf['WEB_DIR'])
            parent = web_owner(os.path.dirname(conf['WEB_DIR']))
            if parent and os.geteuid() == 0:
                os.chown(conf['WEB_DIR'], *parent)
        protect = not args.no_web_password and (args.web_password or args.web_password_file
                                                or ask_yes('Protect the dashboard with a password?', True, yes))
        if protect:
            user = args.web_user or ask('Dashboard user name', 'admin', yes)
            if args.web_password_file:
                with open(args.web_password_file) as f:
                    password = f.read().strip()
            else:
                password = args.web_password or (getpass.getpass('Dashboard password (empty = make one up): ')
                                                 if not yes and sys.stdin.isatty() else '')
            if not password:
                password = secrets.token_urlsafe(12)
                password_note = f'Dashboard login: {user} / {password}  (shown once; change it with setup)'
            write_atomic(HTPASSWD, f'{user}:{apr1(password)}\n', mode=0o644)
            server = web_server()
            if server != 'nginx':
                write_atomic(f"{conf['WEB_DIR']}/.htaccess",
                             f'# {MARK}: password protection for the dashboard\n'
                             f'AuthType Basic\nAuthName "CPU steal monitor"\nAuthUserFile {HTPASSWD}\nRequire valid-user\n'
                             '# Keeps a CMS in the parent folder (e.g. WordPress) from swallowing the login prompt\n'
                             'ErrorDocument 401 default\n'
                             '<IfModule mod_headers.c>\n  Header set Cache-Control "private, no-store"\n</IfModule>\n',
                             owner=web_owner(conf['WEB_DIR']))
            if server == 'nginx':
                print('\nnginx: add this inside the server block for the dashboard, then reload nginx:\n'
                      f'  location /{os.path.basename(conf["WEB_DIR"])}/ {{\n'
                      f'    auth_basic "CPU steal monitor";\n    auth_basic_user_file {HTPASSWD};\n'
                      '    add_header Cache-Control "private, no-store";\n  }\n')

    # 3. PHP-FPM signals
    if args.php_slowlog is not None:
        conf['PHP_SLOWLOG'] = args.php_slowlog
    elif not yes:
        found = detect_paths(['/var/log/php*-fpm*slow*.log', '/var/log/php-fpm/*slow*.log', '/var/log/php*/*slow*.log',
                              '/usr/local/apps/php*/var/log/*slow*', '/opt/remi/php*/root/var/log/php-fpm/*slow*.log'])
        hint = f" (found: {', '.join(found[:4])})" if found else ''
        conf['PHP_SLOWLOG'] = ask(f'Optional: PHP-FPM slow log(s) to count slow requests from{hint}; '
                                  'comma-separated globs, empty to skip', conf['PHP_SLOWLOG'])
    if args.php_fpm_log is not None:
        conf['PHP_FPM_LOG'] = args.php_fpm_log
    elif not yes:
        found = detect_paths(['/var/log/php*-fpm.log', '/var/log/php-fpm/error.log', '/usr/local/apps/php*/var/log/php-fpm.log'])
        hint = f" (found: {', '.join(found[:4])})" if found else ''
        conf['PHP_FPM_LOG'] = ask(f"Optional: PHP-FPM error log(s) to watch for 'max_children' (pool full){hint}",
                                  conf['PHP_FPM_LOG'])
    if args.php_pool is not None:
        conf['PHP_POOL'] = args.php_pool
    elif not yes and (conf['PHP_SLOWLOG'] or conf['PHP_FPM_LOG']):
        conf['PHP_POOL'] = ask('Only this PHP-FPM pool (empty = all pools)', conf['PHP_POOL'])
    if args.site_label is not None:
        conf['SITE_LABEL'] = args.site_label
    elif not yes and (conf['PHP_SLOWLOG'] or conf['PHP_FPM_LOG']):
        conf['SITE_LABEL'] = ask('Name to show for these PHP numbers (e.g. example.com)', conf['SITE_LABEL'])
    if args.host_label is not None:
        conf['HOST_LABEL'] = args.host_label

    save_conf(conf)
    os.makedirs(DATA, mode=0o755, exist_ok=True)
    py = sys.executable or '/usr/bin/python3'
    if not os.environ.get('CSM_TEST'):
        for name, body in unit_files(conf, py).items():
            write_atomic(f'{UNIT_DIR}/{name}', body)
        write_atomic(WRAPPER, f'#!/bin/sh\nexec {py} -I {os.path.join(APP_DIR, "cpu_steal_monitor.py")} "$@"\n', mode=0o755)
        systemctl('daemon-reload')
        systemctl('enable', '--now', f'{NAME}.service')
        systemctl('restart', f'{NAME}.service')
        systemctl('enable', '--now', f'{NAME}-update.timer')
        if conf['MAIL_TO']:
            systemctl('enable', '--now', f'{NAME}-report.timer')
        else:
            systemctl('disable', '--now', f'{NAME}-report.timer')
    cmd_import_sar(quiet=True)
    cmd_update(argparse.Namespace(all=True))

    print('\nDone. The sampler is running.')
    print(f'  Config: {CONF}   Data: {DATA}')
    if conf['MAIL_TO']:
        print(f"  Daily report to {conf['MAIL_TO']} at {conf['REPORT_TIME']} server time "
              f"(covers the UTC day that ended; the first full one arrives tomorrow).")
    if conf['WEB_DIR']:
        print(f"  Dashboard: {conf['WEB_URL'] or conf['WEB_DIR']} (refreshes every 5 minutes)")
    if password_note:
        print(f'  {password_note}')
    print('  Check it any time with: cpu-steal-monitor status')
    if conf['MAIL_TO'] and (args.test_email or ask_yes('Send a test email now?', False, yes)):
        now = int(time.time())
        subject, text, page = build_report(conf, now - 3600, now, test=True)
        send_mail(conf, subject, text, page)
        print(f"  Test email sent to {conf['MAIL_TO']} (it covers the last hour, so it is mostly empty).")
    return 0


def ask_smtp(conf, yes):
    conf['MAIL_TRANSPORT'] = 'smtp'
    conf['SMTP_HOST'] = ask('SMTP server', conf['SMTP_HOST'], yes)
    conf['SMTP_PORT'] = ask('SMTP port', conf['SMTP_PORT'] or '587', yes)
    conf['SMTP_SECURITY'] = ask('Security (starttls, ssl or none)', conf['SMTP_SECURITY'] or 'starttls', yes)
    conf['SMTP_USER'] = ask('SMTP user name (empty for none)', conf['SMTP_USER'], yes)
    if conf['SMTP_USER'] and not yes:
        conf['SMTP_PASSWORD'] = getpass.getpass('SMTP password: ') or conf['SMTP_PASSWORD']


def cmd_uninstall(args):
    if os.geteuid() != 0:
        raise SystemExit('Run uninstall as root.')
    conf = load_conf()
    for unit in (f'{NAME}-report.timer', f'{NAME}-update.timer', f'{NAME}.service'):
        systemctl('disable', '--now', unit)
    for name in unit_files(conf, sys.executable).keys():
        try:
            os.remove(f'{UNIT_DIR}/{name}')
        except FileNotFoundError:
            pass
    systemctl('daemon-reload')
    web = conf.get('WEB_DIR')
    if web and os.path.isdir(web):
        for p in (f'{web}/index.html',):
            if os.path.exists(p):
                os.remove(p)
        shutil.rmtree(f'{web}/data', ignore_errors=True)
        ht = f'{web}/.htaccess'
        if os.path.exists(ht) and MARK in open(ht).read():
            os.remove(ht)
        try:
            os.rmdir(web)
        except OSError:
            pass
    for p in (WRAPPER, HTPASSWD):
        if os.path.exists(p):
            os.remove(p)
    if args.purge:
        shutil.rmtree(DATA, ignore_errors=True)
        if os.path.exists(CONF):
            os.remove(CONF)
        print(f'Removed the services, the dashboard files, {DATA} and {CONF}.')
    else:
        print(f'Removed the services and the dashboard files. Kept the data in {DATA} and the config in {CONF} '
              '(add --purge to delete them).')
    return 0


# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(prog=NAME, description='Watch CPU steal time on a Linux VPS.')
    ap.add_argument('--version', action='version', version=f'{NAME} {VERSION}')
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('sample', help='run the 5-second sampler (systemd runs this)')
    p = sub.add_parser('update', help='roll up data and refresh the dashboard (runs every 5 minutes)')
    p.add_argument('--all', action='store_true', help='rebuild every day, not just today and yesterday')
    for name, helptext in (('report', 'build the daily report and email it'), ('ticket', 'print a ticket text for your web host')):
        p = sub.add_parser(name, help=helptext)
        p.add_argument('--day', help='UTC day YYYY-MM-DD (default: yesterday)')
        p.add_argument('--hours', type=float, help='the last N hours instead of a day')
        if name == 'report':
            p.add_argument('--test', action='store_true', help='start the subject with TEST')
            p.add_argument('--stdout', action='store_true', help='print the text version, send nothing')
            p.add_argument('--html', metavar='FILE', help='write the HTML version to FILE, send nothing')
            p.add_argument('--to', help='send to this address instead of the configured one')
        else:
            p.add_argument('--since', help='start, UTC, e.g. 2026-10-27T06:00')
            p.add_argument('--until', help='end, UTC (default: now)')
    sub.add_parser('status', help='show what is running and the latest numbers')
    sub.add_parser('import-sar', help='import past steal history from sysstat')
    p = sub.add_parser('setup', help='ask the setup questions and install the systemd units')
    p.add_argument('--yes', action='store_true', help="don't ask; use the flags and current values")
    p.add_argument('--email'); p.add_argument('--no-email', action='store_true')
    p.add_argument('--report-time'); p.add_argument('--mail-from')
    p.add_argument('--sendmail'); p.add_argument('--smtp-host'); p.add_argument('--smtp-port', type=int)
    p.add_argument('--smtp-security', choices=['starttls', 'ssl', 'none'])
    p.add_argument('--smtp-user'); p.add_argument('--smtp-password')
    p.add_argument('--tz', help='extra time zone to show, e.g. America/New_York')
    p.add_argument('--tz-label', help='short name for that time zone')
    p.add_argument('--web-dir'); p.add_argument('--web-url'); p.add_argument('--no-web', action='store_true')
    p.add_argument('--web-user'); p.add_argument('--web-password'); p.add_argument('--web-password-file')
    p.add_argument('--no-web-password', action='store_true')
    p.add_argument('--php-slowlog'); p.add_argument('--php-fpm-log'); p.add_argument('--php-pool')
    p.add_argument('--site-label'); p.add_argument('--host-label')
    p.add_argument('--test-email', action='store_true', help='send a test email at the end')
    p = sub.add_parser('uninstall', help='stop and remove the services')
    p.add_argument('--purge', action='store_true', help='also delete the data and the config')
    args = ap.parse_args(argv)
    handlers = {'sample': cmd_sample, 'update': cmd_update, 'report': cmd_report, 'ticket': cmd_ticket,
                'status': cmd_status, 'import-sar': cmd_import_sar, 'setup': cmd_setup, 'uninstall': cmd_uninstall}
    return handlers[args.cmd](args) or 0


if __name__ == '__main__':
    sys.exit(main())
