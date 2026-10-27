#!/usr/bin/env bash
# Install or update cpu-steal-monitor, then run its setup questions.
#   sudo ./install.sh              ask the questions
#   sudo ./install.sh --yes ...    no questions; see `cpu-steal-monitor setup --help` for the flags
set -euo pipefail
APP=/opt/cpu-steal-monitor
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
die() { echo "Error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run this as root, e.g. sudo ./install.sh"
[ "$(uname -s)" = Linux ] || die "cpu-steal-monitor only works on Linux"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
PY="$(command -v python3 || true)"
[ -n "$PY" ] || die "python3 is required (apt install python3 / dnf install python3)"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || die "Python 3.9 or newer is required"
grep -q '^cpu ' /proc/stat || die "/proc/stat has no cpu line"

install -d -m 755 "$APP"
install -m 755 "$SRC/cpu_steal_monitor.py" "$APP/cpu_steal_monitor.py"
install -m 644 "$SRC/dashboard.html" "$APP/dashboard.html"
install -m 755 "$SRC/uninstall.sh" "$APP/uninstall.sh"
exec "$PY" -I "$APP/cpu_steal_monitor.py" setup "$@"
