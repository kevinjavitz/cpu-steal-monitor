#!/usr/bin/env bash
# Remove cpu-steal-monitor. Keeps the data and config unless you add --purge.
set -euo pipefail
APP=/opt/cpu-steal-monitor
[ "$(id -u)" -eq 0 ] || { echo "Error: run this as root, e.g. sudo $0" >&2; exit 1; }
if [ -f "$APP/cpu_steal_monitor.py" ]; then
  python3 -I "$APP/cpu_steal_monitor.py" uninstall "$@"
fi
rm -rf "$APP"
echo "cpu-steal-monitor is removed."
