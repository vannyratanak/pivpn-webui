#!/usr/bin/env bash
# Run this on the server (as the same non-root user setup.sh was run as,
# not root/sudo — matches that script's convention) to enable background
# log ingestion: Sessions/Client Sessions/Traffic move from live
# journalctl-parse-per-page-load to reading pre-parsed rows from the
# database, populated by deploy/ingest_logs.py once a minute via a systemd
# timer. See that script's docstring and app/vpnlog.py's module docstring
# for why — real 7-day parse costs (~1.5s-4s+) made those tabs slow once
# the original 3-day/6-hour windows were widened.
#
# Requires setup.sh to have already been run (needs the venv + .env +
# installed pivpn-webui-log-helper.sh with its openvpn-tail/flow-tail
# actions — reinstall that helper first if it predates those, see README).
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
  echo "Run this as your normal user (the one setup.sh was run as), not root/sudo." >&2
  exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_DIR"

if [[ ! -x venv/bin/python3 ]]; then
  echo "No venv found at $APP_DIR/venv — run ./setup.sh first." >&2
  exit 1
fi

CURRENT_USER="$(whoami)"

echo "== Installing log ingestion service + timer =="
SERVICE_TMP="$(mktemp)"
sed -e "s#__APP_DIR__#${APP_DIR}#g" -e "s/__USER__/${CURRENT_USER}/g" \
  deploy/pivpn-webui-log-ingest.service.template > "$SERVICE_TMP"
sudo install -m 0644 "$SERVICE_TMP" /etc/systemd/system/pivpn-webui-log-ingest.service
rm -f "$SERVICE_TMP"
sudo install -m 0644 deploy/pivpn-webui-log-ingest.timer /etc/systemd/system/pivpn-webui-log-ingest.timer
sudo systemctl daemon-reload
sudo systemctl enable --now pivpn-webui-log-ingest.timer

echo
echo "Running the first ingest now (this one backfills up to 7 days of"
echo "existing history — SINCE it's the very first run for each cursor,"
echo "see BACKFILL_SINCE in pivpn-webui-log-helper.sh — so it may take a"
echo "little longer than the once-a-minute runs after it)..."
sudo systemctl start pivpn-webui-log-ingest.service
sleep 2
sudo systemctl status pivpn-webui-log-ingest.service --no-pager -n 10 || true

echo
echo "Setup complete. Check progress any time with:"
echo "  sudo systemctl list-timers pivpn-webui-log-ingest.timer"
echo "  sudo journalctl -u pivpn-webui-log-ingest.service --no-pager -n 20"
