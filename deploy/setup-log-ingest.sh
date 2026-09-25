#!/usr/bin/env bash
# Run this on the server (as the same non-root user setup.sh was run as,
# not root/sudo — matches that script's convention) to enable background
# log ingestion: VPN and Traffic tabs use agent WebSocket streams with
# database-backed one-minute recovery; the five-second timer ingests only
# whole-system logs. See ingest_logs.py and app/vpnlog.py
# for why — real 7-day parse costs (~1.5s-4s+) made those tabs slow once
# the original 3-day/6-hour windows were widened.
#
# Requires setup.sh to have already been run (needs the venv + .env +
# installed pivpn-webui-log-helper.sh with its openvpn-tail/flow-tail
# recovery actions. The agent also needs the openvpn-follow/flow-follow
# actions from the same helper version; reinstall that helper on the agent
# before restarting pivpn-webui-agent.
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

echo "== Installing system-log ingestion service + timer =="
SERVICE_TMP="$(mktemp)"
sed -e "s#__APP_DIR__#${APP_DIR}#g" -e "s/__USER__/${CURRENT_USER}/g" \
  deploy/pivpn-webui-log-ingest.service.template > "$SERVICE_TMP"
sudo install -m 0644 "$SERVICE_TMP" /etc/systemd/system/pivpn-webui-log-ingest.service
rm -f "$SERVICE_TMP"
sudo install -m 0644 deploy/pivpn-webui-log-ingest.timer /etc/systemd/system/pivpn-webui-log-ingest.timer
EVENT_SERVICE_TMP="$(mktemp)"
sed -e "s#__APP_DIR__#${APP_DIR}#g" -e "s/__USER__/${CURRENT_USER}/g" \
  deploy/pivpn-webui-event-fallback.service.template > "$EVENT_SERVICE_TMP"
sudo install -m 0644 "$EVENT_SERVICE_TMP" /etc/systemd/system/pivpn-webui-event-fallback.service
rm -f "$EVENT_SERVICE_TMP"
sudo install -m 0644 deploy/pivpn-webui-event-fallback.timer /etc/systemd/system/pivpn-webui-event-fallback.timer
ORG_SERVICE_TMP="$(mktemp)"
sed -e "s#__APP_DIR__#${APP_DIR}#g" -e "s/__USER__/${CURRENT_USER}/g" \
  deploy/pivpn-webui-org-ingest.service.template > "$ORG_SERVICE_TMP"
sudo install -m 0644 "$ORG_SERVICE_TMP" /etc/systemd/system/pivpn-webui-org-ingest.service
rm -f "$ORG_SERVICE_TMP"
sudo install -m 0644 deploy/pivpn-webui-org-ingest.timer /etc/systemd/system/pivpn-webui-org-ingest.timer
sudo systemctl daemon-reload
sudo systemctl enable --now pivpn-webui-log-ingest.timer
sudo systemctl enable --now pivpn-webui-event-fallback.timer
sudo systemctl enable --now pivpn-webui-org-ingest.timer

echo
echo "Running the first ingest now (this one backfills up to 7 days of"
echo "existing history — since it's the very first run for each cursor,"
echo "see BACKFILL_SINCE in pivpn-webui-log-helper.sh — so it may take a"
echo "little longer than the every-10-seconds runs after it)..."
sudo systemctl start pivpn-webui-log-ingest.service
sudo systemctl start pivpn-webui-event-fallback.service
sudo systemctl start pivpn-webui-org-ingest.service
sleep 2
sudo systemctl status pivpn-webui-log-ingest.service --no-pager -n 10 || true
sudo systemctl status pivpn-webui-event-fallback.service --no-pager -n 10 || true

echo
echo "Setup complete. Check progress any time with:"
echo "  sudo systemctl list-timers pivpn-webui-log-ingest.timer"
echo "  sudo journalctl -u pivpn-webui-log-ingest.service --no-pager -n 20"
echo "  sudo systemctl list-timers pivpn-webui-event-fallback.timer"
echo "  sudo journalctl -u pivpn-webui-event-fallback.service --no-pager -n 20"
echo "  sudo systemctl list-timers pivpn-webui-org-ingest.timer"
echo "  sudo journalctl -u pivpn-webui-org-ingest.service --no-pager -n 20"
