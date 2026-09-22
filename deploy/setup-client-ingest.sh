#!/usr/bin/env bash
# Run this on the server (as the same non-root user setup.sh was run as,
# not root/sudo — matches that script's convention) to enable background
# client status ingestion: GET /api/clients and GET /api/clients/<name>
# move from calling the agent live on every request to reading pre-fetched
# rows from the database, populated by deploy/ingest_clients.py every 10
# seconds via a systemd timer. See that script's docstring and
# app/db.py's client_status_cache comment for why — in HUB_MODE, that live
# call is a real multi-second WebSocket round-trip through the hub/agent
# link, repeated independently by every open browser tab's own poll.
#
# Requires setup.sh to have already been run (needs the venv + .env).
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

echo "== Installing client status ingestion service + timer =="
SERVICE_TMP="$(mktemp)"
sed -e "s#__APP_DIR__#${APP_DIR}#g" -e "s/__USER__/${CURRENT_USER}/g" \
  deploy/pivpn-webui-client-ingest.service.template > "$SERVICE_TMP"
sudo install -m 0644 "$SERVICE_TMP" /etc/systemd/system/pivpn-webui-client-ingest.service
rm -f "$SERVICE_TMP"
sudo install -m 0644 deploy/pivpn-webui-client-ingest.timer /etc/systemd/system/pivpn-webui-client-ingest.timer
sudo systemctl daemon-reload
sudo systemctl enable --now pivpn-webui-client-ingest.timer

echo
echo "Running the first ingest now..."
sudo systemctl start pivpn-webui-client-ingest.service
sleep 2
sudo systemctl status pivpn-webui-client-ingest.service --no-pager -n 10 || true

echo
echo "Setup complete. Check progress any time with:"
echo "  sudo systemctl list-timers pivpn-webui-client-ingest.timer"
echo "  sudo journalctl -u pivpn-webui-client-ingest.service --no-pager -n 20"
