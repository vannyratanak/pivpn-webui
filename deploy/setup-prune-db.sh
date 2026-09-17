#!/usr/bin/env bash
# Run this on the server (as the same non-root user setup.sh was run as,
# not root/sudo — matches that script's convention) to enable the daily
# database retention prune (deploy/prune_db.sh) via a systemd timer.
#
# Requires PIVPN_WEBUI_DB_HOST/PIVPN_WEBUI_DB_NAME/PIVPN_WEBUI_DB_USER/
# PIVPN_WEBUI_DB_PASSWORD to already be set in .env, and the psql client
# installed (apt install postgresql-client if this box only has the
# server package).
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
  echo "Run this as your normal user (the one setup.sh was run as), not root/sudo." >&2
  exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_DIR"

if [[ ! -f .env ]] || ! grep -q '^PIVPN_WEBUI_DB_PASSWORD=' .env; then
  echo "PIVPN_WEBUI_DB_HOST/NAME/USER/PASSWORD must be set in .env first." >&2
  exit 1
fi

CURRENT_USER="$(whoami)"

echo "== Installing prune service + timer =="
SERVICE_TMP="$(mktemp)"
sed -e "s#__APP_DIR__#${APP_DIR}#g" -e "s/__USER__/${CURRENT_USER}/g" \
  deploy/pivpn-webui-prune-db.service.template > "$SERVICE_TMP"
sudo install -m 0644 "$SERVICE_TMP" /etc/systemd/system/pivpn-webui-prune-db.service
rm -f "$SERVICE_TMP"
sudo install -m 0644 deploy/pivpn-webui-prune-db.timer /etc/systemd/system/pivpn-webui-prune-db.timer
sudo systemctl daemon-reload
sudo systemctl enable --now pivpn-webui-prune-db.timer

echo
echo "Running a first prune now to confirm it actually connects..."
sudo systemctl start pivpn-webui-prune-db.service
sleep 1
sudo systemctl status pivpn-webui-prune-db.service --no-pager -n 10 || true

echo
echo "Setup complete. Check progress any time with:"
echo "  sudo systemctl list-timers pivpn-webui-prune-db.timer"
echo "  sudo journalctl -u pivpn-webui-prune-db.service --no-pager -n 20"
