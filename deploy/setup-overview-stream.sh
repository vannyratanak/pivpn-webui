#!/usr/bin/env bash
set -euo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_DIR"
if [[ $EUID -eq 0 ]]; then echo 'Run as the application user, not root.' >&2; exit 1; fi
venv/bin/python3 -m pip install 'aiohttp>=3.10,<4'
service_tmp="$(mktemp)"
trap 'rm -f "$service_tmp"' EXIT
sed -e "s#__APP_DIR__#${APP_DIR}#g" -e "s/__USER__/$(whoami)/g" deploy/pivpn-webui-overview-stream.service.template > "$service_tmp"
sudo install -m 0644 "$service_tmp" /etc/systemd/system/pivpn-webui-overview-stream.service
sudo systemctl daemon-reload
sudo systemctl enable pivpn-webui-overview-stream
sudo systemctl restart pivpn-webui-overview-stream
echo 'Overview stream installed. Run setup-nginx.sh to install the /api/overview/events proxy route.'
