#!/usr/bin/env bash
# Run this ON THE SERVER, after setup.sh, to put nginx + TLS in front of
# the app. gunicorn binds to 127.0.0.1 only (see BIND_HOST in .env) and is
# never meant to be reached directly — nginx is what clients actually talk
# to. Installs nginx if it's missing, generates a self-signed cert if you
# don't already have one at the target paths, and installs/enables the
# reverse-proxy vhost from deploy/nginx-pivpn-webui.conf.template.
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
  echo "Run this as your normal user (the one that ran setup.sh), not root/sudo." >&2
  exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

echo "== PiVPN Web UI: nginx + TLS setup =="

if ! command -v nginx >/dev/null 2>&1; then
  echo "nginx not found — installing it (requires sudo)."
  sudo apt-get update
  sudo apt-get install -y nginx
fi

DEFAULT_SERVER_NAME="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || true)"
read -rp "Server name (IP or hostname clients will browse to) [${DEFAULT_SERVER_NAME:-<required>}]: " SERVER_NAME
SERVER_NAME="${SERVER_NAME:-$DEFAULT_SERVER_NAME}"
if [[ -z "$SERVER_NAME" ]]; then
  echo "No server name given and none could be auto-detected — required." >&2
  exit 1
fi

sudo mkdir -p /etc/nginx/ssl

if [[ -f /etc/nginx/ssl/pivpn-webui.crt && -f /etc/nginx/ssl/pivpn-webui.key ]]; then
  echo "Existing cert found at /etc/nginx/ssl/pivpn-webui.{crt,key} — leaving it as-is."
  echo "(Delete those two files first if you want this script to regenerate them.)"
else
  echo "== Generating a self-signed certificate for '${SERVER_NAME}' =="
  echo "Fine for internal/LAN use, where browsers will show a one-time trust"
  echo "warning. If you have a real domain and want a trusted cert instead"
  echo "(e.g. via certbot), place it at those same two paths before running"
  echo "this script and it'll be left alone."
  sudo openssl req -x509 -nodes -days 1095 \
    -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/pivpn-webui.key \
    -out /etc/nginx/ssl/pivpn-webui.crt \
    -subj "/CN=${SERVER_NAME}"
fi

# Key readable by nginx's worker user (www-data on Debian/Ubuntu) and root
# only; cert is public by nature (sent to every client on TLS handshake).
sudo chmod 644 /etc/nginx/ssl/pivpn-webui.crt
sudo chown root:www-data /etc/nginx/ssl/pivpn-webui.key
sudo chmod 640 /etc/nginx/ssl/pivpn-webui.key

CONF_TMP="$(mktemp)"
sed "s/__SERVER_NAME__/${SERVER_NAME}/g" deploy/nginx-pivpn-webui.conf.template > "$CONF_TMP"
sudo install -m 0644 "$CONF_TMP" /etc/nginx/sites-available/pivpn-webui
rm -f "$CONF_TMP"

sudo ln -sf /etc/nginx/sites-available/pivpn-webui /etc/nginx/sites-enabled/pivpn-webui

sudo nginx -t
sudo systemctl reload nginx

echo
echo "Done: https://${SERVER_NAME}/"
echo "Self-signed cert, so browsers will show a one-time trust warning —"
echo "expected unless you supplied a real cert above."
