#!/usr/bin/env bash
# Run this ON THE PI, as the same non-root user that installed PiVPN
# (typically `pi`). Sets up the venv, generates admin credentials, installs
# the root-helper script + sudoers rule + systemd unit.
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
  echo "Run this as your normal user (the one PiVPN was installed as), not root/sudo." >&2
  exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

echo "== PiVPN Web UI setup =="

if ! command -v pivpn >/dev/null 2>&1; then
  echo "Warning: 'pivpn' not found on PATH. Client management won't work until it is." >&2
fi

python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

read -rp "Admin username [admin]: " ADMIN_USERNAME
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"

while true; do
  read -rsp "Admin password: " ADMIN_PASSWORD
  echo
  read -rsp "Confirm password: " ADMIN_PASSWORD2
  echo
  if [[ -n "$ADMIN_PASSWORD" && "$ADMIN_PASSWORD" == "$ADMIN_PASSWORD2" ]]; then
    break
  fi
  echo "Passwords did not match or were empty, try again." >&2
done

ADMIN_PASSWORD_HASH="$(python3 -c "
from werkzeug.security import generate_password_hash
import sys
print(generate_password_hash(sys.argv[1]))
" "$ADMIN_PASSWORD")"
unset ADMIN_PASSWORD ADMIN_PASSWORD2

read -rp "Path PiVPN writes .ovpn files to [$HOME/ovpns]: " OVPN_DIR
OVPN_DIR="${OVPN_DIR:-$HOME/ovpns}"

read -rp "OpenVPN subnet, first 3 octets [10.8.0]: " SUBNET_BASE
SUBNET_BASE="${SUBNET_BASE:-10.8.0}"

BIND_PORT="8443"

cat > .env <<EOF
SECRET_KEY=${SECRET_KEY}
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD_HASH=${ADMIN_PASSWORD_HASH}
PIVPN_OVPN_DIR=${OVPN_DIR}
OPENVPN_CCD_DIR=/etc/openvpn/ccd
OPENVPN_SUBNET_BASE=${SUBNET_BASE}
CCD_HELPER=/usr/local/sbin/pivpn-webui-ccd-helper.sh
LOG_HELPER=/usr/local/sbin/pivpn-webui-log-helper.sh
BIND_HOST=127.0.0.1
BIND_PORT=${BIND_PORT}
EOF
chmod 600 .env

echo "== Installing privileged helper scripts (requires sudo) =="
sudo install -m 0750 -o root -g root deploy/pivpn-webui-ccd-helper.sh /usr/local/sbin/pivpn-webui-ccd-helper.sh
sudo install -m 0750 -o root -g root deploy/pivpn-webui-log-helper.sh /usr/local/sbin/pivpn-webui-log-helper.sh
sudo install -m 0750 -o root -g root deploy/pivpn-webui-routes-helper.sh /usr/local/sbin/pivpn-webui-routes-helper.sh
sudo install -m 0750 -o root -g root deploy/pivpn-webui-client-script-helper.sh /usr/local/sbin/pivpn-webui-client-script-helper.sh

CURRENT_USER="$(whoami)"

SUDOERS_TMP="$(mktemp)"
sed "s/__USER__/${CURRENT_USER}/g" deploy/sudoers-pivpn-webui.template > "$SUDOERS_TMP"
sudo visudo -cf "$SUDOERS_TMP"
sudo install -m 0440 -o root -g root "$SUDOERS_TMP" /etc/sudoers.d/pivpn-webui
rm -f "$SUDOERS_TMP"

echo "== Installing systemd service =="
SERVICE_TMP="$(mktemp)"
sed -e "s#__APP_DIR__#${APP_DIR}#g" -e "s/__USER__/${CURRENT_USER}/g" \
  deploy/pivpn-webui.service.template > "$SERVICE_TMP"
sudo install -m 0644 "$SERVICE_TMP" /etc/systemd/system/pivpn-webui.service
rm -f "$SERVICE_TMP"
sudo systemctl daemon-reload

mkdir -p instance

echo
echo "Setup complete."
echo "  Start it:  sudo systemctl enable --now pivpn-webui"
echo "  Then:      http://127.0.0.1:${BIND_PORT}  (bound to localhost only)"
echo
echo "For remote/browser access, put nginx + TLS in front of it next:"
echo "  ./setup-nginx.sh"
echo
echo "Before relying on client add/remove/renew, verify the exact pivpn CLI"
echo "syntax on this machine (run: pivpn -h && pivpn add -h) against what's"
echo "hardcoded in app/pivpn_ctl.py — PiVPN's flags have changed across versions."
echo
echo "Before relying on the Sessions/System log tabs, verify the OpenVPN"
echo "systemd unit name (run: systemctl list-units | grep openvpn) against"
echo "OPENVPN_UNIT in deploy/pivpn-webui-log-helper.sh — update and reinstall"
echo "with 'sudo install -m 0750 -o root -g root deploy/pivpn-webui-log-helper.sh"
echo "/usr/local/sbin/pivpn-webui-log-helper.sh' if it differs."
