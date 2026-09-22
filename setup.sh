#!/usr/bin/env bash
# Run this on the server PiVPN is installed on, as the same non-root user
# that installed PiVPN. Sets up the venv, provisions PostgreSQL, generates
# admin credentials, installs the root-helper scripts + sudoers rule +
# systemd unit.
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

# Debian/Ubuntu intentionally split venv/ensurepip out of the base Python
# package. Install the matching package automatically so a fresh hub or
# standalone deployment does not stop with the usual "ensurepip is not
# available" message.
if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Python venv support is missing and apt-get is unavailable. Install the matching python3-venv package, then rerun this script." >&2
    exit 1
  fi
  PYTHON_MINOR="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
  echo "== Installing Python venv support (python${PYTHON_MINOR}-venv) =="
  sudo apt-get update -y
  if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "python${PYTHON_MINOR}-venv"; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv
  fi
fi

python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "== Setting up PostgreSQL (requires sudo) =="
# The app has required a real Postgres connection since the SQLite ->
# Postgres migration — config.py's require_secrets() refuses to start
# without PIVPN_WEBUI_DB_HOST/PASSWORD set. This installs/starts a local
# Postgres server and provisions this app's own role + database, so a
# fresh clone of this repo produces a working install again instead of
# failing at startup with that error.
if ! command -v psql >/dev/null 2>&1; then
  echo "Installing PostgreSQL..."
  sudo apt-get update -y
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql
fi
sudo systemctl enable --now postgresql

DB_HOST="localhost"

read -rp "Database name [pivpn_webui]: " DB_NAME
DB_NAME="${DB_NAME:-pivpn_webui}"

read -rp "Database user [pivpn_webui_app]: " DB_USER
DB_USER="${DB_USER:-pivpn_webui_app}"

read -rsp "Database password [press Enter to generate a random one]: " DB_PASSWORD
echo
DB_PASSWORD="${DB_PASSWORD:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')}"

# Re-running this script always issues a fresh DB password here (whatever
# was just typed above, or a freshly generated one if left blank), same
# as it always regenerates SECRET_KEY/admin credentials below — ALTER
# ROLE if this role already exists (a previous run of this same script),
# CREATE ROLE if it doesn't (first run), so .env's value is guaranteed
# correct either way without needing to know which case this is first.
sudo -u postgres psql -v ON_ERROR_STOP=1 -c \
  "ALTER ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASSWORD}';" >/dev/null 2>&1 || \
  sudo -u postgres psql -v ON_ERROR_STOP=1 -c \
  "CREATE ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASSWORD}';" >/dev/null
sudo -u postgres createdb -O "${DB_USER}" "${DB_NAME}" 2>/dev/null || true
# Table creation itself (CREATE TABLE IF NOT EXISTS) happens automatically
# the first time the app starts — see app/db.py's init_db(), called from
# create_app(). Nothing left to do here beyond role + database existing.

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
# `read` never expands a typed `~` (only a shell parsing a command
# argument does) — same class of bug found live in setup-agent.sh's TLS
# cert path prompts, fixed there the same way.
OVPN_DIR="${OVPN_DIR/#\~/$HOME}"

read -rp "OpenVPN subnet, first 3 octets [10.8.0]: " SUBNET_BASE
SUBNET_BASE="${SUBNET_BASE:-10.8.0}"

BIND_PORT="8443"

cat > .env <<EOF
SECRET_KEY=${SECRET_KEY}
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD_HASH=${ADMIN_PASSWORD_HASH}
PIVPN_WEBUI_DB_HOST=${DB_HOST}
PIVPN_WEBUI_DB_NAME=${DB_NAME}
PIVPN_WEBUI_DB_USER=${DB_USER}
PIVPN_WEBUI_DB_PASSWORD=${DB_PASSWORD}
PIVPN_OVPN_DIR=${OVPN_DIR}
OPENVPN_CCD_DIR=/etc/openvpn/ccd
OPENVPN_SUBNET_BASE=${SUBNET_BASE}
CCD_HELPER=/usr/local/sbin/pivpn-webui-ccd-helper.sh
LOG_HELPER=/usr/local/sbin/pivpn-webui-log-helper.sh
BIND_HOST=127.0.0.1
BIND_PORT=${BIND_PORT}
EOF
chmod 600 .env
unset DB_PASSWORD

CURRENT_USER="$(whoami)"

# HUB_ONLY_INSTALL=1 (set by setup-hub.sh) means this box runs the Flask
# app + hub_gateway.py only, no local PiVPN/OpenVPN — every privileged
# call app/privileged.py's run_root() would make is unconditionally
# routed to the agent instead once HUB_MODE=true (see that function: it
# never takes the local code path at all in that mode). These 4 scripts
# and the sudoers grant letting them run as root exist purely for that
# local path, so on a hub they'd just be an unused root-privilege surface
# — skip installing them there. setup-agent.sh installs its own copies
# (with its own, narrower sudoers grant) on the box that actually needs
# them: the real PiVPN box, wherever that ends up.
if [[ "${HUB_ONLY_INSTALL:-0}" != "1" ]]; then
  echo "== Installing privileged helper scripts (requires sudo) =="
  sudo install -m 0750 -o root -g root deploy/pivpn-webui-ccd-helper.sh /usr/local/sbin/pivpn-webui-ccd-helper.sh
  sudo install -m 0750 -o root -g root deploy/pivpn-webui-log-helper.sh /usr/local/sbin/pivpn-webui-log-helper.sh
  sudo install -m 0750 -o root -g root deploy/pivpn-webui-routes-helper.sh /usr/local/sbin/pivpn-webui-routes-helper.sh
  sudo install -m 0750 -o root -g root deploy/pivpn-webui-client-script-helper.sh /usr/local/sbin/pivpn-webui-client-script-helper.sh

  SUDOERS_TMP="$(mktemp)"
  sed -e "s/__USER__/${CURRENT_USER}/g" -e "s#__APP_DIR__#${APP_DIR}#g" \
    deploy/sudoers-pivpn-webui.template > "$SUDOERS_TMP"
  sudo visudo -cf "$SUDOERS_TMP"
  sudo install -m 0440 -o root -g root "$SUDOERS_TMP" /etc/sudoers.d/pivpn-webui
  rm -f "$SUDOERS_TMP"
else
  echo "== Skipping privileged helper scripts + sudoers grant (hub-only install) =="
  echo "   Run setup-agent.sh on the actual PiVPN box for these."
fi

echo "== Installing systemd service =="
SERVICE_TMP="$(mktemp)"
sed -e "s#__APP_DIR__#${APP_DIR}#g" -e "s/__USER__/${CURRENT_USER}/g" \
  deploy/pivpn-webui.service.template > "$SERVICE_TMP"
sudo install -m 0644 "$SERVICE_TMP" /etc/systemd/system/pivpn-webui.service
rm -f "$SERVICE_TMP"

if [[ "${HUB_ONLY_INSTALL:-0}" != "1" ]]; then
  echo "== Installing CRL permission watcher =="
  # PiVPN's own removeOVPN.sh does `cp -a .../pki/crl.pem /etc/openvpn/crl.pem`
  # on every revoke (which Renew also triggers, via revoke+reissue) — `-a`
  # preserves Easy-RSA's restrictive 0600 root:root source permissions, which
  # the unprivileged `openvpn` daemon can't read, silently breaking every
  # client's TLS handshake (`VERIFY ERROR: CRL not loaded`) until something
  # re-chmods it. This watches the file and fixes it within about a second of
  # any change, regardless of what triggered it (this app, raw CLI, cron).
  # Same reasoning as the helper scripts above for skipping it on a hub:
  # /etc/openvpn/crl.pem only ever exists on a box with local PiVPN.
  sudo install -m 0644 deploy/fix-crl-perms.service /etc/systemd/system/fix-crl-perms.service
  sudo install -m 0644 deploy/fix-crl-perms.path /etc/systemd/system/fix-crl-perms.path
  sudo systemctl daemon-reload
  sudo systemctl enable --now fix-crl-perms.path
fi

mkdir -p instance

echo
echo "Setup complete."
echo "  Start it:  sudo systemctl enable --now pivpn-webui"
echo "  Then:      http://127.0.0.1:${BIND_PORT}  (bound to localhost only)"
echo
echo "For remote/browser access, put nginx + TLS in front of it next:"
echo "  ./setup-nginx.sh"

if [[ "${HUB_ONLY_INSTALL:-0}" != "1" ]]; then
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
  echo
  echo "The CRL permission watcher (fix-crl-perms.path) assumes PiVPN's default"
  echo "crl-verify path, /etc/openvpn/crl.pem — check crl-verify in"
  echo "/etc/openvpn/server.conf matches; update PathModified in"
  echo "deploy/fix-crl-perms.path and reinstall if it doesn't."
fi
