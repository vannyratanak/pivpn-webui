#!/usr/bin/env bash
# Run this ON THE SERVER, after setup.sh, to put nginx + TLS in front of
# the app. gunicorn binds to 127.0.0.1 only (see BIND_HOST in .env) and is
# never meant to be reached directly — nginx is what clients actually talk
# to. Installs nginx if it's missing, generates a self-signed cert if you
# don't already have one at the target paths, and installs/enables the
# reverse-proxy vhost from deploy/nginx-pivpn-webui.conf.template.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_NAME=""
SAN=""

require_non_root() {
  if [[ $EUID -eq 0 ]]; then
    echo "Run this as your normal user (the one that ran setup.sh), not root/sudo." >&2
    exit 1
  fi
}

install_nginx_if_missing() {
  if ! command -v nginx >/dev/null 2>&1; then
    echo "nginx not found — installing it (requires sudo)."
    sudo apt-get update
    sudo apt-get install -y nginx
  fi
}

disable_server_tokens() {
  # Hide the nginx version banner (the Server: response header, and the
  # version string nginx's own default error pages print) — trivial recon
  # info an attacker doesn't need handed to them for free. server_tokens is
  # an http-block-only directive, so it can't live in the per-vhost template
  # (deploy/nginx-pivpn-webui.conf.template) the way the other hardening
  # headers do — this edits the main nginx.conf directly instead, idempotent
  # (safe to re-run). Debian/Ubuntu's stock nginx.conf ships this line
  # already present but commented out, so the common case is just
  # uncommenting it; falls back to appending after a line every stock
  # nginx.conf has, or a manual instruction, for anything that doesn't.
  if ! grep -qE '^\s*server_tokens\s+off\s*;' /etc/nginx/nginx.conf; then
    if grep -qE '^\s*#\s*server_tokens off;' /etc/nginx/nginx.conf; then
      sudo sed -i -E 's/^(\s*)#\s*server_tokens off;/\1server_tokens off;/' /etc/nginx/nginx.conf
      echo "Uncommented 'server_tokens off;' in /etc/nginx/nginx.conf."
    elif grep -q 'types_hash_max_size 2048;' /etc/nginx/nginx.conf; then
      sudo sed -i '/types_hash_max_size 2048;/a\\tserver_tokens off;' /etc/nginx/nginx.conf
      echo "Added 'server_tokens off;' to /etc/nginx/nginx.conf."
    else
      echo "Could not find a safe anchor line in /etc/nginx/nginx.conf to add" >&2
      echo "'server_tokens off;' automatically — add it yourself inside the" >&2
      echo "http {} block to hide the nginx version banner." >&2
    fi
  fi
}

read_server_name() {
  local default_server_name
  default_server_name="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || true)"
  read -rp "Server name (IP or hostname clients will browse to) [${default_server_name:-<required>}]: " SERVER_NAME
  SERVER_NAME="${SERVER_NAME:-$default_server_name}"
  if [[ -z "$SERVER_NAME" ]]; then
    echo "No server name given and none could be auto-detected — required." >&2
    exit 1
  fi
}

compute_san() {
  # Modern TLS verification (every current mobile/desktop browser included)
  # checks the connection target against the certificate's SAN (Subject
  # Alternative Name), not just its CN — a CN-only cert fails hostname
  # verification even though the name is right, since CN-based fallback
  # matching was deprecated. An IP address specifically needs an "IP:" SAN
  # entry, not a "DNS:" one, or it fails the same way even with SAN present.
  # (Same reasoning as setup-hub-tls.sh's cert — this script's own cert
  # never got the same fix, so browsers strict about it, like iOS Safari,
  # refused to connect at all even with a manually-accepted exception.)
  if [[ "$SERVER_NAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SAN="IP:${SERVER_NAME}"
  else
    SAN="DNS:${SERVER_NAME}"
  fi
}

generate_cert() {
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
      -subj "/C=KH/ST=Asia/L=Phnom Penh/O=The Council for the Development of Cambodia/OU=DTPC/CN=${SERVER_NAME}" \
      -addext "subjectAltName=${SAN}"
  fi

  # Key readable by nginx's worker user (www-data on Debian/Ubuntu) and root
  # only; cert is public by nature (sent to every client on TLS handshake).
  sudo chmod 644 /etc/nginx/ssl/pivpn-webui.crt
  sudo chown root:www-data /etc/nginx/ssl/pivpn-webui.key
  sudo chmod 640 /etc/nginx/ssl/pivpn-webui.key
}

install_vhost() {
  local conf_tmp
  conf_tmp="$(mktemp)"
  sed "s/__SERVER_NAME__/${SERVER_NAME}/g" deploy/nginx-pivpn-webui.conf.template > "$conf_tmp"
  sudo install -m 0644 "$conf_tmp" /etc/nginx/sites-available/pivpn-webui
  rm -f "$conf_tmp"

  sudo ln -sf /etc/nginx/sites-available/pivpn-webui /etc/nginx/sites-enabled/pivpn-webui

  sudo nginx -t
  sudo systemctl reload nginx
}

print_done() {
  echo
  echo "Done: https://${SERVER_NAME}/"
  echo "Self-signed cert, so browsers will show a one-time trust warning —"
  echo "expected unless you supplied a real cert above."
}

main() {
  require_non_root
  cd "$APP_DIR"

  echo "== PiVPN Web UI: nginx + TLS setup =="

  install_nginx_if_missing
  disable_server_tokens
  read_server_name
  compute_san
  generate_cert
  install_vhost
  print_done
}

main "$@"
