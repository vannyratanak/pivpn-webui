#!/usr/bin/env bash
# Reduce stale online status on PiVPN's OpenVPN server. Run only on the
# agent (the box that runs OpenVPN), not on the hub.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

CONF=/etc/openvpn/server.conf
UNIT=openvpn@server
[[ -r "$CONF" ]] || { echo "Missing $CONF" >&2; exit 1; }

TMP="$(mktemp /etc/openvpn/server.conf.XXXXXX)"
BACKUP="${CONF}.bak.$(date +%Y%m%d%H%M%S)"
trap 'rm -f "$TMP"' EXIT

# OpenVPN writes its status file every second. keepalive 5 15 sends a
# ping every 5s and detects an unresponsive client within 30s on the
# server (OpenVPN doubles the timeout server-side).
awk '
  /^[[:space:]]*keepalive([[:space:]]|$)/ {
    if (!keepalive) print "keepalive 5 15"
    keepalive=1
    next
  }
  /^[[:space:]]*status([[:space:]]|$)/ {
    if (!status) print $1, $2, 1
    status=1
    next
  }
  { print }
  END {
    if (!keepalive) print "keepalive 5 15"
    if (!status) print "status /var/log/openvpn-status.log 1"
  }
' "$CONF" > "$TMP"

if cmp -s "$CONF" "$TMP"; then
  echo "OpenVPN status/keepalive settings already tuned."
  exit 0
fi

cp -a "$CONF" "$BACKUP"
chown --reference="$CONF" "$TMP"
chmod --reference="$CONF" "$TMP"
mv "$TMP" "$CONF"

if ! systemctl restart "$UNIT" || ! systemctl is-active --quiet "$UNIT"; then
  echo "OpenVPN did not restart with the new settings; restoring $BACKUP" >&2
  cp -a "$BACKUP" "$CONF"
  systemctl restart "$UNIT" || true
  exit 1
fi

echo "OpenVPN restarted with status refresh=1s and silent-client timeout=30s."
echo "Previous config saved at $BACKUP"
