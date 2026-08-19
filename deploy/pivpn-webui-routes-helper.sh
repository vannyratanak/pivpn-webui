#!/bin/bash
# Installed to /usr/local/sbin/pivpn-webui-routes-helper.sh, owned by root,
# invoked via a narrow NOPASSWD sudoers entry (see sudoers-pivpn-webui.template).
# This is the ONLY thing the web app is allowed to do as root to
# server.conf, and it validates its own arguments — sudoers argument
# globbing is not trusted as the security boundary, this script is.
#
# Manages `push "route <network> <netmask>"` lines, each tagged with a
# marker comment so add/remove only ever touch lines this script wrote
# itself — any route already in server.conf before this script existed is
# left untouched. `list` surfaces every push-route line either way (tagged
# ones as "managed", anything else as "unmanaged") so the UI reflects
# server.conf's real state; only add/remove are scoped to tagged lines.
set -euo pipefail

CONF="/etc/openvpn/server.conf"
UNIT="openvpn@server"
MARKER="# pivpn-webui-route"
IP_RE='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'

usage() {
  echo "usage: $0 list | add <network> <netmask> | remove <network> <netmask>" >&2
  exit 1
}

valid_ip() { [[ "$1" =~ $IP_RE ]]; }

action="${1:-}"
[[ -n "$action" ]] || usage

case "$action" in
  list)
    grep -E '^push "route [0-9.]+ [0-9.]+"' "$CONF" 2>/dev/null | while IFS= read -r cfg_line; do
      network="$(sed -nE 's/^push "route ([0-9.]+) [0-9.]+".*/\1/p' <<<"$cfg_line")"
      netmask="$(sed -nE 's/^push "route [0-9.]+ ([0-9.]+)".*/\1/p' <<<"$cfg_line")"
      [[ -n "$network" && -n "$netmask" ]] || continue
      if [[ "$cfg_line" == *"$MARKER"* ]]; then
        echo "$network $netmask managed"
      else
        echo "$network $netmask unmanaged"
      fi
    done || true
    ;;
  add)
    network="${2:-}"; netmask="${3:-}"
    valid_ip "$network" || { echo "bad network: $network" >&2; exit 1; }
    valid_ip "$netmask" || { echo "bad netmask: $netmask" >&2; exit 1; }
    line="push \"route $network $netmask\" $MARKER"
    grep -qxF "$line" "$CONF" || printf '%s\n' "$line" >> "$CONF"
    systemctl restart "$UNIT"
    ;;
  remove)
    network="${2:-}"; netmask="${3:-}"
    valid_ip "$network" || { echo "bad network: $network" >&2; exit 1; }
    valid_ip "$netmask" || { echo "bad netmask: $netmask" >&2; exit 1; }
    line="push \"route $network $netmask\" $MARKER"
    tmp="$(mktemp)"
    grep -vxF "$line" "$CONF" > "$tmp"
    cat "$tmp" > "$CONF"
    rm -f "$tmp"
    systemctl restart "$UNIT"
    ;;
  *)
    usage
    ;;
esac
