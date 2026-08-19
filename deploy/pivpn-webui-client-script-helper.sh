#!/bin/bash
# Installed to /usr/local/sbin/pivpn-webui-client-script-helper.sh, owned by
# root, invoked via a narrow NOPASSWD sudoers entry (see
# sudoers-pivpn-webui.template). This is the ONLY thing the web app is
# allowed to do as root under SCRIPT_DIR — it validates its own arguments,
# sudoers argument globbing is not trusted as the security boundary, this
# script is.
#
# Writes/deletes a read-only reference file mirroring a VPN client's current
# FORWARD-chain rules as plain iptables commands, so someone on the CLI can
# see what's configured without the web UI. NOT wired into OpenVPN's
# client-connect — the web app's own sync (app/firewall.py's sync_all) is
# what actually (re)applies these rules; a client-connect hook re-adding
# them from this file too would double-apply and, since a plain `iptables
# -D` by IP doesn't know about the app's pivpn-webui:<id> comment tags,
# silently strip them and desync the DB from live iptables.
set -euo pipefail

SCRIPT_DIR="/etc/openvpn/scripts"
NAME_RE='^[A-Za-z0-9_-]{1,32}$'

usage() {
  echo "usage: $0 write <client-name>   (script content on stdin)" >&2
  echo "       $0 delete <client-name>" >&2
  exit 1
}

action="${1:-}"
name="${2:-}"
[[ -n "$action" && -n "$name" ]] || usage
[[ "$name" =~ $NAME_RE ]] || { echo "invalid client name: $name" >&2; exit 1; }

path="$SCRIPT_DIR/firewall-$name.sh"

case "$action" in
  write)
    mkdir -p "$SCRIPT_DIR"
    tmp="$(mktemp "$SCRIPT_DIR/.firewall-$name.XXXXXX")"
    cat > "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$path"
    ;;
  delete)
    rm -f "$path"
    ;;
  *)
    usage
    ;;
esac
