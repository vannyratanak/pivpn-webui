#!/bin/bash
# Installed to /usr/local/sbin/pivpn-webui-ccd-helper.sh, owned by root,
# invoked via a narrow NOPASSWD sudoers entry (see sudoers-pivpn-webui.template).
# This is the ONLY thing the web app is allowed to do as root on the
# OpenVPN client-config-dir, and it validates its own arguments — sudoers
# argument globbing is not trusted as the security boundary, this script is.
set -euo pipefail

CCD_DIR="/etc/openvpn/ccd"
# PiVPN's OpenVPN status file location, per `grep '^status ' /etc/openvpn/server.conf`
# on a real install. Verify against your own box; PiVPN doesn't pin this path
# across every version/fork.
STATUS_LOG="/var/log/openvpn-status.log"
# Separate throwaway OpenVPN instance (server-tcp-test.conf) used to test
# external reachability via a Cloudflare Tunnel — its own status log, kept
# apart from production's so the two never collide. Remove this action (and
# its call site in app/pivpn_ctl.py) once that test instance is torn down.
STATUS_LOG_TCP_TEST="/var/log/openvpn-tcp-test-status.log"
NAME_RE='^[A-Za-z0-9_-]{1,32}$'

usage() {
  echo "usage: $0 list | status | status-tcp-test" >&2
  exit 1
}

# PiVPN's own makeOVPN.sh/removeOVPN.sh already write and clean up ccd files
# (static per-client tunnel IPs) as part of `pivpn add`/`pivpn revoke` — this
# helper only ever reads that state (for the block/unblock feature's IP
# lookup and the connected-sessions view), never writes it.
action="${1:-}"
[[ -n "$action" ]] || usage

case "$action" in
  list)
    mkdir -p "$CCD_DIR"
    # Pure bash builtins only (no basename/grep/awk subprocess per file) —
    # this loop used to spawn 3 processes per CCD file, so it scaled with
    # client count: fine at 4 clients, ~1s+ of pure fork/exec overhead at 20+.
    for f in "$CCD_DIR"/*; do
      [[ -f "$f" ]] || continue
      base="${f##*/}"
      [[ "$base" =~ $NAME_RE ]] || continue
      ip=""
      while IFS= read -r line; do
        if [[ "$line" == "ifconfig-push "* ]]; then
          read -r _ ip _ <<< "$line"
          break
        fi
      done < "$f"
      [[ -n "$ip" ]] && printf '%s %s\n' "$base" "$ip"
    done
    ;;
  status)
    # Fixed path, not caller-supplied — nothing to validate here, and that's
    # the point: this action can never be pointed at an arbitrary file.
    [[ -r "$STATUS_LOG" ]] && cat "$STATUS_LOG"
    ;;
  status-tcp-test)
    [[ -r "$STATUS_LOG_TCP_TEST" ]] && cat "$STATUS_LOG_TCP_TEST"
    ;;
  *)
    usage
    ;;
esac
