#!/bin/bash
# Installed to /usr/local/sbin/pivpn-webui-log-helper.sh, owned by root,
# invoked via a narrow NOPASSWD sudoers entry (see sudoers-pivpn-webui.template).
# Read-only journal access for the web UI's log views. Only the three fixed
# journalctl invocations below are exposed — no caller-supplied unit names,
# line counts, or other arguments ever reach journalctl. Like ccd-helper.sh,
# sudoers argument globbing is not trusted as the security boundary; this
# script (fixed action names, no interpolation) is.
set -euo pipefail

# PiVPN's OpenVPN server runs as this systemd unit on Debian/Raspbian
# (OpenVPN mode). Verify with `systemctl list-units | grep openvpn` on your
# Pi and update if it differs (e.g. some installs use
# openvpn-server@server.service instead).
OPENVPN_UNIT="openvpn@server"
WEBUI_UNIT="pivpn-webui"

# A plain "-n 300" caps *raw journal lines*, not events — one OpenVPN
# connection alone logs 15-20 lines of cipher/peer-info detail, so a burst
# of reconnects (a flaky client, someone testing) can silently shrink the
# effective visible window down to a few minutes, hiding sessions that are
# only hours old. --since gives a real, predictable time window regardless
# of how chatty traffic gets; -n stays on alongside it purely as a safety
# cap against a truly pathological volume within that window, not as the
# primary limit.
SINCE="3 days ago"
LINES=5000

# Flow-log rows (see deploy/setup-traffic-log.sh) are a different order of
# magnitude from connect/disconnect events — one browsing session alone can
# open hundreds of connections in minutes. The same 3-day/5000-line window
# used above would silently collapse down to just the last few minutes, so
# this action gets its own, much shorter window instead.
SINCE_FLOW="6 hours ago"
LINES_FLOW=5000

# The prefix setup-traffic-log.sh's LOG rule tags every flow line with.
FLOW_LOG_PREFIX="VPNFLOW"

usage() {
  echo "usage: $0 openvpn | webui | system | flow" >&2
  exit 1
}

action="${1:-}"
[[ -n "$action" ]] || usage

case "$action" in
  openvpn)
    journalctl -u "$OPENVPN_UNIT" --since "$SINCE" -n "$LINES" --no-pager -o short-iso
    ;;
  webui)
    journalctl -u "$WEBUI_UNIT" --since "$SINCE" -n "$LINES" --no-pager -o short-iso
    ;;
  system)
    journalctl --since "$SINCE" -n "$LINES" --no-pager -o short-iso
    ;;
  flow)
    journalctl -k --since "$SINCE_FLOW" -n "$LINES_FLOW" --no-pager -o short-iso -g "$FLOW_LOG_PREFIX"
    ;;
  *)
    usage
    ;;
esac
