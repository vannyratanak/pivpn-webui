#!/bin/bash
# Installed to /usr/local/sbin/pivpn-webui-log-helper.sh, owned by root,
# invoked via a narrow NOPASSWD sudoers entry (see sudoers-pivpn-webui.template).
# Read-only journal access for the web UI's log views. Only the fixed
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
#
# openvpn gets its own (smaller-for-now) window, split out from
# webui/system below — vpnlog.py regex-parses every raw line of this one
# (pairing connect/disconnect events), measured at ~1.5s for a real 7-day
# volume (~13k lines) on this box, so widening it isn't free the way
# webui/system's plain-text display is. Left at 3 days until that parsing
# cost is addressed properly (see the project notes on moving Sessions to
# DB-backed storage); bump SINCE_OPENVPN/LINES_OPENVPN directly if you want
# more history sooner and can accept the added per-request parse time.
SINCE_OPENVPN="3 days ago"
LINES_OPENVPN=5000

# webui/system are never regex-parsed — vpnlog.py just splits and reverses
# the raw lines for display (verified: ~30k lines/week parses in ~0.02s on
# this box) — so their window can be widened for free, independent of
# openvpn's above.
LINES=60000

# webui/system's window is caller-selectable (the Logs page's System tab
# range dropdown — same 1h/6h/12h/1d/7d set the DB-backed tabs already use),
# passed as this script's $2. Resolved through this fixed lookup (sets
# $since directly rather than echo+command-substitution — under `set -e`,
# a function's `exit` only actually aborts the script when called as a
# plain statement; wrapping the call in "$(...)" would swallow that exit
# and silently fall through with $since empty) — a caller can only ever
# select one of these five exact --since values, never interpolated into
# journalctl directly.
resolve_since() {
  case "${1:-7d}" in
    1h) since="1 hour ago" ;;
    6h) since="6 hours ago" ;;
    12h) since="12 hours ago" ;;
    1d) since="1 day ago" ;;
    7d) since="7 days ago" ;;
    *) echo "unknown range: $1" >&2; exit 1 ;;
  esac
}

# Flow-log rows (see deploy/setup-traffic-log.sh) are a different order of
# magnitude from connect/disconnect events — one browsing session alone can
# open hundreds of connections in minutes. The same 3-day/5000-line window
# used above would silently collapse down to just the last few minutes, so
# this action gets its own, much shorter window instead.
SINCE_FLOW="6 hours ago"
LINES_FLOW=5000

# The prefix setup-traffic-log.sh's LOG rule tags every flow line with.
FLOW_LOG_PREFIX="VPNFLOW"

# deploy/ingest_logs.py's incremental fetch — used by the *-tail actions
# below, not by openvpn/flow/webui/system above (those stay fixed-window,
# kept around as manual/diagnostic commands; the live web app no longer
# reads through them once vpn_events/traffic_flows are DB-backed). Cursor
# files are root-owned (this script always runs as root) and journalctl
# creates/updates them itself via --cursor-file — never touched directly by
# the unprivileged ingest_logs.py process.
STATE_DIR="/var/lib/pivpn-webui"
OPENVPN_CURSOR="$STATE_DIR/openvpn.cursor"
FLOW_CURSOR="$STATE_DIR/flow.cursor"
SYSTEM_CURSOR="$STATE_DIR/system.cursor"
# Only takes effect on each cursor file's very first-ever use (no cursor
# yet to resume from) — a real backfill of history that already exists in
# the journal, not an ongoing limit. Once a cursor exists, it's always more
# recent than this, so --since is normally a no-op safety floor; the one
# case it actually matters again is the ingest timer having been down for
# longer than this, in which case it correctly caps the backfill at this
# window rather than however long the gap actually was.
BACKFILL_SINCE="7 days ago"

usage() {
  echo "usage: $0 openvpn | webui [range] | system [range] | flow | openvpn-tail | openvpn-follow [cursor] | flow-tail | flow-follow [cursor] | system-tail" >&2
  echo "  range (webui/system only): 1h | 6h | 12h | 1d | 7d (default 7d)" >&2
  exit 1
}

action="${1:-}"
[[ -n "$action" ]] || usage

case "$action" in
  openvpn)
    journalctl -u "$OPENVPN_UNIT" --since "$SINCE_OPENVPN" -n "$LINES_OPENVPN" --no-pager -o short-iso
    ;;
  webui)
    resolve_since "${2:-}"
    journalctl -u "$WEBUI_UNIT" --since "$since" -n "$LINES" --no-pager -o short-iso
    ;;
  system)
    resolve_since "${2:-}"
    journalctl --since "$since" -n "$LINES" --no-pager -o short-iso
    ;;
  flow)
    # journalctl -g/--grep exits 1 (not 0) when the pattern matches nothing
    # — unlike every other action above, which just print an empty stream
    # and exit 0 when there's nothing to show. Under `set -e` that turns
    # "no traffic in this window" (completely normal — a quiet period
    # longer than SINCE_FLOW, or before setup-traffic-log.sh's ever been
    # run) into a hard script failure the web UI shows as a broken command
    # instead of an empty Traffic tab. Exit 1 specifically is that benign
    # case (its own "-- No entries --" line already gets silently skipped
    # by the app's own line parser, same as any other unparseable line);
    # anything else nonzero is a real problem and should still fail loudly.
    set +e
    journalctl -k --since "$SINCE_FLOW" -n "$LINES_FLOW" --no-pager -o short-iso -g "$FLOW_LOG_PREFIX"
    rc=$?
    set -e
    [[ $rc -eq 0 || $rc -eq 1 ]] || exit "$rc"
    ;;
  openvpn-tail)
    mkdir -p "$STATE_DIR"
    journalctl -u "$OPENVPN_UNIT" --cursor-file="$OPENVPN_CURSOR" --since "$BACKFILL_SINCE" --no-pager -o short-iso
    ;;
  openvpn-follow)
    # Persistent follow used by the agent's WebSocket event stream. Cursor
    # comes from the hub only after the corresponding batch is committed.
    if [[ $# -gt 2 ]]; then usage; fi
    if [[ $# -eq 2 ]]; then
      cursor="$2"
      cursor_re='^[A-Za-z0-9_:=;.-]+$'
      [[ ${#cursor} -le 2048 && "$cursor" =~ $cursor_re ]] || {
        echo "invalid journal cursor" >&2
        exit 2
      }
      exec journalctl -u "$OPENVPN_UNIT" --after-cursor="$cursor" --follow --no-pager -o json
    fi
    exec journalctl -u "$OPENVPN_UNIT" --follow --lines=0 --no-pager -o json
    ;;
  system-tail)
    # Same incremental-fetch shape as openvpn-tail — no -g/grep filter
    # (same as the fixed-window `system` action above), so no special
    # exit-1-means-no-matches handling needed either.
    mkdir -p "$STATE_DIR"
    journalctl --cursor-file="$SYSTEM_CURSOR" --since "$BACKFILL_SINCE" --no-pager -o short-iso
    ;;
  flow-tail)
    # Same benign-exit-1 handling as `flow` above — an incremental fetch
    # with nothing new since the last run is the normal, expected case for
    # most ticks, not an error.
    mkdir -p "$STATE_DIR"
    set +e
    journalctl -k --cursor-file="$FLOW_CURSOR" --since "$BACKFILL_SINCE" --no-pager -o short-iso -g "$FLOW_LOG_PREFIX"
    rc=$?
    set -e
    [[ $rc -eq 0 || $rc -eq 1 ]] || exit "$rc"
    ;;
  flow-follow)
    # A dedicated follower for the agent's live WebSocket stream. The
    # opaque cursor is supplied by the hub only after the preceding batch
    # was committed. Validate it before passing it to journalctl; with no
    # cursor, start at the current end (the periodic ingest timer handles
    # any initial history/backfill).
    if [[ $# -gt 2 ]]; then usage; fi
    if [[ $# -eq 2 ]]; then
      cursor="$2"
      cursor_re='^[A-Za-z0-9_:=;.-]+$'
      [[ ${#cursor} -le 2048 && "$cursor" =~ $cursor_re ]] || {
        echo "invalid journal cursor" >&2
        exit 2
      }
      exec journalctl -k --after-cursor="$cursor" --follow --no-pager -o json -g "$FLOW_LOG_PREFIX"
    fi
    exec journalctl -k --follow --lines=0 --no-pager -o json -g "$FLOW_LOG_PREFIX"
    ;;
  *)
    usage
    ;;
esac
