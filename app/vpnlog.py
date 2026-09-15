"""Read-only journal access for the Logs page (Sessions + System tabs).

Goes through the pivpn-webui-log-helper.sh root helper (see deploy/ and
app/privileged.py) — three fixed journalctl invocations, no user input
reaches the shell.

IMPORTANT — verify before relying on this in production: OpenVPN's log
line format isn't strictly standardized across versions/configs. The
CONNECT_RE / DISCONNECT_RE patterns below match the commonly-seen
"Peer Connection Initiated" / "SIGTERM ... client-instance exiting"
messages, but if your server's `verb` level or log format differs, session
parsing may fall back to raw/unparsed rows rather than raise an error —
this is a "best effort" view, not something else depends on it.
"""
import re
import subprocess
from datetime import datetime

import config
from app import iplookup, pivpn_ctl
from app.privileged import run_root

CONNECT_RE = re.compile(
    r"\[(?P<name>[^\]]+)\] Peer Connection Initiated with \[AF_INET6?\](?P<addr>[0-9a-fA-F:.]+):(?P<port>\d+)"
)
DISCONNECT_RE = re.compile(
    r"^(?P<name>[^/\s]+)/(?P<addr>[0-9a-fA-F:.]+):(?P<port>\d+) SIGTERM"
)

# journalctl -o short-iso lines look like: "2026-08-17T10:22:31+0700 host proc[pid]: message"
JOURNAL_LINE_RE = re.compile(r"^(?P<ts>\S+)\s+\S+\s+\S+?(?:\[\d+\])?:\s?(?P<msg>.*)$")

# One line per new connection from the kernel's netfilter LOG target (see
# deploy/setup-traffic-log.sh's mangle-table FORWARD rule) — the standard
# `IN=... OUT=... SRC=... DST=... ... PROTO=... SPT=... DPT=...` shape every
# iptables/nftables LOG line uses, unlike OpenVPN's own log lines this
# format is stable/kernel-defined, not something that drifts per version.
FLOW_RE = re.compile(
    r"IN=(?P<in_if>\S*)\s+OUT=(?P<out_if>\S*).*?"
    r"SRC=(?P<src>[0-9.]+)\s+DST=(?P<dst>[0-9.]+).*?"
    r"PROTO=(?P<proto>\w+)(?:\s+SPT=(?P<sport>\d+))?(?:\s+DPT=(?P<dport>\d+))?"
)


def _format_ts(ts: str) -> str:
    """journalctl -o short-iso gives '2026-08-17T10:22:31+0700' — reformat
    to the same 'YYYY-MM-DD HH:MM:SS' style used elsewhere in the app (see
    db.add_audit). The offset is dropped rather than shown, since it's just
    the box's own local timezone repeated on every single row."""
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ts


def _split_journal_line(raw_line: str) -> tuple[str, str]:
    m = JOURNAL_LINE_RE.match(raw_line)
    if not m:
        return "", raw_line
    return _format_ts(m.group("ts")), m.group("msg")


def _parse_openvpn_events() -> list[dict]:
    """Every connect/disconnect/other event from the OpenVPN service
    journal, oldest first (the order they actually happened in) — shared by
    list_sessions (raw event log) and list_client_sessions (paired into
    per-client sessions with a duration), so pairing always sees the full,
    correctly-ordered event stream rather than an already-reversed/truncated
    view."""
    out = run_root([config.LOG_HELPER, "openvpn"])
    events = []
    for raw_line in out.splitlines():
        ts, msg = _split_journal_line(raw_line.strip())
        if not msg:
            continue
        m = CONNECT_RE.search(msg)
        if m:
            events.append({
                "ts": ts, "event": "connected", "client": m.group("name"),
                "address": f"{m.group('addr')}:{m.group('port')}", "detail": "",
            })
            continue
        m = DISCONNECT_RE.search(msg)
        if m:
            events.append({
                "ts": ts, "event": "disconnected", "client": m.group("name"),
                "address": f"{m.group('addr')}:{m.group('port')}", "detail": "",
            })
            continue
        events.append({"ts": ts, "event": "other", "client": "", "address": "", "detail": msg})
    return events


def list_sessions(limit: int = 300) -> list[dict]:
    """Best-effort connect/disconnect events parsed from the OpenVPN
    service journal, most recent first."""
    events = _parse_openvpn_events()
    events.reverse()
    return events[:limit]


def _format_duration(start: str, end: str) -> str | None:
    try:
        start_dt = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
        end_dt = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None
    seconds = int((end_dt - start_dt).total_seconds())
    if seconds < 0:
        return None
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def resolve_real_address(address: str) -> str | None:
    """If a real VPN server relays traffic through another box (see
    RELAY_* in config.py), every session's logged address is that relay's
    own tunnel-facing IP, not the client's actual internet address — the
    relay has to relabel it that way for replies to route back correctly.
    The relay's own connection-tracking table still remembers the real
    mapping for as long as the connection is active; this asks it.

    Returns None (never raises) whenever there's nothing useful to show:
    no relay configured at all, this particular address isn't from the
    relay, the SSH call itself fails, or the connection has since ended
    (conntrack forgets it the moment a client disconnects) — a disabled
    or temporarily-unreachable relay should never break the Logs page,
    only silently fall back to showing the relabeled address as before."""
    if not config.RELAY_HOST or not config.RELAY_TUNNEL_IP:
        return None
    ip, _, port = address.rpartition(":")
    if ip != config.RELAY_TUNNEL_IP or not port.isdigit():
        return None
    try:
        result = subprocess.run(
            [
                "ssh", "-o", "ConnectTimeout=3", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                f"{config.RELAY_SSH_USER}@{config.RELAY_HOST}",
                config.RELAY_LOOKUP_SCRIPT, port,
            ],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = result.stdout.strip()
    return out if result.returncode == 0 and out else None


def list_client_sessions(limit: int = 300) -> list[dict]:
    """Per-client login sessions — each a paired connect+disconnect (or
    still-open connect with no disconnect yet), most recent first. Answers
    "how many sessions, when, how long" per client, as opposed to
    list_sessions' flat raw event log.

    A client reconnecting mid-window is handled by tracking one "currently
    open" connect per client name and closing it against that same client's
    next disconnect — correct for PiVPN's one-cert-per-client-name model,
    but would misattribute session boundaries if two devices ever shared a
    common name (not supported by pivpn add anyway).
    """
    events = _parse_openvpn_events()
    open_sessions: dict[str, dict] = {}
    sessions = []
    for e in events:
        if e["event"] == "connected":
            stale = open_sessions.get(e["client"])
            if stale:
                # Reconnected without a matching disconnect ever being
                # logged (e.g. a ping-timeout/unclean drop, not a clean
                # SIGTERM — see DISCONNECT_RE). Close out the stale open
                # session here instead of just overwriting it below —
                # otherwise that entire earlier session silently vanishes
                # from the list instead of ever being shown.
                sessions.append({
                    "client": e["client"], "start": stale["start"], "end": None,
                    "address": stale["address"], "duration": None, "ongoing": False,
                    "status_note": "Ended (exact time unknown)",
                })
            open_sessions[e["client"]] = {"start": e["ts"], "address": e["address"]}
        elif e["event"] == "disconnected":
            pending = open_sessions.pop(e["client"], None)
            start = pending["start"] if pending else None
            address = pending["address"] if pending else e["address"]
            sessions.append({
                "client": e["client"], "start": start, "end": e["ts"], "address": address,
                "duration": _format_duration(start, e["ts"]) if start else None,
                "ongoing": False,
            })
    for client, pending in open_sessions.items():
        sessions.append({
            "client": client, "start": pending["start"], "end": None,
            "address": pending["address"], "duration": None, "ongoing": True,
        })
    # Most-recent-first within each group, then ongoing sessions pulled to
    # the very top regardless of when they started — otherwise a client
    # that reconnects often (each reconnect being its own short, already-
    # ended session) keeps burying anyone who's actually connected right
    # now further down the list. list.sort() is stable, so this second
    # pass preserves the recency order the first pass already established
    # within both the ongoing and ended groups.
    sessions.sort(key=lambda s: s["start"] or "", reverse=True)
    sessions.sort(key=lambda s: not s["ongoing"])
    sessions = sessions[:limit]

    # Only bother resolving still-open sessions — a relay's conntrack
    # entry disappears the moment a client disconnects, so a lookup for
    # anything already-ended would just fail anyway. Keeps this to at most
    # a handful of SSH calls per page load instead of one per row shown.
    for s in sessions:
        if s["ongoing"]:
            s["real_address"] = resolve_real_address(s["address"])
    return sessions


def _client_ip_map() -> dict[str, str]:
    """Best-effort VPN virtual IP -> client name map, used to label traffic
    flow rows with a name instead of a bare IP. Static ccd IPs are loaded
    first, then overwritten by whoever's connected right now — live status
    is more authoritative (covers a client with no ccd-pinned IP, whose
    virtual address is only known while actually connected), but a flow
    logged just after that same client disconnects should still resolve via
    its static IP rather than fall back to showing a bare IP."""
    ip_to_name = {}
    for name, ip in pivpn_ctl.list_client_ips().items():
        if ip:
            ip_to_name[ip] = name
    for name, info in pivpn_ctl.list_connected_clients().items():
        vip = info.get("virtual_address")
        if vip:
            ip_to_name[vip] = name
    return ip_to_name


def list_traffic_flows(limit: int = 300) -> list[dict]:
    """Per-flow, client-initiated connections (src client -> dst anywhere),
    parsed from the kernel LOG lines deploy/setup-traffic-log.sh's
    mangle-table FORWARD rule produces — one line per NEW connection from
    the VPN client subnet, not every packet, most recent first.

    Genuinely different volume profile than the other Logs tabs (a single
    browsing session can open hundreds of connections in minutes), so the
    log helper uses a much shorter time window for this action specifically
    — see SINCE_FLOW in deploy/pivpn-webui-log-helper.sh.

    Best-effort, same as the rest of this module: a source IP that doesn't
    resolve to a known client (already disconnected, mapping gone stale) is
    shown as a bare IP rather than dropped, and setup-traffic-log.sh never
    having been run at all just means an empty list, not an error."""
    ip_to_name = _client_ip_map()
    out = run_root([config.LOG_HELPER, "flow"])
    parsed = []
    for raw_line in out.splitlines():
        ts, msg = _split_journal_line(raw_line.strip())
        m = FLOW_RE.search(msg)
        if not m:
            continue
        parsed.append((ts, m))
    parsed.reverse()
    parsed = parsed[:limit]

    # One org lookup per unique destination in this batch, not per row —
    # the same handful of destinations (a DNS server, a CDN edge) repeats
    # across most rows, and iplookup.get_ip_org already caches in the DB
    # across requests too, but there's no reason to pay even a dict/DB
    # lookup twice for the same IP within a single page render. Resolved
    # via get_ip_orgs_bulk so any not-yet-cached destinations (common with
    # CDN-heavy traffic, e.g. after enabling full-tunnel) are looked up
    # concurrently instead of serially timing out one at a time.
    org_by_dst = iplookup.get_ip_orgs_bulk([m.group("dst") for _, m in parsed])
    flows = []
    for ts, m in parsed:
        src = m.group("src")
        dst = m.group("dst")
        flows.append({
            "ts": ts,
            "client": ip_to_name.get(src, src),
            "src": src,
            "dst": dst,
            "dst_org": org_by_dst[dst],
            "proto": m.group("proto"),
            "sport": m.group("sport") or "",
            "dport": m.group("dport") or "",
            "in_if": m.group("in_if"),
            "out_if": m.group("out_if"),
        })
    return flows


def list_webui_log(limit: int = 300) -> list[str]:
    out = run_root([config.LOG_HELPER, "webui"])
    lines = [ln for ln in out.splitlines() if ln.strip()]
    lines.reverse()
    return lines[:limit]


def list_system_log(limit: int = 300) -> list[str]:
    out = run_root([config.LOG_HELPER, "system"])
    lines = [ln for ln in out.splitlines() if ln.strip()]
    lines.reverse()
    return lines[:limit]
