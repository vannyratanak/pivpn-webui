"""Read access for the Logs page's tabs.

WebUI service logs (a small, single-unit tail) still go straight through
the pivpn-webui-log-helper.sh root helper (see deploy/ and
app/privileged.py) on every request — fixed journalctl invocations, no
user input reaches the shell.

VPN Sessions/Client Sessions/Traffic/System instead read from the database
(db.list_vpn_events / db.list_traffic_flows / db.list_system_log_page) —
deploy/ingest_logs.py populates those tables periodically via the same
root helper's openvpn-tail/flow-tail/system-tail actions, off any request
path. VPN Sessions/Client Sessions/Traffic moved off live fetching because
those three are regex-parsed/paired/WHOIS-resolved, and doing that per
page load stopped being cheap once a week of history (not the original
3-day/6-hour windows) was wanted — see ingest_logs.py's own docstring for
the real numbers. System moved for a related but distinct reason: a real
7-day/60k-line pull is itself fast to *run* (~1.5s), but the several-MB
payload that produces was cheap only as long as this process and the box
being queried were the same one — once this app started reaching the box
over a socket instead (see the hub/agent work), transferring that payload
on every single page view stopped being free.

IMPORTANT — verify before relying on this in production: OpenVPN's log
line format isn't strictly standardized across versions/configs. The
CONNECT_RE / DISCONNECT_RE patterns below match the commonly-seen
"Peer Connection Initiated" / "SIGTERM ... client-instance exiting"
messages, but if your server's `verb` level or log format differs, session
parsing may fall back to raw/unparsed rows rather than raise an error —
this is a "best effort" view, not something else depends on it.
"""
import concurrent.futures
import re
import subprocess
from datetime import datetime

import config
from app import db, hub_client, pivpn_ctl

# Bounds how many resolve_real_address SSH calls a single ingest tick can
# have in flight at once — same reasoning as iplookup._MAX_CONCURRENT_WHOIS:
# high enough that a normal burst (a handful of clients reconnecting
# together) finishes in roughly one round-trip instead of N, low enough not
# to open dozens of SSH connections to the relay at once.
_MAX_CONCURRENT_RESOLVES = 8

CONNECT_RE = re.compile(
    r"\[(?P<name>[^\]]+)\] Peer Connection Initiated with \[AF_INET6?\](?P<addr>[0-9a-fA-F:.]+):(?P<port>\d+)"
)

# Two distinct shapes both mean "this client's session just ended":
# - SIGTERM: a clean client-initiated disconnect.
# - "[name] Inactivity timeout (--ping-restart), restarting": the server's
#   own keepalive noticing a client that went silent (network drop, sleep,
#   crash) and force-closing it — this is what actually catches a client
#   that never sends a clean disconnect at all, real end time instead of
#   the "Ended (exact time unknown)" stale-reconnect fallback in
#   list_client_sessions below. The (?P=name) backreference excludes the
#   *server's own* relay-keepalive line ("[relay-server] Inactivity
#   timeout...", no leading "name/addr:port " prefix at all) from ever
#   matching here — found live in this server's own system log.
DISCONNECT_RE = re.compile(
    r"^(?P<name>[^/\s]+)/(?P<addr>[0-9a-fA-F:.]+):(?P<port>\d+) "
    r"(?:SIGTERM|\[(?P=name)\] Inactivity timeout \(--ping-restart\), restarting)"
)

# journalctl -o short-iso lines look like: "2026-08-17T10:22:31+0700 host proc[pid]: message"
JOURNAL_LINE_RE = re.compile(r"^(?P<ts>\S+)\s+\S+\s+\S+?(?:\[\d+\])?:\s?(?P<msg>.*)$")
# Same shape as JOURNAL_LINE_RE, but with the process-name group also
# named/captured — see _split_journal_line_with_process.
JOURNAL_LINE_WITH_PROCESS_RE = re.compile(r"^(?P<ts>\S+)\s+\S+\s+(?P<process>\S+?)(?:\[\d+\])?:\s?(?P<msg>.*)$")

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


def _split_journal_line_with_process(raw_line: str) -> tuple[str, str, str]:
    """Like _split_journal_line, but also captures the process name (e.g.
    'sudo', 'sshd', 'gunicorn') as its own field, for system_log_lines'
    Process column — a raw whole-system line is far noisier than
    OpenVPN's own (every sudo call, every systemd unit transition, every
    ssh login), so surfacing *what* logged each line, scannable/
    searchable on its own instead of buried in free text, matters more
    here than it did for the single-source OpenVPN/flow ingestion
    _split_journal_line already serves. A separate function/regex rather
    than changing _split_journal_line itself, which openvpn-tail/flow-tail
    ingestion (and its own tests) already depend on returning a 2-tuple."""
    m = JOURNAL_LINE_WITH_PROCESS_RE.match(raw_line)
    if not m:
        return "", "", raw_line
    return _format_ts(m.group("ts")), m.group("process"), m.group("msg")


def _parse_openvpn_events() -> list[dict]:
    """Every connect/disconnect/other event, oldest first (the order they
    actually happened in) — shared by list_sessions (raw event log) and
    list_client_sessions (paired into per-client sessions with a
    duration), so pairing always sees the full, correctly-ordered event
    stream rather than an already-reversed/truncated view.

    Reads from the vpn_events table (populated periodically by
    deploy/ingest_logs.py, not on any request path) rather than a live
    journalctl fetch+regex-parse — see that script's docstring for why:
    doing this parse on every single page load was measured at ~1.5s for a
    real 7-day/13k-line volume on a live server."""
    return db.list_vpn_events()


def list_sessions(
    q: str | None = None, page: int = 1, page_size: int = 50, since: str | None = None
) -> tuple[list[dict], int]:
    """Best-effort connect/disconnect events parsed from the OpenVPN
    service journal, most recent first, server-side paginated and
    searched over the full retained history. Returns (events,
    total_matching_count). Flat event log, no pairing involved (unlike
    list_client_sessions below), so this can go straight to a paginated
    SQL query instead of reading everything into Python first."""
    return db.list_vpn_events_page(q=q, page=page, page_size=page_size, since=since)


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
    only silently fall back to showing the relabeled address as before.

    In HUB_MODE this box's own SSH keys are irrelevant — the relay only
    trusts a dedicated, forced-command key generated specifically for
    (and living only on) the box actually running the relay tunnel, i.e.
    the *agent's* box (see README's "Real client IPs behind a relay"
    section: `ssh-keygen ... -C 'thisserver-to-relay-real-ip'`, installed
    to that one box's ~/.ssh only). Same bug class as _server_ip/
    _iface_ip/list_interfaces — found the same way, by reasoning through
    what a hub-mode run of each locally-scoped helper would actually see."""
    if config.HUB_MODE:
        return _resolve_real_address_remote(address)
    return _resolve_real_address_local(address)


def _resolve_real_address_local(address: str) -> str | None:
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


def _resolve_real_address_remote(address: str) -> str | None:
    try:
        response = hub_client.call(config.DEFAULT_SERVER_ID, "resolve_real_address", address=address, timeout=8)
    except hub_client.HubClientError:
        return None
    if not response.get("ok"):
        return None
    return response.get("result")


def resolve_real_addresses_bulk(addresses: list[str]) -> dict[str, str | None]:
    """Same resolution rules as resolve_real_address, one call per unique
    address in `addresses`, but runs the underlying SSH calls concurrently
    instead of one at a time.

    Each call is a real SSH round-trip to the relay (~1-1.5s measured
    live). deploy/ingest_logs.py calls this once per ingest tick for every
    'connected' event it just saw — a burst of simultaneous new
    connections (e.g. every client reconnecting after a server restart)
    would otherwise pay that cost once per connection, sequentially, in a
    loop: 30 clients reconnecting together would take ~30-45s for that one
    tick. Running them through a bounded thread pool instead means the
    whole batch takes roughly as long as its single slowest lookup."""
    result: dict[str, str | None] = {}
    to_resolve = list(dict.fromkeys(addresses))
    if not to_resolve:
        return result
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(_MAX_CONCURRENT_RESOLVES, len(to_resolve))
    ) as pool:
        future_to_addr = {pool.submit(resolve_real_address, addr): addr for addr in to_resolve}
        for future in concurrent.futures.as_completed(future_to_addr):
            result[future_to_addr[future]] = future.result()
    return result


def sort_client_sessions(sessions: list[dict]) -> None:
    """In place. Most-recent-first within each group, then ongoing sessions
    pulled to the very top regardless of when they started — otherwise a
    client that reconnects often (each reconnect being its own short,
    already-ended session) keeps burying anyone who's actually connected
    right now further down the list. list.sort() is stable, so the second
    pass preserves the recency order the first pass already established
    within both the ongoing and ended groups.

    A free function, not folded into list_client_sessions below, because
    routes.py's live-connected-status cross-check can flip a session's
    `ongoing` flag *after* list_client_sessions has already returned and
    sorted (a session the log parser thought was still open, relabeled
    "Ended (exact time unknown)" once it's confirmed not actually
    connected — see that cross-check's own comment). That correction has
    to re-run this same sort, or the relabeled session keeps the top-
    pinned position it only ever earned by looking ongoing in the first
    place, instead of falling back into its real chronological spot."""
    sessions.sort(key=lambda s: s["start"] or "", reverse=True)
    sessions.sort(key=lambda s: not s["ongoing"])


def list_client_sessions(
    q: str | None = None, page: int = 1, page_size: int = 50, since: str | None = None,
    client: str | None = None,
) -> tuple[list[dict], int]:
    """Per-client login sessions — each a paired connect+disconnect (or
    still-open connect with no disconnect yet), most recent first,
    searched and paginated over the full retained history. Returns
    (sessions, total_matching_count).

    Unlike list_sessions/list_traffic_flows, this can't push search/
    pagination down into SQL: pairing a connect with its disconnect needs
    to see the *whole* chronological event stream first (a session's two
    halves can be far apart in the raw table), so search+pagination has to
    apply to the already-paired result instead — real event volume here
    (~13k/week observed live) is small enough that doing this in Python
    each request is still fast.

    Answers "how many sessions, when, how long" per client, as opposed to
    list_sessions' flat raw event log.

    A client reconnecting mid-window is handled by tracking one "currently
    open" connect per client name and closing it against that same client's
    next disconnect — correct for PiVPN's one-cert-per-client-name model,
    but would misattribute session boundaries if two devices ever shared a
    common name (not supported by pivpn add anyway).

    real_address (the relay's real-IP resolution — see resolve_real_address)
    is carried straight through from the 'connected' event's own stored
    value (deploy/ingest_logs.py resolves it once, within about a minute of
    the connection actually starting) rather than looked up live here. That
    used to only work for still-ongoing sessions, since a live lookup
    against the relay's conntrack table fails the instant a client
    disconnects — resolving it this early instead means an already-*ended*
    session can now show a real address too, wherever ingestion caught it
    in time.

    `since` (a 'YYYY-MM-DD HH:MM:SS' cutoff, same format as `start`/`end`)
    filters to sessions that *started* at or after it — applied here, in
    Python, after pairing, for the same reason `q` is: pairing needs the
    full event stream regardless of the window being displayed.

    `client`, if given, is an exact (not substring) match on session
    client name — the client detail page's own session-log tab uses this
    to scope the whole history to just one client, unlike `q` which
    substring-searches every field including client for the main Logs
    page's free-text search.
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
                    "real_address": stale["real_address"],
                })
            open_sessions[e["client"]] = {
                "start": e["ts"], "address": e["address"], "real_address": e.get("real_address"),
            }
        elif e["event"] == "disconnected":
            pending = open_sessions.pop(e["client"], None)
            start = pending["start"] if pending else None
            address = pending["address"] if pending else e["address"]
            sessions.append({
                "client": e["client"], "start": start, "end": e["ts"], "address": address,
                "duration": _format_duration(start, e["ts"]) if start else None,
                "ongoing": False,
                "real_address": pending["real_address"] if pending else None,
            })
    for open_client, pending in open_sessions.items():
        sessions.append({
            "client": open_client, "start": pending["start"], "end": None,
            "address": pending["address"], "duration": None, "ongoing": True,
            "real_address": pending["real_address"],
        })
    sort_client_sessions(sessions)

    if client:
        sessions = [s for s in sessions if s.get("client") == client]

    if since:
        sessions = [s for s in sessions if (s.get("start") or "") >= since]

    if q:
        needle = q.lower()
        sessions = [
            s for s in sessions
            if needle in " ".join(
                str(s.get(f) or "") for f in
                ("client", "start", "end", "duration", "address", "status_note", "real_address")
            ).lower()
        ]

    total = len(sessions)
    start = (page - 1) * page_size
    return sessions[start:start + page_size], total


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


def list_traffic_flows(
    q: str | None = None, page: int = 1, page_size: int = 50, since: str | None = None,
    client: str | None = None,
) -> tuple[list[dict], int]:
    """Per-flow, client-initiated connections (src client -> dst anywhere),
    most recent first, server-side paginated and searched over the full
    retained history (not just a fixed-size recent slice — see db.py's
    list_traffic_flows for why this matters once retention holds a real
    week of data). Returns (flows, total_matching_count).

    `client`, if given, is an exact match pushed down into the SQL query
    (unlike `q`, a substring search across several columns) — the client
    detail page's own traffic tab uses this to answer "where has this one
    client actually gone", scoped server-side rather than filtering a
    mixed-client page in JS.

    Reads from the traffic_flows table (populated periodically by
    deploy/ingest_logs.py, not on any request path) — client name and
    destination org are already resolved at ingest time (that script's own
    call to _client_ip_map()/iplookup.get_ip_orgs_bulk), not here, so this
    is a plain read with no WHOIS calls or regex parsing on the request
    path at all. See ingest_logs.py's docstring for why: doing this same
    work per page load was measured at ~4s+ at this app's real traffic
    volume once a week of history (not just the original 6-hour window)
    was wanted.

    Best-effort, same as the rest of this module: a source IP that never
    resolved to a known client at ingest time (already disconnected,
    mapping gone stale) is shown as a bare IP rather than dropped, and
    setup-traffic-log.sh never having been run at all just means an empty
    list, not an error."""
    rows, total = db.list_traffic_flows(q=q, page=page, page_size=page_size, since=since, client=client)
    flows = []
    for row in rows:
        flows.append({
            "ts": row["ts"],
            "client": row["client"] or row["src"],
            "src": row["src"],
            "dst": row["dst"],
            "dst_org": row["dst_org"],
            "proto": row["proto"],
            "sport": row["sport"] or "",
            "dport": row["dport"] or "",
            "in_if": row["in_if"],
            "out_if": row["out_if"],
        })
    return flows, total


def list_system_log(
    q: str | None = None, page: int = 1, page_size: int = 50, since: str | None = None
) -> tuple[list[dict], int]:
    """Whole-system journal lines, most recent first, server-side
    paginated and searched over the full retained history — same
    conventions as list_traffic_flows above. Reads from the
    system_log_lines table (populated periodically by
    deploy/ingest_logs.py's system-tail ingestion, not on any request
    path) rather than live-fetching journalctl on every request: a real
    7-day/60k-line pull is itself fast (~1.5s on this app's real box),
    but the resulting several-MB payload was what actually caused
    timeouts once this app started running with the box it's controlling
    over a socket instead of always being the same process — see the
    hub/agent work. Best-effort, same as the rest of this module: the
    `system` fixed-window helper action is still there for a manual/
    diagnostic pull (see deploy/pivpn-webui-log-helper.sh), this function
    just isn't what the live page uses anymore."""
    rows, total = db.list_system_log_page(q=q, page=page, page_size=page_size, since=since)
    return [{"ts": r["ts"], "process": r["process"], "message": r["message"]} for r in rows], total
