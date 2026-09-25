#!/usr/bin/env python3
"""Pulls recovery batches of OpenVPN events and Traffic-tab flow lines, plus
whole-system journal lines on the fast system-log timer, and stores them as
structured rows in the app's own database (app/db.py's
vpn_events/traffic_flows/system_log_lines tables) — so the Sessions,
Client Sessions, Traffic, and System tabs can read instantly instead of
re-parsing/re-fetching raw journal text on every single page load.

Why this exists: regex-parsing a real week's worth of raw journal lines on
every request was measured at ~1.5s (OpenVPN events, ~13k lines/week) to
~4s+ (Traffic flows, thousands of lines/day) on a live server — fine for
the original 3-day/6-hour windows, not fine once someone wants a week of
history. journald itself already keeps far more than either window (a
month+, confirmed live), so the fix isn't fetching more — it's not paying
that parse cost on every page load.

Meant to be run periodically by systemd (the whole-system log timer runs
every five seconds; VPN and traffic recovery runs once a minute), as the
same unprivileged user the main app runs as — it only ever reaches root-only data through
run_root() -> the same narrow sudoers-gated helper script the web app
itself uses (pivpn-webui-log-helper.sh's openvpn-tail/flow-tail actions),
never directly. The normal live path for VPN and traffic events is the
agent's acknowledged WebSocket journal stream; these periodic reads provide
backfill and recovery.

Incremental via journalctl --cursor-file (see those actions): each run
only ever sees lines since the last one, so this stays cheap indefinitely
regardless of how much history piles up — the *parsing* cost that
motivated this doesn't reappear as an *ingestion* cost, since ingestion
only ever processes one tick's worth of new lines, not the full window.

Traffic destination WHOIS lookups are intentionally handled separately by
deploy/ingest_ip_orgs.py. Flow rows are committed with cached organization
data when available, then cold destinations are enriched asynchronously.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from app import db, iplookup
from app.privileged import PrivilegedCommandError, run_root
from app.vpnlog import (
    CONNECT_RE,
    DISCONNECT_RE,
    FLOW_RE,
    _split_journal_line,
    _split_journal_line_with_process,
    resolve_real_addresses_bulk,
)

RETENTION_DAYS = 7
# Generous relative to the ~15s default — the very first run on a fresh
# install backfills a full week of history in one shot (see
# pivpn-webui-log-helper.sh's BACKFILL_SINCE), which is a lot more data
# than any single normal tick.
FETCH_TIMEOUT_SECONDS = 180


def ingest_vpn_events() -> int:
    out = run_root([config.LOG_HELPER, "openvpn-tail"], timeout=FETCH_TIMEOUT_SECONDS)
    connect_events = []      # (ts, client, address)
    disconnect_events = []   # (ts, client, address)
    other_events = []        # (ts, detail)
    for raw_line in out.splitlines():
        ts, msg = _split_journal_line(raw_line.strip())
        if not msg:
            continue
        m = CONNECT_RE.search(msg)
        if m:
            connect_events.append((ts, m.group("name"), f"{m.group('addr')}:{m.group('port')}"))
            continue
        m = DISCONNECT_RE.search(msg)
        if m:
            disconnect_events.append((ts, m.group("name"), f"{m.group('addr')}:{m.group('port')}"))
            continue
        # Stored too, not dropped — the VPN Sessions tab deliberately shows
        # unrecognized lines as event='other' with the raw text, a
        # diagnostic fallback for a server whose OpenVPN log format doesn't
        # match CONNECT_RE/DISCONNECT_RE (see this app's own module
        # docstring). Losing that here would be a real feature regression.
        other_events.append((ts, msg))

    rows = [
        (ts, "connected", client, addr, "", None)
        for ts, client, addr in connect_events
    ]
    rows += [(ts, "disconnected", client, addr, "", None) for ts, client, addr in disconnect_events]
    rows += [(ts, "other", "", "", detail, None) for ts, detail in other_events]
    db.insert_vpn_events(rows)

    # Relay lookups are useful enrichment, but never delay storing the
    # connection event itself. Resolve in parallel after the insert and
    # patch the rows when answers arrive.
    real_addresses = resolve_real_addresses_bulk([addr for _, _, addr in connect_events])
    db.update_vpn_event_real_addresses(real_addresses)
    return len(rows)


def ingest_traffic_flows() -> int:
    out = run_root([config.LOG_HELPER, "flow-tail"], timeout=FETCH_TIMEOUT_SECONDS)
    parsed = []
    for raw_line in out.splitlines():
        ts, msg = _split_journal_line(raw_line.strip())
        if not ts:
            continue
        m = FLOW_RE.search(msg)
        if m:
            parsed.append((ts, m))
    if not parsed:
        return 0

    # Use only local cache state here. WHOIS used to run inline before these
    # rows were committed, so one slow registry could delay fresh traffic
    # and every later log stream. A separate worker resolves misses.
    clients = db.list_client_status_cache()
    ip_to_name = {}
    for client in clients:
        if client.get("ip"):
            ip_to_name[client["ip"]] = client["name"]
        session = client.get("session")
        if session and session.get("virtual_address"):
            ip_to_name[session["virtual_address"]] = client["name"]
    orgs = iplookup.get_cached_ip_orgs([m.group("dst") for _, m in parsed])

    rows = []
    for ts, m in parsed:
        src = m.group("src")
        dst = m.group("dst")
        rows.append((
            ts, src, dst, orgs.get(dst), ip_to_name.get(src),
            m.group("proto"), m.group("sport"), m.group("dport"),
            m.group("in_if"), m.group("out_if"),
        ))
    # Commit the flow facts immediately; organization enrichment is
    # independent and can safely catch up after these rows are visible.
    db.insert_traffic_flows(rows)
    return len(rows)


def ingest_system_log() -> int:
    """Unlike the other two, this isn't filtered to any particular pattern
    at all — it's the *entire* journal (every sudo call, every systemd
    unit transition, every ssh login), so it's a genuinely higher volume
    than vpn_events/traffic_flows. No WHOIS/pairing work needed though,
    just a straight parse-and-insert."""
    out = run_root([config.LOG_HELPER, "system-tail"], timeout=FETCH_TIMEOUT_SECONDS)
    rows = []
    for raw_line in out.splitlines():
        ts, process, msg = _split_journal_line_with_process(raw_line.strip())
        if not ts:
            continue
        rows.append((ts, process, msg))
    db.insert_system_log_lines(rows)
    return len(rows)


def _best_effort(fn):
    """Unattended entry point (the systemd timer, or a fresh setup-hub.sh
    run — see that script's own step ordering: background ingestion is
    started at step 5, before step 6 registers the first agent at all,
    so the very first tick here always finds nobody connected yet) — a
    transient or not-yet-registered agent shouldn't crash-loop this
    every 10 seconds. Deliberately NOT applied inside routes.py's/api.py's
    /logs/refresh: that's an interactive click expecting a real answer,
    including "the agent isn't connected" as an actionable 502, not a
    silent no-op."""
    try:
        return fn()
    except PrivilegedCommandError as exc:
        print(f"ingest_logs: {fn.__name__} skipped, agent unreachable: {exc}", file=sys.stderr)
        return 0


def main(mode="all"):
    if mode not in {"all", "system-only", "events-only"}:
        raise ValueError(f"unknown ingest mode: {mode}")
    n_system = _best_effort(ingest_system_log) if mode in {"all", "system-only"} else 0
    n_events = _best_effort(ingest_vpn_events) if mode in {"all", "events-only"} else 0
    n_flows = _best_effort(ingest_traffic_flows) if mode in {"all", "events-only"} else 0
    db.prune_old_logs(RETENTION_DAYS)
    print(f"ingested {n_events} vpn event(s), {n_flows} traffic flow(s), {n_system} system log line(s)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "all")
