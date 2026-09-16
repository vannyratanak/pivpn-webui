#!/usr/bin/env python3
"""Pulls new OpenVPN connect/disconnect events and Traffic-tab flow lines
since the last run, and stores them as structured rows in the app's own
database (app/db.py's vpn_events/traffic_flows tables) — so the Sessions,
Client Sessions, and Traffic tabs can read instantly instead of re-parsing
raw journal text on every single page load.

Why this exists: regex-parsing a real week's worth of raw journal lines on
every request was measured at ~1.5s (OpenVPN events, ~13k lines/week) to
~4s+ (Traffic flows, thousands of lines/day) on a live server — fine for
the original 3-day/6-hour windows, not fine once someone wants a week of
history. journald itself already keeps far more than either window (a
month+, confirmed live), so the fix isn't fetching more — it's not paying
that parse cost on every page load.

Meant to be run periodically by systemd (see
deploy/pivpn-webui-log-ingest.timer / .service), as the same unprivileged
user the main app runs as — it only ever reaches root-only data through
run_root() -> the same narrow sudoers-gated helper script the web app
itself uses (pivpn-webui-log-helper.sh's openvpn-tail/flow-tail actions),
never directly.

Incremental via journalctl --cursor-file (see those actions): each run
only ever sees lines since the last one, so this stays cheap indefinitely
regardless of how much history piles up — the *parsing* cost that
motivated this doesn't reappear as an *ingestion* cost, since ingestion
only ever processes one tick's worth of new lines, not the full window.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from app import db, iplookup
from app.privileged import run_root
from app.vpnlog import CONNECT_RE, DISCONNECT_RE, FLOW_RE, _client_ip_map, _split_journal_line

RETENTION_DAYS = 7
# Generous relative to the ~15s default — the very first run on a fresh
# install backfills a full week of history in one shot (see
# pivpn-webui-log-helper.sh's BACKFILL_SINCE), which is a lot more data
# than any single normal tick.
FETCH_TIMEOUT_SECONDS = 180


def ingest_vpn_events() -> int:
    out = run_root([config.LOG_HELPER, "openvpn-tail"], timeout=FETCH_TIMEOUT_SECONDS)
    rows = []
    for raw_line in out.splitlines():
        ts, msg = _split_journal_line(raw_line.strip())
        if not msg:
            continue
        m = CONNECT_RE.search(msg)
        if m:
            rows.append((ts, "connected", m.group("name"), f"{m.group('addr')}:{m.group('port')}", ""))
            continue
        m = DISCONNECT_RE.search(msg)
        if m:
            rows.append((ts, "disconnected", m.group("name"), f"{m.group('addr')}:{m.group('port')}", ""))
            continue
        # Stored too, not dropped — the VPN Sessions tab deliberately shows
        # unrecognized lines as event='other' with the raw text, a
        # diagnostic fallback for a server whose OpenVPN log format doesn't
        # match CONNECT_RE/DISCONNECT_RE (see this app's own module
        # docstring). Losing that here would be a real feature regression.
        rows.append((ts, "other", "", "", msg))
    db.insert_vpn_events(rows)
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

    # Resolved once for this whole batch, not per row — same reasoning as
    # the old request-time code: a client's VPN IP doesn't change mid-batch,
    # and get_ip_orgs_bulk already dedups + parallelizes the actual WHOIS
    # calls internally.
    ip_to_name = _client_ip_map()
    orgs = iplookup.get_ip_orgs_bulk([m.group("dst") for _, m in parsed])

    rows = []
    for ts, m in parsed:
        src = m.group("src")
        dst = m.group("dst")
        rows.append((
            ts, src, dst, orgs.get(dst), ip_to_name.get(src),
            m.group("proto"), m.group("sport"), m.group("dport"),
            m.group("in_if"), m.group("out_if"),
        ))
    db.insert_traffic_flows(rows)
    return len(rows)


def main():
    n_events = ingest_vpn_events()
    n_flows = ingest_traffic_flows()
    db.prune_old_logs(RETENTION_DAYS)
    print(f"ingested {n_events} vpn event(s), {n_flows} traffic flow(s)")


if __name__ == "__main__":
    main()
