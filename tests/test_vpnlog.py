import subprocess
import threading

import config
from app import db, pivpn_ctl, vpnlog
from app.vpnlog import (
    CONNECT_RE,
    DISCONNECT_RE,
    FLOW_RE,
    _client_ip_map,
    _format_duration,
    _split_journal_line,
    list_client_sessions,
    list_traffic_flows,
    resolve_real_address,
    resolve_real_addresses_bulk,
)

# Real lines captured live from a production install (macbook-phanne
# connecting through the relay tunnel) — not synthetic examples, since this
# module has already had one silent-parsing bug from a format that only
# looked right on paper (see its own docstring).

REAL_JOURNAL_CONNECT = (
    "2026-08-21T13:20:11+0700 vpn ovpn-server[23975]: "
    "[macbook-phanne] Peer Connection Initiated with [AF_INET]10.66.66.1:2642"
)
REAL_JOURNAL_DISCONNECT = (
    "2026-08-21T12:47:07+0700 vpn ovpn-server[23975]: "
    "macbook-phanne/10.66.66.1:2201 SIGTERM[soft,remote-exit] received, client-instance exiting"
)


def test_split_journal_line_parses_real_connect_line():
    ts, msg = _split_journal_line(REAL_JOURNAL_CONNECT)
    assert ts == "2026-08-21 13:20:11"
    assert msg == "[macbook-phanne] Peer Connection Initiated with [AF_INET]10.66.66.1:2642"


def test_split_journal_line_unparseable_falls_back_to_raw():
    ts, msg = _split_journal_line("not a journal line at all")
    assert ts == ""
    assert msg == "not a journal line at all"


def test_connect_re_matches_real_line():
    _, msg = _split_journal_line(REAL_JOURNAL_CONNECT)
    m = CONNECT_RE.search(msg)
    assert m is not None
    assert m.group("name") == "macbook-phanne"
    assert m.group("addr") == "10.66.66.1"
    assert m.group("port") == "2642"


def test_disconnect_re_matches_real_line():
    _, msg = _split_journal_line(REAL_JOURNAL_DISCONNECT)
    m = DISCONNECT_RE.search(msg)
    assert m is not None
    assert m.group("name") == "macbook-phanne"
    assert m.group("addr") == "10.66.66.1"
    assert m.group("port") == "2201"


def test_disconnect_re_does_not_match_connect_line():
    # a real prior bug class: two regexes with a plausible but wrong overlap
    _, msg = _split_journal_line(REAL_JOURNAL_CONNECT)
    assert DISCONNECT_RE.search(msg) is None


def test_connect_re_does_not_match_disconnect_line():
    _, msg = _split_journal_line(REAL_JOURNAL_DISCONNECT)
    assert CONNECT_RE.search(msg) is None


def test_format_duration_normal():
    assert _format_duration("2026-08-21 12:37:38", "2026-08-21 12:45:30") == "7m 52s"


def test_format_duration_hours():
    assert _format_duration("2026-08-21 10:00:00", "2026-08-21 12:15:30") == "2h 15m"


def test_format_duration_seconds_only():
    assert _format_duration("2026-08-21 12:00:00", "2026-08-21 12:00:45") == "45s"


def test_format_duration_negative_returns_none():
    # end before start (clock skew, or a stray unmatched pair) — don't show
    # a nonsense negative duration
    assert _format_duration("2026-08-21 12:00:00", "2026-08-21 11:00:00") is None


def test_format_duration_unparseable_returns_none():
    assert _format_duration("garbage", "2026-08-21 12:00:00") is None


def test_format_duration_none_start_returns_none():
    assert _format_duration(None, "2026-08-21 12:00:00") is None


# --- list_client_sessions: ongoing sessions must sort to the top,
# regardless of how long ago they started — a client that reconnects
# often (each reconnect its own short, already-ended session) shouldn't
# be able to bury someone who's actually connected right now further down
# the list just by having more recent (but finished) activity.
#
# Seeds app/db.py's vpn_events table directly (via the temp_db fixture)
# rather than faking raw journal text — list_client_sessions reads from
# that table now (populated by deploy/ingest_logs.py in production, not on
# any request path), not a live journalctl fetch. The CONNECT_RE/
# DISCONNECT_RE parsing this used to also exercise is covered separately
# in tests/test_ingest_logs.py, where that parsing now actually lives.

def _connected(ts, name, addr, real_address=None):
    return (ts, "connected", name, addr, "", real_address)


def _disconnected(ts, name, addr):
    return (ts, "disconnected", name, addr, "", None)


def test_ongoing_session_sorts_above_more_recent_ended_ones(temp_db):
    db.insert_vpn_events([
        # "old" started much earlier and never disconnected — still ongoing
        _connected("2026-08-21 13:00:00", "old", "10.66.66.1:1"),
        # "test" connected and disconnected much more recently, but it's over
        _connected("2026-08-21 15:50:00", "test", "10.66.66.1:2"),
        _disconnected("2026-08-21 15:50:10", "test", "10.66.66.1:2"),
    ])
    sessions, _total = list_client_sessions()
    assert [s["client"] for s in sessions] == ["old", "test"]
    assert sessions[0]["ongoing"] is True
    assert sessions[1]["ongoing"] is False


def test_multiple_ongoing_still_sorted_by_recency_among_themselves(temp_db):
    db.insert_vpn_events([
        _connected("2026-08-21 10:00:00", "early-bird", "10.66.66.1:1"),
        _connected("2026-08-21 14:00:00", "late-riser", "10.66.66.1:2"),
    ])
    sessions, _total = list_client_sessions()
    assert [s["client"] for s in sessions] == ["late-riser", "early-bird"]
    assert all(s["ongoing"] for s in sessions)


def test_reconnect_without_matching_disconnect_does_not_lose_the_earlier_session(temp_db):
    # Regression test for a real bug: a second "connected" event for the
    # same client name (e.g. a ping-timeout/unclean drop that never logs
    # DISCONNECT_RE's SIGTERM pattern, followed by a reconnect) used to
    # silently overwrite the still-open first session in open_sessions —
    # that entire earlier session vanished from the list, never shown as
    # ended or ongoing, just gone.
    db.insert_vpn_events([
        _connected("2026-08-21 09:00:00", "nurak", "10.66.66.1:1"),
        # no disconnect for the first connection — tunnel just died
        _connected("2026-08-21 09:30:00", "nurak", "10.66.66.1:2"),
        _disconnected("2026-08-21 10:00:00", "nurak", "10.66.66.1:2"),
    ])
    sessions, _total = list_client_sessions()
    assert len(sessions) == 2  # both the orphaned first session and the paired second one
    starts = {s["start"] for s in sessions}
    assert "2026-08-21 09:00:00" in starts  # the first session is still present, not lost
    orphaned = next(s for s in sessions if s["start"] == "2026-08-21 09:00:00")
    assert orphaned["ongoing"] is False
    assert orphaned["end"] is None
    assert orphaned["status_note"] == "Ended (exact time unknown)"


def test_real_address_carries_through_from_the_connected_event(temp_db):
    # real_address is resolved once by deploy/ingest_logs.py, at ingest
    # time (see that script) — not looked up live here anymore. Confirms
    # it survives into all three session shapes list_client_sessions
    # produces: still-ongoing, cleanly disconnected, and stale-closed
    # (reconnected without a matching disconnect ever logged).
    db.insert_vpn_events([
        _connected("2026-08-21 09:00:00", "nurak", "10.66.66.1:1", real_address="1.2.3.4:5"),
        _connected("2026-08-21 09:30:00", "nurak", "10.66.66.1:2", real_address="1.2.3.4:6"),
        _disconnected("2026-08-21 10:00:00", "nurak", "10.66.66.1:2"),
        _connected("2026-08-21 11:00:00", "mobile", "10.66.66.1:3", real_address="9.9.9.9:7"),
    ])
    sessions, _total = list_client_sessions()

    stale = next(s for s in sessions if s.get("status_note") == "Ended (exact time unknown)")
    assert stale["real_address"] == "1.2.3.4:5"

    closed = next(s for s in sessions if s["client"] == "nurak" and s["end"] is not None)
    assert closed["real_address"] == "1.2.3.4:6"

    ongoing = next(s for s in sessions if s["client"] == "mobile")
    assert ongoing["ongoing"] is True
    assert ongoing["real_address"] == "9.9.9.9:7"


def test_sort_client_sessions_resorts_a_session_relabeled_from_ongoing_to_ended():
    # Regression test for routes.py's live-connected-status cross-check:
    # once a session that list_client_sessions sorted as ongoing (pinned to
    # the top) gets relabeled to ended (see routes.py's client_sessions
    # branch), re-running this same sort must drop it back into its real
    # chronological spot, not leave it sitting in the top-pinned position
    # it only ever earned by looking ongoing in the first place.
    sessions = [
        {"client": "stale", "start": "2026-09-15 09:46:39", "ongoing": False,
         "status_note": "Ended (exact time unknown)"},
        {"client": "recent", "start": "2026-09-15 13:30:30", "ongoing": False},
    ]
    vpnlog.sort_client_sessions(sessions)
    assert [s["client"] for s in sessions] == ["recent", "stale"]


# --- resolve_real_address: the relay real-IP lookup. Every branch here
# must fail closed to "show the fallback address" (return None), never
# raise — a disabled/unreachable relay should never break the Logs page.

def _fake_run(returncode=0, stdout=""):
    def run(argv, capture_output, text, timeout):
        return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout=stdout, stderr="")
    return run


def test_resolve_no_relay_configured_returns_none(monkeypatch):
    monkeypatch.setattr(config, "RELAY_HOST", None)
    monkeypatch.setattr(config, "RELAY_TUNNEL_IP", None)
    assert resolve_real_address("10.66.66.1:36530") is None


def test_resolve_address_not_from_relay_returns_none(monkeypatch):
    monkeypatch.setattr(config, "RELAY_HOST", "157.245.207.122")
    monkeypatch.setattr(config, "RELAY_TUNNEL_IP", "10.66.66.1")
    # a normal, direct (non-relayed) client address — nothing to resolve
    assert resolve_real_address("10.202.226.4:5000") is None


def test_resolve_malformed_address_returns_none(monkeypatch):
    monkeypatch.setattr(config, "RELAY_HOST", "157.245.207.122")
    monkeypatch.setattr(config, "RELAY_TUNNEL_IP", "10.66.66.1")
    assert resolve_real_address("not-an-address") is None


def test_resolve_success(monkeypatch):
    monkeypatch.setattr(config, "RELAY_HOST", "157.245.207.122")
    monkeypatch.setattr(config, "RELAY_TUNNEL_IP", "10.66.66.1")
    monkeypatch.setattr(subprocess, "run", _fake_run(returncode=0, stdout="27.109.114.181:36530\n"))
    assert resolve_real_address("10.66.66.1:36530") == "27.109.114.181:36530"


def test_resolve_lookup_script_not_found_returns_none(monkeypatch):
    # e.g. the connection already ended and conntrack forgot it
    monkeypatch.setattr(config, "RELAY_HOST", "157.245.207.122")
    monkeypatch.setattr(config, "RELAY_TUNNEL_IP", "10.66.66.1")
    monkeypatch.setattr(subprocess, "run", _fake_run(returncode=1, stdout=""))
    assert resolve_real_address("10.66.66.1:36530") is None


def test_resolve_ssh_failure_returns_none_not_raise(monkeypatch):
    monkeypatch.setattr(config, "RELAY_HOST", "157.245.207.122")
    monkeypatch.setattr(config, "RELAY_TUNNEL_IP", "10.66.66.1")

    def raise_timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="ssh", timeout=5)

    monkeypatch.setattr(subprocess, "run", raise_timeout)
    assert resolve_real_address("10.66.66.1:36530") is None


def test_resolve_ssh_binary_missing_returns_none_not_raise(monkeypatch):
    monkeypatch.setattr(config, "RELAY_HOST", "157.245.207.122")
    monkeypatch.setattr(config, "RELAY_TUNNEL_IP", "10.66.66.1")

    def raise_oserror(*a, **k):
        raise OSError("ssh not found")

    monkeypatch.setattr(subprocess, "run", raise_oserror)
    assert resolve_real_address("10.66.66.1:36530") is None


def test_resolve_real_addresses_bulk_dedups_and_resolves_each_once(monkeypatch):
    monkeypatch.setattr(config, "RELAY_HOST", "157.245.207.122")
    monkeypatch.setattr(config, "RELAY_TUNNEL_IP", "10.66.66.1")
    calls = []
    lock = threading.Lock()

    def run(argv, capture_output, text, timeout):
        port = argv[-1]
        with lock:
            calls.append(port)
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout=f"1.2.3.4:{port}\n", stderr="")

    monkeypatch.setattr(subprocess, "run", run)

    result = resolve_real_addresses_bulk(["10.66.66.1:1", "10.66.66.1:2", "10.66.66.1:1"])

    assert result == {"10.66.66.1:1": "1.2.3.4:1", "10.66.66.1:2": "1.2.3.4:2"}
    assert sorted(calls) == ["1", "2"]  # each unique address queried exactly once


def test_resolve_real_addresses_bulk_empty_input_returns_empty(monkeypatch):
    assert resolve_real_addresses_bulk([]) == {}


def test_resolve_real_addresses_bulk_runs_concurrently_not_serially(monkeypatch):
    # Two addresses, each blocking until both lookups are in flight at
    # once — proves a batch doesn't serialize N SSH round-trips in the
    # ingest tick that calls this (the exact slowness a burst of
    # simultaneous new connections would otherwise cause). Would
    # deadlock/timeout under a one-at-a-time loop.
    monkeypatch.setattr(config, "RELAY_HOST", "157.245.207.122")
    monkeypatch.setattr(config, "RELAY_TUNNEL_IP", "10.66.66.1")
    both_started = threading.Barrier(2, timeout=5)

    def run(argv, capture_output, text, timeout):
        both_started.wait()
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="1.2.3.4:9\n", stderr="")

    monkeypatch.setattr(subprocess, "run", run)

    result = resolve_real_addresses_bulk(["10.66.66.1:1", "10.66.66.1:2"])

    assert result == {"10.66.66.1:1": "1.2.3.4:9", "10.66.66.1:2": "1.2.3.4:9"}


# --- FLOW_RE / list_traffic_flows: the netfilter LOG target's own line
# shape (kernel-defined, stable across versions, unlike OpenVPN's own log
# format — see this module's docstring) produced by
# deploy/setup-traffic-log.sh's mangle-table FORWARD rule.

# Real line captured live from a production install (a real "mobile" client
# making a DNS-over-TLS connection through .10) — includes the "MAC= "
# (empty) field between OUT= and SRC= that a hand-written example would
# easily miss.
TCP_FLOW_LINE = (
    "2026-09-15T10:11:14+0700 vpn kernel: VPNFLOW IN=tun0 OUT=ens18 MAC= "
    "SRC=10.202.226.2 DST=149.112.112.112 LEN=64 TOS=0x00 PREC=0x00 TTL=63 "
    "ID=0 DF PROTO=TCP SPT=52250 DPT=443 WINDOW=65535 RES=0x00 CWR ECE SYN URGP=0"
)
# Synthetic (ordinary client browsing traffic doesn't generate ICMP) — just
# exercises the no-ports branch.
ICMP_FLOW_LINE = (
    "2026-09-15T09:41:00+0700 vpn kernel: VPNFLOW IN=tun0 OUT=ens18 MAC= "
    "SRC=10.202.226.4 DST=1.1.1.1 LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF "
    "PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1"
)


def test_flow_re_matches_tcp_line_with_ports():
    _, msg = _split_journal_line(TCP_FLOW_LINE)
    m = FLOW_RE.search(msg)
    assert m is not None
    assert m.group("in_if") == "tun0"
    assert m.group("out_if") == "ens18"
    assert m.group("src") == "10.202.226.2"
    assert m.group("dst") == "149.112.112.112"
    assert m.group("proto") == "TCP"
    assert m.group("sport") == "52250"
    assert m.group("dport") == "443"


def test_flow_re_matches_icmp_line_without_ports():
    _, msg = _split_journal_line(ICMP_FLOW_LINE)
    m = FLOW_RE.search(msg)
    assert m is not None
    assert m.group("proto") == "ICMP"
    assert m.group("sport") is None
    assert m.group("dport") is None


# --- list_traffic_flows: reads pre-resolved rows from app/db.py's
# traffic_flows table (populated by deploy/ingest_logs.py, which resolves
# client name + destination org at ingest time — see that script and
# tests/test_ingest_logs.py, where those concerns now actually live). No
# WHOIS calls, no journalctl fetch, no regex parsing happen on this
# request-time read path anymore.

def _flow_row(ts, src, dst, dst_org=None, client=None, proto="TCP", sport="1234", dport="443"):
    return (ts, src, dst, dst_org, client, proto, sport, dport, "tun0", "ens18")


def test_list_traffic_flows_reads_most_recent_first(temp_db):
    db.insert_traffic_flows([
        _flow_row("2026-09-16 10:00:00", "10.202.226.2", "1.1.1.1", client="mobile"),
        _flow_row("2026-09-16 10:00:05", "10.202.226.77", "149.112.112.112",
                   dst_org="Meta Platforms Ireland Limited"),
    ])

    flows, total = list_traffic_flows()

    assert total == 2
    assert len(flows) == 2
    # most recent first
    assert flows[0]["dst"] == "149.112.112.112"
    assert flows[0]["dst_org"] == "Meta Platforms Ireland Limited"
    assert flows[0]["client"] == "10.202.226.77"  # no client resolved at ingest -> bare IP
    assert flows[1]["client"] == "mobile"
    assert flows[1]["dport"] == "443"


def test_list_traffic_flows_paginates_over_the_full_history(temp_db):
    # Real regression test for "why only 300 rows" — page_size caps what's
    # shown per page, but `total` must reflect everything that matches, so
    # a caller can page all the way through instead of hitting a wall.
    db.insert_traffic_flows([
        _flow_row(f"2026-09-16 10:00:{i:02d}", "10.202.226.2", "1.1.1.1")
        for i in range(5)
    ])
    flows, total = list_traffic_flows(page=1, page_size=2)
    assert total == 5
    assert len(flows) == 2

    flows_p3, total_p3 = list_traffic_flows(page=3, page_size=2)
    assert total_p3 == 5
    assert len(flows_p3) == 1  # last page, partial


def test_list_traffic_flows_search_matches_across_full_history_not_just_one_page(temp_db):
    db.insert_traffic_flows([
        _flow_row("2026-09-16 10:00:00", "10.202.226.2", "1.1.1.1", client="mobile"),
        _flow_row("2026-09-16 10:00:05", "10.202.226.77", "149.112.112.112", client="laptop"),
    ])
    flows, total = list_traffic_flows(q="laptop")
    assert total == 1
    assert flows[0]["client"] == "laptop"


def test_client_ip_map_prefers_live_over_static(monkeypatch):
    # "nurak" has moved off its static ccd IP onto a dynamically-assigned
    # one for this session — the live status should win, not the stale
    # static mapping.
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {"nurak": "10.202.226.2"})
    monkeypatch.setattr(
        pivpn_ctl, "list_connected_clients",
        lambda: {"nurak": {"virtual_address": "10.202.226.9"}},
    )
    assert _client_ip_map() == {"10.202.226.2": "nurak", "10.202.226.9": "nurak"}


