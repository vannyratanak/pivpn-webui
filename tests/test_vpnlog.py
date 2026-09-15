import subprocess

import config
from app import pivpn_ctl, vpnlog
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

def _connect_line(ts, name, addr):
    return f"{ts}+0700 vpn ovpn-server[1]: [{name}] Peer Connection Initiated with [AF_INET]{addr}"


def _disconnect_line(ts, name, addr):
    return f"{ts}+0700 vpn ovpn-server[1]: {name}/{addr} SIGTERM[soft,remote-exit] received, client-instance exiting"


def test_ongoing_session_sorts_above_more_recent_ended_ones(monkeypatch):
    lines = [
        # "old" started much earlier and never disconnected — still ongoing
        _connect_line("2026-08-21T13:00:00", "old", "10.66.66.1:1"),
        # "test" connected and disconnected much more recently, but it's over
        _connect_line("2026-08-21T15:50:00", "test", "10.66.66.1:2"),
        _disconnect_line("2026-08-21T15:50:10", "test", "10.66.66.1:2"),
    ]
    monkeypatch.setattr(vpnlog, "run_root", lambda argv: "\n".join(lines))
    sessions = list_client_sessions()
    assert [s["client"] for s in sessions] == ["old", "test"]
    assert sessions[0]["ongoing"] is True
    assert sessions[1]["ongoing"] is False


def test_multiple_ongoing_still_sorted_by_recency_among_themselves(monkeypatch):
    lines = [
        _connect_line("2026-08-21T10:00:00", "early-bird", "10.66.66.1:1"),
        _connect_line("2026-08-21T14:00:00", "late-riser", "10.66.66.1:2"),
    ]
    monkeypatch.setattr(vpnlog, "run_root", lambda argv: "\n".join(lines))
    sessions = list_client_sessions()
    assert [s["client"] for s in sessions] == ["late-riser", "early-bird"]
    assert all(s["ongoing"] for s in sessions)


def test_reconnect_without_matching_disconnect_does_not_lose_the_earlier_session(monkeypatch):
    # Regression test for a real bug: a second "connected" event for the
    # same client name (e.g. a ping-timeout/unclean drop that never logs
    # DISCONNECT_RE's SIGTERM pattern, followed by a reconnect) used to
    # silently overwrite the still-open first session in open_sessions —
    # that entire earlier session vanished from the list, never shown as
    # ended or ongoing, just gone.
    lines = [
        _connect_line("2026-08-21T09:00:00", "nurak", "10.66.66.1:1"),
        # no disconnect for the first connection — tunnel just died
        _connect_line("2026-08-21T09:30:00", "nurak", "10.66.66.1:2"),
        _disconnect_line("2026-08-21T10:00:00", "nurak", "10.66.66.1:2"),
    ]
    monkeypatch.setattr(vpnlog, "run_root", lambda argv: "\n".join(lines))
    sessions = list_client_sessions()
    assert len(sessions) == 2  # both the orphaned first session and the paired second one
    starts = {s["start"] for s in sessions}
    assert "2026-08-21 09:00:00" in starts  # the first session is still present, not lost
    orphaned = next(s for s in sessions if s["start"] == "2026-08-21 09:00:00")
    assert orphaned["ongoing"] is False
    assert orphaned["end"] is None
    assert orphaned["status_note"] == "Ended (exact time unknown)"


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


def test_list_traffic_flows_resolves_known_client_and_falls_back_to_ip(monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {})
    monkeypatch.setattr(
        pivpn_ctl, "list_connected_clients",
        lambda: {"mobile": {"virtual_address": "10.202.226.2"}},
    )
    unknown_src_line = TCP_FLOW_LINE.replace("10.202.226.2", "10.202.226.77")
    monkeypatch.setattr(vpnlog, "run_root", lambda argv: "\n".join([TCP_FLOW_LINE, unknown_src_line]))
    monkeypatch.setattr(
        vpnlog.iplookup, "get_ip_orgs_bulk",
        lambda ips: {ip: "Meta Platforms Ireland Limited" for ip in ips},
    )

    flows = list_traffic_flows()

    assert len(flows) == 2
    # most recent first
    assert flows[0]["client"] == "10.202.226.77"  # no known mapping -> bare IP
    assert flows[0]["dst"] == "149.112.112.112"
    assert flows[0]["dst_org"] == "Meta Platforms Ireland Limited"
    assert flows[1]["client"] == "mobile"
    assert flows[1]["dport"] == "443"


def test_list_traffic_flows_looks_up_org_once_per_unique_destination(monkeypatch):
    # Two rows, same destination — the bulk org lookup should only be
    # called once for the whole batch (dedup now lives inside
    # get_ip_orgs_bulk itself, see test_iplookup.py for that guarantee),
    # and both rows should pick up its result.
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {})
    monkeypatch.setattr(pivpn_ctl, "list_connected_clients", lambda: {})
    monkeypatch.setattr(vpnlog, "run_root", lambda argv: "\n".join([TCP_FLOW_LINE, TCP_FLOW_LINE]))
    calls = []

    def fake_get_ip_orgs_bulk(ips):
        calls.append(ips)
        return {ip: "Meta Platforms Ireland Limited" for ip in ips}

    monkeypatch.setattr(vpnlog.iplookup, "get_ip_orgs_bulk", fake_get_ip_orgs_bulk)

    flows = list_traffic_flows()

    assert len(flows) == 2
    assert len(calls) == 1
    assert flows[0]["dst_org"] == "Meta Platforms Ireland Limited"
    assert flows[1]["dst_org"] == "Meta Platforms Ireland Limited"
