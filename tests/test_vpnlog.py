import subprocess

import config
from app import vpnlog
from app.vpnlog import (
    CONNECT_RE,
    DISCONNECT_RE,
    _format_duration,
    _split_journal_line,
    list_client_sessions,
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
