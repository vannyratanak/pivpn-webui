from app.vpnlog import (
    CONNECT_RE,
    DISCONNECT_RE,
    _format_duration,
    _split_journal_line,
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
