import subprocess

import app.pivpn_ctl as pivpn_ctl

# Real captured `pivpn list` output (ANSI codes included) from the actual
# test server — see project memory. Using the real format instead of a
# simplified guess is the whole point: this is what caught a parser bug in
# this exact function once already (an old status-log parser that matched
# a format PiVPN doesn't even emit — see the module docstring).
REAL_OUTPUT = (
    ": NOTE : The first entry is your server, which should always be valid!\n"
    "\n"
    "\x1b[1m::: Certificate Status List :::\x1b[0m\n"
    "\x1b[4mStatus\x1b[0m       \x1b[4mName\x1b[0m\x1b[0m"
    "                                          \x1b[4mExpiration\x1b[0m\n"
    "Valid        vpn_2c9dde30-bf2b-4b41-8806-d3ce7e65c9e7      Aug 14 2036\n"
    "Valid        nurak                                          Aug 02 2029\n"
    "Revoked      gg                                             Aug 01 2029\n"
)


def _fake_completed(stdout, returncode=0):
    return subprocess.CompletedProcess(args=["pivpn", "list"], returncode=returncode,
                                        stdout=stdout, stderr="")


def test_list_clients_excludes_server_row(monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", lambda argv, timeout=30: _fake_completed(REAL_OUTPUT))
    clients = pivpn_ctl.list_clients()
    names = [c["name"] for c in clients]
    assert "vpn_2c9dde30-bf2b-4b41-8806-d3ce7e65c9e7" not in names


def test_list_clients_parses_status_and_expiration(monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", lambda argv, timeout=30: _fake_completed(REAL_OUTPUT))
    clients = pivpn_ctl.list_clients()
    nurak = next(c for c in clients if c["name"] == "nurak")
    assert nurak["status"] == "Valid"
    assert nurak["expiration"] == "Aug 02 2029"
    gg = next(c for c in clients if c["name"] == "gg")
    assert gg["status"] == "Revoked"


def test_list_clients_raises_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "_run_pivpn",
                         lambda argv, timeout=30: _fake_completed("", returncode=1))
    try:
        pivpn_ctl.list_clients()
        assert False, "expected PivpnError"
    except pivpn_ctl.PivpnError:
        pass


# --- import_clients: an unbalanced quote must produce a clean per-line
# error, not an unhandled ValueError from shlex.split — found live: an
# import file with a stray quote crashed the whole request with a raw
# 500 instead of the "line N: ..." message every other bad line gets.

def test_import_clients_unbalanced_quote_is_caught_not_raised():
    added, errors = pivpn_ctl.import_clients('name="unbalanced\n')
    assert added == 0
    assert len(errors) == 1
    assert "line 1" in errors[0]


def test_import_clients_one_bad_line_does_not_stop_the_rest(monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "add_client", lambda name, passphrase=None: None)
    text = 'name="unbalanced\nname=validclient\n'
    added, errors = pivpn_ctl.import_clients(text)
    assert added == 1
    assert len(errors) == 1
    assert "line 1" in errors[0]
