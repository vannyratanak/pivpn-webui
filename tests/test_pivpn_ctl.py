import subprocess

import config
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
        raise AssertionError("expected PivpnError")
    except pivpn_ctl.PivpnError:
        pass


# --- renew_client: revoke-then-add is two separate pivpn calls, not one
# atomic operation — if the revoke succeeds but the re-add then fails,
# the client ends up with NO valid cert at all (revoke can't be undone),
# which needs to read very differently from an ordinary renew failure.

class _FakeOvpnPath:
    """Stands in for client_ovpn_path(name)'s return value: add_client
    (via _client_ovpn_exists -> read_client_ovpn) checks .exists() then
    .read_bytes() before running 'pivpn add' (must raise/be False so the
    "already exists" guard doesn't fire) and again after (must flip to
    True, with real bytes to read, only once a simulated add actually
    'succeeds')."""
    def __init__(self):
        self.created = False

    def exists(self):
        return self.created

    def read_bytes(self):
        return b"fake ovpn contents"


def _renew_run_pivpn(fake_path, revoke_rc=0, add_rc=0, add_stdout="boom"):
    def fake(argv, timeout=30):
        if argv[1] == "revoke":
            return _fake_completed("", returncode=revoke_rc)
        if add_rc == 0:
            fake_path.created = True
        return _fake_completed(add_stdout, returncode=add_rc)
    return fake


def test_remove_client_cleans_default_rules_after_successful_revoke(monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "_require_pivpn_binary", lambda: None)
    monkeypatch.setattr(pivpn_ctl, "get_client_ip", lambda name: "10.8.0.5")
    calls = []
    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", lambda argv, timeout=30: _fake_completed(""))
    monkeypatch.setattr(pivpn_ctl.firewall, "remove_default_client_block",
                        lambda name, ip: calls.append((name, ip)))

    pivpn_ctl.remove_client("alice")

    assert calls == [("alice", "10.8.0.5")]


def test_remove_client_does_not_clean_rules_when_revoke_fails(monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "_require_pivpn_binary", lambda: None)
    monkeypatch.setattr(pivpn_ctl, "get_client_ip", lambda name: "10.8.0.5")
    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", lambda argv, timeout=30: _fake_completed("failed", returncode=1))
    calls = []
    monkeypatch.setattr(pivpn_ctl.firewall, "remove_default_client_block",
                        lambda name, ip: calls.append((name, ip)))

    try:
        pivpn_ctl.remove_client("alice")
        raise AssertionError("expected revoke failure")
    except pivpn_ctl.PivpnError:
        pass
    assert calls == []


def test_renew_client_success_returns_new_path(monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "_require_pivpn_binary", lambda: None)
    fake_path = _FakeOvpnPath()
    monkeypatch.setattr(pivpn_ctl, "client_ovpn_path", lambda name: fake_path)
    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", _renew_run_pivpn(fake_path))
    assert pivpn_ctl.renew_client("renewtest") is fake_path


def test_renew_client_passes_a_new_passphrase_through_to_pivpn_add(monkeypatch):
    # The real point of letting renew take a passphrase at all: resetting
    # a client's forgotten password is only possible by issuing a brand
    # new cert (the old one's password can't be recovered or changed
    # without already knowing it) — this is that path, so the new
    # passphrase actually has to reach the `pivpn add` call, not just be
    # accepted and silently dropped.
    monkeypatch.setattr(pivpn_ctl, "_require_pivpn_binary", lambda: None)
    fake_path = _FakeOvpnPath()
    monkeypatch.setattr(pivpn_ctl, "client_ovpn_path", lambda name: fake_path)
    add_argv = []

    def fake_run_pivpn(argv, timeout=30):
        if argv[1] == "revoke":
            return _fake_completed("", returncode=0)
        add_argv.extend(argv)
        fake_path.created = True
        return _fake_completed("", returncode=0)

    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", fake_run_pivpn)
    pivpn_ctl.renew_client("renewtest", passphrase="new-s3cret")
    assert add_argv[:4] == ["pivpn", "add", "-p", "new-s3cret"]


def test_renew_client_with_no_passphrase_is_passwordless(monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "_require_pivpn_binary", lambda: None)
    fake_path = _FakeOvpnPath()
    monkeypatch.setattr(pivpn_ctl, "client_ovpn_path", lambda name: fake_path)
    add_argv = []

    def fake_run_pivpn(argv, timeout=30):
        if argv[1] == "revoke":
            return _fake_completed("", returncode=0)
        add_argv.extend(argv)
        fake_path.created = True
        return _fake_completed("", returncode=0)

    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", fake_run_pivpn)
    pivpn_ctl.renew_client("renewtest")
    assert add_argv[:3] == ["pivpn", "add", "nopass"]


def test_add_client_returns_none_in_hub_mode_not_a_hub_local_path(monkeypatch):
    # client_ovpn_path(name) computes a path on whichever machine calls
    # it — in HUB_MODE that's the hub, not the agent that actually has the
    # file, so it must never be handed back as if it were real. Only
    # _client_ovpn_exists (via read_client_ovpn, already HUB_MODE-aware)
    # decides whether the file exists; client_ovpn_path itself is never
    # called on this path once HUB_MODE is on.
    monkeypatch.setattr(config, "HUB_MODE", True)
    monkeypatch.setattr(pivpn_ctl, "_require_pivpn_binary", lambda: None)
    exists_calls = iter([False, True])  # pre-check: not yet: post-check: now it is
    monkeypatch.setattr(pivpn_ctl, "_client_ovpn_exists", lambda name: next(exists_calls))
    monkeypatch.setattr(pivpn_ctl, "client_ovpn_path",
                         lambda name: (_ for _ in ()).throw(AssertionError("must not be called in hub mode")))
    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", lambda argv, timeout=30: _fake_completed(""))
    # Not this test's concern (see the add_client firewall-hook tests
    # below) — just needs to not blow up the HUB_MODE/path assertion.
    monkeypatch.setattr(pivpn_ctl, "get_client_ip", lambda name: "10.8.0.9")
    monkeypatch.setattr(pivpn_ctl.firewall, "add_default_client_block", lambda name, ip: [1, 2, 3])
    assert pivpn_ctl.add_client("hubtest") is None


# --- add_client's firewall hook: the boss-mandated "block every other
# private network by default" policy (see firewall.add_default_client_block)
# is wired into add_client itself, right after pivpn genuinely created the
# client — so a failure here must never look like the client wasn't
# created (see PivpnAddPartialFailure's own docstring).

def _new_client_run_pivpn(fake_path):
    def fake(argv, timeout=30):
        fake_path.created = True
        return _fake_completed("", returncode=0)
    return fake


def test_add_client_success_applies_default_block_with_the_new_ip(monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "_require_pivpn_binary", lambda: None)
    fake_path = _FakeOvpnPath()
    monkeypatch.setattr(pivpn_ctl, "client_ovpn_path", lambda name: fake_path)
    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", _new_client_run_pivpn(fake_path))
    monkeypatch.setattr(pivpn_ctl, "get_client_ip", lambda name: "10.8.0.42")
    block_calls = []
    monkeypatch.setattr(pivpn_ctl.firewall, "add_default_client_block",
                         lambda name, ip: block_calls.append((name, ip)))
    assert pivpn_ctl.add_client("freshclient") is fake_path
    assert block_calls == [("freshclient", "10.8.0.42")]


def test_add_client_no_ip_found_raises_partial_failure_not_plain_error(monkeypatch):
    # The client is real at this point (pivpn add already succeeded) —
    # this must be distinguishable from an ordinary add failure so callers
    # don't tell the admin the client doesn't exist when it does.
    monkeypatch.setattr(pivpn_ctl, "_require_pivpn_binary", lambda: None)
    fake_path = _FakeOvpnPath()
    monkeypatch.setattr(pivpn_ctl, "client_ovpn_path", lambda name: fake_path)
    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", _new_client_run_pivpn(fake_path))
    monkeypatch.setattr(pivpn_ctl, "get_client_ip", lambda name: None)
    monkeypatch.setattr(pivpn_ctl.firewall, "add_default_client_block",
                         lambda name, ip: (_ for _ in ()).throw(AssertionError("must not be called without an IP")))
    try:
        pivpn_ctl.add_client("freshclient")
        raise AssertionError("expected PivpnAddPartialFailure")
    except pivpn_ctl.PivpnAddPartialFailure as exc:
        assert "freshclient" in str(exc)
        assert "VPN IP couldn't be looked up" in str(exc)


def test_add_client_firewall_error_raises_partial_failure(monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "_require_pivpn_binary", lambda: None)
    fake_path = _FakeOvpnPath()
    monkeypatch.setattr(pivpn_ctl, "client_ovpn_path", lambda name: fake_path)
    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", _new_client_run_pivpn(fake_path))
    monkeypatch.setattr(pivpn_ctl, "get_client_ip", lambda name: "10.8.0.42")

    def _boom(name, ip):
        raise pivpn_ctl.firewall.FirewallError("iptables blew up")

    monkeypatch.setattr(pivpn_ctl.firewall, "add_default_client_block", _boom)
    try:
        pivpn_ctl.add_client("freshclient")
        raise AssertionError("expected PivpnAddPartialFailure")
    except pivpn_ctl.PivpnAddPartialFailure as exc:
        assert "freshclient" in str(exc)
        assert "iptables blew up" in str(exc)


def test_renew_client_never_applies_default_block(monkeypatch):
    # Renewing is revoke+reissue of the SAME client, not a new one — the
    # default-block policy is new-clients-only (see add_client's own
    # apply_default_block docstring). If this regresses, every renew would
    # silently start slapping first-time-only rules onto existing clients,
    # including the pre-existing ones this policy was explicitly scoped to
    # leave alone.
    monkeypatch.setattr(pivpn_ctl, "_require_pivpn_binary", lambda: None)
    fake_path = _FakeOvpnPath()
    monkeypatch.setattr(pivpn_ctl, "client_ovpn_path", lambda name: fake_path)
    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", _renew_run_pivpn(fake_path))
    monkeypatch.setattr(pivpn_ctl, "get_client_ip",
                         lambda name: (_ for _ in ()).throw(AssertionError("must not be called on renew")))
    monkeypatch.setattr(pivpn_ctl.firewall, "add_default_client_block",
                         lambda name, ip: (_ for _ in ()).throw(AssertionError("must not be called on renew")))
    assert pivpn_ctl.renew_client("renewtest") is fake_path


def test_renew_client_partial_failure_raises_distinct_error(monkeypatch):
    # revoke succeeds, the re-add then fails — this is the case that used
    # to surface as an ordinary-looking PivpnError, no different from any
    # other renew failure, even though the client now has zero access
    # instead of just being stuck on the old cert.
    monkeypatch.setattr(pivpn_ctl, "_require_pivpn_binary", lambda: None)
    fake_path = _FakeOvpnPath()
    monkeypatch.setattr(pivpn_ctl, "client_ovpn_path", lambda name: fake_path)
    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", _renew_run_pivpn(fake_path, revoke_rc=0, add_rc=1))
    try:
        pivpn_ctl.renew_client("renewtest")
        raise AssertionError("expected PivpnRenewPartialFailure")
    except pivpn_ctl.PivpnRenewPartialFailure as exc:
        assert "NO valid VPN access" in str(exc)
        assert "boom" in str(exc)  # underlying pivpn add error still surfaced


def test_renew_client_revoke_failure_is_plain_pivpn_error_not_partial(monkeypatch):
    # If revoke itself never succeeds, the old cert was never touched —
    # this must stay a plain PivpnError, not the "you now have zero
    # access" PivpnRenewPartialFailure (add_client is never even reached).
    monkeypatch.setattr(pivpn_ctl, "_require_pivpn_binary", lambda: None)
    fake_path = _FakeOvpnPath()
    monkeypatch.setattr(pivpn_ctl, "client_ovpn_path", lambda name: fake_path)
    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", _renew_run_pivpn(fake_path, revoke_rc=1))
    try:
        pivpn_ctl.renew_client("renewtest")
        raise AssertionError("expected PivpnError")
    except pivpn_ctl.PivpnRenewPartialFailure:
        raise AssertionError("revoke never succeeded — must not report itself as a partial failure") from None
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


def test_import_clients_counts_a_partial_failure_client_as_added(monkeypatch):
    # The client from that line really was created (pivpn add succeeded) —
    # only its default-block firewall rules failed. Undercounting it as a
    # failure would tell the admin the client doesn't exist when it does.
    def fake_add_client(name, passphrase=None):
        raise pivpn_ctl.PivpnAddPartialFailure(
            f"'{name}' was created, but its default internal-network block "
            "could not be applied: boom"
        )

    monkeypatch.setattr(pivpn_ctl, "add_client", fake_add_client)
    added, errors = pivpn_ctl.import_clients("name=partialclient\n")
    assert added == 1
    assert len(errors) == 1
    assert "line 1" in errors[0]
    assert "partialclient" in errors[0]


def test_import_clients_partial_failure_mixed_with_a_genuine_failure(monkeypatch):
    def fake_add_client(name, passphrase=None):
        if name == "partialclient":
            raise pivpn_ctl.PivpnAddPartialFailure(f"'{name}' partial boom")
        if name == "brokenclient":
            raise pivpn_ctl.PivpnError(f"'{name}' totally failed")
        return None

    monkeypatch.setattr(pivpn_ctl, "add_client", fake_add_client)
    text = "name=goodclient\nname=partialclient\nname=brokenclient\n"
    added, errors = pivpn_ctl.import_clients(text)
    # goodclient and partialclient both really exist now; brokenclient does
    # not. partialclient still surfaces its own warning in errors (line 2)
    # alongside brokenclient's genuine failure (line 3) — added counts both
    # real clients, errors reports both messages, for different reasons.
    assert added == 2
    assert len(errors) == 2
    assert any("line 2" in e and "partialclient" in e for e in errors)
    assert any("line 3" in e and "brokenclient" in e for e in errors)


# --- add_client: a real TOCTOU race — two near-simultaneous calls for the
# same name (a double-click on "Create client" is the realistic trigger;
# the button isn't disabled while the request is in flight) could both
# pass the "does this .ovpn already exist?" check before either's `pivpn
# add` (a slow, multi-second subprocess doing real cert generation)
# finished, and both proceed. Reproduced live against an isolated test
# client on .12 (revoked immediately after): one request succeeded, the
# other got a confusing "pivpn add reported success but the .ovpn file
# was not found" error that reads like a PIVPN_OVPN_DIR misconfiguration,
# not what it actually was.

def test_add_client_race_never_produces_a_confusing_error(tmp_path, monkeypatch):
    import threading
    import time

    monkeypatch.setattr(pivpn_ctl, "_require_pivpn_binary", lambda: None)
    ovpn_path = tmp_path / "racer.ovpn"
    monkeypatch.setattr(pivpn_ctl, "client_ovpn_path", lambda name: ovpn_path)
    # raising=False: lets this same test run unmodified against the
    # pre-fix code too (where this attribute doesn't exist yet) to prove
    # the race is real, not just theoretical.
    monkeypatch.setattr(pivpn_ctl, "_ADD_CLIENT_LOCK_PATH", tmp_path / ".add-client.lock", raising=False)
    # Not this test's concern (see the add_client firewall-hook tests
    # below) — just needs the winning thread to reach a normal return.
    monkeypatch.setattr(pivpn_ctl, "get_client_ip", lambda name: "10.8.0.9")
    monkeypatch.setattr(pivpn_ctl.firewall, "add_default_client_block", lambda name, ip: [1, 2, 3])

    def _slow_run_pivpn(argv, timeout=30):
        time.sleep(0.2)  # simulate pivpn add's real cert-generation latency
        ovpn_path.write_text("fake ovpn content")
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(pivpn_ctl, "_run_pivpn", _slow_run_pivpn)

    results = []
    barrier = threading.Barrier(2)

    def try_add():
        barrier.wait()  # line both threads up to maximize the race window
        try:
            pivpn_ctl.add_client("racer")
            results.append("ok")
        except pivpn_ctl.PivpnError as exc:
            results.append(str(exc))

    t1 = threading.Thread(target=try_add)
    t2 = threading.Thread(target=try_add)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert results.count("ok") == 1
    assert sum(1 for r in results if "already exists" in r) == 1
    # The confusing, misleading error must never happen — either the
    # request succeeds, or it's cleanly refused as a duplicate.
    assert not any("was not found" in r for r in results)
