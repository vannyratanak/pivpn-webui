from tests.conftest import TEST_PASSWORD

import app.pivpn_ctl as pivpn_ctl
import config
from app import db


def test_login_page_loads(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"password" in resp.data.lower()


def test_clients_requires_login(client):
    resp = client.get("/clients")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_with_correct_credentials_redirects_to_clients(client):
    resp = client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients"


def test_login_with_wrong_credentials_reshows_form(client):
    resp = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 200
    assert b"Invalid username or password" in resp.data


def test_successful_login_issues_a_session_cookie_with_an_expiry(client):
    # A plain Flask session cookie has no Max-Age/Expires at all (it dies
    # with the browser) unless the session is explicitly marked
    # permanent — this confirms login() actually does that, not just that
    # PERMANENT_SESSION_LIFETIME is configured somewhere and unused.
    resp = client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "Max-Age" in set_cookie or "Expires" in set_cookie


def test_session_lifetime_matches_configured_hours(client):
    import config
    from datetime import timedelta
    assert client.application.config["PERMANENT_SESSION_LIFETIME"] == timedelta(hours=config.SESSION_LIFETIME_HOURS)


def test_session_cookie_secure_defaults_on(client):
    # Confirms the app config actually picks up config.SESSION_COOKIE_SECURE
    # (default True) — not just that the setting exists somewhere unused.
    import config
    assert client.application.config["SESSION_COOKIE_SECURE"] == config.SESSION_COOKIE_SECURE
    assert config.SESSION_COOKIE_SECURE is True


def test_logout_requires_login(client):
    resp = client.get("/logout")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


# --- _client_ip: X-Real-IP is only trustworthy when BIND_HOST=127.0.0.1
# guarantees nginx is the sole caller (nginx's vhost always overwrites
# that header with the real source). In the README's documented LAN-only
# mode (BIND_HOST=0.0.0.0), gunicorn is reachable directly and nothing
# rewrites a client-supplied header — trusting it there would let a
# client spoof any IP it wants, defeating the login rate-limit and the
# firewall self-lockout guard, both of which key off this value.

def test_client_ip_trusts_x_real_ip_behind_loopback_nginx(client, monkeypatch):
    monkeypatch.setattr(config, "BIND_HOST", "127.0.0.1")
    from app.routes import _client_ip
    with client.application.test_request_context(headers={"X-Real-IP": "203.0.113.9"}):
        assert _client_ip() == "203.0.113.9"


def test_client_ip_ignores_x_real_ip_when_lan_exposed(client, monkeypatch):
    monkeypatch.setattr(config, "BIND_HOST", "0.0.0.0")
    from app.routes import _client_ip
    with client.application.test_request_context(
        headers={"X-Real-IP": "203.0.113.9"},
        environ_overrides={"REMOTE_ADDR": "192.168.1.50"},
    ):
        assert _client_ip() == "192.168.1.50"


def test_login_rate_limit_not_bypassable_via_spoofed_x_real_ip_when_lan_exposed(client, monkeypatch):
    # Regression test for the exact bypass: rotating X-Real-IP on every
    # attempt used to reset the rate limiter's notion of "which IP", no
    # matter how many times the real client actually failed.
    monkeypatch.setattr(config, "BIND_HOST", "0.0.0.0")
    from app.routes import LOGIN_MAX_ATTEMPTS
    for i in range(LOGIN_MAX_ATTEMPTS + 1):
        resp = client.post(
            "/login", data={"username": "admin", "password": "wrong"},
            headers={"X-Real-IP": f"10.0.0.{i}"},
            environ_overrides={"REMOTE_ADDR": "192.168.1.50"},
        )
    assert b"Too many failed login attempts" in resp.data


# --- login rate-limiting: a plain in-process counter wouldn't be seen by
# both gunicorn worker processes in production, so this is backed by
# sqlite (see db.py) — tracked per source IP, 5 failures / 5 minutes.

def test_login_lockout_after_max_failed_attempts(client):
    from app.routes import LOGIN_MAX_ATTEMPTS
    for _ in range(LOGIN_MAX_ATTEMPTS):
        client.post("/login", data={"username": "admin", "password": "wrong"})
    resp = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert b"Too many failed login attempts" in resp.data


def test_login_lockout_blocks_even_correct_credentials(client):
    from app.routes import LOGIN_MAX_ATTEMPTS
    for _ in range(LOGIN_MAX_ATTEMPTS):
        client.post("/login", data={"username": "admin", "password": "wrong"})
    # the whole point: once locked out, even the real password is refused
    # until the window passes — otherwise this is just a slower guesser.
    resp = client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    assert b"Too many failed login attempts" in resp.data
    assert resp.status_code == 200  # not the 302-to-/clients a real login gets


def test_login_under_the_limit_still_works(client):
    from app.routes import LOGIN_MAX_ATTEMPTS
    for _ in range(LOGIN_MAX_ATTEMPTS - 1):
        client.post("/login", data={"username": "admin", "password": "wrong"})
    resp = client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients"


def test_successful_login_clears_the_failure_count(client):
    # log in for real once, then confirm a fresh run of failures afterward
    # starts counting from zero again — success shouldn't leave the IP
    # sitting one attempt away from a lockout it never triggered.
    from app.routes import LOGIN_MAX_ATTEMPTS
    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    client.get("/logout")
    for _ in range(LOGIN_MAX_ATTEMPTS - 1):
        resp = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert b"Too many failed login attempts" not in resp.data


# --- renew route: a PivpnRenewPartialFailure (revoke succeeded, re-add
# failed — client now has zero access) needs a distinct audit tag from an
# ordinary renew failure, so it's easy to spot in Logs later.

def test_renew_partial_failure_gets_distinct_audit_tag(client, monkeypatch):
    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})

    def fake_renew(name):
        raise pivpn_ctl.PivpnRenewPartialFailure(f"'{name}' was revoked but re-add failed.")

    monkeypatch.setattr("app.routes.pivpn_ctl.renew_client", fake_renew)
    resp = client.post("/clients/testclient/renew")
    assert resp.status_code == 302

    latest = db.list_audit(limit=1)[0]
    assert latest["action"] == "client_renew_partial"
    assert latest["result"] == "error"


def test_renew_ordinary_failure_keeps_plain_audit_tag(client, monkeypatch):
    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})

    def fake_renew(name):
        raise pivpn_ctl.PivpnError("pivpn revoke failed")

    monkeypatch.setattr("app.routes.pivpn_ctl.renew_client", fake_renew)
    resp = client.post("/clients/testclient/renew")
    assert resp.status_code == 302

    latest = db.list_audit(limit=1)[0]
    assert latest["action"] == "client_renew"
    assert latest["result"] == "error"
