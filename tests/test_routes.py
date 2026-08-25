from werkzeug.security import generate_password_hash

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


# --- user management: CRUD, password change, and RBAC (admin vs. moderator).
# The `client` fixture's own login always uses the bootstrapped admin
# (username "admin", TEST_PASSWORD) — _add_moderator inserts a second
# account directly via db.insert_user for tests that need to log in as
# something with restricted access.

MOD_PASSWORD = "modpass456"


def _login_admin(client):
    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})


def _add_moderator(username="mod"):
    db.insert_user(username, generate_password_hash(MOD_PASSWORD), "moderator")
    return username


def _login_moderator(client, username="mod"):
    client.post("/login", data={"username": username, "password": MOD_PASSWORD})


def test_users_page_requires_login(client):
    resp = client.get("/users")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_users_page_loads_for_admin(client):
    _login_admin(client)
    resp = client.get("/users")
    assert resp.status_code == 200
    assert b"admin" in resp.data


def test_add_user_creates_moderator(client):
    _login_admin(client)
    resp = client.post("/users/add", data={
        "username": "newmod", "password": "x", "confirm": "x", "role": "moderator",
    })
    assert resp.status_code == 302
    row = db.get_user_by_username("newmod")
    assert row is not None
    assert row["role"] == "moderator"


def test_add_user_duplicate_username_rejected(client):
    _login_admin(client)
    resp = client.post("/users/add", data={
        "username": "admin", "password": "x", "confirm": "x", "role": "admin",
    })
    assert resp.status_code == 302
    assert db.count_users() == 1  # no duplicate row inserted


def test_add_user_password_mismatch_rejected(client):
    _login_admin(client)
    client.post("/users/add", data={
        "username": "newmod", "password": "x", "confirm": "y", "role": "moderator",
    })
    assert db.get_user_by_username("newmod") is None


def test_add_user_invalid_role_rejected(client):
    _login_admin(client)
    client.post("/users/add", data={
        "username": "newmod", "password": "x", "confirm": "x", "role": "superadmin",
    })
    assert db.get_user_by_username("newmod") is None


def test_add_user_requires_admin(client):
    _add_moderator()
    _login_moderator(client)
    resp = client.post("/users/add", data={
        "username": "newmod2", "password": "x", "confirm": "x", "role": "moderator",
    })
    assert resp.status_code == 403
    assert db.get_user_by_username("newmod2") is None


def test_delete_last_user_refused(client):
    _login_admin(client)
    admin_row = db.get_user_by_username("admin")
    resp = client.post(f"/users/{admin_row['id']}/delete")
    assert resp.status_code == 302
    assert db.count_users() == 1


def test_delete_self_refused_even_with_other_users(client):
    _add_moderator()
    _login_admin(client)
    admin_row = db.get_user_by_username("admin")
    resp = client.post(f"/users/{admin_row['id']}/delete")
    assert resp.status_code == 302
    assert db.get_user_by_username("admin") is not None  # still there


def test_delete_other_user_succeeds(client):
    _add_moderator()
    _login_admin(client)
    mod_row = db.get_user_by_username("mod")
    resp = client.post(f"/users/{mod_row['id']}/delete")
    assert resp.status_code == 302
    assert db.get_user_by_username("mod") is None


def test_delete_user_db_busy_degrades_cleanly(client, monkeypatch):
    # Regression test: delete_user_guarded's BEGIN IMMEDIATE can raise
    # sqlite3.OperationalError if it can't acquire the write lock within
    # the connection's timeout (extremely unlikely given how fast this
    # app's own writes are, but a raw 500 is a worse failure mode than a
    # clean "try again" message when it does happen).
    import sqlite3
    _add_moderator()
    _login_admin(client)
    mod_row = db.get_user_by_username("mod")

    def fake_guarded(user_id):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("app.routes.db.delete_user_guarded", fake_guarded)
    resp = client.post(f"/users/{mod_row['id']}/delete")
    assert resp.status_code == 302
    assert db.get_user_by_username("mod") is not None  # nothing deleted


def test_delete_last_admin_refused_even_with_moderators_present(client):
    # Regression test: the old guard only checked "is this the last user
    # overall", which missed this exact case — one admin plus any number
    # of moderators, deleting the admin, leaves moderators who can't
    # create a new admin to recover from it. count_users() would be 2
    # here, so the old check would have let this through.
    _add_moderator()
    second_moderator = "mod2"
    _add_moderator(second_moderator)
    _login_admin(client)
    admin_row = db.get_user_by_username("admin")
    resp = client.post(f"/users/{admin_row['id']}/delete")
    assert resp.status_code == 302
    assert db.get_user_by_username("admin") is not None
    assert db.count_users() == 3  # nothing was deleted


def test_delete_last_moderator_allowed_when_admin_remains(client):
    # The "last remaining account" style guard should only ever protect
    # admins — deleting the very last moderator carries no lockout risk
    # at all as long as an admin still exists.
    _add_moderator()
    _login_admin(client)
    mod_row = db.get_user_by_username("mod")
    resp = client.post(f"/users/{mod_row['id']}/delete")
    assert resp.status_code == 302
    assert db.get_user_by_username("mod") is None
    assert db.count_users() == 1


def test_delete_user_requires_admin(client):
    _add_moderator()
    _login_moderator(client)
    admin_row = db.get_user_by_username("admin")
    resp = client.post(f"/users/{admin_row['id']}/delete")
    assert resp.status_code == 403
    assert db.get_user_by_username("admin") is not None


def test_reset_password_requires_admin(client):
    _add_moderator()
    _login_moderator(client)
    admin_row = db.get_user_by_username("admin")
    resp = client.post(f"/users/{admin_row['id']}/reset-password", data={
        "password": "hacked", "confirm": "hacked",
    })
    assert resp.status_code == 403


def test_reset_password_success_lets_target_log_in_with_new_password(client):
    _add_moderator()
    _login_admin(client)
    mod_row = db.get_user_by_username("mod")
    resp = client.post(f"/users/{mod_row['id']}/reset-password", data={
        "password": "newmodpass", "confirm": "newmodpass",
    })
    assert resp.status_code == 302
    client.get("/logout")
    resp = client.post("/login", data={"username": "mod", "password": "newmodpass"})
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients"


def test_change_own_password_requires_correct_current_password(client):
    _login_admin(client)
    resp = client.post("/account/password", data={
        "current_password": "wrong", "password": "newpass", "confirm": "newpass",
    })
    assert resp.status_code == 302
    client.get("/logout")
    # old password still works, new one doesn't
    resp = client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    assert resp.headers["Location"] == "/clients"


def test_change_own_password_success(client):
    _login_admin(client)
    client.post("/account/password", data={
        "current_password": TEST_PASSWORD, "password": "newpass789", "confirm": "newpass789",
    })
    client.get("/logout")
    resp = client.post("/login", data={"username": "admin", "password": "newpass789"})
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients"


def test_moderator_cannot_access_firewall(client):
    _add_moderator()
    _login_moderator(client)
    assert client.get("/firewall").status_code == 403


def test_moderator_cannot_access_vpn_routes(client):
    _add_moderator()
    _login_moderator(client)
    assert client.get("/vpn-routes").status_code == 403


def test_moderator_can_access_clients(client):
    _add_moderator()
    _login_moderator(client)
    assert client.get("/clients").status_code == 200


def test_moderator_logs_tab_falls_back_from_disallowed_tab(client):
    _add_moderator()
    _login_moderator(client)
    resp = client.get("/logs?tab=system")
    assert resp.status_code == 200
    # A moderator asking for ?tab=system must not actually get it — the
    # System tab's own markers shouldn't render at all.
    assert b"System journal" not in resp.data


def test_moderator_cannot_reach_activity_tab(client):
    _add_moderator()
    _login_moderator(client)
    resp = client.get("/logs?tab=activity")
    assert resp.status_code == 200
    assert b"Every audited action" not in resp.data


def test_admin_activity_tab_shows_full_unfiltered_log(client):
    _login_admin(client)
    # A non-auth action (login/logout are the only things the old Auth
    # tab ever showed) — Activity is the only place this should surface.
    client.post("/users/add", data={
        "username": "activitytest", "password": "x", "confirm": "x", "role": "moderator",
    })
    resp = client.get("/logs?tab=activity")
    assert resp.status_code == 200
    assert b"user_add" in resp.data
    assert b"activitytest" in resp.data


def test_admin_still_has_full_firewall_access(client):
    _login_admin(client)
    assert client.get("/firewall").status_code == 200
    assert client.get("/vpn-routes").status_code == 200


def test_reorder_route_degrades_cleanly_on_privileged_command_error(client, monkeypatch):
    # Regression test: firewall.reorder_rule's chain rebuild happens after
    # its own DB write already committed — a PrivilegedCommandError from
    # that rebuild (e.g. a raced concurrent chain mutation, or any other
    # iptables failure) used to propagate straight through this JSON
    # endpoint uncaught, surfacing as a raw 500 instead of the endpoint's
    # documented {ok, error} shape, and skipping the audit trail entirely.
    _login_admin(client)
    r1 = db.insert_rule({"kind": "input", "action": "ACCEPT", "protocol": "tcp",
                          "src": None, "dport": "443", "enabled": 1, "position": 1.0})
    r2 = db.insert_rule({"kind": "input", "action": "DROP", "protocol": "tcp",
                          "src": None, "dport": "80", "enabled": 1, "position": 2.0})
    import app.firewall as firewall_module
    from app.privileged import PrivilegedCommandError

    def _boom(argv):
        raise PrivilegedCommandError("boom")

    monkeypatch.setattr(firewall_module, "run_root", _boom)
    resp = client.post(f"/firewall/{r2}/reorder", json={"target_id": r1, "place": "before"})
    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False
    audit = db.list_audit(limit=5)
    assert any(a["action"] == "firewall_rule_reorder" and a["result"] == "error" for a in audit)


def test_delete_user_form_survives_a_quote_in_the_username(client):
    # Regression test for a real bug: usernames have no character-set
    # validation (unlike client names, which are regex-restricted), and
    # the Delete button's confirmation used an inline
    # onsubmit="return confirm('...{{ username }}...');" — a username
    # containing a single quote breaks that embedded JS string. Live-
    # verified in a real browser: the browser decodes the HTML entity back
    # to a literal ' before compiling the onsubmit attribute as JS, so the
    # confirm() call's string literal gets cut short — a syntax error that
    # silently no-ops the whole handler instead of throwing, meaning the
    # form submits with NO confirmation prompt at all. Fixed by moving to
    # a data-confirm="..." attribute read via JS's .dataset (a real
    # string value, never compiled as JS source) instead of an inline
    # onsubmit with embedded dynamic content — this test locks in that the
    # vulnerable pattern doesn't reappear for a username containing a
    # quote (or any other character that could break embedded JS).
    _login_admin(client)
    db.insert_user("O'Brien", generate_password_hash(MOD_PASSWORD), "moderator")
    resp = client.get("/users")
    html = resp.data.decode()
    assert "onsubmit" not in html
    assert 'data-confirm="Permanently remove O&#39;Brien? This cannot be undone."' in html

