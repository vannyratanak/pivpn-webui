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
    assert b'id="login-error" role="alert"' in resp.data
    assert b'value="admin"' in resp.data
    assert b'value="wrong"' not in resp.data


def test_login_validates_missing_fields_without_javascript(client):
    resp = client.post("/login", data={"username": "   ", "password": ""})
    assert resp.status_code == 200
    assert b"Enter your username." in resp.data
    assert b"Enter your password." in resp.data
    assert b'aria-invalid="true"' in resp.data
    assert b"Invalid username or password" not in resp.data


def test_login_preserves_username_when_password_missing(client):
    resp = client.post("/login", data={"username": "admin"})
    assert resp.status_code == 200
    assert b'value="admin"' in resp.data
    assert b"Enter your password." in resp.data


def test_login_resume_validates_password_and_restores_session(client):
    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    client.post("/account/lock")
    page = client.get("/login")
    assert b"Resume session" in page.data
    assert b'name="username"' not in page.data
    missing = client.post("/login", data={})
    assert b"Enter your password." in missing.data
    assert b"Enter your username." not in missing.data
    resumed = client.post("/login", data={"password": TEST_PASSWORD})
    assert resumed.status_code == 302
    assert resumed.headers["Location"] == "/clients"
    assert client.get_cookie("idle_lock") is None
    assert client.get_cookie("html_jwt") is not None


def test_successful_login_issues_an_html_jwt_cookie_with_an_expiry(client):
    # Identity lives in a JWT cookie (auth.py's issue_html_jwt_cookie),
    # not Flask's own session — this confirms login() actually sets one,
    # with a real Max-Age (a JWT's expiry is fixed at issuance, unlike a
    # plain Flask session cookie, which has none unless marked permanent).
    resp = client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    set_cookie = next(c for c in resp.headers.getlist("Set-Cookie") if c.startswith("html_jwt="))
    assert "Max-Age" in set_cookie or "Expires" in set_cookie
    assert "HttpOnly" in set_cookie


def test_html_jwt_cookie_lifetime_matches_configured_hours(client):
    import config
    from flask_jwt_extended import decode_token

    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    token = client.get_cookie("html_jwt").value
    with client.application.app_context():
        claims = decode_token(token)
    lifetime_seconds = claims["exp"] - claims["iat"]
    assert lifetime_seconds == config.SESSION_LIFETIME_HOURS * 3600


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


def test_logout_actually_clears_access_regression(client):
    # Regression test for a real bug caught by live testing: the
    # after_request sliding-refresh hook (see __init__.py) re-issues a
    # fresh html_jwt cookie on every authenticated response, including
    # logout()'s own — silently overwriting its cookie-clear with a
    # brand new valid one, so a client following the exact same cookie
    # jar could still load a protected page right after "logging out".
    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    assert client.get("/clients").status_code == 200

    client.get("/logout")
    resp = client.get("/clients")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_second_login_invalidates_the_first_browser_session(client):
    # Single-active-session: logging in from a second "browser" (a
    # second test client, its own separate cookie jar, same account)
    # must immediately invalidate the first one's session — its very
    # next request should be treated as logged out, not still valid.
    #
    # Both clients are created fresh here rather than using the `client`
    # fixture object directly for either one — that fixture holds its
    # client open inside a `with` block for the whole test (so
    # flask.session/etc. stay inspectable afterward), and mixing that
    # preserved-context client with a second independent one in the same
    # test produces bogus results (confirmed live: current_user resolved
    # incorrectly for the second client's own request). Two fresh clients
    # off the same app avoids that entirely.
    session_a = client.application.test_client()
    session_b = client.application.test_client()

    session_a.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    assert session_a.get("/clients").status_code == 200

    session_b.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    assert session_b.get("/clients").status_code == 200

    resp = session_a.get("/clients")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_idle_timeout_forces_relogin_after_the_configured_window(client, monkeypatch):
    # idle_timed_out (see auth.py) reads config.IDLE_TIMEOUT_MINUTES fresh
    # on every check, so simulating "the window already elapsed" doesn't
    # need to actually sleep or mock time.time() — a threshold that's
    # already negative is guaranteed to be exceeded by any real elapsed
    # time, however small.
    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    assert client.get("/clients").status_code == 200

    monkeypatch.setattr(config, "IDLE_TIMEOUT_MINUTES", -1)
    resp = client.get("/clients")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_heartbeat_requires_login(client):
    resp = client.post("/account/heartbeat")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_heartbeat_returns_no_content_when_logged_in(client):
    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    resp = client.post("/account/heartbeat")
    assert resp.status_code == 204


def test_heartbeat_keeps_the_session_alive_within_the_idle_window(client, monkeypatch):
    # The scenario idle-timeout.js exists for: a page that only talks to
    # /api/... (never touching this cookie-authenticated blueprint again)
    # still needs *something* to keep the cookie's "la" claim fresh during
    # real use, or genuinely-active users would get idle-logged-out anyway.
    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    monkeypatch.setattr(config, "IDLE_TIMEOUT_MINUTES", 15)
    assert client.post("/account/heartbeat").status_code == 204
    assert client.get("/clients").status_code == 200


def test_idle_timeout_meta_present_only_when_logged_in(client):
    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    resp = client.get("/clients")
    assert b'meta name="idle-timeout-minutes"' in resp.data
    assert f'content="{config.IDLE_TIMEOUT_MINUTES}"'.encode() in resp.data

    client.get("/logout")
    resp = client.get("/login")
    assert b'meta name="idle-timeout-minutes"' not in resp.data


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
    # Row data (and the actual username check) now comes from GET
    # /api/users (see tests/test_api.py's test_list_users_excludes_
    # password_hash and friends) — this view only renders the shell now,
    # same as /clients.
    _login_admin(client)
    resp = client.get("/users")
    assert resp.status_code == 200


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
    # Regression test: delete_user_guarded's SELECT ... FOR UPDATE can
    # raise psycopg2.errors.LockNotAvailable if it can't acquire the row
    # lock within locked_transaction's 5s lock_timeout (extremely
    # unlikely given how fast this app's own writes are, but a raw 500
    # is a worse failure mode than a clean "try again" message when it
    # does happen).
    import psycopg2.errors
    _add_moderator()
    _login_admin(client)
    mod_row = db.get_user_by_username("mod")

    def fake_guarded(user_id):
        raise psycopg2.errors.LockNotAvailable("could not obtain lock on row")

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


def test_admin_activity_tab_loads(client):
    # Real content (a non-auth action showing up here, unlike Auth) is
    # covered by tests/test_api.py's test_activity_tab_range_and_search_
    # filter now — this view only renders the shell (see main.logs's own
    # comment), same as /clients.
    _login_admin(client)
    resp = client.get("/logs?tab=activity")
    assert resp.status_code == 200


def test_admin_still_has_full_firewall_access(client):
    _login_admin(client)
    assert client.get("/firewall").status_code == 200
    assert client.get("/vpn-routes").status_code == 200


def test_logs_tab_loads(client):
    # Real search/range/pagination/relabeling behavior all moved to
    # tests/test_api.py (GET /api/logs) along with the DB queries
    # themselves — this view only renders the shell now (see main.logs's
    # own comment), same as /clients. Covers every tab loading + the
    # search/range widgets echoing back the requested query params.
    _login_admin(client)
    for tab in ("sessions", "client_sessions", "traffic", "system", "activity", "auth"):
        resp = client.get(f"/logs?tab={tab}")
        assert resp.status_code == 200, tab


def test_logs_invalid_range_value_falls_back_to_default_in_the_shell(client):
    # An unrecognized ?range= falls back to the same default (1h) as no
    # range at all — not "no cutoff". The actual filtering behavior this
    # implies is tested against real data in test_api.py; this only checks
    # that the shell's own range <select> reflects the resolved value.
    _login_admin(client)
    resp_bogus = client.get("/logs?tab=sessions&range=bogus")
    assert resp_bogus.status_code == 200
    assert b'value="1h" selected' in resp_bogus.data

    resp_missing = client.get("/logs?tab=sessions")
    assert resp_missing.status_code == 200
    assert b'value="1h" selected' in resp_missing.data


def test_logs_refresh_requires_login(client):
    resp = client.post("/logs/refresh", data={"tab": "client_sessions"})
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_logs_refresh_not_admin_gated(client, monkeypatch):
    # Deliberately not @admin_required — this is the same read-only
    # background job that already runs on its own every 10s regardless of
    # who's logged in, not a new capability moderators shouldn't have.
    from deploy import ingest_logs

    monkeypatch.setattr(ingest_logs, "ingest_vpn_events", lambda: 0)
    monkeypatch.setattr(ingest_logs, "ingest_traffic_flows", lambda: 0)
    _add_moderator()
    _login_moderator(client)
    resp = client.post("/logs/refresh", data={"tab": "client_sessions"})
    assert resp.status_code == 302
    assert "/logs?tab=client_sessions" in resp.headers["Location"]


def test_logs_refresh_calls_ingestion_and_redirects_to_requested_tab(client, monkeypatch):
    from deploy import ingest_logs

    calls = []
    monkeypatch.setattr(ingest_logs, "ingest_vpn_events", lambda: calls.append("events") or 1)
    monkeypatch.setattr(ingest_logs, "ingest_traffic_flows", lambda: calls.append("flows") or 2)
    monkeypatch.setattr(ingest_logs, "ingest_system_log", lambda: calls.append("system") or 3)
    pruned = []
    monkeypatch.setattr(db, "prune_old_logs", lambda days: pruned.append(days))

    _login_admin(client)
    resp = client.post("/logs/refresh", data={"tab": "traffic"})

    assert resp.status_code == 302
    assert "/logs?tab=traffic" in resp.headers["Location"]
    assert calls == ["events", "flows", "system"]
    assert pruned == [ingest_logs.RETENTION_DAYS]


def test_logs_refresh_degrades_cleanly_on_privileged_command_error(client, monkeypatch):
    from deploy import ingest_logs
    from app.privileged import PrivilegedCommandError

    def boom():
        raise PrivilegedCommandError("boom")

    monkeypatch.setattr(ingest_logs, "ingest_vpn_events", boom)
    _login_admin(client)
    resp = client.post("/logs/refresh", data={"tab": "sessions"})
    assert resp.status_code == 302
    assert "/logs?tab=sessions" in resp.headers["Location"]


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
    # the Delete button's confirmation used to use an inline
    # onsubmit="return confirm('...{{ username }}...');" — a username
    # containing a single quote breaks that embedded JS string. Fixed
    # originally by moving to a data-confirm="..." attribute read via
    # JS's .dataset instead of an inline onsubmit with embedded dynamic
    # content.
    #
    # Post-JWT-conversion, user rows (and the Delete button's confirm
    # message) are built entirely client-side by users-page.js from GET
    # /api/users JSON — via escapeHtml() + a data-username attribute +
    # window.askConfirm's own template literal, never an inline onsubmit
    # with embedded content — so this vulnerability class can't reappear
    # here regardless of what characters a username contains. That part
    # only runs in a real browser (no JS executes in this test client);
    # what's left to check at this layer is that the static shell never
    # regains the old vulnerable pattern.
    _login_admin(client)
    db.insert_user("O'Brien", generate_password_hash(MOD_PASSWORD), "moderator")
    resp = client.get("/users")
    assert "onsubmit" not in resp.data.decode()


# --- client_detail: a shell page now (see clients()'s own precedent) —
# status/session/rules all come from client-detail-page.js's own fetch()
# calls against /api/clients/<name> and /api/clients/<name>/rules after
# this loads, so "does this client actually exist"/"what does its status
# look like"/"which rules are scoped to it" moved to test_api.py's
# coverage of those endpoints. Only the syntactic name check and the
# login/role gate still happen at this route.

def test_client_detail_requires_login(client):
    resp = client.get("/clients/laptop-anna")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_client_detail_allows_moderator(client):
    # Unlike the main Firewall page (still admin-only), a moderator gets
    # full rule management scoped to one client here — same "client
    # control" territory as the Clients list' own renew/block/remove.
    _add_moderator()
    _login_moderator(client)
    assert client.get("/clients/laptop-anna").status_code == 200


def test_client_detail_invalid_name_format_404s(client):
    # validate_name (letters/digits/-/_ only) rejects this before the
    # page even renders — the one check still done server-side here.
    _login_admin(client)
    assert client.get("/clients/not a valid name!").status_code == 404


# --- /firewall/forward, /firewall/<id>/toggle, /firewall/<id>/delete
# always redirect to the Firewall page, unconditionally — the client
# detail page's own add/toggle/delete actions use their own separate
# /clients/<name>/rules/... routes below instead of sharing these, so nothing
# here needs to (or should) vary its redirect target.

def test_add_forward_always_redirects_to_firewall_page(client):
    _login_admin(client)
    resp = client.post("/firewall/forward", data={
        "action": "DROP", "protocol": "tcp", "src": "10.202.226.2", "dst": "", "dport": "",
    })
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/firewall"


def test_toggle_rule_always_redirects_to_firewall_page(client):
    _login_admin(client)
    rule_id = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})
    resp = client.post(f"/firewall/{rule_id}/toggle")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/firewall"


def test_delete_rule_always_redirects_to_firewall_page(client):
    _login_admin(client)
    rule_id = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})
    resp = client.post(f"/firewall/{rule_id}/delete")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/firewall"


# --- /clients/<name>/rules/...: the client detail page's own add/toggle/
# delete actions, kept separate from /firewall/... above so they can always
# redirect back to that client's page without the Firewall page's own
# routes ever needing to vary.

def _cache_clients_for_rule_tests(rows):
    db.replace_client_status_cache([
        {
            "status": "Valid", "expiration": "", "list_position": i,
            "session_real_address": None, "session_virtual_address": None,
            "session_bytes_recv": None, "session_bytes_sent": None,
            "session_since": None, **row,
        }
        for i, row in enumerate(rows)
    ])

def test_client_add_rule_allows_moderator(client, monkeypatch):
    monkeypatch.setattr("app.routes.pivpn_ctl.list_client_ips", lambda: {"laptop-anna": "10.202.226.2"})
    monkeypatch.setattr("app.firewall.run_root", lambda argv, **kwargs: "")
    _add_moderator()
    _login_moderator(client)
    resp = client.post("/clients/laptop-anna/rules/add", data={
        "action": "DROP", "protocol": "tcp", "dst": "", "dport": "",
    })
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"
    assert len(db.list_rules()) == 1


def test_client_add_rule_redirects_back_to_client_page(client, monkeypatch):
    monkeypatch.setattr("app.routes.pivpn_ctl.list_client_ips", lambda: {"laptop-anna": "10.202.226.2"})
    monkeypatch.setattr("app.firewall.run_root", lambda argv, **kwargs: "")
    _login_admin(client)
    resp = client.post("/clients/laptop-anna/rules/add", data={
        "action": "DROP", "protocol": "tcp", "dst": "", "dport": "",
    })
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"
    rules = db.list_rules()
    assert len(rules) == 1
    assert rules[0]["src"] == "10.202.226.2"  # taken from the client's own IP, not the form


def test_client_add_rule_without_a_vpn_ip_flashes_and_does_not_create_a_rule(client, monkeypatch):
    monkeypatch.setattr("app.routes.pivpn_ctl.list_client_ips", lambda: {})
    _login_admin(client)
    resp = client.post("/clients/laptop-anna/rules/add", data={"action": "DROP", "protocol": "tcp"})
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"
    assert db.list_rules() == []


def test_client_toggle_rule_redirects_back_to_client_page(client, monkeypatch):
    _cache_clients_for_rule_tests([{"name": "laptop-anna", "ip": "10.202.226.2"}])
    _login_admin(client)
    rule_id = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})
    resp = client.post(f"/clients/laptop-anna/rules/{rule_id}/toggle")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"


def test_client_delete_rule_redirects_back_to_client_page(client, monkeypatch):
    _cache_clients_for_rule_tests([{"name": "laptop-anna", "ip": "10.202.226.2"}])
    _login_admin(client)
    rule_id = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})
    resp = client.post(f"/clients/laptop-anna/rules/{rule_id}/delete")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"
    assert db.list_rules() == []


def test_client_scoped_rule_mutations_cannot_target_another_client(client, monkeypatch):
    _cache_clients_for_rule_tests([
        {"name": "laptop-anna", "ip": "10.202.226.2"},
        {"name": "other-client", "ip": "10.202.226.5"},
    ])
    _login_admin(client)
    rule_id = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.5"})

    toggle = client.post(f"/clients/laptop-anna/rules/{rule_id}/toggle")
    delete = client.post(f"/clients/laptop-anna/rules/{rule_id}/delete")

    assert toggle.status_code == 404
    assert delete.status_code == 404
    assert db.get_rule(rule_id)["enabled"] == 1


# --- /clients/<name>/rules/bulk-disable and /bulk-delete: same underlying
# _bulk_disable_or_delete() as /firewall/bulk-disable and /bulk-delete, but
# restricted server-side to rules that actually belong to this client — a
# submitted rule_id for a *different* client is silently dropped rather
# than acted on, same "never trust scope from the form" rule
# client_add_rule's docstring already applies to src.

def _stub_two_clients(monkeypatch):
    monkeypatch.setattr(
        "app.routes.pivpn_ctl.list_client_ips",
        lambda: {"laptop-anna": "10.202.226.2", "phone-bob": "10.202.226.3"},
    )


def test_client_bulk_disable_allows_moderator(client, monkeypatch):
    _stub_two_clients(monkeypatch)
    monkeypatch.setattr("app.firewall.run_root", lambda argv, **kwargs: "")
    _add_moderator()
    _login_moderator(client)
    anna_rule = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})
    resp = client.post("/clients/laptop-anna/rules/bulk-disable", data={"rule_ids": [str(anna_rule)]})
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"
    assert db.get_rule(anna_rule)["enabled"] == 0


def test_client_bulk_disable_only_affects_this_clients_rules(client, monkeypatch):
    _stub_two_clients(monkeypatch)
    monkeypatch.setattr("app.firewall.run_root", lambda argv, **kwargs: "")
    _login_admin(client)
    anna_rule = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})
    bob_rule = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.3"})
    resp = client.post("/clients/laptop-anna/rules/bulk-disable", data={
        "rule_ids": [str(anna_rule), str(bob_rule)],
    })
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"
    assert db.get_rule(anna_rule)["enabled"] == 0
    assert db.get_rule(bob_rule)["enabled"] == 1  # untouched — not this client's rule


def test_client_bulk_delete_only_affects_this_clients_rules(client, monkeypatch):
    _stub_two_clients(monkeypatch)
    _login_admin(client)
    anna_rule = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})
    bob_rule = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.3"})
    resp = client.post("/clients/laptop-anna/rules/bulk-delete", data={
        "rule_ids": [str(anna_rule), str(bob_rule)],
    })
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"
    assert db.get_rule(anna_rule) is None
    assert db.get_rule(bob_rule) is not None  # untouched — not this client's rule


def test_client_bulk_delete_invalid_name_404s(client):
    _login_admin(client)
    resp = client.post("/clients/not a valid name!/rules/bulk-delete", data={"rule_ids": ["1"]})
    assert resp.status_code == 404


# --- /clients/<name>/rules/resync and /persist: the client detail page's
# own Apply Rules/Save Rules buttons — same underlying system-wide
# firewall.sync_all()/save_persistent() as /firewall/resync and
# /firewall/persist, kept as their own routes purely so the redirect
# target can differ (see client_add_rule's docstring).

def test_client_resync_rules_allows_moderator(client):
    _add_moderator()
    _login_moderator(client)
    resp = client.post("/clients/laptop-anna/rules/resync")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"


def test_client_resync_rules_redirects_back_to_client_page(client):
    _login_admin(client)
    resp = client.post("/clients/laptop-anna/rules/resync")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"


def test_client_resync_rules_invalid_name_404s(client):
    _login_admin(client)
    resp = client.post("/clients/not a valid name!/rules/resync")
    assert resp.status_code == 404


def test_client_persist_rules_allows_moderator(client, monkeypatch):
    monkeypatch.setattr("app.firewall.run_root", lambda argv, **kwargs: "")
    _add_moderator()
    _login_moderator(client)
    resp = client.post("/clients/laptop-anna/rules/persist")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"


def test_client_persist_rules_redirects_back_to_client_page(client, monkeypatch):
    monkeypatch.setattr("app.firewall.run_root", lambda argv, **kwargs: "")
    _login_admin(client)
    resp = client.post("/clients/laptop-anna/rules/persist")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"


def test_client_persist_rules_invalid_name_404s(client):
    _login_admin(client)
    resp = client.post("/clients/not a valid name!/rules/persist")
    assert resp.status_code == 404



def test_logout_revokes_the_browser_bearer_token(client):
    client.post('/login', data={'username': 'admin', 'password': TEST_PASSWORD})
    token = client.post('/account/api-token').json['access_token']
    client.get('/logout')
    resp = client.get('/api/clients', headers={'Authorization': f'Bearer {token}'})
    assert resp.status_code == 401
