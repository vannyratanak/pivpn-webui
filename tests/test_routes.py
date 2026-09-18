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


def test_client_sessions_relabeled_ended_session_resorts_below_more_recent_ones(client, monkeypatch):
    # Regression test: a session the log parser thinks is still "ongoing"
    # (no matching disconnect ever logged — e.g. a killed process/unclean
    # drop) gets correctly relabeled "Ended (exact time unknown)" once this
    # route's live-connected-clients check confirms it's not actually
    # connected — but it used to keep the top-pinned position it only ever
    # earned by looking ongoing at sort time, even after being relabeled,
    # burying a genuinely more recent (and fully closed) session below it.
    #
    # Seeds app/db.py's vpn_events table directly (via the `client`
    # fixture's own temp DB) — list_client_sessions reads from there now,
    # not a live journalctl fetch (see app/vpnlog.py's module docstring).
    db.insert_vpn_events([
        ("2026-09-15 09:46:39", "connected", "staleclient", "10.66.66.1:1", "", None),
        ("2026-09-15 13:30:30", "connected", "recentclient", "10.66.66.1:2", "", None),
        ("2026-09-15 13:30:48", "disconnected", "recentclient", "10.66.66.1:2", "", None),
    ])
    # Neither client is actually connected right now — this is what makes
    # "staleclient" (log-ongoing but not live-connected) get relabeled.
    monkeypatch.setattr("app.routes.pivpn_ctl.list_connected_clients", lambda: {})

    _login_admin(client)
    resp = client.get("/logs?tab=client_sessions&range=7d")
    assert resp.status_code == 200
    assert b"Ended (exact time unknown)" in resp.data

    body = resp.data.decode()
    # recentclient's session both started and ended later than staleclient's
    # sole (stale) connect — it must render first now that staleclient has
    # been correctly recognized as not actually ongoing anymore.
    assert body.index("recentclient") < body.index("staleclient")


def test_traffic_tab_search_matches_across_full_history(client, monkeypatch):
    db.insert_traffic_flows([
        ("2026-09-16 10:00:00", "10.202.226.2", "1.1.1.1", None, "mobile",
         "TCP", "1234", "443", "tun0", "ens18"),
        ("2026-09-16 10:00:05", "10.202.226.3", "2.2.2.2", None, "laptop",
         "TCP", "1235", "443", "tun0", "ens18"),
    ])
    _login_admin(client)
    resp = client.get("/logs?tab=traffic&q=laptop&range=7d")
    assert resp.status_code == 200
    assert b"laptop" in resp.data
    assert b"mobile" not in resp.data
    assert b"1 total" in resp.data


def test_traffic_tab_pagination_reaches_rows_past_the_old_300_cap(client, monkeypatch):
    # The actual regression this exists for: with the old fixed limit=300,
    # anything past the 300th-most-recent row was simply unreachable from
    # the UI, no matter what. Seeds 21 rows at page_size=10 (a real,
    # supported option) to prove page 3 reaches the oldest, distinct row
    # in a genuine partial last page -- real pagination, not just "shows
    # some rows".
    db.insert_traffic_flows([
        (f"2026-09-16 10:{i:02d}:00", "10.202.226.2", "1.1.1.1", None, f"client{i}",
         "TCP", "1234", "443", "tun0", "ens18")
        for i in range(21)
    ])
    _login_admin(client)
    resp = client.get("/logs?tab=traffic&page=3&page_size=10&range=7d")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "client0" in body  # most recent first -> last (partial) page has the oldest
    assert "client1<" not in body  # client1..client9 belong on earlier pages
    assert "Page 3 of 3" in body


def test_sessions_tab_pagination_and_search(client, monkeypatch):
    db.insert_vpn_events([
        ("2026-09-16 10:00:00", "connected", "mobile", "10.66.66.1:1", "", None),
        ("2026-09-16 10:00:05", "connected", "laptop", "10.66.66.1:2", "", None),
    ])
    _login_admin(client)
    resp = client.get("/logs?tab=sessions&q=laptop")
    assert resp.status_code == 200
    assert b"laptop" in resp.data
    assert b"mobile" not in resp.data


def test_client_sessions_tab_search(client, monkeypatch):
    db.insert_vpn_events([
        ("2026-09-16 10:00:00", "connected", "mobile", "10.66.66.1:1", "", None),
        ("2026-09-16 10:00:05", "connected", "laptop", "10.66.66.1:2", "", None),
    ])
    monkeypatch.setattr(
        "app.routes.pivpn_ctl.list_connected_clients",
        lambda: {"mobile": {}, "laptop": {}},
    )
    _login_admin(client)
    resp = client.get("/logs?tab=client_sessions&q=laptop")
    assert resp.status_code == 200
    assert b"laptop" in resp.data
    assert b"mobile" not in resp.data


def test_logs_range_filters_out_events_older_than_the_window(client, monkeypatch):
    from datetime import datetime, timedelta
    now = datetime.now()
    recent_ts = now.strftime("%Y-%m-%d %H:%M:%S")
    old_ts = (now - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S")
    db.insert_vpn_events([
        (old_ts, "connected", "old-client", "10.66.66.1:1", "", None),
        (recent_ts, "connected", "recent-client", "10.66.66.1:2", "", None),
    ])
    _login_admin(client)
    resp = client.get("/logs?tab=sessions&range=1h")
    assert resp.status_code == 200
    assert b"recent-client" in resp.data
    assert b"old-client" not in resp.data


def test_logs_invalid_range_value_falls_back_to_default(client, monkeypatch):
    db.insert_vpn_events([
        ("2020-01-01 00:00:00", "connected", "ancient-client", "10.66.66.1:1", "", None),
    ])
    _login_admin(client)
    resp = client.get("/logs?tab=sessions&range=bogus")
    assert resp.status_code == 200
    # An unrecognized ?range= falls back to the same default (1h) as no
    # range at all — not "no cutoff" — so a 2020 event stays filtered out.
    assert b"ancient-client" not in resp.data
    assert b'value="1h" selected' in resp.data


def test_logs_no_range_param_defaults_to_1h(client, monkeypatch):
    db.insert_vpn_events([
        ("2020-01-01 00:00:00", "connected", "ancient-client", "10.66.66.1:1", "", None),
    ])
    _login_admin(client)
    resp = client.get("/logs?tab=sessions")
    assert resp.status_code == 200
    assert b"ancient-client" not in resp.data
    assert b'value="1h" selected' in resp.data


def test_activity_tab_range_and_search_filter_via_the_route(client, monkeypatch):
    # Activity/User Auth read audit_log directly (no separate ingestion
    # table), but go through the exact same q/range/page parsing in
    # logs() as Sessions/Client Sessions/Traffic — this locks that in.
    from datetime import datetime, timedelta
    conn = db.get_conn()
    old_ts = (datetime.now() - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, target, result) VALUES (%s, %s, %s, %s, %s)",
        (old_ts, "admin", "client_add", "old-client", "ok"),
    )
    conn.commit()
    conn.close()
    _login_admin(client)
    db.add_audit("admin", "client_add", target="fresh-client", result="ok")

    resp = client.get("/logs?tab=activity")
    assert resp.status_code == 200
    assert b"fresh-client" in resp.data
    assert b"old-client" not in resp.data  # default 1h range excludes a 3-day-old entry

    resp = client.get("/logs?tab=activity&range=7d&q=old")
    assert resp.status_code == 200
    assert b"old-client" in resp.data
    assert b"fresh-client" not in resp.data


def test_auth_tab_only_shows_login_logout_actions(client, monkeypatch):
    _login_admin(client)
    db.add_audit("admin", "client_add", target="laptop-anna", result="ok")
    resp = client.get("/logs?tab=auth&range=7d")
    assert resp.status_code == 200
    assert b"login" in resp.data  # this test's own _login_admin call
    assert b"laptop-anna" not in resp.data


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
    pruned = []
    monkeypatch.setattr(db, "prune_old_logs", lambda days: pruned.append(days))

    _login_admin(client)
    resp = client.post("/logs/refresh", data={"tab": "traffic"})

    assert resp.status_code == 302
    assert "/logs?tab=traffic" in resp.headers["Location"]
    assert calls == ["events", "flows"]
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


# --- client_detail: per-client status/session summary plus exactly the
# firewall rules scoped to that client (via firewall.rule_client_name), and
# the shared _redirect_after_rule_change() next= behavior its "add a rule"
# form (and the Firewall page's own toggle/delete forms) rely on.

def _stub_single_client(monkeypatch, name="laptop-anna", ip="10.202.226.2", session=None):
    monkeypatch.setattr("app.routes.pivpn_ctl.list_clients", lambda: [
        {"status": "Valid", "name": name, "expiration": "2027-01-01", "raw": ""},
    ])
    monkeypatch.setattr("app.routes.pivpn_ctl.list_client_ips", lambda: {name: ip})
    monkeypatch.setattr(
        "app.routes.pivpn_ctl.list_connected_clients",
        lambda: ({name: session} if session else {}),
    )


def test_client_detail_requires_login(client):
    resp = client.get("/clients/laptop-anna")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_client_detail_requires_admin(client):
    _add_moderator()
    _login_moderator(client)
    assert client.get("/clients/laptop-anna").status_code == 403


def test_client_detail_unknown_client_404s(client, monkeypatch):
    _login_admin(client)
    _stub_single_client(monkeypatch, name="laptop-anna")
    assert client.get("/clients/someone-else").status_code == 404


def test_client_detail_invalid_name_format_404s(client, monkeypatch):
    # validate_name (letters/digits/-/_ only) rejects this before it ever
    # gets to the pivpn_ctl lookup — same 404 either way.
    _login_admin(client)
    _stub_single_client(monkeypatch, name="laptop-anna")
    assert client.get("/clients/not a valid name!").status_code == 404


def test_client_detail_shows_status_and_ip(client, monkeypatch):
    _login_admin(client)
    _stub_single_client(
        monkeypatch, name="laptop-anna", ip="10.202.226.2",
        session={"real_address": "203.0.113.9:5000", "virtual_address": "10.202.226.2",
                 "bytes_recv": "1000", "bytes_sent": "2000", "since": "2026-09-16 10:00:00"},
    )
    resp = client.get("/clients/laptop-anna")
    assert resp.status_code == 200
    html = resp.data.decode()
    assert "laptop-anna" in html
    assert "10.202.226.2" in html
    assert "Connected since 2026-09-16 10:00:00" in html


def test_client_detail_shows_only_this_clients_rules(client, monkeypatch):
    monkeypatch.setattr("app.routes.pivpn_ctl.list_clients", lambda: [
        {"status": "Valid", "name": "laptop-anna", "expiration": "", "raw": ""},
    ])
    monkeypatch.setattr(
        "app.routes.pivpn_ctl.list_client_ips",
        lambda: {"laptop-anna": "10.202.226.2", "phone-bob": "10.202.226.3"},
    )
    monkeypatch.setattr("app.routes.pivpn_ctl.list_connected_clients", lambda: {})
    _login_admin(client)

    db.insert_rule({
        "kind": "forward", "action": "DROP", "protocol": "tcp",
        "src": "10.202.226.2", "dst": "1.2.3.4", "dport": "443",
        "comment": "annas-rule",
    })
    db.insert_rule({
        "kind": "forward", "action": "DROP", "protocol": "tcp",
        "src": "10.202.226.3", "dst": "1.2.3.4", "dport": "443",
        "comment": "bobs-rule",
    })
    db.insert_rule({
        "kind": "client_block", "action": "DROP",
        "client_name": "laptop-anna", "client_ip": "10.202.226.2",
        "comment": "annas-block",
    })

    resp = client.get("/clients/laptop-anna")
    html = resp.data.decode()
    assert resp.status_code == 200
    assert "annas-rule" in html
    assert "annas-block" in html
    assert "bobs-rule" not in html


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

def test_client_add_rule_requires_admin(client):
    _add_moderator()
    _login_moderator(client)
    resp = client.post("/clients/laptop-anna/rules/add", data={"action": "DROP", "protocol": "tcp"})
    assert resp.status_code == 403


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


def test_client_toggle_rule_redirects_back_to_client_page(client):
    _login_admin(client)
    rule_id = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})
    resp = client.post(f"/clients/laptop-anna/rules/{rule_id}/toggle")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"


def test_client_delete_rule_redirects_back_to_client_page(client):
    _login_admin(client)
    rule_id = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})
    resp = client.post(f"/clients/laptop-anna/rules/{rule_id}/delete")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"
    assert db.list_rules() == []


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


def test_client_bulk_disable_requires_admin(client):
    _add_moderator()
    _login_moderator(client)
    resp = client.post("/clients/laptop-anna/rules/bulk-disable", data={"rule_ids": ["1"]})
    assert resp.status_code == 403


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

def test_client_resync_rules_requires_admin(client):
    _add_moderator()
    _login_moderator(client)
    resp = client.post("/clients/laptop-anna/rules/resync")
    assert resp.status_code == 403


def test_client_resync_rules_redirects_back_to_client_page(client):
    _login_admin(client)
    resp = client.post("/clients/laptop-anna/rules/resync")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/clients/laptop-anna"


def test_client_resync_rules_invalid_name_404s(client):
    _login_admin(client)
    resp = client.post("/clients/not a valid name!/rules/resync")
    assert resp.status_code == 404


def test_client_persist_rules_requires_admin(client):
    _add_moderator()
    _login_moderator(client)
    resp = client.post("/clients/laptop-anna/rules/persist")
    assert resp.status_code == 403


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

