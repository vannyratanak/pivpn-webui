import os

import pytest
from werkzeug.security import generate_password_hash

import config
from app import db

TEST_PASSWORD = "testpass123"

# All 7 tables ever created by db.SCHEMA — truncated before every test for
# isolation. A real Postgres server (unlike SQLite's throwaway per-test
# temp file) is shared across the whole test run, so isolation has to come
# from clearing data, not a fresh file path.
_ALL_TABLES = (
    "firewall_rules", "audit_log", "login_failures", "users",
    "ip_org_cache", "vpn_events", "traffic_flows",
)


def _configure_test_db(monkeypatch):
    monkeypatch.setattr(config, "DB_HOST", os.environ.get("TEST_DB_HOST", "localhost"))
    monkeypatch.setattr(config, "DB_PORT", int(os.environ.get("TEST_DB_PORT", "5432")))
    monkeypatch.setattr(config, "DB_NAME", os.environ.get("TEST_DB_NAME", "pivpn_webui_test"))
    monkeypatch.setattr(config, "DB_USER", os.environ.get("TEST_DB_USER", os.environ.get("USER", "postgres")))
    # A local trust-auth Postgres (the usual test setup) ignores this
    # value entirely, but require_secrets() correctly treats an empty
    # string the same as unset — a dummy non-empty value satisfies that
    # check without loosening it for real (production) deployments.
    monkeypatch.setattr(config, "DB_PASSWORD", os.environ.get("TEST_DB_PASSWORD", "unused-local-trust-auth"))

    # init_db() first to guarantee the tables exist at all (idempotent —
    # CREATE TABLE IF NOT EXISTS, a harmless no-op on every call after the
    # first). Then TRUNCATE for isolation. Then init_db() again — this is
    # NOT redundant: init_db() also bootstraps a users row from
    # ADMIN_USERNAME/ADMIN_PASSWORD_HASH when the table is empty (see
    # db.py), and every test needs that check to see this test's own
    # freshly-truncated, genuinely-empty table and this test's own
    # monkeypatched config — a single call before TRUNCATE would see
    # whatever the *previous* test left behind instead.
    db.init_db()
    conn = db.get_conn()
    try:
        conn.execute(f"TRUNCATE {', '.join(_ALL_TABLES)} RESTART IDENTITY CASCADE")
        conn.commit()
    finally:
        conn.close()
    db.init_db()


@pytest.fixture
def temp_db(monkeypatch):
    """An already-initialized, freshly-truncated Postgres test database for
    tests that call app/db.py functions directly (not through the Flask
    `client` fixture below) — e.g. iplookup's cache or vpnlog's DB-backed
    Sessions/Traffic reads."""
    _configure_test_db(monkeypatch)


@pytest.fixture
def client(monkeypatch):
    """A real Flask test client, backed by a freshly-truncated Postgres
    test database — never the real production database. Nothing here
    touches iptables or pivpn: with a fresh empty DB, create_app()'s
    startup sync_all() has zero enabled rules to loop over, so no
    subprocess call happens at all."""
    monkeypatch.setattr(config, "SECRET_KEY", "test-secret-key")
    monkeypatch.setattr(config, "ADMIN_USERNAME", "admin")
    monkeypatch.setattr(config, "ADMIN_PASSWORD_HASH", generate_password_hash(TEST_PASSWORD))
    _configure_test_db(monkeypatch)

    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    # CSRF middleware itself isn't what these tests are checking — disabling
    # it here keeps route tests focused on route behavior. Real requests in
    # production still go through it untouched; this only affects the test
    # client.
    app.config["WTF_CSRF_ENABLED"] = False

    with app.test_client() as test_client:
        yield test_client
