import os
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

import config
from app import db

TEST_PASSWORD = "testpass123"

# All tables ever created by db.SCHEMA — truncated before every test for
# isolation. A real Postgres server (unlike SQLite's throwaway per-test
# temp file) is shared across the whole test run, so isolation has to come
# from clearing data, not a fresh file path.
_ALL_TABLES = (
    "firewall_rules", "audit_log", "login_failures", "users",
    "ip_org_cache", "vpn_events", "traffic_flows", "servers",
    "system_log_lines", "client_status_cache",
)


@pytest.fixture(autouse=True)
def _force_local_execution(monkeypatch):
    """Every test exercises the local-execution path — forced off here,
    unconditionally, for every single test (not just ones using the
    client/temp_db fixtures below) regardless of what a developer's own
    .env happens to have set (e.g. mid hub/agent manual testing, which is
    exactly how this was caught: HUB_MODE=true leaking from a real .env
    silently made every pivpn_ctl test that doesn't touch the DB at all —
    plain _run_pivpn-mocking unit tests — route through a nonexistent
    hub_gateway.py instead of the mock)."""
    monkeypatch.setattr(config, "HUB_MODE", False)


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
    # DB_PATH is a leftover from the pre-Postgres SQLite era (see its own
    # comment in config.py) — nothing here reads it as a real database
    # anymore, but app/__init__.py's _sync_firewall_once and
    # _seed_client_status_cache_once both still derive their startup-lock
    # file's *directory* from it (Path(config.DB_PATH).parent). Left
    # untouched, that's one fixed real path on disk shared by every test
    # process on this machine — including a concurrent second session's
    # own test run, using its own separate TEST_DB_NAME and therefore
    # legitimately expecting independent state. Two such runs racing for
    # that one shared lock file would make whichever loses silently skip
    # its own seeding, same failure shape a shared real DB would cause
    # (see the TEST_DB_NAME convention above) — caught live exactly that
    # way: test_seed_client_status_cache_once_runs_on_app_startup failed
    # with an empty cache under a concurrent second session's test run.
    # Keying the directory by DB_NAME gives each TEST_DB_NAME (hence each
    # concurrent session) its own lock-file directory instead.
    monkeypatch.setattr(config, "DB_PATH", str(Path(config.DB_PATH).parent / config.DB_NAME / "pivpn_webui.db"))

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
    subprocess call happens at all. _seed_client_status_cache_once has no
    such natural no-op (it always calls pivpn_ctl.list_clients(), not
    conditioned on any DB row existing first), so it's neutralized here
    directly instead — otherwise every single test using this fixture
    would attempt a real `pivpn list` subprocess call (harmlessly failing
    fast with `pivpn` not on PATH, but printing a diagnostic line to
    stderr on every single test in the suite)."""
    monkeypatch.setattr(config, "SECRET_KEY", "test-secret-key")
    monkeypatch.setattr(config, "ADMIN_USERNAME", "admin")
    monkeypatch.setattr(config, "ADMIN_PASSWORD_HASH", generate_password_hash(TEST_PASSWORD))
    _configure_test_db(monkeypatch)
    monkeypatch.setattr("app._seed_client_status_cache_once", lambda app: None)

    from app import create_app
    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as test_client:
        yield test_client
