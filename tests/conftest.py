import pytest
from werkzeug.security import generate_password_hash

import config

TEST_PASSWORD = "testpass123"


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A real Flask test client, backed by a throwaway temp-file DB — never
    the real instance/pivpn_webui.db. Nothing here touches iptables or
    pivpn: with a fresh empty DB, create_app()'s startup sync_all() has
    zero enabled rules to loop over, so no subprocess call happens at all."""
    monkeypatch.setattr(config, "SECRET_KEY", "test-secret-key")
    monkeypatch.setattr(config, "ADMIN_USERNAME", "admin")
    monkeypatch.setattr(config, "ADMIN_PASSWORD_HASH", generate_password_hash(TEST_PASSWORD))
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))

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
