import time

import pytest
from werkzeug.security import generate_password_hash

import config
from app import db
from app.auth import User, idle_timed_out, verify_credentials
from tests.conftest import _configure_test_db


@pytest.fixture
def _db(tmp_path, monkeypatch):
    # Neutralize init_db()'s bootstrap-from-.env path (see db.py) — these
    # tests create users explicitly via _add_user, and a real local .env's
    # ADMIN_PASSWORD_HASH would otherwise race it to create its own "admin".
    monkeypatch.setattr(config, "ADMIN_USERNAME", None)
    monkeypatch.setattr(config, "ADMIN_PASSWORD_HASH", None)
    _configure_test_db(monkeypatch)


def _add_user(username="admin", password="secret123", role="admin"):
    return db.insert_user(username, generate_password_hash(password), role)


def test_correct_credentials(_db):
    _add_user()
    user = verify_credentials("admin", "secret123")
    assert isinstance(user, User)
    assert user.username == "admin"


def test_wrong_password(_db):
    _add_user()
    assert verify_credentials("admin", "wrong") is None


def test_wrong_username(_db):
    _add_user()
    assert verify_credentials("someone_else", "secret123") is None


def test_role_carried_through(_db):
    _add_user("mod", "secret123", role="moderator")
    user = verify_credentials("mod", "secret123")
    assert user.role == "moderator"
    assert user.is_admin is False


def test_idle_timed_out_false_for_recent_activity(monkeypatch):
    monkeypatch.setattr(config, "IDLE_TIMEOUT_MINUTES", 15)
    assert idle_timed_out({"la": int(time.time())}) is False


def test_idle_timed_out_true_past_the_configured_window(monkeypatch):
    monkeypatch.setattr(config, "IDLE_TIMEOUT_MINUTES", 15)
    stale = int(time.time()) - (16 * 60)
    assert idle_timed_out({"la": stale}) is True


def test_idle_timed_out_true_for_a_token_with_no_la_claim(monkeypatch):
    # Same precedent as token_superseded's handling of a missing "gen"
    # claim — a token issued before this feature existed forces one
    # re-login rather than being silently trusted as "never idle".
    monkeypatch.setattr(config, "IDLE_TIMEOUT_MINUTES", 15)
    assert idle_timed_out({}) is True
