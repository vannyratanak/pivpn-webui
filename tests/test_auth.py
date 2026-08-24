import pytest
from werkzeug.security import generate_password_hash

import config
from app import db
from app.auth import User, verify_credentials


@pytest.fixture
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    # Neutralize init_db()'s bootstrap-from-.env path (see db.py) — these
    # tests create users explicitly via _add_user, and a real local .env's
    # ADMIN_PASSWORD_HASH would otherwise race it to create its own "admin".
    monkeypatch.setattr(config, "ADMIN_USERNAME", None)
    monkeypatch.setattr(config, "ADMIN_PASSWORD_HASH", None)
    db.init_db()


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
