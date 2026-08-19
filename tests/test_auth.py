from werkzeug.security import generate_password_hash

import config
from app.auth import verify_credentials


def _set_creds(monkeypatch, username="admin", password="secret123"):
    monkeypatch.setattr(config, "ADMIN_USERNAME", username)
    monkeypatch.setattr(config, "ADMIN_PASSWORD_HASH", generate_password_hash(password))


def test_correct_credentials(monkeypatch):
    _set_creds(monkeypatch)
    assert verify_credentials("admin", "secret123") is True


def test_wrong_password(monkeypatch):
    _set_creds(monkeypatch)
    assert verify_credentials("admin", "wrong") is False


def test_wrong_username(monkeypatch):
    _set_creds(monkeypatch)
    assert verify_credentials("someone_else", "secret123") is False
