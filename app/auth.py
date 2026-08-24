from functools import wraps

from flask import abort
from flask_login import LoginManager, UserMixin, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from app import db

login_manager = LoginManager()
login_manager.login_view = "main.login"


class User(UserMixin):
    """Wraps a users-table row. role is 'admin' (full access) or
    'moderator' (client control + Logs' Client Sessions/Auth tabs only,
    view-only on the Users list) — see admin_required and routes.py's
    per-route/per-tab gating."""

    def __init__(self, id, username, role):
        self.id = str(id)
        self.username = username
        self.role = role

    @property
    def is_admin(self):
        return self.role == "admin"


@login_manager.user_loader
def load_user(user_id):
    try:
        row = db.get_user(int(user_id))
    except (TypeError, ValueError):
        return None
    return User(row["id"], row["username"], row["role"]) if row else None


def verify_credentials(username: str, password: str) -> User | None:
    row = db.get_user_by_username(username)
    if not row or not check_password_hash(row["password_hash"], password):
        return None
    return User(row["id"], row["username"], row["role"])


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def admin_required(fn):
    """Only two roles exist and only one gate direction is needed (admin-only
    vs. both) — a generic multi-role decorator would be speculative
    complexity neither role actually needs yet."""

    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)

    return wrapped
