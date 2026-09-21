from datetime import timedelta
from functools import wraps

from flask import abort
from flask_jwt_extended import create_access_token, decode_token
from flask_login import LoginManager, UserMixin, current_user
from werkzeug.security import check_password_hash, generate_password_hash

import config
from app import db

login_manager = LoginManager()
login_manager.login_view = "main.login"

# The browser's own identity cookie — a JWT, not a Flask session. Kept as
# its own cookie (not flask_jwt_extended's JWT_TOKEN_LOCATION=cookies
# setting) so app/api.py's blueprint keeps authenticating purely via the
# Authorization header, exactly as before: letting a cookie also satisfy
# @jwt_required() there would reopen the CSRF hole that blueprint's own
# csrf.exempt() was deliberately relying on that header-only requirement
# to stay closed (see app/__init__.py's comment on that exempt() call).
HTML_JWT_COOKIE_NAME = "html_jwt"


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


def issue_html_jwt_cookie(response, user):
    """Called from routes.py's login() (and __init__.py's after_request,
    to keep the old sliding-idle-timeout behavior — see that hook's own
    comment) instead of flask_login's login_user(), which would put the
    identity in Flask's own session cookie instead of here.

    httpOnly: page JavaScript can never read this cookie, so an XSS bug
    elsewhere on the page can't steal it — same protection Flask's
    session cookie already had. Secure: only sent over HTTPS, matching
    SESSION_COOKIE_SECURE (see config.py's own comment on why that one
    real exception — plain-HTTP LAN mode — needs it set to false).
    SameSite=Lax: sent on normal top-level navigation, not on a
    cross-site page's background POST — the CSRF token already required
    in every form's hidden field is the real defense against that case;
    this is defense in depth, not a replacement for it."""
    token = create_access_token(
        identity=user.username,
        additional_claims={"role": user.role},
        expires_delta=timedelta(hours=config.SESSION_LIFETIME_HOURS),
    )
    response.set_cookie(
        HTML_JWT_COOKIE_NAME, token,
        httponly=True, secure=config.SESSION_COOKIE_SECURE, samesite="Lax",
        max_age=config.SESSION_LIFETIME_HOURS * 3600,
    )


def clear_html_jwt_cookie(response):
    response.delete_cookie(HTML_JWT_COOKIE_NAME)


@login_manager.request_loader
def load_user_from_jwt_cookie(req):
    """Replaces the old session-based user_loader — login() never calls
    flask_login's login_user() anymore, so Flask's session never carries
    a user id for that callback to look up; this is the only way
    current_user gets populated now. Every request re-verifies the JWT
    cookie's signature fresh — there's no server-side session state for
    identity at all (Flask's own session cookie still exists, but only
    for flash() messages and CSRF token storage, both unrelated to who's
    logged in)."""
    token = req.cookies.get(HTML_JWT_COOKIE_NAME)
    if not token:
        return None
    try:
        claims = decode_token(token)
    except Exception:
        # Deliberately broad: expired, tampered, signed with an old
        # JWT_SECRET_KEY after a rotation, or just garbage left over from
        # a stale cookie should all mean "not logged in", never a 500 —
        # this is untrusted client input by definition.
        return None
    row = db.get_user_by_username(claims.get("sub", ""))
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
