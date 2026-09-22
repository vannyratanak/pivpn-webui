import time
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
# Reaching the sign-in page is normal; the form already explains what to do.
login_manager.login_message = None

# The browser's own identity cookie — a JWT, not a Flask session. Kept as
# its own cookie (not flask_jwt_extended's JWT_TOKEN_LOCATION=cookies
# setting) so app/api.py's blueprint keeps authenticating purely via the
# Authorization header, exactly as before: a cookie is attached to a
# request automatically by the browser, a bearer header never is — letting
# a cookie also satisfy @jwt_required() there would let a forged cross-site
# request ride along on it, which is exactly the class of attack a bearer-
# only API is naturally immune to as long as it stays header-only.
HTML_JWT_COOKIE_NAME = "html_jwt"
# Short-lived cookie that marks a session as "idle-locked" (screen-locked,
# Cisco-style) — set by /account/lock when the idle timer fires, cleared on
# the next successful credential check.  It is NOT the auth cookie: it only
# remembers the username so the login page can offer a "resume as <user>"
# prompt instead of a blank form.  httpOnly so JS cannot read it; Lax/Secure
# matches the html_jwt cookie.  Max-age is SESSION_LIFETIME_HOURS so a
# locked screen doesn't show a stale username after a full natural expiry.
LOCK_COOKIE_NAME = "idle_lock"


class User(UserMixin):
    """Wraps a users-table row. role is 'admin' (full access) or
    'moderator' (client control + Logs' Client Sessions/Auth tabs only,
    view-only on the Users list) — see admin_required and routes.py's
    per-route/per-tab gating."""

    def __init__(self, id, username, role, session_generation=0):
        self.id = str(id)
        self.username = username
        self.role = role
        # Carried through so __init__.py's sliding-refresh hook can
        # re-embed the *same* generation on every reissued cookie without
        # a second database write — see issue_html_jwt_cookie below and
        # the users.session_generation column's own comment.
        self.session_generation = session_generation

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
    cross-site page's background POST — this is what actually stops a
    forged cross-site request from riding along on this cookie, now that
    there's no separate CSRF token layered on top of it."""
    token = create_access_token(
        identity=user.username,
        # "la" = last-active-at (unix seconds). Stamped fresh every time
        # this function runs — see IDLE_TIMEOUT_MINUTES's own comment for
        # why a request reaching here at all counts as real activity, and
        # load_user_from_jwt_cookie for where this claim is enforced.
        additional_claims={"role": user.role, "gen": user.session_generation, "la": int(time.time())},
        expires_delta=timedelta(hours=config.SESSION_LIFETIME_HOURS),
    )
    response.set_cookie(
        HTML_JWT_COOKIE_NAME, token,
        httponly=True, secure=config.SESSION_COOKIE_SECURE, samesite="Lax",
        max_age=config.SESSION_LIFETIME_HOURS * 3600,
    )


def clear_html_jwt_cookie(response):
    response.delete_cookie(HTML_JWT_COOKIE_NAME)


def issue_lock_cookie(response, username: str):
    """Set the idle-lock cookie for `username`.  Called by /account/lock
    just before clearing the html_jwt; tells the login page who to show in
    the 'resume session' banner so the user only needs to re-enter their
    password, not their username too."""
    response.set_cookie(
        LOCK_COOKIE_NAME, username,
        httponly=True, secure=config.SESSION_COOKIE_SECURE, samesite="Lax",
        max_age=config.SESSION_LIFETIME_HOURS * 3600,
    )


def clear_lock_cookie(response):
    response.delete_cookie(LOCK_COOKIE_NAME)


def peek_locked_username(req) -> str | None:
    """Return the username stored in the lock cookie, or None if absent.
    Used by login() to decide whether to render the 'resume session' variant
    of the login page — no authentication, just a plain cookie read."""
    return req.cookies.get(LOCK_COOKIE_NAME) or None


def token_superseded(claims: dict, row: dict) -> bool:
    """True if `claims` belongs to a login that's since been superseded by
    a newer one for the same account — the single-active-session check.
    Every login (browser or API, see routes.py's/api.py's login())
    bumps users.session_generation and embeds the new value as this
    token's "gen" claim; a token whose "gen" no longer matches the
    account's *current* value was issued by an earlier login that a later
    one has since displaced, so it's treated as logged out from here on
    — without ever having to reach out and kill that other session
    directly. A token with no "gen" claim at all (issued before this
    feature existed) never matches a real generation number (0 is a
    valid starting value, but the claim itself is simply absent), so
    existing sessions are naturally treated as superseded the first time
    this check runs — a one-time forced re-login, not a bug."""
    return claims.get("gen") != row.get("session_generation")


@login_manager.request_loader
def load_user_from_jwt_cookie(req):
    """Replaces the old session-based user_loader — login() never calls
    flask_login's login_user() anymore, so Flask's session never carries
    a user id for that callback to look up; this is the only way
    current_user gets populated now. Every request re-verifies the JWT
    cookie's signature fresh — there's no server-side session state for
    identity at all (Flask's own session cookie still exists, but only
    for flash() messages, unrelated to who's logged in)."""
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
    if not row or token_superseded(claims, row):
        return None
    if idle_timed_out(claims):
        return None
    return User(row["id"], row["username"], row["role"], row["session_generation"])


def idle_timed_out(claims: dict) -> bool:
    """True if `claims`' last recorded activity is older than
    IDLE_TIMEOUT_MINUTES — see that setting's own comment in config.py.
    A token with no "la" claim (issued before this feature existed) is
    treated as timed out, same precedent as token_superseded's handling
    of a missing "gen" claim: a one-time forced re-login, not a bug."""
    last_active = claims.get("la")
    if last_active is None:
        return True
    return time.time() - last_active > config.IDLE_TIMEOUT_MINUTES * 60


def verify_credentials(username: str, password: str) -> User | None:
    row = db.get_user_by_username(username)
    if not row or not check_password_hash(row["password_hash"], password):
        return None
    return User(row["id"], row["username"], row["role"], row["session_generation"])


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
