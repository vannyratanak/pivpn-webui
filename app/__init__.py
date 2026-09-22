import fcntl
from datetime import timedelta
from pathlib import Path

from flask import Flask, g
from flask_jwt_extended import JWTManager
from flask_login import current_user

import config
from app import db
from app.auth import issue_html_jwt_cookie, login_manager, token_superseded

jwt = JWTManager()


@jwt.token_in_blocklist_loader
def _api_token_superseded(jwt_header, jwt_payload):
    """Runs automatically before every @jwt_required()-protected route in
    app/api.py — the API side of the same single-active-session check
    the browser cookie's own request_loader applies (see auth.py's
    token_superseded). A newer login for this account, whether from the
    browser or another API call, makes every older token here fail on
    its very next use — Flask-JWT-Extended's own name for this callback
    is "is this token in the blocklist", so True here means reject."""
    row = db.get_user_by_username(jwt_payload.get("sub", ""))
    return not row or token_superseded(jwt_payload, row)

# Holds this worker's lock_file object for the life of the process — see
# _sync_firewall_once. A function-local variable's refcount hits zero the
# moment the function returns, which closes the file and releases the
# flock almost immediately (confirmed via a real two-process repro) —
# not "for this worker's entire lifetime" as intended, letting a
# later-starting sibling worker acquire the same lock and re-run
# sync_all(), reproducing the exact duplicate-rule bug this exists to
# prevent. A module-level reference survives past the function call.
_firewall_sync_lock_file = None


def _sync_firewall_once(app):
    """gunicorn runs multiple worker processes (see the -w flag in the
    systemd unit), and each one calls create_app() independently on
    startup. Without this lock, every worker's sync_all() races the
    others and each ends up re-adding every rule, leaving N duplicate
    copies of everything in iptables instead of one."""
    global _firewall_sync_lock_file
    lock_path = Path(config.DB_PATH).parent / ".firewall-sync.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_file = open(lock_path, "w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_file.close()
        return  # another worker already has this covered

    _firewall_sync_lock_file = lock_file

    from app import firewall
    try:
        firewall.sync_all()
    except Exception as exc:  # pragma: no cover - best effort on boot
        app.logger.warning("Firewall sync on startup failed: %s", exc)
    # Deliberately not unlocked/closed here: the lock needs to stay held for
    # this worker's entire lifetime, otherwise a worker that later restarts
    # (e.g. after a crash) would race the still-running ones all over again.


def create_app():
    config.require_secrets()

    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE
    app.config["JWT_SECRET_KEY"] = config.JWT_SECRET_KEY
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=config.JWT_ACCESS_TOKEN_MINUTES)

    db.init_db()
    login_manager.init_app(app)
    jwt.init_app(app)

    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)

    from app.api import bp as api_bp
    app.register_blueprint(api_bp)

    @app.after_request
    def _refresh_html_jwt_cookie(response):
        # A JWT's expiry is normally fixed at issuance — unlike the old
        # session cookie (SESSION_REFRESH_EACH_REQUEST, Flask's own
        # default), it does not extend itself just because a request came
        # in. Re-issuing a fresh cookie on every authenticated response is
        # what makes SESSION_LIFETIME_HOURS still mean "N hours since your
        # *last* request" instead of turning into a hard cutoff from
        # login time — matching the exact behavior login()'s old
        # session.permanent = True line documented before this switch to
        # JWT-based identity (see auth.py's issue_html_jwt_cookie).
        #
        # issue_html_jwt_cookie also re-stamps the "la" (last-active)
        # claim to now on every call, including this one — see
        # IDLE_TIMEOUT_MINUTES's comment in config.py and auth.py's
        # idle_timed_out for the shorter, activity-based clock this
        # layers on top of the N-hours-since-last-request one above.
        #
        # g.skip_jwt_cookie_refresh: set by logout() — current_user is
        # still "authenticated" for the rest of *this* request (resolved
        # once at request start, before logout's own cookie-clear ran),
        # so without this check this hook would re-issue a fresh cookie
        # right after logout() just cleared it, silently undoing it.
        if current_user.is_authenticated and not g.get("skip_jwt_cookie_refresh", False):
            issue_html_jwt_cookie(response, current_user)
        return response

    from app.firewall import IP_CIDR_PATTERN, IP_PATTERN, KIND_DISPLAY_LABEL
    app.jinja_env.globals["ip_cidr_pattern"] = IP_CIDR_PATTERN
    app.jinja_env.globals["ip_pattern"] = IP_PATTERN
    app.jinja_env.globals["kind_display_label"] = KIND_DISPLAY_LABEL
    app.jinja_env.globals["idle_timeout_minutes"] = config.IDLE_TIMEOUT_MINUTES

    with app.app_context():
        _sync_firewall_once(app)

    return app
