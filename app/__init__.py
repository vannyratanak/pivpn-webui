import fcntl
from datetime import timedelta
from pathlib import Path

from flask import Flask
from flask_wtf import CSRFProtect

import config
from app import db
from app.auth import login_manager

csrf = CSRFProtect()

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
    # See routes.py's login() for where session.permanent actually gets
    # set — this alone doesn't apply a limit to the plain (non-permanent)
    # session cookie Flask uses by default.
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=config.SESSION_LIFETIME_HOURS)
    app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE

    db.init_db()
    login_manager.init_app(app)
    csrf.init_app(app)

    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)

    with app.app_context():
        _sync_firewall_once(app)

    return app
