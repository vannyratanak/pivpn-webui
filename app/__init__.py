import fcntl
from pathlib import Path

from flask import Flask
from flask_wtf import CSRFProtect

import config
from app import db
from app.auth import login_manager

csrf = CSRFProtect()


def _sync_firewall_once(app):
    """gunicorn runs multiple worker processes (see the -w flag in the
    systemd unit), and each one calls create_app() independently on
    startup. Without this lock, every worker's sync_all() races the
    others and each ends up re-adding every rule, leaving N duplicate
    copies of everything in iptables instead of one."""
    lock_path = Path(config.DB_PATH).parent / ".firewall-sync.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_file = open(lock_path, "w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return  # another worker already has this covered

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

    db.init_db()
    login_manager.init_app(app)
    csrf.init_app(app)

    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)

    with app.app_context():
        _sync_firewall_once(app)

    return app
