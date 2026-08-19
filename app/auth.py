from flask_login import LoginManager, UserMixin
from werkzeug.security import check_password_hash

import config

login_manager = LoginManager()
login_manager.login_view = "main.login"


class AdminUser(UserMixin):
    """Single static admin account — this app has exactly one user."""
    id = "admin"


@login_manager.user_loader
def load_user(user_id):
    if user_id == "admin":
        return AdminUser()
    return None


def verify_credentials(username: str, password: str) -> bool:
    if username != config.ADMIN_USERNAME:
        return False
    return check_password_hash(config.ADMIN_PASSWORD_HASH, password)
