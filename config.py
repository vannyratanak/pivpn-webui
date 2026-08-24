import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = os.environ.get("SECRET_KEY")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")

# A logged-in session with no expiry at all (the previous default — plain
# Flask session cookies never expire unless marked permanent) stays valid
# forever if it ever leaks: a stolen laptop, a shared computer, an XSS
# elsewhere in the same browser profile. Sliding window, not a fixed
# absolute one — combined with Flask's SESSION_REFRESH_EACH_REQUEST
# (default on), the cookie's expiry renews on every request, so this is
# "N hours since your *last* request," not "N hours since you logged in."
SESSION_LIFETIME_HOURS = int(os.environ.get("SESSION_LIFETIME_HOURS", "8"))

OVPN_DIR = os.environ.get("PIVPN_OVPN_DIR", str(Path.home() / "ovpns"))
OPENVPN_CCD_DIR = os.environ.get("OPENVPN_CCD_DIR", "/etc/openvpn/ccd")
OPENVPN_SUBNET_BASE = os.environ.get("OPENVPN_SUBNET_BASE", "10.8.0")

# PiVPN's own default cert lifetime. Passed explicitly on every `pivpn add`
# because without -d/--days, makeOVPN.sh falls back to an interactive
# readline prompt ("How many days should the certificate last?") that hangs
# non-interactively (no tty under gunicorn) and makes add_client fail.
PIVPN_CERT_DAYS = os.environ.get("PIVPN_CERT_DAYS", "1080")

DB_PATH = os.environ.get("PIVPN_WEBUI_DB", str(BASE_DIR / "instance" / "pivpn_webui.db"))

BIND_HOST = os.environ.get("BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("BIND_PORT", "8443"))

CCD_HELPER = os.environ.get("CCD_HELPER", "/usr/local/sbin/pivpn-webui-ccd-helper.sh")
LOG_HELPER = os.environ.get("LOG_HELPER", "/usr/local/sbin/pivpn-webui-log-helper.sh")
ROUTES_HELPER = os.environ.get("ROUTES_HELPER", "/usr/local/sbin/pivpn-webui-routes-helper.sh")
CLIENT_SCRIPT_HELPER = os.environ.get("CLIENT_SCRIPT_HELPER", "/usr/local/sbin/pivpn-webui-client-script-helper.sh")

# Optional — only meaningful for a server whose real VPN traffic gets
# relayed through another box (see docs/relay setup). All four are unset
# by default, and resolve_real_address() treats that as "no relay, don't
# even try" rather than an error — a plain install with no relay involved
# should never attempt an SSH call it has no way to succeed at.
RELAY_HOST = os.environ.get("RELAY_HOST")
RELAY_SSH_USER = os.environ.get("RELAY_SSH_USER", "root")
RELAY_TUNNEL_IP = os.environ.get("RELAY_TUNNEL_IP")
RELAY_LOOKUP_SCRIPT = os.environ.get("RELAY_LOOKUP_SCRIPT", "/usr/local/sbin/vpn-real-ip.sh")

IPTABLES_BIN = os.environ.get("IPTABLES_BIN", "/usr/sbin/iptables")
NETFILTER_PERSISTENT_BIN = os.environ.get("NETFILTER_PERSISTENT_BIN", "/usr/sbin/netfilter-persistent")
CAT_BIN = os.environ.get("CAT_BIN", "/bin/cat")
PERSISTED_RULES_PATH = os.environ.get("PERSISTED_RULES_PATH", "/etc/iptables/rules.v4")

# Only enforced when this module is actually imported by the running app
# (wsgi.py / app factory), not by setup.sh or other tooling that imports
# config for its defaults before the .env file exists.
def require_secrets():
    if not SECRET_KEY or not ADMIN_PASSWORD_HASH:
        raise RuntimeError(
            "SECRET_KEY and ADMIN_PASSWORD_HASH must be set in the environment (.env). "
            "Run setup.sh to generate them."
        )
