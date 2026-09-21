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

# JWT for the API (app/api.py) — a separate credential from the browser's
# session cookie above, for scripts/other systems calling this app without
# logging in through a browser. Deliberately its own secret, not a reuse of
# SECRET_KEY: SECRET_KEY also signs the session cookie and CSRF tokens, so
# rotating it (e.g. after a suspected leak of one) would otherwise force
# rotating the other too, for no real reason — they protect different
# things. Falls back to SECRET_KEY only if JWT_SECRET_KEY was never set,
# so this stays a zero-config addition for anyone not using the API yet.
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or SECRET_KEY
# Short-lived on purpose — a leaked API token (logged by some intermediary,
# committed to a script by accident) self-expires quickly. 15 minutes is
# Flask-JWT-Extended's own conventional default for access tokens.
JWT_ACCESS_TOKEN_MINUTES = int(os.environ.get("JWT_ACCESS_TOKEN_MINUTES", "15"))

# A browser only ever sends a "Secure" cookie back over HTTPS — without
# it, the session cookie would still be sent in plaintext over any HTTP
# connection that reaches this app. Defaults on because the two primary
# documented access paths (setup-nginx.sh's reverse proxy, or the relay)
# are both HTTPS-only. The one real exception is the README's "LAN-only"
# option (BIND_HOST=0.0.0.0, deliberately plain HTTP, no TLS at all) —
# that mode needs this set to false in .env, or the cookie a login just
# issued would never come back on the next request and login would look
# like it silently fails (redirect-loops back to /login).
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() != "false"

OVPN_DIR = os.environ.get("PIVPN_OVPN_DIR", str(Path.home() / "ovpns"))
OPENVPN_CCD_DIR = os.environ.get("OPENVPN_CCD_DIR", "/etc/openvpn/ccd")
OPENVPN_SUBNET_BASE = os.environ.get("OPENVPN_SUBNET_BASE", "10.8.0")

# PiVPN's own default cert lifetime. Passed explicitly on every `pivpn add`
# because without -d/--days, makeOVPN.sh falls back to an interactive
# readline prompt ("How many days should the certificate last?") that hangs
# non-interactively (no tty under gunicorn) and makes add_client fail.
PIVPN_CERT_DAYS = os.environ.get("PIVPN_CERT_DAYS", "1080")

DB_PATH = os.environ.get("PIVPN_WEBUI_DB", str(BASE_DIR / "instance" / "pivpn_webui.db"))

# Postgres — replaces DB_PATH's SQLite file as of the Postgres migration.
# No default host: unlike every other setting here, there's no sane
# fallback for "which database" — .env must set this explicitly (see
# require_secrets below, which now also enforces it).
DB_HOST = os.environ.get("PIVPN_WEBUI_DB_HOST")
DB_PORT = int(os.environ.get("PIVPN_WEBUI_DB_PORT", "5432"))
DB_NAME = os.environ.get("PIVPN_WEBUI_DB_NAME", "pivpn_webui")
DB_USER = os.environ.get("PIVPN_WEBUI_DB_USER", "pivpn_webui_app")
DB_PASSWORD = os.environ.get("PIVPN_WEBUI_DB_PASSWORD")

BIND_HOST = os.environ.get("BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("BIND_PORT", "8443"))
# Optional — lets wsgi.py's own dev-server invocation (python3 wsgi.py)
# terminate TLS itself with a self-signed cert, for quickly reaching this
# app from another device (e.g. a phone/tablet on the LAN) without setting
# up nginx (setup-nginx.sh) first. Both unset (the default) means plain
# HTTP, same as always. Not how a real deployment should serve TLS long
# term — nginx in front is still the documented path for that — this is
# just the dev server's own ssl_context, off by default.
BIND_TLS_CERT = os.environ.get("BIND_TLS_CERT")
BIND_TLS_KEY = os.environ.get("BIND_TLS_KEY")

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

# Hub/agent split — lets this app run with the PiVPN box's own kernel/CLI
# operations (run_root/_run_pivpn/read_client_ovpn) executed on a remote
# box over a socket instead of locally. Off by default: every existing
# single-box deployment (e.g. .10) is untouched by this, since HUB_MODE
# unset makes every branch point in app/privileged.py and app/pivpn_ctl.py
# fall through to the same local-subprocess code that's always run there.
HUB_MODE = os.environ.get("HUB_MODE", "false").lower() == "true"
DEFAULT_SERVER_ID = int(os.environ.get("DEFAULT_SERVER_ID", "0")) or None
GATEWAY_SOCKET_PATH = os.environ.get(
    "GATEWAY_SOCKET_PATH", str(BASE_DIR / "instance" / "gateway.sock")
)

# hub_gateway.py side only — TLS for the agent-facing WebSocket (the one
# thing on this whole hub<->agent path that was ever unencrypted: the
# Unix socket to Flask never leaves this machine, and the agent's own
# outbound `sudo` calls are local to it). Both unset (the default) means
# hub_gateway.py serves plain ws:// exactly as before — nothing about an
# existing HUB_MODE=false or already-deployed agent breaks by upgrading
# this code. Set both to turn a real cert+key on; there's no "cert but no
# key" half-state, hub_gateway.py refuses to start with just one set.
GATEWAY_TLS_CERT = os.environ.get("GATEWAY_TLS_CERT")
GATEWAY_TLS_KEY = os.environ.get("GATEWAY_TLS_KEY")

# Agent-side only (agent.py) — which hub to dial out to and how to
# authenticate as this particular box. HUB_URL/AGENT_SERVER_ID/AGENT_TOKEN
# are all required for the agent to run at all; irrelevant to the main
# Flask app/hub_gateway.py.
HUB_URL = os.environ.get("HUB_URL")
AGENT_SERVER_ID = int(os.environ["AGENT_SERVER_ID"]) if os.environ.get("AGENT_SERVER_ID") else None
AGENT_TOKEN = os.environ.get("AGENT_TOKEN")
# Only meaningful (and only read) when HUB_URL starts with wss:// — the
# hub_gateway.py cert is self-signed (see setup-hub-tls.sh), so it isn't
# signed by anything in the system's default trust store the way a real
# CA-issued cert would be. This tells agent.py to trust that one specific
# cert instead, the same "pin the exact file, not a CA" approach
# resolve_real_address's own forced-command SSH key already uses. Left
# unset, a wss:// HUB_URL falls back to the system trust store, which is
# the right behavior once hub_gateway.py ever gets a real CA-signed cert.
HUB_TLS_CERT = os.environ.get("HUB_TLS_CERT")

# Only enforced when this module is actually imported by the running app
# (wsgi.py / app factory), not by setup.sh or other tooling that imports
# config for its defaults before the .env file exists.
def require_secrets():
    if not SECRET_KEY or not ADMIN_PASSWORD_HASH:
        raise RuntimeError(
            "SECRET_KEY and ADMIN_PASSWORD_HASH must be set in the environment (.env). "
            "Run setup.sh to generate them."
        )
    if not DB_HOST or not DB_PASSWORD:
        raise RuntimeError(
            "PIVPN_WEBUI_DB_HOST and PIVPN_WEBUI_DB_PASSWORD must be set in the environment (.env) "
            "— the app now requires a Postgres connection, not just the SQLite file path."
        )
    if HUB_MODE and not DEFAULT_SERVER_ID:
        raise RuntimeError(
            "DEFAULT_SERVER_ID must be set in the environment (.env) when HUB_MODE=true."
        )
