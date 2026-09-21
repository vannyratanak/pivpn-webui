#!/usr/bin/env python3
"""Hub-side CLI for onboarding a remote agent box (see config.py's
HUB_MODE docstring). Run on the hub machine:

    python3 manage_servers.py register pivpn-test

Prints the new server's id and a one-time token — paste both into the
agent box's own .env (AGENT_SERVER_ID / AGENT_TOKEN) before starting
agent.py there. The raw token only ever exists here, once; only its hash
is stored (see app/db.py's create_server/servers table), so there's no
way to recover it later — registering again under a new name is the
recovery path if it's lost.

If this hub has a CA set up (see setup-hub-tls.sh), this also signs a
mutual-TLS client certificate for the agent and prints where to copy it —
see hub_gateway.py's GATEWAY_CLIENT_CA for why that's worth doing.
"""
import subprocess
import sys
from pathlib import Path

from app import db

APP_DIR = Path(__file__).resolve().parent
CA_CERT = APP_DIR / "instance" / "hub-ca.crt"
CA_KEY = APP_DIR / "instance" / "hub-ca.key"
AGENTS_DIR = APP_DIR / "instance" / "agents"


def _sign_agent_cert(name: str) -> tuple[Path, Path] | None:
    """Returns (cert_path, key_path), or None if this hub has no CA yet
    (setup-hub-tls.sh was never run, or was run before mutual TLS
    existed) — register() treats that as "skip mTLS for now", not a hard
    failure, since plain hello/token auth (or even plain ws://) still
    works without this."""
    if not (CA_CERT.exists() and CA_KEY.exists()):
        return None
    AGENTS_DIR.mkdir(parents=True, exist_ok=True)
    key = AGENTS_DIR / f"{name}.key"
    csr = AGENTS_DIR / f"{name}.csr"
    crt = AGENTS_DIR / f"{name}.crt"
    try:
        subprocess.run(
            ["openssl", "req", "-new", "-nodes", "-newkey", "rsa:2048",
             "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={name}"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["openssl", "x509", "-req", "-in", str(csr),
             "-CA", str(CA_CERT), "-CAkey", str(CA_KEY), "-CAcreateserial",
             "-out", str(crt), "-days", "1095"],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as exc:
        print(f"Warning: failed to sign a client cert for {name!r}: {exc.stderr}", file=sys.stderr)
        return None
    finally:
        csr.unlink(missing_ok=True)
    key.chmod(0o600)
    return crt, key


def register(name: str):
    db.init_db()  # safe to call even before the Flask app has ever started — CREATE TABLE IF NOT EXISTS
    try:
        server_id, token = db.create_server(name)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Registered server #{server_id} ({name!r}). Add this to that box's agent .env:\n")
    print(f"AGENT_SERVER_ID={server_id}")
    print(f"AGENT_TOKEN={token}")

    cert_pair = _sign_agent_cert(name)
    if cert_pair:
        _print_cert_instructions(name, *cert_pair)
    else:
        print()
        print("(No hub CA found at instance/hub-ca.crt — skipping mutual-TLS cert.")
        print(" Run ./setup-hub-tls.sh, then re-run this command, if you want one.)")


def _print_cert_instructions(name: str, crt: Path, key: Path):
    print()
    print("This hub has mutual-TLS set up (instance/hub-ca.crt) — copy these")
    print("two files to that box (the .key especially must stay private):")
    print(f"  scp {crt} {key} <agent-user>@<agent-host>:~/pivpn-webui/instance/")
    print()
    print("...and add to that box's agent .env:")
    print(f"AGENT_TLS_CERT=<path where you copied it>/{name}.crt")
    print(f"AGENT_TLS_KEY=<path where you copied it>/{name}.key")


def issue_cert(name: str):
    """For an agent that's already registered (has a server_id/token) but
    needs a mutual-TLS client cert added retroactively — unlike
    register(), this never touches the servers table, so it can't
    conflict with the box's existing identity or regenerate its token."""
    cert_pair = _sign_agent_cert(name)
    if not cert_pair:
        print(
            "Error: no hub CA found at instance/hub-ca.crt — run ./setup-hub-tls.sh first.",
            file=sys.stderr,
        )
        sys.exit(1)
    _print_cert_instructions(name, *cert_pair)


def rotate_token(name: str):
    """Issues a fresh token for an agent that's already registered —
    the renewal path once its current token is approaching
    config.AGENT_TOKEN_TTL_DAYS, or any time sooner after a suspected
    leak. Its id/name/certificate are untouched; only the token itself
    (and its expiry) changes, so agent.py just needs its .env's
    AGENT_TOKEN updated and to be restarted — no re-copying of any TLS
    files."""
    db.init_db()
    result = db.rotate_server_token(name)
    if not result:
        print(f"Error: no server named '{name}' is registered.", file=sys.stderr)
        sys.exit(1)
    server_id, token = result
    print(f"Rotated token for server #{server_id} ({name!r}). Update that box's agent .env:\n")
    print(f"AGENT_TOKEN={token}")
    print("\n(AGENT_SERVER_ID is unchanged — no need to touch it or any TLS cert/key files.)")
    print("Restart that box's agent.py to pick up the new token.")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "register":
        register(sys.argv[2])
        return
    if len(sys.argv) == 3 and sys.argv[1] == "issue-cert":
        issue_cert(sys.argv[2])
        return
    if len(sys.argv) == 3 and sys.argv[1] == "rotate-token":
        rotate_token(sys.argv[2])
        return
    print(f"Usage: {sys.argv[0]} register <name>", file=sys.stderr)
    print(f"       {sys.argv[0]} issue-cert <name>     (mutual-TLS cert for an already-registered agent)", file=sys.stderr)
    print(f"       {sys.argv[0]} rotate-token <name>   (fresh token for an already-registered agent)", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
