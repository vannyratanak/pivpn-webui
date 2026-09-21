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
"""
import sys

from app import db


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


def main():
    if len(sys.argv) != 3 or sys.argv[1] != "register":
        print(f"Usage: {sys.argv[0]} register <name>", file=sys.stderr)
        sys.exit(1)
    register(sys.argv[2])


if __name__ == "__main__":
    main()
