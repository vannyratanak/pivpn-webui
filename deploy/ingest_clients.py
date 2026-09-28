#!/usr/bin/env python3
"""Pulls the current client list/status (pivpn_ctl.list_clients(),
list_client_ips(), list_connected_clients()) and stores it as structured
rows in the app's own database (app/db.py's client_status_cache table) —
so GET /api/clients and GET /api/clients/<name> can read instantly
instead of calling the agent live on every single request.

Why this exists: in HUB_MODE (see config.py), each of those three
pivpn_ctl calls is a real WebSocket round-trip through the hub/agent
link, taking multiple seconds under normal conditions — and every open
browser tab's own status poll (see clients-page.js) used to repeat that
independently, multiplying one already-slow call by however many tabs
happened to be open. Same fix as deploy/ingest_logs.py already applies to
Sessions/Traffic/System: move the slow part into a periodic background
job, and let every request just read a Postgres table.

blocked is NOT part of this cache — see client_status_cache's own
comment in app/db.py. It's already a fast local read (db.get_client_block,
no agent call), so api.py still computes it live on every request.

Meant to be run periodically by systemd (see
deploy/pivpn-webui-client-ingest.timer / .service), as the same
unprivileged user the main app runs as. Also called directly (not via the
timer) right after a client add/renew/remove/import in app/api.py, the
same way deploy/ingest_logs.py's functions are called directly from
POST /logs/refresh — so a client you just added or removed shows up
immediately instead of waiting for the next 10s tick.

Full-snapshot, not incremental: unlike ingest_logs.py's journalctl-cursor
approach (only ever new lines since last run), there's no "new since last
time" concept for a client list — every tick re-fetches the complete
current state and replaces the cache wholesale (db.replace_client_status_cache),
so a removed client's row disappears on the very next run.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db, pivpn_ctl


def ingest_client_status(*, allow_empty: bool = False) -> int:
    # Record the database time before the slower hub/agent requests. A live
    # agent snapshot arriving during those calls is newer and must win over
    # this potentially stale full snapshot when it is finally committed.
    snapshot_started_at = db.client_status_snapshot_started_at()
    try:
        clients = [c for c in pivpn_ctl.list_clients() if c["status"].lower() == "valid"]
    except pivpn_ctl.PivpnError as exc:
        # Best-effort, same as list_connected_clients()'s own docstring —
        # leave the existing cache in place (stale but present) rather
        # than wiping it on a transient pivpn/agent hiccup.
        print(f"ingest_clients: pivpn list failed, leaving cache as-is: {exc}", file=sys.stderr)
        return 0

    # list_clients() can also *succeed* with zero rows during a transient
    # hub/agent link hiccup (a stale or mid-reconnect websocket returning a
    # technically-ok but empty response) rather than raising PivpnError —
    # reproduced live: a ~70s agent-side network blip caused several ticks
    # of this, and since replace_client_status_cache does a full-snapshot
    # DELETE, every client got wiped and then re-inserted as "brand new"
    # as they trickled back in over the next few ticks, each getting a
    # fresh expiration_changed_at — scrambling the Clients page's
    # create/renew-recency order for every client, not just whichever one
    # actually triggered the ingest. allow_empty=True is only for callers
    # that just performed a removal themselves and know zero is plausible
    # (see app/api.py's remove/bulk-remove routes) — the periodic timer has
    # no such context, so an unexplained drop to zero there is always
    # treated as suspicious rather than authoritative.
    if not clients and not allow_empty and db.list_client_status_cache():
        print(
            "ingest_clients: pivpn list returned zero valid clients while the cache is "
            "non-empty and no removal was expected — leaving cache as-is",
            file=sys.stderr,
        )
        return 0

    connected = pivpn_ctl.list_connected_clients()
    client_ips = pivpn_ctl.list_client_ips()

    rows = []
    for i, c in enumerate(clients):
        session = connected.get(c["name"])
        rows.append({
            "name": c["name"],
            "status": c["status"],
            "expiration": c.get("expiration", ""),
            "list_position": i,
            "ip": client_ips.get(c["name"]),
            "session_real_address": session.get("real_address") if session else None,
            "session_virtual_address": session.get("virtual_address") if session else None,
            "session_bytes_recv": session.get("bytes_recv") if session else None,
            "session_bytes_sent": session.get("bytes_sent") if session else None,
            "session_since": session.get("since") if session else None,
        })
    db.replace_client_status_cache(rows, session_snapshot_started_at=snapshot_started_at)
    return len(rows)


def main():
    n = ingest_client_status()
    print(f"cached {n} client(s)")


if __name__ == "__main__":
    main()
