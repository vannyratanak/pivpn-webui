"""Tiny sqlite3 wrapper for firewall rule storage.

No ORM on purpose — one table, few columns, and it keeps the dependency
footprint (and thus what has to install cleanly on a Pi) small.
"""
import contextlib
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import config


@contextlib.contextmanager
def locked_transaction():
    """Yields a connection with SQLite's write lock already held (BEGIN
    IMMEDIATE) — for callers whose read-check-write sequence must be
    atomic against a *second concurrent caller doing the same kind of
    check*, not just internally consistent within one connection.

    Every other function in this module opens its own connection per
    call, which is fine for a single read or a single write, but a
    read-then-decide-then-write guard (e.g. "is this the last admin?",
    "would this rule change lock the admin out?") built from two separate
    calls has a real gap: two near-simultaneous requests can each read
    the same pre-write state before either commits, both pass their own
    check (correctly, for the state each one saw), and both proceed —
    landing on an outcome neither check alone would have allowed. BEGIN
    IMMEDIATE takes the write lock before anything is read, so a second
    concurrent caller blocks until this one's commit (or rollback)
    finishes, then reads the real, post-write state.

    Commits on clean exit (including a plain `return` from inside the
    `with` block — Python's context manager protocol treats that as
    normal exit, not an exception); rolls back and re-raises on any
    exception."""
    conn = sqlite3.connect(config.DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()

SCHEMA = """
CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,          -- 'forward' | 'input' | 'portforward' | 'masquerade' | 'client_block'
    action TEXT,                 -- 'ACCEPT' | 'DROP' | 'MASQUERADE'
    protocol TEXT,               -- 'tcp' | 'udp' | 'all'
    src TEXT,
    dst TEXT,
    dport TEXT,
    ext_port TEXT,
    target_ip TEXT,
    target_port TEXT,
    ext_iface TEXT,
    out_iface TEXT,
    snat_ip TEXT,
    client_name TEXT,
    client_ip TEXT,
    comment TEXT,
    source TEXT NOT NULL DEFAULT 'webui',  -- 'webui' | 'cli' (discovered from a manually-run iptables command)
    enabled INTEGER NOT NULL DEFAULT 1,
    position REAL,                -- display/apply order among rules sharing a chain — see firewall.py's _rebuild_chain
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT CURRENT_TIMESTAMP,
    actor TEXT,
    action TEXT NOT NULL,
    target TEXT,
    result TEXT NOT NULL,   -- 'ok' | 'error'
    detail TEXT
);

-- Login rate-limiting. A plain in-process counter doesn't work here:
-- gunicorn runs 2 worker processes (separate OS processes, no shared
-- memory), so a counter living in one worker's memory would only ever
-- see roughly half of an attacker's requests. This table is the shared
-- state both workers see.
CREATE TABLE IF NOT EXISTS login_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    ts TEXT DEFAULT CURRENT_TIMESTAMP
);

-- No 'active' column on purpose: CRUD means a real delete, not a
-- soft-disable flag. role: 'admin' (full access) | 'moderator' (client
-- control + Logs' Client Sessions/Auth tabs only, view-only on this table)
-- — see app/auth.py's admin_required.
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Destination IP -> organization, for the Traffic log (see
-- app/iplookup.py). org-to-IP-block ownership essentially never changes,
-- so this is a permanent cache, not a TTL'd one — org IS NULL means "we
-- already looked this IP up and found nothing usable," which is itself
-- worth remembering so a persistently-unresolvable IP only ever costs one
-- real WHOIS query, not one per page load.
CREATE TABLE IF NOT EXISTS ip_org_cache (
    ip TEXT PRIMARY KEY,
    org TEXT,
    looked_up_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Structured OpenVPN journal lines, ingested periodically by
-- deploy/ingest_logs.py (see that script and
-- pivpn-webui-log-helper.sh's openvpn-tail action) instead of vpnlog.py
-- regex-parsing raw journal text on every single page load — measured at
-- ~1.5s for a real 7-day/13k-line volume on a live server, once someone
-- actually wants a week of history rather than the original 3-day window.
-- Stores every line, not just matched connect/disconnect ones — the VPN
-- Sessions tab deliberately also shows unrecognized lines as event='other'
-- with the raw text in `detail` (a diagnostic fallback for when this
-- server's OpenVPN log format doesn't match CONNECT_RE/DISCONNECT_RE), and
-- losing that by only storing matches would be a real feature regression,
-- not just an implementation-detail change.
-- The UNIQUE constraint is a deliberate belt-and-suspenders against
-- ingest_logs.py ever reprocessing the same journal line twice (confirmed
-- live: journalctl --cursor-file can re-emit the last-seen entry on the
-- very next invocation) — INSERT OR IGNORE makes a duplicate ingest a
-- no-op instead of a duplicate row.
CREATE TABLE IF NOT EXISTS vpn_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,                    -- 'YYYY-MM-DD HH:MM:SS', same format used everywhere else in this app
    event TEXT NOT NULL,                 -- 'connected' | 'disconnected' | 'other'
    client TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',     -- only populated for event='other'
    real_address TEXT,                   -- only populated for event='connected' behind the relay; see _MIGRATIONS below for why this also needs an ALTER TABLE path
    UNIQUE (ts, event, client, address, detail)
);
CREATE INDEX IF NOT EXISTS idx_vpn_events_ts ON vpn_events(ts);

-- Structured per-flow traffic rows, same ingestion story as vpn_events
-- above but for the Traffic tab (see setup-traffic-log.sh's mangle-table
-- LOG rule) — measured at ~4s+ for a real 7-day volume at this app's
-- current traffic rate (thousands of flows/day), the clearest case for
-- moving off live per-request parsing. dst_org/client are resolved once,
-- at ingest time (via app/iplookup.py's same WHOIS+cache path, and
-- app/vpnlog.py's _client_ip_map()) rather than per page view — ingestion
-- isn't on any HTTP request's critical path, so there's no reason to defer
-- that work the way the request-time code used to.
CREATE TABLE IF NOT EXISTS traffic_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    dst_org TEXT,           -- NULL = private/reserved address, or a WHOIS lookup that found nothing
    client TEXT,            -- resolved client name at ingest time; NULL if src didn't map to a known client
    proto TEXT NOT NULL,
    sport TEXT,
    dport TEXT,
    in_if TEXT,
    out_if TEXT,
    UNIQUE (ts, src, dst, proto, sport, dport)
);
CREATE INDEX IF NOT EXISTS idx_traffic_flows_ts ON traffic_flows(ts);
"""


def get_conn():
    Path(config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# Columns added after the initial release — CREATE TABLE IF NOT EXISTS won't
# retrofit these onto a database that already exists, so migrate explicitly.
# Keyed by table, then column -> DDL.
_MIGRATIONS = {
    "firewall_rules": {
        "out_iface": "ALTER TABLE firewall_rules ADD COLUMN out_iface TEXT",
        "source": "ALTER TABLE firewall_rules ADD COLUMN source TEXT NOT NULL DEFAULT 'webui'",
        "snat_ip": "ALTER TABLE firewall_rules ADD COLUMN snat_ip TEXT",
        "position": "ALTER TABLE firewall_rules ADD COLUMN position REAL",
    },
    "vpn_events": {
        # Resolved once, at ingest time (deploy/ingest_logs.py), for
        # 'connected' rows whose address is behind the relay — see
        # app/vpnlog.py's resolve_real_address. Added after vpn_events
        # itself already existed on at least one real install (.10), hence
        # a migration rather than just a column in CREATE TABLE.
        "real_address": "ALTER TABLE vpn_events ADD COLUMN real_address TEXT",
    },
}


def init_db():
    conn = get_conn()
    try:
        # WAL ("write-ahead log") mode: a write in progress (the log
        # ingestion job, every 10s) no longer blocks a concurrent read (a
        # page load), and vice versa — the default rollback-journal mode
        # makes one wait for the other. This setting is sticky (persists
        # in the database file itself), so setting it once here at
        # startup is enough — every later connection from get_conn()/
        # locked_transaction() picks it up automatically, no per-call
        # pragma needed. synchronous=NORMAL is WAL mode's own recommended
        # pairing (SQLite docs): still safe against an application crash,
        # just not against the OS losing power at the exact wrong instant
        # — a trade this app already makes elsewhere for a Pi-friendly
        # footprint, not a new risk being introduced here.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(SCHEMA)
        for table, columns in _MIGRATIONS.items():
            existing_cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            for col, ddl in columns.items():
                if col not in existing_cols:
                    conn.execute(ddl)
        # Rows from before the position column existed (or any row inserted
        # without one) — fall back to id order, which is what they sorted by
        # already.
        conn.execute("UPDATE firewall_rules SET position = id WHERE position IS NULL")
        # One-time bootstrap: this app used to have exactly one hardcoded
        # account, authenticated against ADMIN_USERNAME/ADMIN_PASSWORD_HASH
        # in .env (see config.py). The first time this runs against a users
        # table with nothing in it yet, carry that account over as a real
        # row — every existing install's current login keeps working with
        # zero manual steps, and .env's values become unused dead config
        # from here on (verify_credentials only ever reads the users table
        # once it has at least one row).
        (user_count,) = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        if user_count == 0 and config.ADMIN_USERNAME and config.ADMIN_PASSWORD_HASH:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (config.ADMIN_USERNAME, config.ADMIN_PASSWORD_HASH),
            )
        conn.commit()
    finally:
        conn.close()


def insert_rule(rule: dict) -> int:
    conn = get_conn()
    try:
        if rule.get("position") is None:
            # Default: append after everything currently in the table, same
            # as this app's rules have always ended up live via -A anyway.
            (max_pos,) = conn.execute("SELECT COALESCE(MAX(position), 0) FROM firewall_rules").fetchone()
            rule = {**rule, "position": max_pos + 1}
        cols = list(rule.keys())
        placeholders = ",".join("?" for _ in cols)
        sql = f"INSERT INTO firewall_rules ({','.join(cols)}) VALUES ({placeholders})"
        cur = conn.execute(sql, [rule[c] for c in cols])
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_rules(enabled_only: bool = False) -> list[dict]:
    conn = get_conn()
    try:
        sql = "SELECT * FROM firewall_rules"
        if enabled_only:
            sql += " WHERE enabled=1"
        sql += " ORDER BY position, id"
        return [dict(r) for r in conn.execute(sql).fetchall()]
    finally:
        conn.close()


def set_positions(mapping: dict[int, float]):
    """Bulk position update for a reorder swap — both rows change together,
    in one transaction, so a crash mid-write can't leave two rules sharing
    (or missing) a position."""
    conn = get_conn()
    try:
        conn.executemany(
            "UPDATE firewall_rules SET position=? WHERE id=?",
            [(pos, rule_id) for rule_id, pos in mapping.items()],
        )
        conn.commit()
    finally:
        conn.close()


def get_rule(rule_id: int):
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM firewall_rules WHERE id=?", (rule_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_client_block(client_name: str):
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM firewall_rules WHERE kind='client_block' AND client_name=?",
            (client_name,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def delete_rule(rule_id: int):
    conn = get_conn()
    try:
        conn.execute("DELETE FROM firewall_rules WHERE id=?", (rule_id,))
        conn.commit()
    finally:
        conn.close()


def set_enabled(rule_id: int, enabled: bool):
    conn = get_conn()
    try:
        conn.execute("UPDATE firewall_rules SET enabled=? WHERE id=?", (1 if enabled else 0, rule_id))
        conn.commit()
    finally:
        conn.close()


def get_user(user_id: int):
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_username(username: str):
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_users() -> list[dict]:
    conn = get_conn()
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM users ORDER BY username").fetchall()]
    finally:
        conn.close()


def count_users() -> int:
    conn = get_conn()
    try:
        (count,) = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        return count
    finally:
        conn.close()


def count_admins() -> int:
    conn = get_conn()
    try:
        (count,) = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()
        return count
    finally:
        conn.close()


def insert_user(username: str, password_hash: str, role: str = "admin") -> int:
    conn = get_conn()
    try:
        try:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"A user named '{username}' already exists.") from exc
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def delete_user(user_id: int):
    conn = get_conn()
    try:
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def delete_user_guarded(user_id: int) -> tuple[dict | None, str | None]:
    """Atomically check-and-delete in one locked transaction. A separate
    count_admins()-then-delete_user() pair (the original implementation)
    has a real TOCTOU race: gunicorn runs multiple worker processes, so
    two near-simultaneous requests can each read the same pre-delete
    admin count before either commits, both see "not the last admin",
    and both proceed — landing on zero admins even though each check was
    individually correct for the state it saw at the time. Reproduced
    live against an isolated DB copy before this existed.

    BEGIN IMMEDIATE takes SQLite's write lock before reading anything, so
    a second concurrent call blocks until the first's delete (or
    refusal) fully commits, and then reads the real, post-delete count —
    the same fix shape as the firewall self-lockout guards, just for a
    race between two different admins instead of one admin's own request
    sequence.

    Returns (deleted_row, None) on success, or (target_row_or_None,
    reason) where reason is 'not_found' or 'last_admin' on refusal —
    the caller still gets the row (for its username) even when refused,
    except when it never existed at all. A refusal's early `return`
    still ends the transaction cleanly (see locked_transaction's
    docstring) — nothing was written yet either way, so there's no
    behavioral difference from an explicit rollback."""
    with locked_transaction() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            return None, "not_found"
        if row["role"] == "admin":
            (admin_count,) = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()
            if admin_count <= 1:
                return dict(row), "last_admin"
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        return dict(row), None


def set_user_password(user_id: int, password_hash: str):
    conn = get_conn()
    try:
        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, user_id))
        conn.commit()
    finally:
        conn.close()


# How long audit_log rows stick around before add_audit opportunistically
# prunes them — long enough to matter for a real incident review, short
# enough that the table doesn't grow forever from background noise. That
# noise is real, not hypothetical: the login page is now reachable from
# the public internet via the relay, and every failed attempt (including
# ones from bots that have no idea this is PiVPN, just scanning) writes
# a row here — see login_failures for the separate, shorter-lived table
# that actually drives rate-limiting.
AUDIT_LOG_RETENTION_DAYS = 90


def add_audit(actor: str, action: str, target: str = "", result: str = "ok", detail: str = ""):
    # SQLite's CURRENT_TIMESTAMP (the column default) is hardcoded to UTC by
    # the SQL standard, regardless of the system's configured timezone — so
    # it's passed explicitly here instead, using the box's actual local time
    # (Asia/Phnom_Penh) via datetime.now(). The prune cutoff below is
    # computed the same way, for the same reason — comparing it against
    # datetime('now', ...) (UTC) would silently prune the wrong rows by
    # the box's UTC offset.
    conn = get_conn()
    try:
        cutoff = (datetime.now() - timedelta(days=AUDIT_LOG_RETENTION_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
        conn.execute(
            "INSERT INTO audit_log (ts, actor, action, target, result, detail) VALUES (?,?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), actor, action, target, result, (detail or "")[:500]),
        )
        conn.commit()
    finally:
        conn.close()


def list_audit(limit: int = 200) -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def record_login_failure(ip: str):
    """Also opportunistically prunes anything old enough that no lockout
    window could ever care about it again — no separate cleanup job
    needed for a table that only ever grows one row per failed attempt.
    Unlike add_audit, this deliberately stays in SQLite's own UTC
    CURRENT_TIMESTAMP (not datetime.now()'s local time) so the window
    comparison in count_recent_login_failures can use datetime('now', ...)
    directly — both sides of that comparison need to agree on a clock,
    and mixing local-time inserts with a UTC-based comparison would
    silently make every window wrong by the box's UTC offset."""
    conn = get_conn()
    try:
        conn.execute("DELETE FROM login_failures WHERE ts < datetime('now', '-1 hour')")
        conn.execute("INSERT INTO login_failures (ip) VALUES (?)", (ip,))
        conn.commit()
    finally:
        conn.close()


def count_recent_login_failures(ip: str, window_seconds: int) -> int:
    conn = get_conn()
    try:
        (count,) = conn.execute(
            "SELECT COUNT(*) FROM login_failures WHERE ip = ? AND ts > datetime('now', ?)",
            (ip, f"-{window_seconds} seconds"),
        ).fetchone()
        return count
    finally:
        conn.close()


def clear_login_failures(ip: str):
    conn = get_conn()
    try:
        conn.execute("DELETE FROM login_failures WHERE ip = ?", (ip,))
        conn.commit()
    finally:
        conn.close()


def list_audit_by_actions(actions: tuple[str, ...], limit: int = 200) -> list[dict]:
    conn = get_conn()
    try:
        placeholders = ",".join("?" for _ in actions)
        rows = conn.execute(
            f"SELECT * FROM audit_log WHERE action IN ({placeholders}) ORDER BY id DESC LIMIT ?",
            (*actions, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_cached_ip_org(ip: str) -> tuple[bool, str | None]:
    """(found, org) — found=False means this IP has never been looked up
    at all (org=None alone can't distinguish that from "looked up, found
    nothing"), which is exactly what a cache-fill caller needs to know."""
    conn = get_conn()
    try:
        row = conn.execute("SELECT org FROM ip_org_cache WHERE ip = ?", (ip,)).fetchone()
        return (True, row["org"]) if row else (False, None)
    finally:
        conn.close()


def cache_ip_org(ip: str, org: str | None):
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO ip_org_cache (ip, org) VALUES (?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET org = excluded.org, looked_up_at = CURRENT_TIMESTAMP",
            (ip, org),
        )
        conn.commit()
    finally:
        conn.close()


def insert_vpn_events(rows: list[tuple[str, str, str, str, str, str | None]]):
    """Each row: (ts, event, client, address, detail, real_address).
    INSERT OR IGNORE so a duplicate ingest of an already-seen line (see the
    table's own comment) is silently a no-op rather than a duplicate row."""
    if not rows:
        return
    conn = get_conn()
    try:
        conn.executemany(
            "INSERT OR IGNORE INTO vpn_events (ts, event, client, address, detail, real_address) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()


def list_vpn_events(limit: int = 50000) -> list[dict]:
    """Oldest first — matches what app/vpnlog.py's pairing logic expects
    (it walks events in the order they actually happened), same contract
    the old live-journalctl path had. Default limit is a generous safety
    cap, not the real bound — prune_old_logs already keeps this table down
    to roughly a week's worth (~13k rows/week observed live), and taking
    the *oldest* N here (not the most recent) would be wrong once a cap
    this low ever actually binds, so it's set well above any realistic
    7-day row count instead of relying on that not mattering."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT ts, event, client, address, detail, real_address FROM vpn_events "
            "ORDER BY ts ASC, id ASC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def insert_traffic_flows(rows: list[tuple]):
    """Each row: (ts, src, dst, dst_org, client, proto, sport, dport,
    in_if, out_if). INSERT OR IGNORE for the same reprocessing-safety
    reason as insert_vpn_events above."""
    if not rows:
        return
    conn = get_conn()
    try:
        conn.executemany(
            "INSERT OR IGNORE INTO traffic_flows "
            "(ts, src, dst, dst_org, client, proto, sport, dport, in_if, out_if) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()


def list_traffic_flows(limit: int = 300) -> list[dict]:
    """Most recent first — this is a display list, unlike list_vpn_events
    above (which feeds a pairing algorithm that wants chronological
    order)."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT ts, src, dst, dst_org, client, proto, sport, dport, in_if, out_if "
            "FROM traffic_flows ORDER BY ts DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def prune_old_logs(days: int):
    """Deletes vpn_events/traffic_flows rows older than `days` — without
    this, traffic_flows in particular grows without bound (thousands of
    rows/day at this app's observed traffic rate), unlike journald's own
    log rotation which did this for free under the old live-parsing
    design. Called once per ingest_logs.py run, not on any request path."""
    conn = get_conn()
    try:
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("DELETE FROM vpn_events WHERE ts < ?", (cutoff,))
        conn.execute("DELETE FROM traffic_flows WHERE ts < ?", (cutoff,))
        conn.commit()
    finally:
        conn.close()
