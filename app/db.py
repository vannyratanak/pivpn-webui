"""Tiny sqlite3 wrapper for firewall rule storage.

No ORM on purpose — one table, few columns, and it keeps the dependency
footprint (and thus what has to install cleanly on a Pi) small.
"""
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import config

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
"""


def get_conn():
    Path(config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# Columns added after the initial release — CREATE TABLE IF NOT EXISTS won't
# retrofit these onto a database that already exists, so migrate explicitly.
_MIGRATIONS = {
    "out_iface": "ALTER TABLE firewall_rules ADD COLUMN out_iface TEXT",
    "source": "ALTER TABLE firewall_rules ADD COLUMN source TEXT NOT NULL DEFAULT 'webui'",
    "snat_ip": "ALTER TABLE firewall_rules ADD COLUMN snat_ip TEXT",
    "position": "ALTER TABLE firewall_rules ADD COLUMN position REAL",
}


def init_db():
    conn = get_conn()
    try:
        conn.executescript(SCHEMA)
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(firewall_rules)")}
        for col, ddl in _MIGRATIONS.items():
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
