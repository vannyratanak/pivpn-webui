"""Tiny sqlite3 wrapper for firewall rule storage.

No ORM on purpose — one table, few columns, and it keeps the dependency
footprint (and thus what has to install cleanly on a Pi) small.
"""
import sqlite3
from datetime import datetime
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


def add_audit(actor: str, action: str, target: str = "", result: str = "ok", detail: str = ""):
    # SQLite's CURRENT_TIMESTAMP (the column default) is hardcoded to UTC by
    # the SQL standard, regardless of the system's configured timezone — so
    # it's passed explicitly here instead, using the box's actual local time
    # (Asia/Phnom_Penh) via datetime.now().
    conn = get_conn()
    try:
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
