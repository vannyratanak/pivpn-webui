import config
from app import db


def _use_temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()


def test_init_db_creates_both_tables(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    conn = db.get_conn()
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert {"firewall_rules", "audit_log"}.issubset(tables)


def test_insert_and_list_rule(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    rule_id = db.insert_rule({"kind": "forward", "action": "DROP", "src": "10.0.0.0/8"})
    rules = db.list_rules()
    assert len(rules) == 1
    assert rules[0]["id"] == rule_id
    assert rules[0]["kind"] == "forward"
    assert rules[0]["enabled"] == 1  # DB column default, not passed explicitly


def test_list_rules_enabled_only_filters(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    db.insert_rule({"kind": "forward", "action": "DROP", "enabled": 1})
    db.insert_rule({"kind": "forward", "action": "DROP", "enabled": 0})
    assert len(db.list_rules()) == 2
    assert len(db.list_rules(enabled_only=True)) == 1


def test_delete_rule(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    rule_id = db.insert_rule({"kind": "forward", "action": "DROP"})
    db.delete_rule(rule_id)
    assert db.list_rules() == []


def test_add_audit_and_query(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    db.add_audit("admin", "login", result="ok", detail="from 127.0.0.1")
    conn = db.get_conn()
    row = conn.execute("SELECT actor, action, result FROM audit_log").fetchone()
    conn.close()
    assert (row["actor"], row["action"], row["result"]) == ("admin", "login", "ok")


def test_login_failures_count_per_ip(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    db.record_login_failure("203.0.113.9")
    db.record_login_failure("203.0.113.9")
    db.record_login_failure("198.51.100.5")  # a different IP, counted separately
    assert db.count_recent_login_failures("203.0.113.9", window_seconds=300) == 2
    assert db.count_recent_login_failures("198.51.100.5", window_seconds=300) == 1
    assert db.count_recent_login_failures("10.0.0.1", window_seconds=300) == 0  # never seen


def test_login_failures_outside_window_not_counted(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    conn = db.get_conn()
    conn.execute(
        "INSERT INTO login_failures (ip, ts) VALUES (?, datetime('now', '-10 minutes'))",
        ("203.0.113.9",),
    )
    conn.commit()
    conn.close()
    assert db.count_recent_login_failures("203.0.113.9", window_seconds=300) == 0


def test_clear_login_failures(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    db.record_login_failure("203.0.113.9")
    db.clear_login_failures("203.0.113.9")
    assert db.count_recent_login_failures("203.0.113.9", window_seconds=300) == 0
