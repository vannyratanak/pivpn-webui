from datetime import datetime, timedelta

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
    assert {"firewall_rules", "audit_log", "users"}.issubset(tables)


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


def test_add_audit_prunes_rows_older_than_retention(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    conn = db.get_conn()
    old_ts = (datetime.now() - timedelta(days=db.AUDIT_LOG_RETENTION_DAYS + 1)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, result) VALUES (?, ?, ?, ?)",
        (old_ts, "admin", "login", "ok"),
    )
    conn.commit()
    conn.close()
    db.add_audit("admin", "logout", result="ok")  # triggers the opportunistic prune
    rows = db.list_audit(limit=100)
    assert len(rows) == 1  # only the fresh one survives
    assert rows[0]["action"] == "logout"


def test_add_audit_keeps_rows_within_retention(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    conn = db.get_conn()
    recent_ts = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, result) VALUES (?, ?, ?, ?)",
        (recent_ts, "admin", "login", "ok"),
    )
    conn.commit()
    conn.close()
    db.add_audit("admin", "logout", result="ok")
    assert len(db.list_audit(limit=100)) == 2  # both survive


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


# --- users table: CRUD, uniqueness, and the one-time bootstrap-from-.env
# path in init_db(). _use_temp_db_no_bootstrap additionally blanks
# ADMIN_USERNAME/ADMIN_PASSWORD_HASH so a real local .env's values (if any)
# can't race these tests by auto-creating their own "admin" row first.

def _use_temp_db_no_bootstrap(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ADMIN_USERNAME", None)
    monkeypatch.setattr(config, "ADMIN_PASSWORD_HASH", None)
    _use_temp_db(tmp_path, monkeypatch)


def test_insert_and_get_user(tmp_path, monkeypatch):
    _use_temp_db_no_bootstrap(tmp_path, monkeypatch)
    user_id = db.insert_user("alice", "hash123", "moderator")
    row = db.get_user(user_id)
    assert row["username"] == "alice"
    assert row["role"] == "moderator"
    assert db.get_user_by_username("alice")["id"] == user_id


def test_insert_user_defaults_to_admin_role(tmp_path, monkeypatch):
    _use_temp_db_no_bootstrap(tmp_path, monkeypatch)
    user_id = db.insert_user("alice", "hash123")
    assert db.get_user(user_id)["role"] == "admin"


def test_insert_duplicate_username_raises(tmp_path, monkeypatch):
    _use_temp_db_no_bootstrap(tmp_path, monkeypatch)
    db.insert_user("alice", "hash123")
    try:
        db.insert_user("alice", "hash456")
        assert False, "expected ValueError"
    except ValueError:
        pass
    assert db.count_users() == 1  # the failed insert never landed


def test_list_users_ordered_by_username(tmp_path, monkeypatch):
    _use_temp_db_no_bootstrap(tmp_path, monkeypatch)
    db.insert_user("zeb", "h")
    db.insert_user("alice", "h")
    usernames = [u["username"] for u in db.list_users()]
    assert usernames == ["alice", "zeb"]


def test_delete_user(tmp_path, monkeypatch):
    _use_temp_db_no_bootstrap(tmp_path, monkeypatch)
    user_id = db.insert_user("alice", "hash123")
    db.delete_user(user_id)
    assert db.get_user(user_id) is None
    assert db.count_users() == 0


def test_set_user_password(tmp_path, monkeypatch):
    _use_temp_db_no_bootstrap(tmp_path, monkeypatch)
    user_id = db.insert_user("alice", "oldhash")
    db.set_user_password(user_id, "newhash")
    assert db.get_user(user_id)["password_hash"] == "newhash"


def test_init_db_bootstraps_admin_from_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ADMIN_USERNAME", "admin")
    monkeypatch.setattr(config, "ADMIN_PASSWORD_HASH", "somehash")
    _use_temp_db(tmp_path, monkeypatch)
    users = db.list_users()
    assert len(users) == 1
    assert users[0]["username"] == "admin"
    assert users[0]["password_hash"] == "somehash"
    assert users[0]["role"] == "admin"


def test_init_db_bootstrap_only_runs_once(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ADMIN_USERNAME", "admin")
    monkeypatch.setattr(config, "ADMIN_PASSWORD_HASH", "somehash")
    _use_temp_db(tmp_path, monkeypatch)
    db.set_user_password(db.get_user_by_username("admin")["id"], "changed-by-user")
    db.init_db()  # e.g. the next app restart — must not re-bootstrap and clobber the change
    assert db.count_users() == 1
    assert db.get_user_by_username("admin")["password_hash"] == "changed-by-user"


def test_init_db_no_bootstrap_without_config(tmp_path, monkeypatch):
    _use_temp_db_no_bootstrap(tmp_path, monkeypatch)
    assert db.count_users() == 0
