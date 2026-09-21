from werkzeug.security import generate_password_hash

from tests.conftest import TEST_PASSWORD

import app.pivpn_ctl as pivpn_ctl
from app import db, firewall

MOD_PASSWORD = "modpass456"


def _login(client, username="admin", password=TEST_PASSWORD):
    resp = client.post("/api/login", json={"username": username, "password": password})
    return resp


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _moderator_token(client, username="mod1"):
    db.insert_user(username, generate_password_hash(MOD_PASSWORD), "moderator")
    return _login(client, username=username, password=MOD_PASSWORD).get_json()["access_token"]


def _admin_token(client):
    return _login(client).get_json()["access_token"]


def test_login_with_correct_credentials_returns_a_token(client):
    resp = _login(client)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["access_token"]
    assert body["role"] == "admin"


def test_login_with_wrong_credentials_is_rejected(client):
    resp = _login(client, password="wrong")
    assert resp.status_code == 401
    assert "error" in resp.get_json()


def test_login_with_missing_body_is_rejected_not_500(client):
    resp = client.post("/api/login")
    assert resp.status_code == 401


def test_clients_endpoint_requires_a_token(client):
    resp = client.get("/api/clients")
    assert resp.status_code == 401


def test_clients_endpoint_rejects_garbage_token(client):
    resp = client.get("/api/clients", headers=_auth_header("not-a-real-token"))
    assert resp.status_code in (401, 422)


def test_clients_endpoint_returns_enriched_client_list(client, monkeypatch):
    token = _login(client).get_json()["access_token"]
    monkeypatch.setattr("app.api.pivpn_ctl.list_clients", lambda: [
        {"name": "laptop-anna", "status": "Valid"},
        {"name": "old-phone", "status": "Revoked"},
    ])
    monkeypatch.setattr("app.api.pivpn_ctl.list_client_ips", lambda: {"laptop-anna": "10.8.0.2"})
    monkeypatch.setattr("app.api.pivpn_ctl.list_connected_clients", lambda: {"laptop-anna": {"bytes_recv": 100}})
    monkeypatch.setattr("app.api.db.get_client_block", lambda name: None)

    resp = client.get("/api/clients", headers=_auth_header(token))
    assert resp.status_code == 200
    body = resp.get_json()
    # revoked clients are dropped, same as the browser Clients page
    assert [c["name"] for c in body["clients"]] == ["laptop-anna"]
    assert body["clients"][0]["ip"] == "10.8.0.2"
    assert body["clients"][0]["session"] == {"bytes_recv": 100}
    assert body["connected_count"] == 1


def test_client_status_endpoint_shows_status_ip_and_session(client, monkeypatch):
    # This is client_detail.html's own data source now — see
    # client-detail-page.js.
    token = _login(client).get_json()["access_token"]
    monkeypatch.setattr("app.api.pivpn_ctl.list_clients", lambda: [
        {"status": "Valid", "name": "laptop-anna", "expiration": "2027-01-01", "raw": ""},
    ])
    monkeypatch.setattr("app.api.pivpn_ctl.list_client_ips", lambda: {"laptop-anna": "10.202.226.2"})
    monkeypatch.setattr("app.api.pivpn_ctl.list_connected_clients", lambda: {
        "laptop-anna": {"since": "2026-09-16 10:00:00"},
    })
    monkeypatch.setattr("app.api.db.get_client_block", lambda name: None)

    resp = client.get("/api/clients/laptop-anna", headers=_auth_header(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["name"] == "laptop-anna"
    assert body["ip"] == "10.202.226.2"
    assert body["blocked"] is False
    assert body["session"]["since"] == "2026-09-16 10:00:00"


def test_client_status_uses_current_valid_row_when_history_has_duplicates(client, monkeypatch):
    token = _login(client).get_json()["access_token"]
    monkeypatch.setattr("app.api.pivpn_ctl.list_clients", lambda: [
        {"status": "Revoked", "name": "mobile", "expiration": "2027-01-01"},
        {"status": "Valid", "name": " mobile ", "expiration": "2029-01-01"},
    ])
    monkeypatch.setattr("app.api.pivpn_ctl.list_client_ips", lambda: {"mobile": "10.8.0.2"})
    monkeypatch.setattr("app.api.pivpn_ctl.list_connected_clients", lambda: {})
    monkeypatch.setattr("app.api.db.get_client_block", lambda name: None)
    resp = client.get("/api/clients/mobile", headers=_auth_header(token))
    assert resp.status_code == 200
    assert resp.get_json()["expiration"] == "2029-01-01"


def test_client_status_endpoint_for_unknown_client_is_404(client, monkeypatch):
    token = _login(client).get_json()["access_token"]
    monkeypatch.setattr("app.api.pivpn_ctl.list_clients", lambda: [])
    resp = client.get("/api/clients/ghost", headers=_auth_header(token))
    assert resp.status_code == 404


def test_client_status_endpoint_rejects_invalid_name_before_touching_pivpn(client, monkeypatch):
    token = _login(client).get_json()["access_token"]

    def _boom():
        raise AssertionError("list_clients should not be called for an invalid name")

    monkeypatch.setattr("app.api.pivpn_ctl.list_clients", _boom)
    resp = client.get("/api/clients/not valid!", headers=_auth_header(token))
    assert resp.status_code == 400


def test_firewall_rules_endpoint_requires_admin_role(client, monkeypatch):
    # register + log in as a moderator to prove the role check actually
    # bites, not just that some token was missing
    from app import db
    db.insert_user("mod1", "hash", role="moderator")
    monkeypatch.setattr("app.auth.check_password_hash", lambda *_: True)
    token = _login(client, username="mod1", password="anything").get_json()["access_token"]

    resp = client.get("/api/firewall/rules", headers=_auth_header(token))
    assert resp.status_code == 403


def test_firewall_rules_endpoint_returns_enriched_rules_for_admin(client, monkeypatch):
    token = _login(client).get_json()["access_token"]
    monkeypatch.setattr("app.api.pivpn_ctl.list_client_ips", lambda: {"laptop-anna": "10.8.0.2"})
    monkeypatch.setattr("app.api.db.list_rules", lambda: [
        {"id": 1, "kind": "block_ip", "target": "10.8.0.2"},
    ])
    monkeypatch.setattr("app.api.firewall.persisted_rule_ids", lambda: {"1"})
    monkeypatch.setattr("app.api.firewall.describe_rule", lambda r: "blocked")
    monkeypatch.setattr("app.api.firewall.rule_client_name", lambda r, ip_to_name: "laptop-anna")

    resp = client.get("/api/firewall/rules", headers=_auth_header(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["rules"][0]["persisted"] is True
    assert body["rules"][0]["client_name"] == "laptop-anna"


def test_firewall_rules_endpoint_does_not_run_cli_discovery(client, monkeypatch):
    """A plain GET must not trigger discover_cli_rules()'s DB writes as a
    side effect — that's the browser Firewall page's job, not this
    endpoint's. See app/api.py's firewall_rules() docstring."""
    token = _login(client).get_json()["access_token"]

    def _boom(*a, **k):
        raise AssertionError("discover_cli_rules should not be called by the API")

    monkeypatch.setattr("app.api.firewall.discover_cli_rules", _boom, raising=False)
    monkeypatch.setattr("app.api.pivpn_ctl.list_client_ips", lambda: {})
    monkeypatch.setattr("app.api.db.list_rules", lambda: [])
    monkeypatch.setattr("app.api.firewall.persisted_rule_ids", lambda: set())

    resp = client.get("/api/firewall/rules", headers=_auth_header(token))
    assert resp.status_code == 200


# --- client lifecycle: create/renew/remove/download/block, mirroring
# routes.py's own add_client/renew_client/remove_client/download_client/
# block_client views, JSON in and out instead of a form+redirect.

def test_add_client_creates_and_audits(client, monkeypatch):
    token = _login(client).get_json()["access_token"]
    calls = {}
    monkeypatch.setattr("app.api.pivpn_ctl.add_client", lambda name, passphrase=None: calls.update(name=name, passphrase=passphrase))

    resp = client.post("/api/clients", json={"name": "laptop-anna", "passphrase": "s3cret"}, headers=_auth_header(token))
    assert resp.status_code == 201
    assert resp.get_json() == {"created": "laptop-anna"}
    assert calls == {"name": "laptop-anna", "passphrase": "s3cret"}

    from app import db
    audit = db.list_audit(limit=5)
    assert any(a["action"] == "client_add" and a["actor"] == "admin" for a in audit)


def test_add_client_failure_returns_400_with_message(client, monkeypatch):
    token = _login(client).get_json()["access_token"]

    def _boom(name, passphrase=None):
        raise pivpn_ctl.PivpnError("name already in use")

    monkeypatch.setattr("app.api.pivpn_ctl.add_client", _boom)
    resp = client.post("/api/clients", json={"name": "dup"}, headers=_auth_header(token))
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "name already in use"


def test_renew_client_success(client, monkeypatch):
    token = _login(client).get_json()["access_token"]
    monkeypatch.setattr("app.api.pivpn_ctl.renew_client", lambda name: None)
    resp = client.post("/api/clients/laptop-anna/renew", headers=_auth_header(token))
    assert resp.status_code == 200
    assert resp.get_json() == {"renewed": "laptop-anna"}


def test_renew_client_partial_failure_is_flagged_distinctly(client, monkeypatch):
    token = _login(client).get_json()["access_token"]

    def _boom(name):
        raise pivpn_ctl.PivpnRenewPartialFailure(f"'{name}' was revoked but re-add failed.")

    monkeypatch.setattr("app.api.pivpn_ctl.renew_client", _boom)
    resp = client.post("/api/clients/laptop-anna/renew", headers=_auth_header(token))
    assert resp.status_code == 502
    body = resp.get_json()
    assert body["partial_failure"] is True

    from app import db
    audit = db.list_audit(limit=5)
    assert any(a["action"] == "client_renew_partial" and a["result"] == "error" for a in audit)


def test_remove_client_success(client, monkeypatch):
    token = _login(client).get_json()["access_token"]
    monkeypatch.setattr("app.api.pivpn_ctl.remove_client", lambda name: None)
    resp = client.delete("/api/clients/laptop-anna", headers=_auth_header(token))
    assert resp.status_code == 200
    assert resp.get_json() == {"removed": "laptop-anna"}


def test_remove_client_failure_returns_400(client, monkeypatch):
    token = _login(client).get_json()["access_token"]

    def _boom(name):
        raise pivpn_ctl.PivpnError("no such client")

    monkeypatch.setattr("app.api.pivpn_ctl.remove_client", _boom)
    resp = client.delete("/api/clients/ghost", headers=_auth_header(token))
    assert resp.status_code == 400


def test_bulk_remove_clients_success(client, monkeypatch):
    token = _login(client).get_json()["access_token"]
    monkeypatch.setattr("app.api.pivpn_ctl.remove_client", lambda name: None)
    resp = client.post(
        "/api/clients/bulk-remove", json={"names": ["a", "b"]}, headers=_auth_header(token)
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"removed": ["a", "b"], "errors": []}


def test_bulk_remove_clients_partial_failure(client, monkeypatch):
    token = _login(client).get_json()["access_token"]

    def _remove(name):
        if name == "ghost":
            raise pivpn_ctl.PivpnError("no such client")

    monkeypatch.setattr("app.api.pivpn_ctl.remove_client", _remove)
    resp = client.post(
        "/api/clients/bulk-remove", json={"names": ["a", "ghost"]}, headers=_auth_header(token)
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["removed"] == ["a"]
    assert len(body["errors"]) == 1
    assert "ghost" in body["errors"][0]


def test_bulk_remove_clients_requires_a_token(client):
    resp = client.post("/api/clients/bulk-remove", json={"names": ["a"]})
    assert resp.status_code == 401


def test_import_clients_success(client, monkeypatch):
    import io

    token = _login(client).get_json()["access_token"]
    monkeypatch.setattr("app.api.pivpn_ctl.import_clients", lambda text: (2, []))
    resp = client.post(
        "/api/clients/import",
        data={"clients_file": (io.BytesIO(b"name=a\nname=b\n"), "clients.txt")},
        headers=_auth_header(token),
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"added": 2, "errors": []}


def test_import_clients_reports_line_errors(client, monkeypatch):
    import io

    token = _login(client).get_json()["access_token"]
    monkeypatch.setattr("app.api.pivpn_ctl.import_clients", lambda text: (1, ["line 2: bad name"]))
    resp = client.post(
        "/api/clients/import",
        data={"clients_file": (io.BytesIO(b"name=a\nbogus\n"), "clients.txt")},
        headers=_auth_header(token),
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["added"] == 1
    assert body["errors"] == ["line 2: bad name"]


def test_import_clients_missing_file_is_400(client):
    token = _login(client).get_json()["access_token"]
    resp = client.post("/api/clients/import", data={}, headers=_auth_header(token), content_type="multipart/form-data")
    assert resp.status_code == 400


def test_download_client_returns_ovpn_bytes(client, monkeypatch):
    token = _login(client).get_json()["access_token"]
    monkeypatch.setattr("app.api.pivpn_ctl.read_client_ovpn", lambda name: b"client\nremote 1.2.3.4 1194\n")
    resp = client.get("/api/clients/laptop-anna/download", headers=_auth_header(token))
    assert resp.status_code == 200
    assert resp.data == b"client\nremote 1.2.3.4 1194\n"
    assert resp.headers["Content-Disposition"] == 'attachment; filename="laptop-anna.ovpn"'


def test_download_client_missing_file_is_404(client, monkeypatch):
    token = _login(client).get_json()["access_token"]

    def _boom(name):
        raise FileNotFoundError()

    monkeypatch.setattr("app.api.pivpn_ctl.read_client_ovpn", _boom)
    resp = client.get("/api/clients/laptop-anna/download", headers=_auth_header(token))
    assert resp.status_code == 404


def test_download_client_invalid_name_is_400(client, monkeypatch):
    token = _login(client).get_json()["access_token"]

    def _boom():
        raise AssertionError("read_client_ovpn should not be called for an invalid name")

    monkeypatch.setattr("app.api.pivpn_ctl.read_client_ovpn", _boom)
    resp = client.get("/api/clients/not valid!/download", headers=_auth_header(token))
    assert resp.status_code == 400


def test_block_client_success(client, monkeypatch):
    token = _login(client).get_json()["access_token"]
    monkeypatch.setattr("app.api.pivpn_ctl.get_client_ip", lambda name: "10.202.226.2")
    calls = {}
    monkeypatch.setattr(
        "app.api.firewall.set_client_block",
        lambda name, ip, blocked, admin_ip=None: calls.update(name=name, ip=ip, blocked=blocked),
    )
    resp = client.post("/api/clients/laptop-anna/block", json={"blocked": True}, headers=_auth_header(token))
    assert resp.status_code == 200
    assert resp.get_json() == {"name": "laptop-anna", "blocked": True}
    assert calls == {"name": "laptop-anna", "ip": "10.202.226.2", "blocked": True}


def test_block_client_without_a_static_ip_is_400(client, monkeypatch):
    token = _login(client).get_json()["access_token"]
    monkeypatch.setattr("app.api.pivpn_ctl.get_client_ip", lambda name: None)
    resp = client.post("/api/clients/laptop-anna/block", json={"blocked": True}, headers=_auth_header(token))
    assert resp.status_code == 400


# --- per-client firewall rules

def test_client_add_rule_uses_the_clients_own_ip_as_src(client, monkeypatch):
    token = _admin_token(client)
    monkeypatch.setattr("app.api.pivpn_ctl.list_client_ips", lambda: {"laptop-anna": "10.202.226.2"})
    monkeypatch.setattr("app.firewall.run_root", lambda argv, **kwargs: "")
    resp = client.post(
        "/api/clients/laptop-anna/rules",
        json={"action": "DROP", "protocol": "tcp", "dst": "", "dport": ""},
        headers=_auth_header(token),
    )
    assert resp.status_code == 201
    rules = db.list_rules()
    assert len(rules) == 1
    assert rules[0]["src"] == "10.202.226.2"


def test_client_add_rule_without_a_vpn_ip_is_400(client, monkeypatch):
    token = _admin_token(client)
    monkeypatch.setattr("app.api.pivpn_ctl.list_client_ips", lambda: {})
    resp = client.post("/api/clients/laptop-anna/rules", json={"action": "DROP"}, headers=_auth_header(token))
    assert resp.status_code == 400
    assert db.list_rules() == []


def test_client_toggle_and_delete_rule(client, monkeypatch):
    token = _admin_token(client)
    monkeypatch.setattr("app.firewall.run_root", lambda argv, **kwargs: "")
    rule_id = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})

    resp = client.post(f"/api/clients/laptop-anna/rules/{rule_id}/toggle", headers=_auth_header(token))
    assert resp.status_code == 200

    resp = client.delete(f"/api/clients/laptop-anna/rules/{rule_id}", headers=_auth_header(token))
    assert resp.status_code == 200
    assert db.list_rules() == []


def test_client_rules_only_returns_rules_matching_that_clients_ip(client, monkeypatch):
    token = _admin_token(client)
    monkeypatch.setattr("app.api.pivpn_ctl.list_client_ips", lambda: {"laptop-anna": "10.202.226.2", "mac": "10.202.226.5"})
    db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})
    db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.5"})

    resp = client.get("/api/clients/laptop-anna/rules", headers=_auth_header(token))
    assert resp.status_code == 200
    rules = resp.get_json()["rules"]
    assert len(rules) == 1
    assert rules[0]["src"] == "10.202.226.2"


def test_client_rules_endpoint_works_for_a_moderator(client):
    # Unlike GET /api/firewall/rules (admin-only), this client-scoped one
    # matches client_detail.html's own moderator access.
    token = _moderator_token(client)
    resp = client.get("/api/clients/laptop-anna/rules", headers=_auth_header(token))
    assert resp.status_code == 200


def test_client_resync_and_persist_rules(client, monkeypatch):
    token = _moderator_token(client)
    sync_calls = []
    monkeypatch.setattr("app.api.firewall.sync_all", lambda: sync_calls.append(1))
    persist_calls = []
    monkeypatch.setattr("app.api.firewall.save_persistent", lambda: persist_calls.append(1))

    resp = client.post("/api/clients/laptop-anna/rules/resync", headers=_auth_header(token))
    assert resp.status_code == 200
    assert sync_calls == [1]

    resp = client.post("/api/clients/laptop-anna/rules/persist", headers=_auth_header(token))
    assert resp.status_code == 200
    assert persist_calls == [1]


def test_client_bulk_disable_only_affects_that_clients_rules(client, monkeypatch):
    token = _admin_token(client)
    monkeypatch.setattr("app.api.pivpn_ctl.list_client_ips", lambda: {"laptop-anna": "10.202.226.2", "mac": "10.202.226.5"})
    monkeypatch.setattr("app.firewall.run_root", lambda argv, **kwargs: "")
    mine = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})
    other = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.5"})

    resp = client.post(
        "/api/clients/laptop-anna/rules/bulk-disable",
        json={"rule_ids": [mine, other]},
        headers=_auth_header(token),
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["changed"] == 1

    rules = {r["id"]: r for r in db.list_rules()}
    assert rules[mine]["enabled"] == 0
    assert rules[other]["enabled"] == 1


def test_client_bulk_delete_only_affects_that_clients_rules(client, monkeypatch):
    token = _admin_token(client)
    monkeypatch.setattr("app.api.pivpn_ctl.list_client_ips", lambda: {"laptop-anna": "10.202.226.2", "mac": "10.202.226.5"})
    monkeypatch.setattr("app.firewall.run_root", lambda argv, **kwargs: "")
    mine = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})
    other = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.5"})

    resp = client.post(
        "/api/clients/laptop-anna/rules/bulk-delete",
        json={"rule_ids": [mine, other]},
        headers=_auth_header(token),
    )
    assert resp.status_code == 200
    assert resp.get_json()["changed"] == 1

    remaining_ids = {r["id"] for r in db.list_rules()}
    assert remaining_ids == {other}


# --- global firewall rules: admin-only, mirrors the browser's Firewall page

def test_add_forward_rule_rejects_moderator(client):
    token = _moderator_token(client)
    resp = client.post("/api/firewall/forward", json={"action": "DROP", "protocol": "tcp", "src": "10.202.226.2"}, headers=_auth_header(token))
    assert resp.status_code == 403


def test_add_forward_rule_success(client, monkeypatch):
    token = _admin_token(client)
    monkeypatch.setattr("app.firewall.run_root", lambda argv, **kwargs: "")
    resp = client.post(
        "/api/firewall/forward",
        json={"action": "DROP", "protocol": "tcp", "src": "10.202.226.2", "dst": "", "dport": ""},
        headers=_auth_header(token),
    )
    assert resp.status_code == 201
    assert len(db.list_rules()) == 1


def test_add_input_rule_success(client, monkeypatch):
    token = _admin_token(client)
    monkeypatch.setattr("app.firewall.run_root", lambda argv, **kwargs: "")
    resp = client.post(
        "/api/firewall/input",
        json={"action": "DROP", "protocol": "tcp", "src": "1.2.3.4", "dport": "22"},
        headers=_auth_header(token),
    )
    assert resp.status_code == 201


def test_add_snat_rule_failure_returns_400(client, monkeypatch):
    token = _admin_token(client)

    def _boom(**kwargs):
        raise firewall.FirewallError("bad interface")

    monkeypatch.setattr("app.api.firewall.add_snat_rule", _boom)
    resp = client.post("/api/firewall/snat", json={"src": "10.202.226.0/24", "snat_ip": "1.2.3.4"}, headers=_auth_header(token))
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "bad interface"


def test_add_portforward_rule_success(client, monkeypatch):
    token = _admin_token(client)
    monkeypatch.setattr("app.api.firewall.add_portforward_rule", lambda **kwargs: 42)
    resp = client.post(
        "/api/firewall/portforward",
        json={"ext_port": "8080", "target_ip": "10.202.226.2", "target_port": "80"},
        headers=_auth_header(token),
    )
    assert resp.status_code == 201
    assert resp.get_json()["rule_id"] == 42


def test_toggle_and_delete_global_rule_requires_admin(client, monkeypatch):
    token = _moderator_token(client)
    resp = client.post("/api/firewall/rules/1/toggle", headers=_auth_header(token))
    assert resp.status_code == 403
    resp = client.delete("/api/firewall/rules/1", headers=_auth_header(token))
    assert resp.status_code == 403


def test_toggle_and_delete_global_rule_success(client, monkeypatch):
    token = _admin_token(client)
    monkeypatch.setattr("app.firewall.run_root", lambda argv, **kwargs: "")
    rule_id = db.insert_rule({"kind": "forward", "action": "DROP", "protocol": "tcp", "src": "10.202.226.2"})

    resp = client.post(f"/api/firewall/rules/{rule_id}/toggle", headers=_auth_header(token))
    assert resp.status_code == 200
    resp = client.delete(f"/api/firewall/rules/{rule_id}", headers=_auth_header(token))
    assert resp.status_code == 200
    assert db.list_rules() == []


# --- VPN routes: admin-only

def test_vpn_routes_requires_admin(client):
    token = _moderator_token(client)
    assert client.get("/api/vpn-routes", headers=_auth_header(token)).status_code == 403
    assert client.post("/api/vpn-routes", json={}, headers=_auth_header(token)).status_code == 403
    assert client.delete("/api/vpn-routes", json={}, headers=_auth_header(token)).status_code == 403


def test_vpn_routes_list_add_remove(client, monkeypatch):
    token = _admin_token(client)
    monkeypatch.setattr("app.vpn_routes.list_routes", lambda: [{"network": "10.9.0.0", "netmask": "255.255.255.0", "managed": True}])
    resp = client.get("/api/vpn-routes", headers=_auth_header(token))
    assert resp.status_code == 200
    assert resp.get_json()["routes"][0]["network"] == "10.9.0.0"

    calls = {}
    monkeypatch.setattr("app.vpn_routes.add_route", lambda network, netmask: calls.update(network=network, netmask=netmask))
    resp = client.post("/api/vpn-routes", json={"network": "10.9.0.0", "netmask": "255.255.255.0"}, headers=_auth_header(token))
    assert resp.status_code == 201
    assert calls == {"network": "10.9.0.0", "netmask": "255.255.255.0"}

    monkeypatch.setattr("app.vpn_routes.remove_route", lambda network, netmask: None)
    resp = client.delete("/api/vpn-routes", json={"network": "10.9.0.0", "netmask": "255.255.255.0"}, headers=_auth_header(token))
    assert resp.status_code == 200


def test_vpn_routes_add_invalid_network_is_400(client, monkeypatch):
    token = _admin_token(client)
    resp = client.post("/api/vpn-routes", json={"network": "not-an-ip", "netmask": "255.255.255.0"}, headers=_auth_header(token))
    assert resp.status_code == 400


# --- Logs: role-gated tabs

def test_logs_moderator_cannot_read_system_tab(client):
    token = _moderator_token(client)
    resp = client.get("/api/logs?tab=system", headers=_auth_header(token))
    assert resp.status_code == 403


def test_logs_moderator_can_read_client_sessions_tab(client, monkeypatch):
    token = _moderator_token(client)
    # ongoing is a required field on every real row (the relabeling pass
    # right after this call reads it unconditionally) — a realistic mock
    # needs it even though this test itself is only about role-gating.
    monkeypatch.setattr("app.vpnlog.list_client_sessions", lambda **kwargs: ([{"client": "laptop-anna", "ongoing": False}], 1))
    resp = client.get("/api/logs?tab=client_sessions", headers=_auth_header(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["entries"] == [{"client": "laptop-anna", "ongoing": False}]
    assert body["total"] == 1


def test_logs_admin_can_read_activity_tab(client, monkeypatch):
    token = _admin_token(client)
    resp = client.get("/api/logs?tab=activity", headers=_auth_header(token))
    assert resp.status_code == 200


def test_logs_refresh(client, monkeypatch):
    token = _admin_token(client)
    calls = []
    monkeypatch.setattr("deploy.ingest_logs.ingest_vpn_events", lambda: calls.append("vpn_events"))
    monkeypatch.setattr("deploy.ingest_logs.ingest_traffic_flows", lambda: calls.append("traffic"))
    monkeypatch.setattr("deploy.ingest_logs.ingest_system_log", lambda: calls.append("system"))
    resp = client.post("/api/logs/refresh", headers=_auth_header(token))
    assert resp.status_code == 200
    assert calls == ["vpn_events", "traffic", "system"]


# --- Logs: data behavior (search/range/pagination/relabeling) — moved here
# from tests/test_routes.py's old /logs (browser view) versions once that
# view stopped querying the DB at all (see app/routes.py's logs() and
# logs.html/logs-page.js) — this is the only place any of this is exercised
# against real data anymore.

def test_client_sessions_relabeled_ended_session_resorts_below_more_recent_ones(client, monkeypatch):
    # Regression test: a session the log parser thinks is still "ongoing"
    # (no matching disconnect ever logged — e.g. a killed process/unclean
    # drop) gets correctly relabeled "Ended (exact time unknown)" once
    # this endpoint's live-connected-clients check confirms it's not
    # actually connected — but it used to keep the top-pinned position it
    # only ever earned by looking ongoing at sort time, even after being
    # relabeled, burying a genuinely more recent (and fully closed)
    # session below it.
    db.insert_vpn_events([
        ("2026-09-15 09:46:39", "connected", "staleclient", "10.66.66.1:1", "", None),
        ("2026-09-15 13:30:30", "connected", "recentclient", "10.66.66.1:2", "", None),
        ("2026-09-15 13:30:48", "disconnected", "recentclient", "10.66.66.1:2", "", None),
    ])
    # Neither client is actually connected right now — this is what makes
    # "staleclient" (log-ongoing but not live-connected) get relabeled.
    monkeypatch.setattr("app.api.pivpn_ctl.list_connected_clients", lambda: {})

    token = _admin_token(client)
    resp = client.get("/api/logs?tab=client_sessions&range=7d", headers=_auth_header(token))
    assert resp.status_code == 200
    entries = resp.get_json()["entries"]
    names = [e["client"] for e in entries]
    assert any(e["status_note"] == "Ended (exact time unknown)" for e in entries if e["client"] == "staleclient")
    # recentclient's session both started and ended later than
    # staleclient's sole (stale) connect — it must come first now that
    # staleclient has been correctly recognized as not actually ongoing.
    assert names.index("recentclient") < names.index("staleclient")


def test_traffic_tab_search_matches_across_full_history(client):
    db.insert_traffic_flows([
        ("2026-09-16 10:00:00", "10.202.226.2", "1.1.1.1", None, "mobile",
         "TCP", "1234", "443", "tun0", "ens18"),
        ("2026-09-16 10:00:05", "10.202.226.3", "2.2.2.2", None, "laptop",
         "TCP", "1235", "443", "tun0", "ens18"),
    ])
    token = _admin_token(client)
    resp = client.get("/api/logs?tab=traffic&q=laptop&range=7d", headers=_auth_header(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["total"] == 1
    assert body["entries"][0]["client"] == "laptop"


def test_traffic_tab_pagination_reaches_rows_past_the_old_300_cap(client):
    # The actual regression this exists for: with the old fixed limit=300,
    # anything past the 300th-most-recent row was simply unreachable, no
    # matter what. Seeds 21 rows at page_size=10 (a real, supported
    # option) to prove page 3 reaches the oldest, distinct row in a
    # genuine partial last page — real pagination, not just "shows some
    # rows".
    db.insert_traffic_flows([
        (f"2026-09-16 10:{i:02d}:00", "10.202.226.2", "1.1.1.1", None, f"client{i}",
         "TCP", "1234", "443", "tun0", "ens18")
        for i in range(21)
    ])
    token = _admin_token(client)
    resp = client.get("/api/logs?tab=traffic&page=3&page_size=10&range=7d", headers=_auth_header(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["page"] == 3
    assert body["total"] == 21
    assert len(body["entries"]) == 1
    assert body["entries"][0]["client"] == "client0"  # most recent first -> last page has the oldest


def test_sessions_tab_pagination_and_search(client):
    db.insert_vpn_events([
        ("2026-09-16 10:00:00", "connected", "mobile", "10.66.66.1:1", "", None),
        ("2026-09-16 10:00:05", "connected", "laptop", "10.66.66.1:2", "", None),
    ])
    token = _admin_token(client)
    # range=7d: these fixed timestamps age past the default 1h window as
    # real wall-clock time moves on — not what this test is about.
    resp = client.get("/api/logs?tab=sessions&q=laptop&range=7d", headers=_auth_header(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["total"] == 1
    assert body["entries"][0]["client"] == "laptop"


def test_client_sessions_tab_search(client, monkeypatch):
    db.insert_vpn_events([
        ("2026-09-16 10:00:00", "connected", "mobile", "10.66.66.1:1", "", None),
        ("2026-09-16 10:00:05", "connected", "laptop", "10.66.66.1:2", "", None),
    ])
    monkeypatch.setattr(
        "app.api.pivpn_ctl.list_connected_clients",
        lambda: {"mobile": {}, "laptop": {}},
    )
    token = _admin_token(client)
    # range=7d: same fixed-timestamp-vs-wall-clock reasoning as
    # test_sessions_tab_pagination_and_search above.
    resp = client.get("/api/logs?tab=client_sessions&q=laptop&range=7d", headers=_auth_header(token))
    assert resp.status_code == 200
    clients = [e["client"] for e in resp.get_json()["entries"]]
    assert clients == ["laptop"]


def test_logs_range_filters_out_events_older_than_the_window(client):
    from datetime import datetime, timedelta
    now = datetime.now()
    recent_ts = now.strftime("%Y-%m-%d %H:%M:%S")
    old_ts = (now - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S")
    db.insert_vpn_events([
        (old_ts, "connected", "old-client", "10.66.66.1:1", "", None),
        (recent_ts, "connected", "recent-client", "10.66.66.1:2", "", None),
    ])
    token = _admin_token(client)
    resp = client.get("/api/logs?tab=sessions&range=1h", headers=_auth_header(token))
    assert resp.status_code == 200
    clients = [e["client"] for e in resp.get_json()["entries"]]
    assert "recent-client" in clients
    assert "old-client" not in clients


def test_logs_invalid_range_value_falls_back_to_default(client):
    db.insert_vpn_events([
        ("2020-01-01 00:00:00", "connected", "ancient-client", "10.66.66.1:1", "", None),
    ])
    token = _admin_token(client)
    # An unrecognized ?range= falls back to the same default (1h) as no
    # range at all — not "no cutoff" — so a 2020 event stays filtered out.
    resp = client.get("/api/logs?tab=sessions&range=bogus", headers=_auth_header(token))
    assert resp.status_code == 200
    clients = [e["client"] for e in resp.get_json()["entries"]]
    assert "ancient-client" not in clients


def test_activity_tab_range_and_search_filter(client):
    # Activity/User Auth read audit_log directly (no separate ingestion
    # table), but go through the exact same q/range/page parsing as
    # Sessions/Client Sessions/Traffic — this locks that in.
    from datetime import datetime, timedelta
    conn = db.get_conn()
    old_ts = (datetime.now() - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, target, result) VALUES (%s, %s, %s, %s, %s)",
        (old_ts, "admin", "client_add", "old-client", "ok"),
    )
    conn.commit()
    conn.close()
    token = _admin_token(client)
    db.add_audit("admin", "client_add", target="fresh-client", result="ok")

    resp = client.get("/api/logs?tab=activity", headers=_auth_header(token))
    assert resp.status_code == 200
    targets = [e["target"] for e in resp.get_json()["entries"]]
    assert "fresh-client" in targets
    assert "old-client" not in targets  # default 1h range excludes a 3-day-old entry

    resp = client.get("/api/logs?tab=activity&range=7d&q=old", headers=_auth_header(token))
    assert resp.status_code == 200
    targets = [e["target"] for e in resp.get_json()["entries"]]
    assert "old-client" in targets
    assert "fresh-client" not in targets


def test_auth_tab_only_shows_login_logout_actions(client):
    # Seeded directly rather than via /api/login — that endpoint doesn't
    # audit logins itself (only the browser's routes.py login() does);
    # this test is only about the auth tab's own action-filtering, not
    # about who calls db.add_audit("login", ...).
    token = _admin_token(client)
    db.add_audit("admin", "login", detail="from 1.2.3.4")
    db.add_audit("admin", "client_add", target="laptop-anna", result="ok")
    resp = client.get("/api/logs?tab=auth&range=7d", headers=_auth_header(token))
    assert resp.status_code == 200
    entries = resp.get_json()["entries"]
    assert any(e["action"] == "login" for e in entries)
    assert not any(e["target"] == "laptop-anna" for e in entries)


# --- Users

def test_list_users_excludes_password_hash(client):
    token = _admin_token(client)
    resp = client.get("/api/users", headers=_auth_header(token))
    assert resp.status_code == 200
    for u in resp.get_json()["users"]:
        assert "password_hash" not in u
        assert "session_generation" not in u


def test_add_user_requires_admin(client):
    token = _moderator_token(client)
    resp = client.post("/api/users", json={"username": "x", "password": "y", "role": "moderator"}, headers=_auth_header(token))
    assert resp.status_code == 403


def test_add_user_success(client):
    token = _admin_token(client)
    resp = client.post("/api/users", json={"username": "newmod", "password": "abc12345", "role": "moderator"}, headers=_auth_header(token))
    assert resp.status_code == 201
    assert any(u["username"] == "newmod" for u in db.list_users())


def test_add_user_invalid_role_is_400(client):
    token = _admin_token(client)
    resp = client.post("/api/users", json={"username": "x", "password": "y", "role": "superadmin"}, headers=_auth_header(token))
    assert resp.status_code == 400


def test_delete_user_last_admin_is_blocked(client):
    token = _admin_token(client)
    admin_row = db.get_user_by_username("admin")
    resp = client.delete(f"/api/users/{admin_row['id']}", headers=_auth_header(token))
    assert resp.status_code == 400
    assert "last remaining admin" in resp.get_json()["error"]


def test_delete_user_success(client):
    token = _admin_token(client)
    db.insert_user("throwaway", generate_password_hash("x"), "moderator")
    row = next(u for u in db.list_users() if u["username"] == "throwaway")
    resp = client.delete(f"/api/users/{row['id']}", headers=_auth_header(token))
    assert resp.status_code == 200
    assert resp.get_json() == {"deleted": "throwaway"}


def test_delete_user_requires_admin(client):
    token = _moderator_token(client)
    resp = client.delete("/api/users/999", headers=_auth_header(token))
    assert resp.status_code == 403


def test_reset_user_password_requires_admin(client):
    token = _moderator_token(client)
    resp = client.post("/api/users/1/reset-password", json={"password": "newpass1"}, headers=_auth_header(token))
    assert resp.status_code == 403


def test_reset_user_password_success(client):
    token = _admin_token(client)
    db.insert_user("someone", generate_password_hash("old"), "moderator")
    row = next(u for u in db.list_users() if u["username"] == "someone")
    resp = client.post(f"/api/users/{row['id']}/reset-password", json={"password": "newpass1"}, headers=_auth_header(token))
    assert resp.status_code == 200


def test_change_own_password_wrong_current_is_401(client):
    token = _admin_token(client)
    resp = client.post("/api/account/password", json={"current_password": "wrong", "password": "newpass1"}, headers=_auth_header(token))
    assert resp.status_code == 401


def test_change_own_password_success(client):
    token = _admin_token(client)
    resp = client.post(
        "/api/account/password",
        json={"current_password": TEST_PASSWORD, "password": "newpass1"},
        headers=_auth_header(token),
    )
    assert resp.status_code == 200
    from app.auth import verify_credentials
    assert verify_credentials("admin", "newpass1") is not None


# --- single-active-session: a fresh login (browser or API) invalidates
# every other token/cookie this account already has out there.

def test_second_api_login_invalidates_the_first_api_token(client):
    # /api/users (a plain DB read) rather than /api/clients here — this
    # is testing auth, not client-listing, and needs no pivpn_ctl mock.
    token_a = _admin_token(client)
    assert client.get("/api/users", headers=_auth_header(token_a)).status_code == 200

    token_b = _admin_token(client)
    assert client.get("/api/users", headers=_auth_header(token_b)).status_code == 200

    resp = client.get("/api/users", headers=_auth_header(token_a))
    assert resp.status_code == 401


def test_browser_login_invalidates_an_existing_api_token(client):
    api_token = _admin_token(client)
    assert client.get("/api/users", headers=_auth_header(api_token)).status_code == 200

    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})

    resp = client.get("/api/users", headers=_auth_header(api_token))
    assert resp.status_code == 401


def test_api_login_invalidates_an_existing_browser_session(client):
    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    assert client.get("/clients").status_code == 200

    _admin_token(client)  # a fresh API login for the same account

    resp = client.get("/clients")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


# Complete Firewall-page migration: every mutation remains admin-only,
# uses the existing safety checks, and reports partial failures as JSON.
def test_firewall_management_rejects_moderators_before_side_effects(client, monkeypatch):
    token = _moderator_token(client)
    def forbidden(*args, **kwargs):
        raise AssertionError('unauthorized firewall mutation')
    for name in ('sync_all', 'save_persistent', 'import_rules', 'reorder_rule', 'delete_rule', 'disable_rule'):
        monkeypatch.setattr(firewall, name, forbidden)
    for path in ('import', 'resync', 'persist', 'bulk-delete', 'bulk-disable', 'rules/1/reorder'):
        resp = client.post('/api/firewall/' + path, json={'rule_ids': [1]}, headers=_auth_header(token))
        assert resp.status_code == 403


def test_firewall_bulk_reuses_lockout_guard_and_reports_partial_failure(client, monkeypatch):
    token = _admin_token(client)
    monkeypatch.setattr(pivpn_ctl, 'list_client_ips', lambda: {})
    monkeypatch.setattr(db, 'get_rule', lambda rule_id: {'id': rule_id, 'kind': 'input', 'enabled': True})
    calls = []
    def disable(rule_id, client_ip):
        calls.append((rule_id, client_ip))
        if rule_id == 1:
            raise firewall.FirewallError('Would block your access')
    monkeypatch.setattr(firewall, 'disable_rule', disable)
    resp = client.post('/api/firewall/bulk-disable', json={'rule_ids': [1, 2]}, headers=_auth_header(token))
    assert resp.status_code == 200
    assert resp.json == {'changed': 1, 'skipped': ['rule#1: Would block your access']}
    assert calls == [(1, '127.0.0.1'), (2, '127.0.0.1')]


def test_firewall_bulk_rejects_bad_payload(client):
    token = _admin_token(client)
    for body in ([], {'rule_ids': '1'}, {'rule_ids': None}):
        resp = client.post('/api/firewall/bulk-delete', json=body, headers=_auth_header(token))
        assert resp.status_code == 400


def test_firewall_import_reports_partial_results_and_regenerates_scripts(client, monkeypatch):
    from io import BytesIO
    token = _admin_token(client)
    monkeypatch.setattr(pivpn_ctl, 'list_client_ips', lambda: {'laptop': '10.8.0.2'})
    def import_rules(text, client_ips, client_ip):
        assert text == 'test rules'
        assert client_ips == {'laptop': '10.8.0.2'}
        assert client_ip == '127.0.0.1'
        return 1, ['line 2: refused unrestricted DROP']
    monkeypatch.setattr(firewall, 'import_rules', import_rules)
    regenerated = []
    monkeypatch.setattr(firewall, 'regenerate_client_script', lambda *args: regenerated.append(args))
    resp = client.post('/api/firewall/import', data={'rules_file': (BytesIO(b'test rules'), 'rules.txt')}, headers=_auth_header(token))
    assert resp.status_code == 200
    assert resp.json == {'added': 1, 'errors': ['line 2: refused unrestricted DROP']}
    assert regenerated == [('laptop', '10.8.0.2')]


def test_firewall_import_rejects_missing_or_non_utf8_file(client):
    from io import BytesIO
    token = _admin_token(client)
    for data in ({}, {'rules_file': (BytesIO(b'\xff'), 'rules.txt')}):
        resp = client.post('/api/firewall/import', data=data, headers=_auth_header(token))
        assert resp.status_code == 400


def test_firewall_apply_and_save_report_backend_errors(client, monkeypatch):
    token = _admin_token(client)
    calls = []
    monkeypatch.setattr(firewall, 'sync_all', lambda: calls.append('sync'))
    resp = client.post('/api/firewall/resync', headers=_auth_header(token))
    assert resp.json == {'resynced': True}
    assert calls == ['sync']
    def fail():
        raise firewall.FirewallError('save unavailable')
    monkeypatch.setattr(firewall, 'save_persistent', fail)
    resp = client.post('/api/firewall/persist', headers=_auth_header(token))
    assert resp.status_code == 400
    assert resp.json == {'error': 'save unavailable'}


def test_firewall_reorder_preserves_self_lockout_guard(client, monkeypatch):
    token = _admin_token(client)
    calls = []
    def reorder(rule_id, target_id, place, client_ip):
        calls.append((rule_id, target_id, place, client_ip))
        raise firewall.FirewallError('Would block your access')
    monkeypatch.setattr(firewall, 'reorder_rule', reorder)
    resp = client.post('/api/firewall/rules/1/reorder', json={'target_id': 2, 'place': 'before'}, headers=_auth_header(token))
    assert resp.status_code == 400
    assert resp.json == {'ok': False, 'error': 'Would block your access'}
    assert calls == [(1, 2, 'before', '127.0.0.1')]
