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
    monkeypatch.setattr("app.vpnlog.list_client_sessions", lambda **kwargs: ([{"client": "laptop-anna"}], 1))
    resp = client.get("/api/logs?tab=client_sessions", headers=_auth_header(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["entries"] == [{"client": "laptop-anna"}]
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


# --- Users

def test_list_users_excludes_password_hash(client):
    token = _admin_token(client)
    resp = client.get("/api/users", headers=_auth_header(token))
    assert resp.status_code == 200
    for u in resp.get_json()["users"]:
        assert "password_hash" not in u


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
