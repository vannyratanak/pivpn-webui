"""Token-authenticated JSON API — a second, separate door into this app
for scripts/other systems, alongside the browser UI in routes.py.

Not the same routes as the browser: those render Jinja templates and
assume a human in a browser (CSRF token in a hidden form field, flash
messages, redirects). A script wants JSON in, JSON out, every time, with
a machine-readable error instead of an HTML page. Auth is a JWT bearer
token (see config.JWT_SECRET_KEY) instead of the session cookie
Flask-Login issues — see app/__init__.py's csrf.exempt(api_bp) comment
for why CSRF protection doesn't apply to this blueprint.
"""
from flask import Blueprint, Response, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt, get_jwt_identity, jwt_required

import config
from app import db, firewall, pivpn_ctl
from app.auth import verify_credentials

bp = Blueprint("api", __name__, url_prefix="/api")


def _audit(action, target="", result="ok", detail=""):
    """Same shape as routes.py's own _audit, but keyed off the JWT's
    identity instead of flask_login's current_user — a token-authenticated
    request never populates current_user, so reusing that helper directly
    would log every API action as 'anonymous'."""
    db.add_audit(get_jwt_identity(), action, target, result, detail)


def _client_ip():
    """Same reasoning as routes.py's own _client_ip — see that function's
    docstring for the full explanation of why the trust boundary differs
    by BIND_HOST."""
    if config.BIND_HOST == "127.0.0.1":
        return request.headers.get("X-Real-IP", request.remote_addr)
    return request.remote_addr


@bp.route("/login", methods=["POST"])
def login():
    """POST {"username": ..., "password": ...} -> {"access_token": "..."}.

    Same credential check the browser login form uses (auth.verify_credentials)
    — this is a second way to present the same username/password, not a
    separate account system."""
    data = request.get_json(silent=True) or {}
    user = verify_credentials(data.get("username", ""), data.get("password", ""))
    if not user:
        return jsonify({"error": "invalid username or password"}), 401
    # role baked into the token itself, not looked up per-request from the
    # DB — same tradeoff the session cookie's own identity already makes.
    token = create_access_token(identity=user.username, additional_claims={"role": user.role})
    return jsonify({
        "access_token": token,
        "role": user.role,
        "expires_in_minutes": config.JWT_ACCESS_TOKEN_MINUTES,
    })


def _require_admin():
    """Returns a (response, status) pair if the caller's token isn't
    admin-role, else None. A plain function rather than a decorator: some
    future endpoints may need to restrict only part of their response
    rather than the whole route, same as admin_required's routes.py
    counterpart is applied selectively there."""
    if get_jwt().get("role") != "admin":
        return jsonify({"error": "admin role required"}), 403
    return None


@bp.route("/clients", methods=["GET"])
@jwt_required()
def list_clients():
    """Mirrors routes.py's clients() view (same status filter, same IP/
    connection/block enrichment), as JSON instead of an HTML table. Any
    authenticated caller may read this — the Clients page itself is
    login_required only, not admin-only, so the API matches."""
    try:
        client_list = [c for c in pivpn_ctl.list_clients() if c["status"].lower() == "valid"]
    except pivpn_ctl.PivpnError as exc:
        return jsonify({"error": str(exc)}), 502
    connected = pivpn_ctl.list_connected_clients()
    client_ips = pivpn_ctl.list_client_ips()
    for c in client_list:
        c["ip"] = client_ips.get(c["name"])
        c["blocked"] = db.get_client_block(c["name"]) is not None
        c["session"] = connected.get(c["name"])
    return jsonify({"clients": client_list, "connected_count": sum(1 for c in client_list if c["session"])})


@bp.route("/clients/<name>", methods=["GET"])
@jwt_required()
def client_status(name):
    """Single-client view of /api/clients, for a caller polling just one
    name instead of fetching the whole list every time."""
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        match = next((c for c in pivpn_ctl.list_clients() if c["name"] == name), None)
    except pivpn_ctl.PivpnError as exc:
        return jsonify({"error": str(exc)}), 502
    if not match or match["status"].lower() != "valid":
        return jsonify({"error": f"no valid client named '{name}'"}), 404
    match["ip"] = pivpn_ctl.list_client_ips().get(name)
    match["blocked"] = db.get_client_block(name) is not None
    match["session"] = pivpn_ctl.list_connected_clients().get(name)
    return jsonify(match)


@bp.route("/firewall/rules", methods=["GET"])
@jwt_required()
def firewall_rules():
    """Mirrors routes.py's firewall_rules() view's rule enrichment, as
    JSON. Admin-only, matching that route's own @admin_required.

    Deliberately does NOT call firewall.discover_cli_rules() first the
    way the browser page does — that call can write new rows to the DB
    as a side effect of reconciling with live iptables state, which is
    surprising behavior for a plain GET. A caller that wants that
    reconciliation can still trigger it by loading the Firewall page
    itself; this endpoint just reads what's already tracked."""
    err = _require_admin()
    if err:
        return err
    client_ips = pivpn_ctl.list_client_ips()
    ip_to_name = {ip: name for name, ip in client_ips.items()}
    rules = db.list_rules()
    persisted_ids = firewall.persisted_rule_ids()
    for r in rules:
        r["persisted"] = str(r["id"]) in persisted_ids
        r["detail"] = firewall.describe_rule(r)
        r["client_name"] = firewall.rule_client_name(r, ip_to_name)
    rules.sort(key=lambda r: firewall.KIND_DISPLAY_ORDER.get(r["kind"], 99))
    return jsonify({"rules": rules})


@bp.route("/clients", methods=["POST"])
@jwt_required()
def add_client():
    """Mirrors routes.py's add_client() view. POST {"name": ..., "passphrase": optional}."""
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    passphrase = (data.get("passphrase") or "").strip() or None
    try:
        pivpn_ctl.add_client(name, passphrase=passphrase)
    except pivpn_ctl.PivpnError as exc:
        _audit("client_add", name, "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("client_add", name)
    return jsonify({"created": name}), 201


@bp.route("/clients/<name>/renew", methods=["POST"])
@jwt_required()
def renew_client(name):
    """Mirrors routes.py's renew_client() view."""
    try:
        pivpn_ctl.renew_client(name)
    except pivpn_ctl.PivpnRenewPartialFailure as exc:
        # Distinct from a generic renew failure: the old cert is already
        # revoked (irreversible), not just still in place — see
        # routes.py's own renew_client() for the full reasoning. Flagged
        # with its own audit action so it's easy to spot in Logs later.
        _audit("client_renew_partial", name, "error", str(exc))
        return jsonify({"error": str(exc), "partial_failure": True}), 502
    except pivpn_ctl.PivpnError as exc:
        _audit("client_renew", name, "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("client_renew", name)
    return jsonify({"renewed": name})


@bp.route("/clients/<name>", methods=["DELETE"])
@jwt_required()
def remove_client(name):
    """Mirrors routes.py's remove_client() view."""
    try:
        pivpn_ctl.remove_client(name)
    except pivpn_ctl.PivpnError as exc:
        _audit("client_remove", name, "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("client_remove", name)
    return jsonify({"removed": name})


@bp.route("/clients/<name>/download", methods=["GET"])
@jwt_required()
def download_client(name):
    """Mirrors routes.py's download_client() view — returns the raw
    .ovpn file bytes instead of a JSON envelope, since the whole point is
    a caller can save the response body directly as a usable profile."""
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        data = pivpn_ctl.read_client_ovpn(name)
    except FileNotFoundError:
        return jsonify({"error": f"no .ovpn file for '{name}'"}), 404
    _audit("client_download", name)
    return Response(
        data,
        mimetype="application/x-openvpn-profile",
        headers={"Content-Disposition": f'attachment; filename="{name}.ovpn"'},
    )


@bp.route("/clients/<name>/block", methods=["POST"])
@jwt_required()
def block_client(name):
    """Mirrors routes.py's block_client() view. POST {"blocked": true|false}."""
    data = request.get_json(silent=True) or {}
    blocked = bool(data.get("blocked"))
    action = "client_block" if blocked else "client_unblock"
    ip = pivpn_ctl.get_client_ip(name)
    if not ip:
        msg = f"No static IP assigned to '{name}' yet — cannot block/unblock. Try renewing the client."
        _audit(action, name, "error", "no static IP assigned")
        return jsonify({"error": msg}), 400
    try:
        firewall.set_client_block(name, ip, blocked, admin_ip=_client_ip())
    except firewall.FirewallError as exc:
        _audit(action, name, "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit(action, name)
    return jsonify({"name": name, "blocked": blocked})


# --- per-client firewall rules (mirrors routes.py's client_add_rule/
# client_toggle_rule/client_delete_rule) — any logged-in user, same as
# the browser's client detail page, not admin-only like the global
# firewall endpoints below.

@bp.route("/clients/<name>/rules", methods=["POST"])
@jwt_required()
def client_add_rule(name):
    """POST {"action": "DROP"|"ACCEPT", "protocol": ..., "dst": "", "dport": "", "comment": ""}.

    `src` is always the client's own VPN IP, looked up server-side —
    never trusted from the request, same as the browser route. Unlike
    that route's form (which can add one rule per non-blank destination
    field in a single submit), this only ever creates one rule per call —
    call it again for another destination."""
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError as exc:
        return jsonify({"error": str(exc)}), 400
    client_ip = pivpn_ctl.list_client_ips().get(name)
    if not client_ip:
        return jsonify({"error": f"{name} has no VPN IP yet — it needs to connect at least once first."}), 400
    data = request.get_json(silent=True) or {}
    try:
        rule_id = firewall.add_forward_rule(
            action=data.get("action"),
            protocol=data.get("protocol"),
            src=client_ip,
            dst=data.get("dst", ""),
            dport=data.get("dport"),
            comment=data.get("comment", ""),
        )
    except firewall.FirewallError as exc:
        _audit("firewall_forward_add", "", "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("firewall_forward_add", f"rule#{rule_id}")
    return jsonify({"rule_id": rule_id}), 201


@bp.route("/clients/<name>/rules/<int:rule_id>/toggle", methods=["POST"])
@jwt_required()
def client_toggle_rule(name, rule_id):
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        firewall.toggle_rule(rule_id, client_ip=_client_ip())
    except Exception as exc:
        _audit("firewall_rule_toggle", f"rule#{rule_id}", "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("firewall_rule_toggle", f"rule#{rule_id}")
    return jsonify({"rule_id": rule_id})


@bp.route("/clients/<name>/rules/<int:rule_id>", methods=["DELETE"])
@jwt_required()
def client_delete_rule(name, rule_id):
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        firewall.delete_rule(rule_id, client_ip=_client_ip())
    except firewall.FirewallError as exc:
        _audit("firewall_rule_delete", f"rule#{rule_id}", "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("firewall_rule_delete", f"rule#{rule_id}")
    return jsonify({"deleted": rule_id})


# --- global firewall rules (mirrors routes.py's add_forward/add_input/
# add_snat/add_portforward/toggle_rule/delete_rule) — admin-only, same
# gating as the browser's Firewall page and GET /api/firewall/rules above.

@bp.route("/firewall/forward", methods=["POST"])
@jwt_required()
def add_forward():
    err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    try:
        rule_id = firewall.add_forward_rule(
            action=data.get("action"), protocol=data.get("protocol"),
            src=data.get("src"), dst=data.get("dst"), dport=data.get("dport"),
            comment=data.get("comment", ""),
        )
    except firewall.FirewallError as exc:
        _audit("firewall_forward_add", "", "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("firewall_forward_add", f"rule#{rule_id}")
    return jsonify({"rule_id": rule_id}), 201


@bp.route("/firewall/input", methods=["POST"])
@jwt_required()
def add_input():
    err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    try:
        rule_id = firewall.add_input_rule(
            action=data.get("action"), protocol=data.get("protocol"),
            src=data.get("src"), dport=data.get("dport"),
            comment=data.get("comment", ""), client_ip=_client_ip(),
        )
    except firewall.FirewallError as exc:
        _audit("firewall_input_add", "", "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("firewall_input_add", f"rule#{rule_id}")
    return jsonify({"rule_id": rule_id}), 201


@bp.route("/firewall/snat", methods=["POST"])
@jwt_required()
def add_snat():
    err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    try:
        rule_id = firewall.add_snat_rule(
            src=data.get("src"), snat_ip=data.get("snat_ip"),
            out_iface=data.get("out_iface"), comment=data.get("comment", ""),
        )
    except firewall.FirewallError as exc:
        _audit("firewall_snat_add", "", "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("firewall_snat_add", f"rule#{rule_id}")
    return jsonify({"rule_id": rule_id}), 201


@bp.route("/firewall/portforward", methods=["POST"])
@jwt_required()
def add_portforward():
    err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    try:
        rule_id = firewall.add_portforward_rule(
            ext_port=data.get("ext_port"), target_ip=data.get("target_ip"),
            target_port=data.get("target_port"), protocol=data.get("protocol", "tcp"),
            ext_iface=data.get("ext_iface"), comment=data.get("comment", ""),
        )
    except firewall.FirewallError as exc:
        _audit("firewall_portforward_add", "", "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("firewall_portforward_add", f"rule#{rule_id}")
    return jsonify({"rule_id": rule_id}), 201


@bp.route("/firewall/rules/<int:rule_id>/toggle", methods=["POST"])
@jwt_required()
def toggle_rule(rule_id):
    err = _require_admin()
    if err:
        return err
    try:
        firewall.toggle_rule(rule_id, client_ip=_client_ip())
    except Exception as exc:
        _audit("firewall_rule_toggle", f"rule#{rule_id}", "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("firewall_rule_toggle", f"rule#{rule_id}")
    return jsonify({"rule_id": rule_id})


@bp.route("/firewall/rules/<int:rule_id>", methods=["DELETE"])
@jwt_required()
def delete_rule(rule_id):
    err = _require_admin()
    if err:
        return err
    try:
        firewall.delete_rule(rule_id, client_ip=_client_ip())
    except firewall.FirewallError as exc:
        _audit("firewall_rule_delete", f"rule#{rule_id}", "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("firewall_rule_delete", f"rule#{rule_id}")
    return jsonify({"deleted": rule_id})


# --- VPN routes (mirrors routes.py's vpn_routes_page/add_vpn_route/
# remove_vpn_route) — admin-only, same gating as the browser tab.

@bp.route("/vpn-routes", methods=["GET"])
@jwt_required()
def list_vpn_routes():
    err = _require_admin()
    if err:
        return err
    from app import vpn_routes
    try:
        routes_ = vpn_routes.list_routes()
    except vpn_routes.VpnRouteError as exc:
        return jsonify({"error": str(exc)}), 502
    return jsonify({"routes": routes_})


@bp.route("/vpn-routes", methods=["POST"])
@jwt_required()
def add_vpn_route():
    err = _require_admin()
    if err:
        return err
    from app import vpn_routes
    data = request.get_json(silent=True) or {}
    network, netmask = data.get("network", ""), data.get("netmask", "")
    try:
        vpn_routes.add_route(network, netmask)
    except vpn_routes.VpnRouteError as exc:
        _audit("vpn_route_add", f"{network}/{netmask}", "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("vpn_route_add", f"{network}/{netmask}")
    return jsonify({"network": network, "netmask": netmask}), 201


@bp.route("/vpn-routes", methods=["DELETE"])
@jwt_required()
def remove_vpn_route():
    err = _require_admin()
    if err:
        return err
    from app import vpn_routes
    data = request.get_json(silent=True) or {}
    network, netmask = data.get("network", ""), data.get("netmask", "")
    try:
        vpn_routes.remove_route(network, netmask)
    except vpn_routes.VpnRouteError as exc:
        _audit("vpn_route_remove", f"{network}/{netmask}", "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("vpn_route_remove", f"{network}/{netmask}")
    return jsonify({"removed": f"{network}/{netmask}"})


# --- Logs (mirrors routes.py's logs()/logs_refresh()) — any logged-in
# user, but which tabs are readable still splits by role exactly like the
# browser page: ALL_LOG_TABS for admin, MODERATOR_LOG_TABS otherwise.

_ALL_LOG_TABS = ("sessions", "client_sessions", "traffic", "system", "activity", "auth")
_MODERATOR_LOG_TABS = ("client_sessions", "traffic", "auth")
_AUTH_ACTIONS = ("login", "logout")
_LOG_RANGE_HOURS = {"1h": 1, "6h": 6, "12h": 12, "1d": 24, "7d": 24 * 7}


@bp.route("/logs", methods=["GET"])
@jwt_required()
def logs():
    from datetime import datetime, timedelta

    from app import vpnlog
    from app.privileged import PrivilegedCommandError

    is_admin = get_jwt().get("role") == "admin"
    allowed_tabs = _ALL_LOG_TABS if is_admin else _MODERATOR_LOG_TABS
    default_tab = "client_sessions"
    tab = request.args.get("tab", default_tab)
    if tab not in allowed_tabs:
        return jsonify({"error": f"tab must be one of: {', '.join(allowed_tabs)}"}), 403

    q = (request.args.get("q") or "").strip() or None
    log_range = request.args.get("range") or "1h"
    if log_range not in _LOG_RANGE_HOURS:
        log_range = "1h"
    since = (datetime.now() - timedelta(hours=_LOG_RANGE_HOURS[log_range])).strftime("%Y-%m-%d %H:%M:%S")
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    page_size = request.args.get("page_size", 50, type=int)
    if page_size not in (10, 25, 50, 100):
        page_size = 50

    entries, total = [], 0
    try:
        if tab == "sessions":
            entries, total = vpnlog.list_sessions(q=q, page=page, page_size=page_size, since=since)
        elif tab == "client_sessions":
            entries, total = vpnlog.list_client_sessions(q=q, page=page, page_size=page_size, since=since)
        elif tab == "traffic":
            entries, total = vpnlog.list_traffic_flows(q=q, page=page, page_size=page_size, since=since)
        elif tab == "system":
            entries, total = vpnlog.list_system_log(q=q, page=page, page_size=page_size, since=since)
        elif tab == "activity":
            entries, total = db.list_audit_page(q=q, page=page, page_size=page_size, since=since)
        else:  # auth
            entries, total = db.list_audit_page(q=q, page=page, page_size=page_size, since=since, actions=_AUTH_ACTIONS)
    except PrivilegedCommandError as exc:
        return jsonify({"error": str(exc)}), 502

    return jsonify({"tab": tab, "entries": entries, "page": page, "page_size": page_size, "total": total})


@bp.route("/logs/refresh", methods=["POST"])
@jwt_required()
def logs_refresh():
    """Same as routes.py's logs_refresh() — safe to call any time, from
    anywhere; each ingestion function is already a no-op wherever there's
    nothing new (see that view's own docstring for the full reasoning)."""
    from deploy import ingest_logs
    from app.privileged import PrivilegedCommandError
    try:
        ingest_logs.ingest_vpn_events()
        ingest_logs.ingest_traffic_flows()
        ingest_logs.ingest_system_log()
        db.prune_old_logs(ingest_logs.RETENTION_DAYS)
    except PrivilegedCommandError as exc:
        return jsonify({"error": str(exc)}), 502
    return jsonify({"refreshed": True})


# --- Users (mirrors routes.py's users()/add_user()/delete_user()/
# reset_user_password()/change_own_password()). List is any logged-in
# user (a moderator can see who else has access, same as the browser);
# every write is admin-only except changing your own password.

def _sanitized_user(row):
    return {k: v for k, v in row.items() if k != "password_hash"}


@bp.route("/users", methods=["GET"])
@jwt_required()
def list_users():
    return jsonify({"users": [_sanitized_user(u) for u in db.list_users()]})


@bp.route("/users", methods=["POST"])
@jwt_required()
def add_user():
    err = _require_admin()
    if err:
        return err
    from app.auth import hash_password
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or ""
    if role not in ("admin", "moderator"):
        return jsonify({"error": "role must be 'admin' or 'moderator'"}), 400
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    try:
        db.insert_user(username, hash_password(password), role)
    except ValueError as exc:
        _audit("user_add", username, "error", str(exc))
        return jsonify({"error": str(exc)}), 400
    _audit("user_add", username, detail=f"role={role}")
    return jsonify({"created": username, "role": role}), 201


@bp.route("/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    err = _require_admin()
    if err:
        return err
    import psycopg2.errors

    # Self-delete-by-id is still possible via the API (there's no
    # session identity to compare against like current_user.id — the
    # caller would have to already know their own numeric id) — the real
    # backstop against locking everyone out is delete_user_guarded's own
    # "at least one admin must remain" check below, same as the browser.
    try:
        target, error = db.delete_user_guarded(user_id)
    except psycopg2.errors.LockNotAvailable:
        return jsonify({"error": "database was busy, try again"}), 503
    if error == "not_found":
        return jsonify({"error": "user not found"}), 404
    if error == "last_admin":
        _audit("user_delete", target["username"], "error", "last remaining admin")
        return jsonify({"error": "cannot delete the last remaining admin account"}), 400
    _audit("user_delete", target["username"])
    return jsonify({"deleted": target["username"]})


@bp.route("/users/<int:user_id>/reset-password", methods=["POST"])
@jwt_required()
def reset_user_password(user_id):
    err = _require_admin()
    if err:
        return err
    from app.auth import hash_password
    target = db.get_user(user_id)
    if not target:
        return jsonify({"error": "user not found"}), 404
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    if not password:
        return jsonify({"error": "password is required"}), 400
    db.set_user_password(user_id, hash_password(password))
    _audit("user_password_reset", target["username"])
    return jsonify({"reset": target["username"]})


@bp.route("/account/password", methods=["POST"])
@jwt_required()
def change_own_password():
    """Unlike reset_user_password above (an admin acting on someone
    else's account), this changes the caller's own — requiring the
    current password guards against a leaked-but-not-yet-expired token
    silently taking over the account via a password change, same
    reasoning as the browser route's own current-password check."""
    data = request.get_json(silent=True) or {}
    current = data.get("current_password") or ""
    password = data.get("password") or ""
    username = get_jwt_identity()
    if not verify_credentials(username, current):
        _audit("account_password_change", username, "error", "wrong current password")
        return jsonify({"error": "current password is incorrect"}), 401
    if not password:
        return jsonify({"error": "new password is required"}), 400
    from app.auth import hash_password
    user_row = db.get_user_by_username(username)
    db.set_user_password(user_row["id"], hash_password(password))
    _audit("account_password_change", username)
    return jsonify({"changed": True})
