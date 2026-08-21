from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app import db, firewall, pivpn_ctl, vpn_routes, vpnlog
from app.auth import AdminUser, verify_credentials
from app.privileged import PrivilegedCommandError

bp = Blueprint("main", __name__)


def _audit(action, target="", result="ok", detail=""):
    actor = current_user.get_id() if current_user.is_authenticated else "anonymous"
    db.add_audit(actor, action, target, result, detail)


def _client_ip():
    """The real caller's address, not gunicorn's view of it — gunicorn
    only ever sees nginx's own loopback connection (no ProxyFix is
    configured), so request.remote_addr alone would always read
    127.0.0.1. nginx's vhost already sets X-Real-IP to the actual source;
    this is what the firewall module's self-lockout check needs, since
    that's the address iptables itself will actually match against."""
    return request.headers.get("X-Real-IP", request.remote_addr)


def _regenerate_script_for_ip(ip, client_ips=None):
    """Best-effort: refresh the CLI-visible reference script for whichever
    client owns `ip`, if any. Never lets a helper/permission problem here
    block the rule change that triggered it."""
    if not ip:
        return
    client_ips = client_ips if client_ips is not None else pivpn_ctl.list_client_ips()
    for name, client_ip in client_ips.items():
        if client_ip == ip:
            try:
                firewall.regenerate_client_script(name, ip)
            except PrivilegedCommandError:
                pass
            break


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.clients"))
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if verify_credentials(username, password):
            login_user(AdminUser())
            db.add_audit(username, "login", detail=f"from {request.remote_addr}")
            return redirect(url_for("main.clients"))
        db.add_audit(username or "(blank)", "login", result="error", detail=f"bad credentials from {request.remote_addr}")
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@bp.route("/logout")
@login_required
def logout():
    _audit("logout")
    logout_user()
    return redirect(url_for("main.login"))


@bp.route("/")
@login_required
def index():
    return redirect(url_for("main.clients"))


@bp.route("/clients")
@login_required
def clients():
    try:
        # Revoked certs stay in `pivpn list` forever (PKI audit trail) with
        # status "Revoked" — they're not actionable clients (no .ovpn file,
        # no ccd IP), so they don't belong on this page.
        client_list = [c for c in pivpn_ctl.list_clients() if c["status"].lower() == "valid"]
    except pivpn_ctl.PivpnError as exc:
        client_list = []
        flash(str(exc), "error")
    connected = pivpn_ctl.list_connected_clients()
    client_ips = pivpn_ctl.list_client_ips()
    for c in client_list:
        c["ip"] = client_ips.get(c["name"])
        c["blocked"] = db.get_client_block(c["name"]) is not None
        c["session"] = connected.get(c["name"])
    connected_count = sum(1 for c in client_list if c["session"])
    return render_template(
        "clients.html", clients=client_list,
        connected_count=connected_count, total_count=len(client_list),
    )


@bp.route("/clients/add", methods=["POST"])
@login_required
def add_client():
    name = request.form.get("name", "").strip()
    passphrase = request.form.get("passphrase", "").strip() or None
    try:
        pivpn_ctl.add_client(name, passphrase=passphrase)
        flash(f"Client '{name}' created.", "success")
        _audit("client_add", name)
    except pivpn_ctl.PivpnError as exc:
        flash(str(exc), "error")
        _audit("client_add", name, "error", str(exc))
    return redirect(url_for("main.clients"))


@bp.route("/clients/import", methods=["POST"])
@login_required
def import_clients():
    upload = request.files.get("clients_file")
    if not upload or not upload.filename:
        flash("Choose a file to import.", "error")
        return redirect(url_for("main.clients"))
    try:
        text = upload.read().decode("utf-8")
    except UnicodeDecodeError:
        flash("Could not read that file as text (expected UTF-8).", "error")
        return redirect(url_for("main.clients"))
    added, errors = pivpn_ctl.import_clients(text)
    if added:
        flash(f"Imported {added} client(s).", "success")
    if errors:
        flash(f"{len(errors)} line(s) failed: " + "; ".join(errors[:10]), "error")
    if not added and not errors:
        flash("Nothing to import (file was empty).", "error")
    _audit("client_import", upload.filename, "ok" if not errors else "error",
           f"{added} added, {len(errors)} failed")
    return redirect(url_for("main.clients"))


@bp.route("/clients/<name>/download")
@login_required
def download_client(name):
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError:
        abort(404)
    path = pivpn_ctl.client_ovpn_path(name)
    if not path.exists():
        abort(404)
    _audit("client_download", name)
    return send_file(path, as_attachment=True, download_name=f"{name}.ovpn")


@bp.route("/clients/<name>/renew", methods=["POST"])
@login_required
def renew_client(name):
    try:
        pivpn_ctl.renew_client(name)
        flash(f"'{name}' renewed: old cert revoked, new cert issued. The client must install the new .ovpn file.", "success")
        _audit("client_renew", name)
    except pivpn_ctl.PivpnError as exc:
        flash(str(exc), "error")
        _audit("client_renew", name, "error", str(exc))
    return redirect(url_for("main.clients"))


@bp.route("/clients/<name>/remove", methods=["POST"])
@login_required
def remove_client(name):
    try:
        pivpn_ctl.remove_client(name)
        flash(f"Client '{name}' removed.", "success")
        _audit("client_remove", name)
    except pivpn_ctl.PivpnError as exc:
        flash(str(exc), "error")
        _audit("client_remove", name, "error", str(exc))
    return redirect(url_for("main.clients"))


@bp.route("/clients/bulk-remove", methods=["POST"])
@login_required
def bulk_remove_clients():
    names = request.form.getlist("client_names")
    removed = 0
    errors = []
    for name in names:
        try:
            pivpn_ctl.remove_client(name)
            removed += 1
        except pivpn_ctl.PivpnError as exc:
            errors.append(f"{name}: {exc}")
    if removed:
        flash(f"Removed {removed} client(s).", "success")
    if errors:
        flash(f"{len(errors)} failed: " + "; ".join(errors[:10]), "error")
    if not removed and not errors:
        flash("Nothing selected to remove.", "error")
    _audit("client_bulk_remove", f"{removed} removed, {len(errors)} failed")
    return redirect(url_for("main.clients"))


@bp.route("/clients/<name>/block", methods=["POST"])
@login_required
def block_client(name):
    blocked = request.form.get("blocked") == "1"
    action = "client_block" if blocked else "client_unblock"
    ip = pivpn_ctl.get_client_ip(name)
    if not ip:
        flash(f"No static IP assigned to '{name}' yet — cannot block/unblock. Try renewing the client.", "error")
        _audit(action, name, "error", "no static IP assigned")
        return redirect(url_for("main.clients"))
    try:
        firewall.set_client_block(name, ip, blocked)
        flash(f"Client '{name}' {'blocked' if blocked else 'unblocked'}.", "success")
        _audit(action, name)
    except firewall.FirewallError as exc:
        flash(str(exc), "error")
        _audit(action, name, "error", str(exc))
    return redirect(url_for("main.clients"))


@bp.route("/firewall")
@login_required
def firewall_rules():
    try:
        imported = firewall.discover_cli_rules()
        if imported:
            _audit("firewall_discover", f"{imported} rule(s) imported from CLI")
    except PrivilegedCommandError as exc:
        _audit("firewall_discover", "", "error", str(exc))
    client_ips = pivpn_ctl.list_client_ips()
    ip_to_name = {ip: name for name, ip in client_ips.items()}
    rules = db.list_rules()
    persisted_ids = firewall.persisted_rule_ids()
    for r in rules:
        r["persisted"] = str(r["id"]) in persisted_ids
        r["detail"] = firewall.describe_rule(r, ip_to_name)
    has_unsaved = any(not r["persisted"] for r in rules)

    try:
        valid_clients = [c for c in pivpn_ctl.list_clients() if c["status"].lower() == "valid"]
    except pivpn_ctl.PivpnError:
        valid_clients = []
    vpn_clients = [
        {"name": c["name"], "ip": client_ips[c["name"]]}
        for c in valid_clients if client_ips.get(c["name"])
    ]

    return render_template(
        "firewall.html", rules=rules, has_unsaved=has_unsaved, vpn_clients=vpn_clients,
        interfaces=firewall.list_interfaces(),
    )


@bp.route("/firewall/import", methods=["POST"])
@login_required
def import_rules():
    upload = request.files.get("rules_file")
    if not upload or not upload.filename:
        flash("Choose a file to import.", "error")
        return redirect(url_for("main.firewall_rules"))
    try:
        text = upload.read().decode("utf-8")
    except UnicodeDecodeError:
        flash("Could not read that file as text (expected UTF-8).", "error")
        return redirect(url_for("main.firewall_rules"))
    client_ips = pivpn_ctl.list_client_ips()
    added, errors = firewall.import_rules(text, client_ips=client_ips)
    if added:
        flash(f"Imported {added} rule(s).", "success")
        for name, ip in client_ips.items():
            try:
                firewall.regenerate_client_script(name, ip)
            except PrivilegedCommandError:
                pass
    if errors:
        flash(f"{len(errors)} line(s) failed: " + "; ".join(errors[:10]), "error")
    if not added and not errors:
        flash("Nothing to import (file was empty).", "error")
    _audit("firewall_import", upload.filename, "ok" if not errors else "error",
           f"{added} added, {len(errors)} failed")
    return redirect(url_for("main.firewall_rules"))


@bp.route("/vpn-routes")
@login_required
def vpn_routes_page():
    try:
        routes_ = vpn_routes.list_routes()
    except vpn_routes.VpnRouteError as exc:
        flash(str(exc), "error")
        routes_ = []
    return render_template("vpn_routes.html", vpn_routes=routes_)


@bp.route("/vpn-routes/add", methods=["POST"])
@login_required
def add_vpn_route():
    network = request.form.get("network", "")
    netmask = request.form.get("netmask", "")
    try:
        vpn_routes.add_route(network, netmask)
        flash("Route pushed to VPN clients.", "success")
        _audit("vpn_route_add", f"{network}/{netmask}")
    except vpn_routes.VpnRouteError as exc:
        flash(str(exc), "error")
        _audit("vpn_route_add", f"{network}/{netmask}", "error", str(exc))
    return redirect(url_for("main.vpn_routes_page"))


@bp.route("/vpn-routes/remove", methods=["POST"])
@login_required
def remove_vpn_route():
    network = request.form.get("network", "")
    netmask = request.form.get("netmask", "")
    try:
        vpn_routes.remove_route(network, netmask)
        flash("Route removed.", "success")
        _audit("vpn_route_remove", f"{network}/{netmask}")
    except vpn_routes.VpnRouteError as exc:
        flash(str(exc), "error")
        _audit("vpn_route_remove", f"{network}/{netmask}", "error", str(exc))
    return redirect(url_for("main.vpn_routes_page"))


@bp.route("/firewall/forward", methods=["POST"])
@login_required
def add_forward():
    try:
        rule_id = firewall.add_forward_rule(
            action=request.form.get("action"),
            protocol=request.form.get("protocol"),
            src=request.form.get("src"),
            dst=request.form.get("dst"),
            dport=request.form.get("dport"),
            comment=request.form.get("comment", ""),
        )
        flash("Forward rule added.", "success")
        _audit("firewall_forward_add", f"rule#{rule_id}")
        _regenerate_script_for_ip(request.form.get("src"))
    except firewall.FirewallError as exc:
        flash(str(exc), "error")
        _audit("firewall_forward_add", "", "error", str(exc))
    return redirect(url_for("main.firewall_rules"))


@bp.route("/firewall/snat", methods=["POST"])
@login_required
def add_snat():
    try:
        rule_id = firewall.add_snat_rule(
            src=request.form.get("src"),
            snat_ip=request.form.get("snat_ip"),
            out_iface=request.form.get("out_iface"),
            comment=request.form.get("comment", ""),
        )
        flash("SNAT rule added.", "success")
        _audit("firewall_snat_add", f"rule#{rule_id}")
    except firewall.FirewallError as exc:
        flash(str(exc), "error")
        _audit("firewall_snat_add", "", "error", str(exc))
    return redirect(url_for("main.firewall_rules"))


@bp.route("/firewall/portforward", methods=["POST"])
@login_required
def add_portforward():
    try:
        rule_id = firewall.add_portforward_rule(
            ext_port=request.form.get("ext_port"),
            target_ip=request.form.get("target_ip"),
            target_port=request.form.get("target_port"),
            protocol=request.form.get("protocol", "tcp"),
            ext_iface=request.form.get("ext_iface"),
            comment=request.form.get("comment", ""),
        )
        flash("Port-forward rule added.", "success")
        _audit("firewall_portforward_add", f"rule#{rule_id}")
    except firewall.FirewallError as exc:
        flash(str(exc), "error")
        _audit("firewall_portforward_add", "", "error", str(exc))
    return redirect(url_for("main.firewall_rules"))


@bp.route("/firewall/<int:rule_id>/toggle", methods=["POST"])
@login_required
def toggle_rule(rule_id):
    try:
        rule = db.get_rule(rule_id)
        firewall.toggle_rule(rule_id, client_ip=_client_ip())
        _audit("firewall_rule_toggle", f"rule#{rule_id}")
        if rule and rule["kind"] == "forward":
            _regenerate_script_for_ip(rule["src"])
    except Exception as exc:
        flash(str(exc), "error")
        _audit("firewall_rule_toggle", f"rule#{rule_id}", "error", str(exc))
    return redirect(url_for("main.firewall_rules"))


@bp.route("/firewall/<int:rule_id>/reorder", methods=["POST"])
@login_required
def reorder_rule(rule_id):
    """JSON endpoint for the Firewall page's drag-and-drop reorder — unlike
    every other mutation in this app, this one doesn't redirect back to a
    freshly rendered page: the drop already moved the row in the DOM
    client-side, so a full reload here would just be visible flicker (and
    the classic "reload jumps back to the top" annoyance) for a change the
    page already shows correctly."""
    body = request.get_json(silent=True) or {}
    try:
        target_id = int(body.get("target_id"))
        place = body.get("place")
        firewall.reorder_rule(rule_id, target_id, place, client_ip=_client_ip())
        _audit("firewall_rule_reorder", f"rule#{rule_id} {place} rule#{target_id}")
        return jsonify(ok=True)
    except (TypeError, ValueError):
        return jsonify(ok=False, error="Invalid request."), 400
    except firewall.FirewallError as exc:
        _audit("firewall_rule_reorder", f"rule#{rule_id}", "error", str(exc))
        return jsonify(ok=False, error=str(exc)), 400


@bp.route("/firewall/<int:rule_id>/delete", methods=["POST"])
@login_required
def delete_rule(rule_id):
    rule = db.get_rule(rule_id)
    try:
        firewall.delete_rule(rule_id, client_ip=_client_ip())
        flash("Rule deleted.", "success")
        _audit("firewall_rule_delete", f"rule#{rule_id}")
        if rule and rule["kind"] == "forward":
            _regenerate_script_for_ip(rule["src"])
    except firewall.FirewallError as exc:
        flash(str(exc), "error")
        _audit("firewall_rule_delete", f"rule#{rule_id}", "error", str(exc))
    return redirect(url_for("main.firewall_rules"))


@bp.route("/firewall/bulk-delete", methods=["POST"])
@login_required
def bulk_delete_rules():
    ids = request.form.getlist("rule_ids")
    client_ip = _client_ip()
    client_ips = pivpn_ctl.list_client_ips()
    affected_ips = set()
    deleted = 0
    skipped = []
    for id_str in ids:
        try:
            rule_id = int(id_str)
        except ValueError:
            continue
        rule = db.get_rule(rule_id)
        if not rule:
            continue
        try:
            firewall.delete_rule(rule_id, client_ip=client_ip)
        except firewall.FirewallError as exc:
            skipped.append(f"rule#{rule_id}: {exc}")
            continue
        deleted += 1
        if rule["kind"] == "forward" and rule.get("src"):
            affected_ips.add(rule["src"])
    for ip in affected_ips:
        _regenerate_script_for_ip(ip, client_ips=client_ips)
    if deleted:
        flash(f"Deleted {deleted} rule(s).", "success")
    if skipped:
        flash("Skipped (would block your own access): " + "; ".join(skipped), "error")
    elif not deleted:
        flash("Nothing selected to delete.", "error")
    _audit("firewall_bulk_delete", f"{deleted} rule(s), {len(skipped)} skipped")
    return redirect(url_for("main.firewall_rules"))


@bp.route("/firewall/bulk-disable", methods=["POST"])
@login_required
def bulk_disable_rules():
    ids = request.form.getlist("rule_ids")
    client_ip = _client_ip()
    client_ips = pivpn_ctl.list_client_ips()
    affected_ips = set()
    disabled = 0
    skipped = []
    for id_str in ids:
        try:
            rule_id = int(id_str)
        except ValueError:
            continue
        rule = db.get_rule(rule_id)
        if not rule or not rule["enabled"]:
            continue
        try:
            firewall.disable_rule(rule_id, client_ip=client_ip)
        except firewall.FirewallError as exc:
            skipped.append(f"rule#{rule_id}: {exc}")
            continue
        disabled += 1
        if rule["kind"] == "forward" and rule.get("src"):
            affected_ips.add(rule["src"])
    for ip in affected_ips:
        _regenerate_script_for_ip(ip, client_ips=client_ips)
    if disabled:
        flash(f"Disabled {disabled} rule(s).", "success")
    if skipped:
        flash("Skipped (would block your own access): " + "; ".join(skipped), "error")
    elif not disabled:
        flash("Nothing selected to disable.", "error")
    _audit("firewall_bulk_disable", f"{disabled} rule(s), {len(skipped)} skipped")
    return redirect(url_for("main.firewall_rules"))


@bp.route("/firewall/persist", methods=["POST"])
@login_required
def persist_rules():
    try:
        firewall.save_persistent()
        flash("Firewall rules saved for reboot persistence.", "success")
        _audit("firewall_persist")
    except firewall.FirewallError as exc:
        flash(str(exc), "error")
        _audit("firewall_persist", "", "error", str(exc))
    return redirect(url_for("main.firewall_rules"))


@bp.route("/firewall/resync", methods=["POST"])
@login_required
def resync_rules():
    firewall.sync_all()
    flash("Firewall rules reapplied from the database.", "success")
    _audit("firewall_resync")
    return redirect(url_for("main.firewall_rules"))


AUTH_ACTIONS = ("login", "logout")


@bp.route("/logs")
@login_required
def logs():
    tab = request.args.get("tab", "sessions")
    if tab not in ("sessions", "client_sessions", "system", "auth"):
        tab = "sessions"

    sessions = client_sessions = webui_log = system_log = auth_entries = None
    if tab == "sessions":
        try:
            sessions = vpnlog.list_sessions()
        except PrivilegedCommandError as exc:
            sessions = []
            flash(str(exc), "error")
    elif tab == "client_sessions":
        try:
            client_sessions = vpnlog.list_client_sessions()
            # "ongoing" only means "no disconnect event matched our known log
            # patterns" (see DISCONNECT_RE's SIGTERM-only match in vpnlog.py)
            # — a session that ended via timeout/ping-restart/unclean drop
            # never logs that pattern and would otherwise show as ongoing
            # forever. Cross-check against the live status file (the same
            # source the Clients page uses) and relabel anything not
            # actually connected right now, rather than show stale data.
            connected_now = pivpn_ctl.list_connected_clients()
            for s in client_sessions:
                if s["ongoing"] and s["client"] not in connected_now:
                    s["ongoing"] = False
                    s["status_note"] = "Ended (exact time unknown)"
        except PrivilegedCommandError as exc:
            client_sessions = []
            flash(str(exc), "error")
    elif tab == "system":
        try:
            webui_log = vpnlog.list_webui_log()
        except PrivilegedCommandError as exc:
            webui_log = []
            flash(str(exc), "error")
        try:
            system_log = vpnlog.list_system_log()
        except PrivilegedCommandError as exc:
            system_log = []
            flash(str(exc), "error")
    else:
        auth_entries = db.list_audit_by_actions(AUTH_ACTIONS)

    return render_template(
        "logs.html", tab=tab, sessions=sessions, client_sessions=client_sessions,
        webui_log=webui_log, system_log=system_log, auth_entries=auth_entries,
    )
