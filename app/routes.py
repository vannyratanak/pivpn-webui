import psycopg2.errors

from flask import Blueprint, Response, abort, flash, g, jsonify, redirect, render_template, request, url_for
from flask_jwt_extended import create_access_token
from flask_login import current_user, login_required

import config
from app import db, firewall, pivpn_ctl, vpn_routes
from app.auth import admin_required, clear_html_jwt_cookie, clear_lock_cookie, hash_password, issue_html_jwt_cookie, issue_lock_cookie, peek_locked_username, verify_credentials
from app.privileged import PrivilegedCommandError

bp = Blueprint("main", __name__)


def _audit(action, target="", result="ok", detail=""):
    actor = current_user.username if current_user.is_authenticated else "anonymous"
    db.add_audit(actor, action, target, result, detail)


def _client_ip():
    """The real caller's address, not gunicorn's view of it.

    BIND_HOST=127.0.0.1 (the default — see setup-nginx.sh) means gunicorn
    is only ever reachable through nginx's own loopback connection, so
    request.remote_addr alone would always read 127.0.0.1; nginx's vhost
    sets X-Real-IP to the actual source on every request, unconditionally
    overwriting anything a client tried to send, which is what makes that
    header trustworthy here.

    But BIND_HOST=0.0.0.0 (the README's documented "LAN-only" mode) puts
    gunicorn directly on the network with nothing in front to sanitize
    that header — a client can set X-Real-IP to anything, which would
    trivially defeat both the login rate-limiter and the firewall
    self-lockout guard (both key off this value). request.remote_addr is
    the real TCP peer address in that mode and can't be spoofed via a
    header, so use that instead."""
    if config.BIND_HOST == "127.0.0.1":
        return request.headers.get("X-Real-IP", request.remote_addr)
    return request.remote_addr


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


# Failed attempts are tracked per source IP in sqlite (see db.py — a
# plain in-process counter wouldn't be seen by both gunicorn workers).
# 5 tries / 5 minutes: generous enough that a real admin mistyping their
# own password never gets meaningfully locked out, but enough to blunt
# an automated guesser now that the login page is reachable from the
# public internet via the relay.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_WINDOW_SECONDS = 300


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.clients"))

    # Idle-lock mode: the JS idle timer hit /account/lock, which cleared the
    # html_jwt but left an idle_lock cookie naming the locked user.  We show
    # a "resume session" screen with only a password field — the username is
    # already known — and on success we re-issue the html_jwt WITHOUT bumping
    # session_generation (it's a resume, not a new login; the existing API
    # bearer token and any other still-open tabs stay valid).
    locked_user = peek_locked_username(request)
    username = locked_user or request.form.get("username", "")

    if request.method == "POST":
        ip = _client_ip()
        if db.count_recent_login_failures(ip, LOGIN_LOCKOUT_WINDOW_SECONDS) >= LOGIN_MAX_ATTEMPTS:
            flash("Too many failed login attempts. Try again in a few minutes.", "error")
            return render_template("login.html", locked_user=locked_user, username=username)

        # In locked mode the username comes from the cookie, not the form,
        # so a tampered hidden field can't elevate access — verify_credentials
        # still checks the database, so only valid users pass.
        username = locked_user if locked_user else request.form.get("username", "")
        password = request.form.get("password", "")
        field_errors = {}
        if not username.strip():
            field_errors["username"] = "Enter your username."
        if not password:
            field_errors["password"] = "Enter your password."
        if field_errors:
            return render_template("login.html", locked_user=locked_user,
                                   username=username, field_errors=field_errors)
        user = verify_credentials(username, password)
        if user:
            db.clear_login_failures(ip)
            if locked_user:
                # Resume: keep the existing session generation so the bearer
                # token (API clients, open tabs) doesn't get invalidated.
                db.add_audit(user.username, "login", detail=f"resumed from idle lock from {ip}")
                resp = redirect(url_for("main.clients"))
                issue_html_jwt_cookie(resp, user)
                clear_lock_cookie(resp)
                return resp
            else:
                # Full new login: bump generation to invalidate any other
                # active sessions for this account (single-active-session).
                db.add_audit(user.username, "login", detail=f"from {ip}")
                # Single-active-session: bumping this immediately invalidates
                # every other browser cookie or API token this account still
                # has out there (see auth.py's token_superseded) — the next
                # request any of them makes just gets treated as logged out.
                user.session_generation = db.bump_session_generation(int(user.id))
                resp = redirect(url_for("main.clients"))
                # Identity now lives in a JWT cookie, not Flask's session —
                # see auth.py's issue_html_jwt_cookie for why, and
                # __init__.py's after_request hook for how the old "N hours
                # since your *last* request" idle-timeout behavior is
                # preserved despite a JWT's expiry normally being fixed at
                # issuance.
                issue_html_jwt_cookie(resp, user)
                return resp
        db.record_login_failure(ip)
        db.add_audit(username or "(blank)", "login", result="error", detail=f"bad credentials from {ip}")
        flash("Invalid username or password.", "error")
    return render_template("login.html", locked_user=locked_user, username=username)


@bp.route("/logout")
@login_required
def logout():
    _audit("logout")
    # Invalidate both the browser cookie and the bearer tokens it minted.
    db.bump_session_generation(int(current_user.id))
    resp = redirect(url_for("main.login"))
    clear_html_jwt_cookie(resp)
    # current_user is still resolved as authenticated for the rest of
    # *this* request (flask_login loads it once, at request start, from
    # the cookie that was still valid when the request came in) — without
    # this flag, __init__.py's after_request sliding-refresh hook would
    # see that and re-issue a fresh cookie right after the line above
    # just cleared it, silently undoing the logout. Caught live: curl
    # could still load /clients immediately after calling /logout.
    g.skip_jwt_cookie_refresh = True
    return resp


VALID_ROLES = ("admin", "moderator")


@bp.route("/users")
@login_required
def users():
    # Data (and its row actions — reset-password/delete) now comes from the
    # browser's own GET /api/users call, made by users-page.js after this
    # shell loads — see clients()'s own comment for the pattern this
    # follows. Both roles can still view the resulting page (a moderator
    # sees who else has access), but only admin_required routes below can
    # actually change anything — the template hides those controls for a
    # moderator to match.
    return render_template("users.html")


@bp.route("/users/add", methods=["POST"])
@login_required
@admin_required
def add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")
    role = request.form.get("role", "")
    if role not in VALID_ROLES:
        flash("Invalid role.", "error")
        return redirect(url_for("main.users"))
    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("main.users"))
    if password != confirm:
        flash("Passwords did not match.", "error")
        return redirect(url_for("main.users"))
    try:
        db.insert_user(username, hash_password(password), role)
        flash(f"User '{username}' created.", "success")
        _audit("user_add", username, detail=f"role={role}")
    except ValueError as exc:
        flash(str(exc), "error")
        _audit("user_add", username, "error", str(exc))
    return redirect(url_for("main.users"))


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    # Self-delete doesn't need the atomic guard below — it's based on the
    # requester's own identity, not global state another concurrent
    # request could also be changing, so there's no race to close here.
    if str(user_id) == current_user.id:
        target = db.get_user(user_id)
        flash("Cannot delete your own account while logged in as it.", "error")
        _audit("user_delete", target["username"] if target else "?", "error", "self-delete")
        return redirect(url_for("main.users"))
    # Both this and the self-delete check above protect against the same
    # failure mode the firewall self-lockout checks exist for: a state
    # nobody can recover from without direct DB surgery. Only admins can
    # manage Firewall/VPN Routes/Users at all, so the invariant that
    # actually matters is "at least one admin always exists" — not "at
    # least one user", which would wrongly block deleting the very last
    # moderator (no lockout risk there at all) while missing the real
    # gap: an admin plus any number of moderators, with that admin
    # deleted, leaves moderators who can't create a new admin to recover
    # from it. delete_user_guarded does the count check and the delete in
    # one locked transaction — a separate count-then-delete had a real
    # race between two concurrent requests (see its docstring).
    try:
        target, error = db.delete_user_guarded(user_id)
    except psycopg2.errors.LockNotAvailable:
        # locked_transaction() sets a 5s lock_timeout (matching SQLite's
        # old default busy_timeout) rather than waiting forever — this
        # app's own writes are all fast, short transactions, so
        # contention this long isn't expected, but a raw 500 for "try
        # that again" is a worse failure mode than a clean message when
        # it does happen.
        flash("Could not complete that right now — the database was busy. Try again.", "error")
        _audit("user_delete", str(user_id), "error", "database busy")
        return redirect(url_for("main.users"))
    if error == "not_found":
        flash("User not found.", "error")
    elif error == "last_admin":
        flash("Cannot delete the last remaining admin account.", "error")
        _audit("user_delete", target["username"], "error", "last remaining admin")
    else:
        flash(f"User '{target['username']}' removed.", "success")
        _audit("user_delete", target["username"])
    return redirect(url_for("main.users"))


@bp.route("/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
@admin_required
def reset_user_password(user_id):
    target = db.get_user(user_id)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("main.users"))
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")
    if not password:
        flash("Password is required.", "error")
        return redirect(url_for("main.users"))
    if password != confirm:
        flash("Passwords did not match.", "error")
        return redirect(url_for("main.users"))
    db.set_user_password(user_id, hash_password(password))
    flash(f"Password reset for '{target['username']}'.", "success")
    _audit("user_password_reset", target["username"])
    return redirect(url_for("main.users"))


@bp.route("/account/password", methods=["POST"])
@login_required
def change_own_password():
    # Unlike reset_user_password above (an already-authenticated different
    # admin acting on someone else's account), this changes the acting
    # session's own account — requiring the current password guards against
    # a stolen session cookie silently taking it over.
    current = request.form.get("current_password", "")
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")
    if not verify_credentials(current_user.username, current):
        flash("Current password is incorrect.", "error")
        _audit("account_password_change", current_user.username, "error", "wrong current password")
        return redirect(url_for("main.users"))
    if not password:
        flash("New password is required.", "error")
        return redirect(url_for("main.users"))
    if password != confirm:
        flash("Passwords did not match.", "error")
        return redirect(url_for("main.users"))
    db.set_user_password(int(current_user.id), hash_password(password))
    flash("Your password was changed.", "success")
    _audit("account_password_change", current_user.username)
    return redirect(url_for("main.users"))


@bp.route("/account/api-token", methods=["POST"])
@login_required
def account_api_token():
    """Mints a Bearer token for this already-logged-in browser's own
    JavaScript to use against /api/... (see clients.html's own fetch-based
    rendering) — not a new login: deliberately does NOT call
    db.bump_session_generation, so getting one of these never invalidates
    the cookie session (or any other tab/token) that asked for it.
    Cookie-authenticated like any other browser POST here; the token
    itself is then just an ordinary Authorization: Bearer credential from
    that point on, subject to the exact same expiry and single-active-
    session checks (see app/__init__.py's token_in_blocklist_loader) as
    one issued by /api/login."""
    token = create_access_token(
        identity=current_user.username,
        additional_claims={"role": current_user.role, "gen": current_user.session_generation},
    )
    return jsonify({"access_token": token, "expires_in_minutes": config.JWT_ACCESS_TOKEN_MINUTES})


@bp.route("/account/heartbeat", methods=["POST"])
@login_required
def account_heartbeat():
    """Called by static/js/idle-timeout.js while the user is genuinely
    doing something (click/keypress/scroll) on a fetch()-driven page —
    those pages talk to /api/... over a Bearer token and otherwise never
    touch this cookie-authenticated blueprint, so without this ping the
    "la" (last-active) claim on the browser's own html_jwt cookie would go
    stale from real use alone. The 204 body carries no data; reaching this
    view at all is what matters — __init__.py's after_request hook re-
    issues the cookie with a fresh "la" for any authenticated response,
    this route included."""
    return "", 204


@bp.route("/account/lock", methods=["POST"])
@login_required
def account_lock():
    """Idle-lock the session — Cisco/Huawei-style 'screen lock' rather than
    a full logout.  Called by idle-timeout.js when the idle timer fires.

    Unlike /logout, this does NOT bump session_generation, so the API bearer
    token (pivpn_webui_api_token in localStorage) and any other open tabs
    remain valid — the user just needs to re-enter their password on the
    /login page to lift the lock and get a fresh html_jwt cookie.  The
    idle_lock cookie (set here, cleared on successful resume) is what tells
    the login page to show the 'resume session' UI instead of a full form."""
    username = current_user.username
    _audit("idle_lock")
    resp = redirect(url_for("main.login"))
    clear_html_jwt_cookie(resp)
    issue_lock_cookie(resp, username)
    # Prevent __init__.py's after_request hook from re-issuing the html_jwt
    # right after we just cleared it (same trick as logout()).
    g.skip_jwt_cookie_refresh = True
    return resp


@bp.route("/account/clear-lock")
def account_clear_lock():
    """Clear the idle_lock cookie and go to the normal /login page.

    No authentication required — the html_jwt is already gone when this is
    reached (that's the point of the lock).  This is how the 'Not you?' link
    on the locked-session resume screen discards the locked username and
    offers a clean login form so a different user can sign in."""
    resp = redirect(url_for("main.login"))
    clear_lock_cookie(resp)
    return resp


@bp.route("/")
@login_required
def index():
    return redirect(url_for("main.clients"))


@bp.route("/clients")
@login_required
def clients():
    # Unlike every other page in this app, this one's own data (and its
    # row actions — renew/block/remove/download) comes from the browser's
    # own GET /api/clients call, made by clients-page.js after this shell
    # loads — see that file's top comment. Nothing to fetch or enrich
    # server-side here anymore.
    return render_template("clients.html")


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
    try:
        data = pivpn_ctl.read_client_ovpn(name)
    except FileNotFoundError:
        abort(404)
    _audit("client_download", name)
    return Response(
        data,
        mimetype="application/x-openvpn-profile",
        headers={"Content-Disposition": f'attachment; filename="{name}.ovpn"'},
    )


@bp.route("/clients/<name>")
@login_required
def client_detail(name):
    """One client's own page — status/session, its scoped firewall rules,
    and full rule management (add/toggle/delete/resync/persist/bulk),
    all fetched/mutated by client-detail-page.js via /api/clients/<name>
    and /api/clients/<name>/rules/... after this shell loads — see
    clients()'s own comment for the pattern this follows. Unlike the main
    Firewall page (still admin-only — system-wide rule management), a
    moderator gets full rule management here too, scoped to one client —
    same "client control" territory as the Clients list' own renew/
    block/remove actions, which are already login_required-only.

    Only a syntactic name check happens here (cheap, no CLI/hub round
    trip) — whether a client by this name actually exists is discovered
    by the browser's own first GET /api/clients/<name> call, same as any
    other fetch() error on this page."""
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError:
        abort(404)
    return render_template("client_detail.html", name=name, log_range_options=LOG_RANGE_OPTIONS)


@bp.route("/clients/<name>/rules/add", methods=["POST"])
@login_required
def client_add_rule(name):
    """The client detail page's own "add a rule for this client" form —
    a separate route from the Firewall page's /firewall/forward
    (deliberately not shared, even though both end up calling the same
    firewall.add_forward_rule) so nothing here ever changes that page's
    own behavior. Always redirects back to this same client's page.
    `src` is looked up server-side from the client's own VPN IP rather
    than trusted from the form, since this route's whole premise is
    "this client's rule", not whatever IP happened to be submitted.

    The form's "+" button can add more than one Destination field (all
    named "dst") — one rule gets created per non-blank destination
    entered, so e.g. two filled-in destinations plus one left blank
    creates two rules, not three, on the assumption an unused extra
    field was never meant to become an explicit "any" rule. Only when
    every destination field is blank (including the default single one)
    does that still mean one "any" rule, same as before this feature."""
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError:
        abort(404)
    client_ip = pivpn_ctl.list_client_ips().get(name)
    if not client_ip:
        flash(f"{name} has no VPN IP yet — it needs to connect at least once first.", "error")
        return redirect(url_for("main.client_detail", name=name))
    dsts = [d.strip() for d in request.form.getlist("dst")]
    dsts = [d for d in dsts if d] or [""]
    added = 0
    skipped = []
    for dst in dsts:
        try:
            rule_id = firewall.add_forward_rule(
                action=request.form.get("action"),
                protocol=request.form.get("protocol"),
                src=client_ip,
                dst=dst,
                dport=request.form.get("dport"),
                comment=request.form.get("comment", ""),
            )
            added += 1
            _audit("firewall_forward_add", f"rule#{rule_id}")
        except firewall.FirewallError as exc:
            skipped.append(f"{dst or 'any'}: {exc}")
            _audit("firewall_forward_add", "", "error", str(exc))
    if added:
        flash(f"Added {added} forward rule(s)." if added > 1 else "Forward rule added.", "success")
        _regenerate_script_for_ip(client_ip)
    if skipped:
        flash("Skipped: " + "; ".join(skipped), "error")
    return redirect(url_for("main.client_detail", name=name))


@bp.route("/clients/<name>/rules/<int:rule_id>/toggle", methods=["POST"])
@login_required
def client_toggle_rule(name, rule_id):
    """Same as /firewall/<id>/toggle, kept as its own route (see
    client_add_rule's docstring) purely so its redirect target can differ
    without touching the Firewall page's own route."""
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError:
        abort(404)
    rule = db.get_rule(rule_id)
    ip_to_name = db.list_client_ip_name_map()
    if not rule or firewall.rule_client_name(rule, ip_to_name) != name:
        abort(404)
    try:
        firewall.toggle_rule(rule_id, client_ip=_client_ip())
        _audit("firewall_rule_toggle", f"rule#{rule_id}")
        if rule and rule["kind"] == "forward":
            _regenerate_script_for_ip(rule["src"])
    except Exception as exc:
        flash(str(exc), "error")
        _audit("firewall_rule_toggle", f"rule#{rule_id}", "error", str(exc))
    return redirect(url_for("main.client_detail", name=name))


@bp.route("/clients/<name>/rules/<int:rule_id>/delete", methods=["POST"])
@login_required
def client_delete_rule(name, rule_id):
    """Same as /firewall/<id>/delete, kept as its own route (see
    client_add_rule's docstring) purely so its redirect target can differ
    without touching the Firewall page's own route."""
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError:
        abort(404)
    rule = db.get_rule(rule_id)
    ip_to_name = db.list_client_ip_name_map()
    if not rule or firewall.rule_client_name(rule, ip_to_name) != name:
        abort(404)
    try:
        firewall.delete_rule(rule_id, client_ip=_client_ip())
        flash("Rule deleted.", "success")
        _audit("firewall_rule_delete", f"rule#{rule_id}")
        if rule and rule["kind"] == "forward":
            _regenerate_script_for_ip(rule["src"])
    except firewall.FirewallError as exc:
        flash(str(exc), "error")
        _audit("firewall_rule_delete", f"rule#{rule_id}", "error", str(exc))
    return redirect(url_for("main.client_detail", name=name))


@bp.route("/clients/<name>/rules/resync", methods=["POST"])
@login_required
def client_resync_rules(name):
    """Same as /firewall/resync, kept as its own route (see
    client_add_rule's docstring) purely so its redirect target can differ
    without touching the Firewall page's own route. The reconcile itself
    is still system-wide (firewall.sync_all() doesn't take a client scope
    — there's no such thing as "reconcile just one client's rules" when
    the whole point is mirroring live iptables state 1:1), only where the
    admin lands afterward differs."""
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError:
        abort(404)
    firewall.sync_all()
    flash("Firewall rules reapplied from the database.", "success")
    _audit("firewall_resync")
    return redirect(url_for("main.client_detail", name=name))


@bp.route("/clients/<name>/rules/persist", methods=["POST"])
@login_required
def client_persist_rules(name):
    """Same as /firewall/persist, kept as its own route (see
    client_add_rule's docstring) purely so its redirect target can differ
    — save_persistent() is likewise system-wide, not client-scoped."""
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError:
        abort(404)
    try:
        firewall.save_persistent()
        flash("Firewall rules saved for reboot persistence.", "success")
        _audit("firewall_persist")
    except firewall.FirewallError as exc:
        flash(str(exc), "error")
        _audit("firewall_persist", "", "error", str(exc))
    return redirect(url_for("main.client_detail", name=name))


@bp.route("/clients/<name>/rules/bulk-disable", methods=["POST"])
@login_required
def client_bulk_disable_rules(name):
    """Same as /firewall/bulk-disable, kept as its own route (see
    client_add_rule's docstring) so the redirect target can differ — also
    passes restrict_to_client so a submitted rule_id belonging to a
    different client is silently dropped instead of acted on, same
    principle as client_add_rule looking src up server-side."""
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError:
        abort(404)
    _bulk_disable_or_delete("disable", request.form.getlist("rule_ids"), restrict_to_client=name)
    return redirect(url_for("main.client_detail", name=name))


@bp.route("/clients/<name>/rules/bulk-delete", methods=["POST"])
@login_required
def client_bulk_delete_rules(name):
    """Same as /firewall/bulk-delete, kept as its own route (see
    client_add_rule's docstring) so the redirect target can differ — also
    passes restrict_to_client, same reasoning as
    client_bulk_disable_rules above."""
    try:
        name = pivpn_ctl.validate_name(name)
    except pivpn_ctl.PivpnError:
        abort(404)
    _bulk_disable_or_delete("delete", request.form.getlist("rule_ids"), restrict_to_client=name)
    return redirect(url_for("main.client_detail", name=name))


@bp.route("/clients/<name>/renew", methods=["POST"])
@login_required
def renew_client(name):
    try:
        pivpn_ctl.renew_client(name)
        flash(f"'{name}' renewed: old cert revoked, new cert issued. The client must install the new .ovpn file.", "success")
        _audit("client_renew", name)
    except pivpn_ctl.PivpnRenewPartialFailure as exc:
        # Distinct from a generic renew failure: the old cert is already
        # gone (revoke is irreversible), not just still in place — flag it
        # separately in the audit log so it's easy to spot in Logs later.
        flash(str(exc), "error")
        _audit("client_renew_partial", name, "error", str(exc))
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
        firewall.set_client_block(name, ip, blocked, admin_ip=_client_ip())
        flash(f"Client '{name}' {'blocked' if blocked else 'unblocked'}.", "success")
        _audit(action, name)
    except firewall.FirewallError as exc:
        flash(str(exc), "error")
        _audit(action, name, "error", str(exc))
    return redirect(url_for("main.clients"))


@bp.route("/firewall")
@login_required
@admin_required
def firewall_rules():
    # Data and live reconciliation are loaded by firewall-page.js through
    # /api/firewall/rules and /api/firewall/options after this shell loads.
    return render_template("firewall.html")


@bp.route("/firewall/import", methods=["POST"])
@login_required
@admin_required
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
    added, errors = firewall.import_rules(text, client_ips=client_ips, client_ip=_client_ip())
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
@admin_required
def vpn_routes_page():
    # Data comes from the browser's own GET /api/vpn-routes call (made by
    # vpn-routes-page.js after this shell loads) — see clients()'s own
    # comment for the pattern this follows.
    return render_template("vpn_routes.html")


@bp.route("/vpn-routes/add", methods=["POST"])
@login_required
@admin_required
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
@admin_required
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
@admin_required
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


@bp.route("/firewall/input", methods=["POST"])
@login_required
@admin_required
def add_input():
    try:
        rule_id = firewall.add_input_rule(
            action=request.form.get("action"),
            protocol=request.form.get("protocol"),
            src=request.form.get("src"),
            dport=request.form.get("dport"),
            comment=request.form.get("comment", ""),
            client_ip=_client_ip(),
        )
        flash("Input rule added.", "success")
        _audit("firewall_input_add", f"rule#{rule_id}")
    except firewall.FirewallError as exc:
        flash(str(exc), "error")
        _audit("firewall_input_add", "", "error", str(exc))
    return redirect(url_for("main.firewall_rules"))


@bp.route("/firewall/snat", methods=["POST"])
@login_required
@admin_required
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
@admin_required
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
@admin_required
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
@admin_required
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
    except PrivilegedCommandError as exc:
        # firewall.reorder_rule's chain rebuild (after its own DB write
        # already committed) can fail here same as toggle_rule's route
        # already accounts for — an uncaught PrivilegedCommandError would
        # otherwise surface as a raw 500 (not this endpoint's documented
        # {ok, error} JSON shape) and skip the audit trail entirely.
        _audit("firewall_rule_reorder", f"rule#{rule_id}", "error", str(exc))
        return jsonify(ok=False, error=str(exc)), 400


@bp.route("/firewall/<int:rule_id>/delete", methods=["POST"])
@login_required
@admin_required
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


def _bulk_disable_or_delete(action, ids, *, restrict_to_client=None):
    """Shared by /firewall/bulk-delete, /firewall/bulk-disable, and their
    client-scoped counterparts below. action is 'delete' or 'disable'.

    restrict_to_client, when given, silently drops any submitted rule_id
    that doesn't actually belong to that client — same "never trust scope
    handed to us from the form" rule client_add_rule's docstring already
    applies to src, extended here since these routes take a whole list of
    IDs rather than one path-scoped ID."""
    client_ip = _client_ip()
    client_ips = pivpn_ctl.list_client_ips()
    ip_to_name = {ip: n for n, ip in client_ips.items()}
    affected_ips = set()
    changed = 0
    skipped = []
    for id_str in ids:
        try:
            rule_id = int(id_str)
        except ValueError:
            continue
        rule = db.get_rule(rule_id)
        if not rule:
            continue
        if restrict_to_client and firewall.rule_client_name(rule, ip_to_name) != restrict_to_client:
            continue
        if action == "disable" and not rule["enabled"]:
            continue
        try:
            if action == "disable":
                firewall.disable_rule(rule_id, client_ip=client_ip)
            else:
                firewall.delete_rule(rule_id, client_ip=client_ip)
        except firewall.FirewallError as exc:
            skipped.append(f"rule#{rule_id}: {exc}")
            continue
        changed += 1
        if rule["kind"] == "forward" and rule.get("src"):
            affected_ips.add(rule["src"])
    for ip in affected_ips:
        _regenerate_script_for_ip(ip, client_ips=client_ips)
    verb = "Deleted" if action == "delete" else "Disabled"
    if changed:
        flash(f"{verb} {changed} rule(s).", "success")
    if skipped:
        flash("Skipped (would block your own access): " + "; ".join(skipped), "error")
    elif not changed:
        flash(f"Nothing selected to {action}.", "error")
    _audit(f"firewall_bulk_{action}", f"{changed} rule(s), {len(skipped)} skipped")
    return changed, skipped


@bp.route("/firewall/bulk-delete", methods=["POST"])
@login_required
@admin_required
def bulk_delete_rules():
    _bulk_disable_or_delete("delete", request.form.getlist("rule_ids"))
    return redirect(url_for("main.firewall_rules"))


@bp.route("/firewall/bulk-disable", methods=["POST"])
@login_required
@admin_required
def bulk_disable_rules():
    _bulk_disable_or_delete("disable", request.form.getlist("rule_ids"))
    return redirect(url_for("main.firewall_rules"))


@bp.route("/firewall/persist", methods=["POST"])
@login_required
@admin_required
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
@admin_required
def resync_rules():
    firewall.sync_all()
    flash("Firewall rules reapplied from the database.", "success")
    _audit("firewall_resync")
    return redirect(url_for("main.firewall_rules"))


AUTH_ACTIONS = ("login", "logout", "idle_lock")


ALL_LOG_TABS = ("sessions", "client_sessions", "traffic", "system", "activity", "auth")
MODERATOR_LOG_TABS = ("client_sessions", "traffic", "auth")

# Time-range filter for the three DB-backed tabs (Sessions/Client Sessions/
# Traffic). Ordered for the <select> — 1h first/default, since selecting
# any option re-queries immediately (no separate Search button) and a
# smaller default window is the cheaper first load. Keys double as the
# ?range= query value.
LOG_RANGE_OPTIONS = [
    ("1h", "Last 1 hour"),
    ("6h", "Last 6 hours"),
    ("12h", "Last 12 hours"),
    ("1d", "Last 1 day"),
    ("7d", "Last 7 days"),
]
LOG_RANGE_HOURS = {"1h": 1, "6h": 6, "12h": 12, "1d": 24, "7d": 24 * 7}
LOG_RANGE_DEFAULT = "1h"


@bp.route("/logs")
@login_required
def logs():
    # Data (and its search/range/pagination/refresh) now comes from the
    # browser's own GET /api/logs call, made by logs-page.js after this
    # shell loads — see clients()'s own comment for the pattern this
    # follows, and app/api.py's logs() for the tab-allowlist/range/page
    # validation this used to duplicate here (kept here too, cheaply,
    # only so the shell renders the right selected tab/search/range/page
    # values — no DB access happens in this view anymore).
    allowed_tabs = ALL_LOG_TABS if current_user.is_admin else MODERATOR_LOG_TABS
    default_tab = "client_sessions" if current_user.is_admin else MODERATOR_LOG_TABS[0]
    tab = request.args.get("tab", default_tab)
    # Enforced here, not just hidden in the template — a moderator editing
    # the URL's ?tab= directly must not be able to reach Sessions/System/
    # Activity. Activity is admin-only for the same reason System is: it
    # shows detail (firewall changes, user management) beyond what
    # "client control + who logged in" is meant to expose to a moderator.
    if tab not in allowed_tabs:
        tab = default_tab

    q = (request.args.get("q") or "").strip() or None
    log_range = request.args.get("range") or LOG_RANGE_DEFAULT
    if log_range not in LOG_RANGE_HOURS:
        log_range = LOG_RANGE_DEFAULT
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    try:
        page_size = int(request.args.get("page_size", 10))
    except ValueError:
        page_size = 10
    if page_size not in (10, 25, 50, 100):
        page_size = 10

    return render_template(
        "logs.html", tab=tab, q=q, page=page, page_size=page_size,
        log_range=log_range, log_range_options=LOG_RANGE_OPTIONS,
    )


@bp.route("/logs/refresh", methods=["POST"])
@login_required
def logs_refresh():
    """Runs one ingestion cycle right now instead of waiting for the next
    tick of deploy/ingest_logs.py's systemd timer (every 10s) — the
    Sessions/Client Sessions/Traffic tabs' "Refresh now" button. Calls the
    exact same functions the timer does; running it early is always safe
    to do at any time, from anywhere, since the journal cursor plus each
    table's INSERT OR IGNORE (see db.py) already make re-running ingestion
    a no-op wherever there's nothing new to find — no separate locking
    needed against the timer firing at the same moment.

    Not admin-gated (@login_required only) — a moderator can already see
    Client Sessions, and this is the same read-only background job that
    already runs on its own every 10 seconds regardless of who's logged
    in, not a new capability."""
    from deploy import ingest_logs
    try:
        ingest_logs.ingest_vpn_events()
        ingest_logs.ingest_traffic_flows()
        ingest_logs.ingest_system_log()
        db.prune_old_logs(ingest_logs.RETENTION_DAYS)
    except PrivilegedCommandError as exc:
        flash(str(exc), "error")
    return redirect(url_for("main.logs", tab=request.form.get("tab", "client_sessions")))
