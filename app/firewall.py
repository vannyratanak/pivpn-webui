"""iptables rule management: general FORWARD accept/drop rules, DNAT
port-forwarding, and a per-VPN-client block toggle.

All rules are persisted in sqlite (see db.py) so they can be reapplied after
a reboot or an accidental `iptables -F`. Every apply is idempotent (delete
then add) so re-running sync never produces duplicate rules.
"""
import functools
import ipaddress
import re
import shlex
import subprocess

import config
from app import db
from app.privileged import PrivilegedCommandError, run_root

ALLOWED_PROTO = {"tcp", "udp", "all"}
ALLOWED_ACTION = {"ACCEPT", "DROP"}

# Chains this app manages, and the DB "kind" each maps to. Used by
# discover_cli_rules() to know where to look for manually-added rules.
_DISCOVERY_TARGETS = [
    ("FORWARD", None, "forward"),
    ("INPUT", None, "input"),
    ("PREROUTING", "nat", "portforward"),
    ("POSTROUTING", "nat", "postrouting"),  # -> masquerade or snat, by -j target
]

# Which live iptables chain(s) each kind's _apply() touches — portforward
# spans two (its DNAT half in PREROUTING/nat, its accept half in FORWARD),
# and so does client_block (a FORWARD half stopping the client's own
# outbound traffic, an INPUT half stopping the client from reaching this
# box at all — see _client_block_argv / _client_block_input_argv).
# client_block is deliberately absent from this map: both its halves
# always -I to the very front of their chain regardless of anything else
# there, so it sits outside the position-ordering system entirely rather
# than being reorderable relative to other rules.
_CHAIN_FOR_KIND = {
    "input": [("INPUT", None)],
    "forward": [("FORWARD", None)],
    "masquerade": [("POSTROUTING", "nat")],
    "snat": [("POSTROUTING", "nat")],
    "portforward": [("PREROUTING", "nat"), ("FORWARD", None)],
}

_OWNED_TAG_RE = re.compile(r"^pivpn-webui:(\d+)$")


class FirewallError(RuntimeError):
    pass


def _valid_port(p):
    if p in (None, "", "any"):
        return None
    try:
        n = int(p)
    except (TypeError, ValueError):
        raise FirewallError(f"Invalid port: {p!r}")
    if not (1 <= n <= 65535):
        raise FirewallError(f"Port out of range: {p!r}")
    return str(n)


def _valid_addr(a):
    if a in (None, "", "any"):
        return None
    try:
        ipaddress.ip_network(a, strict=False)
    except ValueError:
        raise FirewallError(f"Invalid IP/CIDR: {a!r}")
    return a


def _valid_ip(a):
    """A single address, not a subnet — for '--to-source', which needs an
    exact IP (or a-b range) to rewrite into, not a network."""
    try:
        ipaddress.ip_address(a)
    except ValueError:
        raise FirewallError(f"Invalid IP address: {a!r}")
    return a


def _valid_proto(p, allow_all=True):
    p = (p or "all").lower()
    choices = ALLOWED_PROTO if allow_all else {"tcp", "udp"}
    if p not in choices:
        raise FirewallError(f"Invalid protocol: {p!r}")
    return p


def _valid_action(a):
    a = (a or "").upper()
    if a not in ALLOWED_ACTION:
        raise FirewallError(f"Invalid action: {a!r}")
    return a


# --- argv builders (one iptables invocation each) ---

def _forward_argv(rule, delete=False):
    argv = [config.IPTABLES_BIN, "-D" if delete else "-A", "FORWARD"]
    if rule["protocol"] != "all":
        argv += ["-p", rule["protocol"]]
    if rule.get("src"):
        argv += ["-s", rule["src"]]
    if rule.get("dst"):
        argv += ["-d", rule["dst"]]
    if rule.get("dport"):
        argv += ["--dport", rule["dport"]]
    argv += ["-m", "comment", "--comment", f"pivpn-webui:{rule['id']}"]
    argv += ["-j", rule["action"]]
    return argv


def _portforward_dnat_argv(rule, delete=False):
    argv = [config.IPTABLES_BIN, "-t", "nat", "-D" if delete else "-A", "PREROUTING"]
    if rule.get("ext_iface"):
        argv += ["-i", rule["ext_iface"]]
    argv += ["-p", rule["protocol"], "--dport", rule["ext_port"]]
    argv += ["-m", "comment", "--comment", f"pivpn-webui:{rule['id']}"]
    argv += ["-j", "DNAT", "--to-destination", f"{rule['target_ip']}:{rule['target_port']}"]
    return argv


def _portforward_forward_argv(rule, delete=False):
    argv = [config.IPTABLES_BIN, "-D" if delete else "-A", "FORWARD"]
    argv += ["-p", rule["protocol"], "-d", rule["target_ip"], "--dport", rule["target_port"]]
    argv += ["-m", "comment", "--comment", f"pivpn-webui:{rule['id']}"]
    argv += ["-j", "ACCEPT"]
    return argv


def _input_argv(rule, delete=False):
    argv = [config.IPTABLES_BIN, "-D" if delete else "-A", "INPUT"]
    if rule["protocol"] != "all":
        argv += ["-p", rule["protocol"]]
    if rule.get("src"):
        argv += ["-s", rule["src"]]
    if rule.get("dport"):
        argv += ["--dport", rule["dport"]]
    argv += ["-m", "comment", "--comment", f"pivpn-webui:{rule['id']}"]
    argv += ["-j", rule["action"]]
    return argv


def _masquerade_argv(rule, delete=False):
    argv = [config.IPTABLES_BIN, "-t", "nat", "-D" if delete else "-A", "POSTROUTING"]
    if rule.get("src"):
        argv += ["-s", rule["src"]]
    if rule.get("out_iface"):
        argv += ["-o", rule["out_iface"]]
    argv += ["-m", "comment", "--comment", f"pivpn-webui:{rule['id']}"]
    argv += ["-j", "MASQUERADE"]
    return argv


def _snat_argv(rule, delete=False):
    """Like masquerade, but with a fixed source IP instead of 'whatever
    out_iface's current address is' — use when the exit IP must stay
    constant (e.g. multiple/changing addresses on the same interface)."""
    argv = [config.IPTABLES_BIN, "-t", "nat", "-D" if delete else "-A", "POSTROUTING"]
    if rule.get("src"):
        argv += ["-s", rule["src"]]
    if rule.get("out_iface"):
        argv += ["-o", rule["out_iface"]]
    argv += ["-m", "comment", "--comment", f"pivpn-webui:{rule['id']}"]
    argv += ["-j", "SNAT", "--to-source", rule["snat_ip"]]
    return argv


def _client_block_argv(rule, delete=False):
    """Stops traffic the client sends *through* this box to somewhere else
    (LAN, internet) — it does not stop the client from reaching the box
    itself, since that's the INPUT chain, a separate rule entirely (see
    _client_block_input_argv)."""
    argv = [config.IPTABLES_BIN, "-D" if delete else "-I", "FORWARD"]
    argv += ["-s", rule["client_ip"]]
    argv += ["-m", "comment", "--comment", f"pivpn-webui:block:{rule['client_name']}"]
    argv += ["-j", "DROP"]
    return argv


def _client_block_input_argv(rule, delete=False):
    """Companion to _client_block_argv: blocks the client from reaching
    this server itself (its web UI, SSH, anything) — without this, a
    "blocked" client can still ping/connect to the box's own address,
    since FORWARD only ever sees traffic passing *through* it."""
    argv = [config.IPTABLES_BIN, "-D" if delete else "-I", "INPUT"]
    argv += ["-s", rule["client_ip"]]
    argv += ["-m", "comment", "--comment", f"pivpn-webui:block-in:{rule['client_name']}"]
    argv += ["-j", "DROP"]
    return argv


def _apply(rule):
    if rule["kind"] == "forward":
        run_root(_forward_argv(rule))
    elif rule["kind"] == "input":
        run_root(_input_argv(rule))
    elif rule["kind"] == "portforward":
        run_root(_portforward_dnat_argv(rule))
        run_root(_portforward_forward_argv(rule))
    elif rule["kind"] == "masquerade":
        run_root(_masquerade_argv(rule))
    elif rule["kind"] == "snat":
        run_root(_snat_argv(rule))
    elif rule["kind"] == "client_block":
        run_root(_client_block_argv(rule))
        run_root(_client_block_input_argv(rule))


def _unapply(rule):
    if rule["kind"] == "forward":
        run_root(_forward_argv(rule, delete=True))
    elif rule["kind"] == "input":
        run_root(_input_argv(rule, delete=True))
    elif rule["kind"] == "portforward":
        run_root(_portforward_dnat_argv(rule, delete=True))
        run_root(_portforward_forward_argv(rule, delete=True))
    elif rule["kind"] == "masquerade":
        run_root(_masquerade_argv(rule, delete=True))
    elif rule["kind"] == "snat":
        run_root(_snat_argv(rule, delete=True))
    elif rule["kind"] == "client_block":
        run_root(_client_block_argv(rule, delete=True))
        run_root(_client_block_input_argv(rule, delete=True))


def _apply_idempotent(rule):
    try:
        _unapply(rule)
    except PrivilegedCommandError:
        pass  # wasn't present yet, that's fine
    _apply(rule)


def _chains_for(rule: dict) -> list[tuple[str, str | None]]:
    return _CHAIN_FOR_KIND.get(rule["kind"], [])


def _apply_to_chain(rule: dict, chain: str, table: str | None):
    """Apply just the piece of _apply(rule) that targets one specific
    chain/table — needed because portforward's two pieces (PREROUTING/nat
    DNAT, FORWARD accept) have to be rebuilt independently when only one of
    those two chains is being rebuilt."""
    if rule["kind"] == "portforward":
        if table == "nat":
            run_root(_portforward_dnat_argv(rule))
        else:
            run_root(_portforward_forward_argv(rule))
    else:
        _apply(rule)


def _rebuild_chain(chain: str, table: str | None):
    """Delete every rule this app currently has live in one chain (matched
    by the plain numeric 'pivpn-webui:<id>' tag only — never a foreign rule,
    never a 'pivpn-webui:block:<name>' client-block, which manages its own
    position via -I and is excluded from _CHAIN_FOR_KIND on purpose), then
    re-add every enabled DB rule that targets it, in `position` order.

    Why this exists: _apply()'s add step is always a plain -A (append), so
    on its own it can only ever put a rule last. That's fine for a brand
    new rule (DB-append and live-append naturally agree), but it's exactly
    how a reorder — or discover_cli_rules() adopting a rule that wasn't
    originally last — would otherwise fail to actually take effect live.
    Rebuilding the whole chain from `position` order is the only way to
    make the live ruleset genuinely match the DB after either of those.

    Briefly drops every app-managed rule in this chain before re-adding
    them (both chains default-ACCEPT on a PiVPN box, so this is a brief
    window of *less* restriction, not a lockout) — acceptable for a
    same-box operation that completes in milliseconds, not something to
    do on every single request.
    """
    for tokens in _list_chain_specs(chain, table):
        parsed = _parse_rule_spec(tokens)
        if not _OWNED_TAG_RE.match(parsed.get("comment", "")):
            continue
        del_argv = [config.IPTABLES_BIN]
        if table:
            del_argv += ["-t", table]
        del_argv += ["-D"] + tokens[1:]
        run_root(del_argv)

    rules = sorted(
        (r for r in db.list_rules(enabled_only=True) if (chain, table) in _chains_for(r)),
        key=lambda r: (r["position"], r["id"]),
    )
    for rule in rules:
        _apply_to_chain(rule, chain, table)


def _input_rule_matches(rule: dict, client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Would this INPUT-kind rule be the one iptables actually matches for
    a request from client_ip to the web UI's port (443)? Mirrors iptables'
    own matching: protocol/port must apply to 443 (or be unrestricted), and
    src (or no src, i.e. 0.0.0.0/0) must contain the address."""
    if rule.get("dport") not in (None, "", "443"):
        return False
    if rule.get("protocol") not in (None, "all", "tcp"):
        return False
    src = rule.get("src")
    if not src:
        return True
    try:
        return client_ip in ipaddress.ip_network(src, strict=False)
    except ValueError:
        return False


def _would_allow_client(input_rules: list[dict], client_ip_str: str) -> bool:
    """Walk a (position-ordered) set of enabled INPUT-kind rules the same
    way iptables does — first match wins — and report whether client_ip
    would reach port 443. No match at all falls through to INPUT's own
    default policy, which is ACCEPT."""
    try:
        client_ip = ipaddress.ip_address(client_ip_str)
    except ValueError:
        return True  # can't parse it — don't block on our own bad data
    for rule in sorted(input_rules, key=lambda r: (r["position"], r["id"])):
        if _input_rule_matches(rule, client_ip):
            return rule["action"] == "ACCEPT"
    return True


def _check_self_lockout(client_ip: str | None, simulated_input_rules: list[dict]):
    """Raise FirewallError if applying a hypothetical INPUT rule set would
    block client_ip's own access to the web UI. client_ip is None when
    there's no real request to protect (discover_cli_rules, sync_all,
    tests) — skip the check entirely in that case, there's nothing to
    guard."""
    if client_ip is None:
        return
    if not _would_allow_client(simulated_input_rules, client_ip):
        raise FirewallError(
            f"This change would block your own current connection ({client_ip}) "
            "from reaching this page — refusing to apply it."
        )


def _check_client_block_self_lockout(admin_ip: str | None, blocked_client_ip: str):
    """Raise FirewallError if blocking blocked_client_ip would cut off the
    request that's asking for it. Unlike _check_self_lockout's position-
    ordered simulation, a client-block's INPUT half is always a blanket
    -I DROP for every port, always inserted at the very front of the chain
    — so there's nothing to simulate: if it's the same address, blocking
    it will unconditionally cut off this request, full stop. admin_ip is
    None when there's no real request to protect (tests, or an internal
    caller) — skip the check in that case."""
    if admin_ip is None:
        return
    if admin_ip == blocked_client_ip:
        raise FirewallError(
            f"This would block your own current connection ({admin_ip}) "
            "from reaching this page — refusing to apply it."
        )


def reorder_rule(rule_id: int, target_id: int, place: str, client_ip: str | None = None):
    """Place `rule_id` immediately before/after `target_id` among rules that
    share a chain with it — what a drag-and-drop drop (rather than a single
    up/down step, see move_rule) needs: the drop target can be any number
    of rows away, not just an adjacent neighbor. Computes an interpolated
    position the same way _positions_for_new_specs does for discovery, then
    rebuilds every chain the moved rule touches."""
    if place not in ("before", "after"):
        raise FirewallError(f"Invalid place: {place!r}")
    rule = db.get_rule(rule_id)
    target = db.get_rule(target_id)
    if not rule or not target:
        raise FirewallError("Rule not found.")
    my_chains = set(_chains_for(rule))
    if not my_chains:
        raise FirewallError("This rule can't be reordered.")
    if not (my_chains & set(_chains_for(target))):
        raise FirewallError("These rules don't share a chain.")

    siblings = sorted(
        (r for r in db.list_rules() if r["id"] != rule_id and my_chains & set(_chains_for(r))),
        key=lambda r: (r["position"], r["id"]),
    )
    target_idx = next(i for i, r in enumerate(siblings) if r["id"] == target_id)
    if place == "before":
        left = siblings[target_idx - 1] if target_idx > 0 else None
        right = siblings[target_idx]
    else:
        left = siblings[target_idx]
        right = siblings[target_idx + 1] if target_idx + 1 < len(siblings) else None

    if left is None and right is None:
        new_pos = 0.0
    elif left is None:
        new_pos = right["position"] - 1
    elif right is None:
        new_pos = left["position"] + 1
    else:
        new_pos = (left["position"] + right["position"]) / 2

    if rule["kind"] == "input":
        simulated = [
            {**r, "position": new_pos} if r["id"] == rule_id else r
            for r in db.list_rules(enabled_only=True) if r["kind"] == "input"
        ]
        _check_self_lockout(client_ip, simulated)

    db.set_positions({rule_id: new_pos})
    for chain, table in my_chains:
        _rebuild_chain(chain, table)


# --- public API used by routes.py ---

def _insert_and_apply(rule: dict) -> int:
    """Insert then apply; if iptables rejects it, roll back the DB insert
    and surface a FirewallError instead of leaking a PrivilegedCommandError
    (and instead of leaving an 'enabled' row that was never actually applied)."""
    rule_id = db.insert_rule(rule)
    rule["id"] = rule_id
    try:
        _apply(rule)
    except PrivilegedCommandError as exc:
        db.delete_rule(rule_id)
        raise FirewallError(str(exc)) from exc
    return rule_id


def add_forward_rule(action, protocol, src, dst, dport, comment=""):
    rule = {
        "kind": "forward",
        "action": _valid_action(action),
        "protocol": _valid_proto(protocol),
        "src": _valid_addr(src),
        "dst": _valid_addr(dst),
        "dport": _valid_port(dport),
        "comment": (comment or "")[:200],
        "enabled": 1,
    }
    return _insert_and_apply(rule)


def add_input_rule(action, protocol, src, dport, comment="", client_ip: str | None = None):
    """Unlike forward/portforward/snat, this can lock the caller out of the
    web UI itself (INPUT is exactly what gates port 443) — a new rule
    always lands last among enabled INPUT rules (db.insert_rule's default
    position, same as every other kind), so simulate it there and run the
    same self-lockout check reorder_rule uses before actually applying
    it."""
    rule = {
        "kind": "input",
        "action": _valid_action(action),
        "protocol": _valid_proto(protocol),
        "src": _valid_addr(src),
        "dport": _valid_port(dport),
        "comment": (comment or "")[:200],
        "enabled": 1,
    }
    existing_input = [r for r in db.list_rules(enabled_only=True) if r["kind"] == "input"]
    max_pos = max((r["position"] for r in existing_input), default=0.0)
    simulated = existing_input + [{**rule, "id": -1, "position": max_pos + 1}]
    _check_self_lockout(client_ip, simulated)
    return _insert_and_apply(rule)


def add_portforward_rule(ext_port, target_ip, target_port, protocol="tcp", ext_iface=None, comment=""):
    target_ip = _valid_addr(target_ip)
    if not target_ip:
        raise FirewallError("Target IP is required for a port-forward rule.")
    ext_port_v = _valid_port(ext_port)
    if not ext_port_v:
        raise FirewallError("External port is required for a port-forward rule.")
    rule = {
        "kind": "portforward",
        "action": "ACCEPT",
        "protocol": _valid_proto(protocol, allow_all=False),
        "ext_port": ext_port_v,
        "target_ip": target_ip,
        "target_port": _valid_port(target_port) or ext_port_v,
        "ext_iface": (ext_iface or "")[:32],
        "comment": (comment or "")[:200],
        "enabled": 1,
    }
    return _insert_and_apply(rule)


def add_snat_rule(src, snat_ip, out_iface=None, comment=""):
    rule = {
        "kind": "snat",
        "action": "SNAT",
        "protocol": "all",
        "src": _valid_addr(src),
        "snat_ip": _valid_ip(snat_ip),
        "out_iface": (out_iface or "")[:32],
        "comment": (comment or "")[:200],
        "enabled": 1,
    }
    return _insert_and_apply(rule)


# --- bulk import: one rule per line, "kind key=value key=value ..." ---
# Every adder takes (fields, client_ip) even though only "input" actually
# uses client_ip (the self-lockout guard) — a uniform signature keeps both
# dispatch call sites below simple, instead of special-casing one kind.

_IMPORT_ADDERS = {
    "forward": lambda f, client_ip: add_forward_rule(
        action=f.get("action"), protocol=f.get("protocol"),
        src=f.get("src"), dst=f.get("dst"), dport=f.get("dport"),
        comment=f.get("comment", ""),
    ),
    "input": lambda f, client_ip: add_input_rule(
        action=f.get("action"), protocol=f.get("protocol"),
        src=f.get("src"), dport=f.get("dport"),
        comment=f.get("comment", ""), client_ip=client_ip,
    ),
    "portforward": lambda f, client_ip: add_portforward_rule(
        ext_port=f.get("ext_port"), target_ip=f.get("target_ip"),
        target_port=f.get("target_port"), protocol=f.get("protocol", "tcp"),
        ext_iface=f.get("ext_iface"), comment=f.get("comment", ""),
    ),
    "snat": lambda f, client_ip: add_snat_rule(
        src=f.get("src"), snat_ip=f.get("snat_ip"),
        out_iface=f.get("out_iface"), comment=f.get("comment", ""),
    ),
}


def _parse_import_line(line: str) -> tuple[str, dict]:
    """'kind key=value key="quoted value" ...' -> (kind, {key: value}).
    shlex handles the quoting so a comment can contain spaces."""
    tokens = shlex.split(line)
    if not tokens:
        raise FirewallError("Empty line.")
    kind = tokens[0].lower()
    if kind not in _IMPORT_ADDERS:
        raise FirewallError(f"Unknown rule kind {tokens[0]!r} (expected forward, input, portforward, or snat).")
    fields = {}
    for tok in tokens[1:]:
        if "=" not in tok:
            raise FirewallError(f"Expected key=value, got {tok!r}.")
        key, _, value = tok.partition("=")
        fields[key] = value
    return kind, fields


_VAR_REF_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")


def _substitute_vars(line: str, variables: dict[str, str]) -> str:
    def repl(m):
        name = m.group(1)
        if name not in variables:
            raise FirewallError(f"Unknown variable ${name} — define it on its own line first, e.g. {name}=10.0.0.5")
        return variables[name]
    return _VAR_REF_RE.sub(repl, line)


def _iptables_line_to_fields(tokens: list[str]) -> tuple[str, dict] | None:
    """Best-effort translation of a raw 'iptables -A FORWARD ...' or
    '-A INPUT ...' command line into (kind, fields), reusing the same
    matcher-walking _parse_rule_spec() already used to adopt live CLI
    rules — lets an existing shell script (the kind admins were hand-writing
    per client before this app existed) be imported close to verbatim
    instead of hand-translated into kind key=value syntax.

    Returns None for anything that isn't a plain single-chain '-A' append
    we model — a '-S'/'-D' cleanup pipeline (piped through grep/sed/bash,
    not a rule to add), '-t nat' rules, or any chain besides FORWARD/INPUT.
    The caller skips those silently rather than erroring: a cleanup step
    isn't something a rule import can represent, and this app's own
    idempotent apply (delete-then-add per rule, see _apply_idempotent)
    already makes that cleanup step unnecessary anyway.
    """
    if not tokens or tokens[0] != "iptables":
        return None
    args = tokens[1:]
    if args[:1] == ["-t"]:
        args = args[2:]  # only filter-table FORWARD/INPUT import this way
    if len(args) < 2 or args[0] != "-A" or args[1] not in ("FORWARD", "INPUT"):
        return None
    kind = "forward" if args[1] == "FORWARD" else "input"
    parsed = _parse_rule_spec(args)
    if parsed.get("action") not in ALLOWED_ACTION:
        return None
    fields = {"action": parsed["action"], "protocol": parsed.get("protocol", "all")}
    for key in ("src", "dst", "dport", "comment"):
        if key in parsed and (kind == "forward" or key != "dst"):
            fields[key] = parsed[key]
    return kind, fields


def _resolve_client_name(value: str, client_ips: dict[str, str]) -> str:
    """If value isn't already a valid IP/CIDR, and matches a known client
    name, resolve it to that client's current VPN IP. Otherwise leave it
    untouched — including if it matches nothing, so the normal "Invalid
    IP/CIDR" validation error still fires with the original typo visible."""
    if not value:
        return value
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        return client_ips.get(value, value)


def import_rules(
    text: str, client_ips: dict[str, str] | None = None, client_ip: str | None = None
) -> tuple[int, list[str]]:
    """Add one rule per non-blank, non-'#'-comment line. Every line is
    independent — one bad line doesn't stop the rest from importing.

    client_ip (the caller's own address, for the self-lockout guard) is
    distinct from client_ips (plural — VPN client name -> IP lookup for
    src/dst) despite the similar name; only an imported 'input' line
    actually uses it.

    A line of the form NAME=value (no rule kind, e.g. "CLIENT_IP=10.8.0.5")
    defines a variable instead of a rule — any later line can reference it
    as $NAME, substituted in before that line is parsed. Lets one template
    (e.g. a whole client's FORWARD policy) be reused by just changing the
    variable lines at the top.

    A rule's src/dst can also just be a VPN client's name (e.g.
    "src=nurak") instead of an IP — resolved via client_ips (name -> current
    VPN IP), the same lookup the Add-rule form's Source dropdown uses. Only
    applies when the value isn't already a valid IP/CIDR, so this never
    shadows a real address.

    A line can also be a raw 'iptables -A FORWARD ...' / '-A INPUT ...'
    command instead of kind key=value syntax — see _iptables_line_to_fields.
    Lets an existing per-client shell script be uploaded close to verbatim.

    Returns (number added, list of 'line N: <error>' messages for the rest).
    """
    added = 0
    errors = []
    client_ips = client_ips or {}
    variables: dict[str, str] = {}
    for i, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            errors.append(f"line {i}: {exc}")
            continue
        if not tokens:
            continue
        if tokens[0] == "iptables":
            try:
                sub_tokens = shlex.split(_substitute_vars(line, variables))
            except ValueError as exc:
                errors.append(f"line {i}: {exc}")
                continue
            result = _iptables_line_to_fields(sub_tokens)
            if result is None:
                continue  # cleanup pipeline / unsupported chain — nothing to import, not an error
            kind, fields = result
            try:
                for key in ("src", "dst"):
                    if key in fields:
                        fields[key] = _resolve_client_name(fields[key], client_ips)
                _IMPORT_ADDERS[kind](fields, client_ip)
                added += 1
            except FirewallError as exc:
                errors.append(f"line {i}: {exc}")
            continue
        if tokens[0].lower() not in _IMPORT_ADDERS:
            name, eq, value = tokens[0].partition("=")
            if len(tokens) == 1 and eq and name.isidentifier():
                variables[name] = value
                continue
            # Clients page's own import format is "name=foo passphrase=bar"
            # per line — an easy file to upload here by mistake, since both
            # pages phrase their dialog the same way ("Import ... from
            # file"). Caught, not just a generic unknown-kind error, so the
            # fix is obvious instead of cryptic.
            if name.lower() == "name" and eq:
                errors.append(
                    f"line {i}: {tokens[0]!r} looks like a client import line, "
                    "not a firewall rule — this file probably belongs on the "
                    "Clients page's Import Client dialog instead."
                )
                continue
            errors.append(
                f"line {i}: Unknown rule kind {tokens[0]!r} "
                "(expected forward, input, portforward, snat, or a NAME=value variable definition)."
            )
            continue
        try:
            kind, fields = _parse_import_line(_substitute_vars(line, variables))
            for key in ("src", "dst"):
                if key in fields:
                    fields[key] = _resolve_client_name(fields[key], client_ips)
            _IMPORT_ADDERS[kind](fields, client_ip)
            added += 1
        except FirewallError as exc:
            errors.append(f"line {i}: {exc}")
    return added, errors


def set_client_block(client_name: str, client_ip: str, blocked: bool, admin_ip: str | None = None):
    existing = db.get_client_block(client_name)
    if blocked:
        if existing:
            return existing["id"]
        _check_client_block_self_lockout(admin_ip, client_ip)
        rule = {
            "kind": "client_block",
            "action": "DROP",
            "protocol": "all",
            "client_name": client_name,
            "client_ip": client_ip,
            "comment": f"Block {client_name}",
            "enabled": 1,
        }
        return _insert_and_apply(rule)
    if existing:
        try:
            _unapply(existing)
        except PrivilegedCommandError as exc:
            raise FirewallError(str(exc)) from exc
        db.delete_rule(existing["id"])
    return None


def _input_rules_without(rule_id: int) -> list[dict]:
    """Currently-enabled INPUT-kind rules, minus one — the simulated state
    for a disable/delete self-lockout check (both remove a rule from what's
    actually enforced, just via a different DB field)."""
    return [r for r in db.list_rules(enabled_only=True) if r["kind"] == "input" and r["id"] != rule_id]


def toggle_rule(rule_id: int, client_ip: str | None = None):
    rule = db.get_rule(rule_id)
    if not rule:
        raise FirewallError("Rule not found.")
    new_state = not rule["enabled"]
    if new_state:
        # DB flip has to happen before any chain rebuild, since rebuild
        # re-derives what's live from db.list_rules(enabled_only=True).
        db.set_enabled(rule_id, True)
        chains = _chains_for(rule)
        if chains:
            for chain, table in chains:
                _rebuild_chain(chain, table)
        else:
            _apply(rule)  # e.g. client_block — outside the position-ordering system, see _CHAIN_FOR_KIND
    else:
        if rule["kind"] == "input":
            _check_self_lockout(client_ip, _input_rules_without(rule_id))
        _unapply(rule)
        db.set_enabled(rule_id, False)


def disable_rule(rule_id: int, client_ip: str | None = None):
    """Explicitly disable (not toggle) — used by bulk-disable, where some
    selected rules may already be disabled and a toggle would wrongly
    re-enable them."""
    rule = db.get_rule(rule_id)
    if not rule or not rule["enabled"]:
        return
    if rule["kind"] == "input":
        _check_self_lockout(client_ip, _input_rules_without(rule_id))
    _unapply(rule)
    db.set_enabled(rule_id, False)


def delete_rule(rule_id: int, client_ip: str | None = None):
    rule = db.get_rule(rule_id)
    if not rule:
        return
    if rule["kind"] == "input":
        _check_self_lockout(client_ip, _input_rules_without(rule_id))
    if rule["enabled"]:
        try:
            _unapply(rule)
        except PrivilegedCommandError:
            pass
    db.delete_rule(rule_id)


def sync_all():
    """Reconcile iptables with the DB — safe to call repeatedly (e.g. on
    every app start, or after a manual iptables flush).

    Rules whose kind participates in position-ordering (see
    _CHAIN_FOR_KIND) are reconciled a whole chain at a time via
    _rebuild_chain, so they come back in the right relative order — a
    plain per-rule delete-then-`-A` re-add (what this used to do) can only
    ever put each rule last as it's processed, which silently broke a
    lower-position ACCEPT that sat before a higher-position catch-all DROP
    every time the app restarted. Anything outside that system (currently
    just client_block, which always -I's to the front on its own) still
    gets applied one rule at a time, same as before."""
    touched_chains: set[tuple[str, str | None]] = set()
    for rule in db.list_rules(enabled_only=True):
        chains = _chains_for(rule)
        if chains:
            touched_chains.update(chains)
        else:
            try:
                _apply_idempotent(rule)
            except PrivilegedCommandError:
                pass
    for chain, table in touched_chains:
        try:
            _rebuild_chain(chain, table)
        except PrivilegedCommandError:
            pass


def persisted_rule_ids() -> set[str]:
    """Which rule ids (as strings) are present in the on-disk
    netfilter-persistent snapshot right now — i.e. would survive a reboot.
    That file only changes when 'Save Rules' is clicked, so comparing
    against it (rather than the live ruleset) is what actually answers
    'is this rule saved or not'."""
    try:
        out = run_root([config.CAT_BIN, config.PERSISTED_RULES_PATH])
    except PrivilegedCommandError:
        return set()
    return set(re.findall(r'pivpn-webui:(\d+)', out))


def save_persistent():
    try:
        run_root([config.NETFILTER_PERSISTENT_BIN, "save"])
    except PrivilegedCommandError as exc:
        raise FirewallError(
            f"Could not persist rules (is iptables-persistent / netfilter-persistent installed?): {exc}"
        ) from exc


# --- discovering rules added directly via the CLI (not through this app) ---

def _list_chain_specs(chain: str, table: str | None = None) -> list[list[str]]:
    """Tokenized `-A ...` rule specs for a chain, via `iptables -S`. Skips
    the `-P <policy>` / `-N <custom-chain>` header lines `-S` also prints."""
    argv = [config.IPTABLES_BIN]
    if table:
        argv += ["-t", table]
    argv += ["-S", chain]
    out = run_root(argv)
    specs = []
    for line in out.splitlines():
        line = line.strip()
        if not line or not line.startswith("-A "):
            continue
        specs.append(shlex.split(line))
    return specs


def _parse_rule_spec(tokens: list[str]) -> dict:
    """Walk a tokenized `-A CHAIN <matchers...> -j <target>` spec into a
    flat dict. Handles the flags this app itself ever emits (see the
    _*_argv builders above) plus '-m tcp/udp --dport', which iptables adds
    on its own when -S echoes back a protocol+port match."""
    d = {}
    i = 2  # tokens[0]='-A', tokens[1]=chain name
    while i < len(tokens):
        tok = tokens[i]
        if tok == "-s":
            d["src"] = tokens[i + 1]; i += 2
        elif tok == "-d":
            d["dst"] = tokens[i + 1]; i += 2
        elif tok == "-p":
            d["protocol"] = tokens[i + 1]; i += 2
        elif tok == "-i":
            d["in_iface"] = tokens[i + 1]; i += 2
        elif tok == "-o":
            d["out_iface"] = tokens[i + 1]; i += 2
        elif tok == "--dport":
            d["dport"] = tokens[i + 1]; i += 2
        elif tok == "-m":
            if tokens[i + 1] == "comment" and i + 3 < len(tokens) and tokens[i + 2] == "--comment":
                d["comment"] = tokens[i + 3]
                i += 4
            else:
                i += 2  # e.g. "-m tcp" alongside --dport — no extra info beyond -p
        elif tok == "-j":
            d["action"] = tokens[i + 1]
            i += 2
            if d["action"] == "DNAT" and i < len(tokens) and tokens[i] == "--to-destination":
                d["to_destination"] = tokens[i + 1]
                i += 2
            elif d["action"] == "SNAT" and i < len(tokens) and tokens[i] == "--to-source":
                d["to_source"] = tokens[i + 1]
                i += 2
        else:
            i += 1  # unrecognized matcher we don't model — skip its flag only
    return d


def _rule_from_parsed(kind: str, parsed: dict) -> dict | None:
    comment = parsed.get("comment", "")
    note = f"(from CLI) {comment}".strip()
    action = parsed.get("action")
    if kind == "forward" and action in ALLOWED_ACTION:
        return {
            "kind": "forward", "action": action,
            "protocol": parsed.get("protocol", "all"),
            "src": parsed.get("src"), "dst": parsed.get("dst"),
            "dport": parsed.get("dport"), "comment": note,
            "enabled": 1, "source": "cli",
        }
    if kind == "input" and action in ALLOWED_ACTION:
        return {
            "kind": "input", "action": action,
            "protocol": parsed.get("protocol", "all"),
            "src": parsed.get("src"), "dport": parsed.get("dport"),
            "comment": note, "enabled": 1, "source": "cli",
        }
    if kind == "portforward" and action == "DNAT" and parsed.get("to_destination"):
        target_ip, _, target_port = parsed["to_destination"].partition(":")
        return {
            "kind": "portforward", "action": "ACCEPT",
            "protocol": parsed.get("protocol", "tcp"),
            "ext_port": parsed.get("dport"),
            "target_ip": target_ip, "target_port": target_port or parsed.get("dport"),
            "ext_iface": parsed.get("in_iface", ""),
            "comment": note, "enabled": 1, "source": "cli",
        }
    if kind == "postrouting" and action == "MASQUERADE":
        return {
            "kind": "masquerade", "action": "MASQUERADE", "protocol": "all",
            "src": parsed.get("src"), "out_iface": parsed.get("out_iface"),
            "comment": note, "enabled": 1, "source": "cli",
        }
    if kind == "postrouting" and action == "SNAT" and parsed.get("to_source"):
        return {
            "kind": "snat", "action": "SNAT", "protocol": "all",
            "src": parsed.get("src"), "out_iface": parsed.get("out_iface"),
            "snat_ip": parsed["to_source"],
            "comment": note, "enabled": 1, "source": "cli",
        }
    return None


@functools.lru_cache(maxsize=None)
def _server_ip() -> str:
    """This box's own address on its default-route interface — a plain
    unprivileged routing-table lookup (no packet sent), not a guess. Cached
    for the life of the process: it can only change via a network config
    change, which needs a service restart to take effect here anyway."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            capture_output=True, text=True, timeout=3,
        ).stdout
        m = re.search(r"\bsrc (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else "this server"
    except (OSError, subprocess.SubprocessError):
        return "this server"


def list_interfaces() -> list[str]:
    """Real network interfaces on this box, for the SNAT rule form's
    Outgoing interface dropdown — loopback excluded (never a meaningful
    NAT exit), everything else included (ens18/ens19-style NICs and tun*
    VPN interfaces alike), since this app doesn't get to assume which one
    an admin's topology needs. Not cached like _server_ip/_iface_ip: unlike
    those, this reads the interface *list itself*, which the whole reason
    someone plugs in a NIC or brings up a new tunnel is to change."""
    try:
        out = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True, timeout=3,
        ).stdout
        names = re.findall(r"^\d+:\s+([^:@]+)[:@]", out, re.MULTILINE)
        return sorted(n for n in names if n != "lo")
    except (OSError, subprocess.SubprocessError):
        return []


@functools.lru_cache(maxsize=None)
def _iface_ip(iface: str) -> str:
    """Current IPv4 address of a network interface, e.g. what MASQUERADE on
    that interface actually rewrites source addresses to. Same caching
    rationale as _server_ip()."""
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=3,
        ).stdout
        m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else iface
    except (OSError, subprocess.SubprocessError):
        return iface


def rule_client_name(rule: dict, client_names: dict[str, str] | None = None) -> str:
    """Which VPN client (if any) a rule is tied to, by IP — for the Active
    Rules table's own Client column, so that's scannable/sortable on its
    own instead of only ever showing up buried inside the Details text.
    client_block already carries the name directly (no IP lookup needed);
    portforward's client-side address is target_ip, not src/dst; every
    other kind checks src then dst, in case a manual rule was written
    with the client as the destination instead."""
    if rule["kind"] == "client_block":
        return rule.get("client_name") or ""
    client_names = client_names or {}
    if rule["kind"] == "portforward":
        return client_names.get(rule.get("target_ip"), "")
    for key in ("src", "dst"):
        name = client_names.get(rule.get(key))
        if name:
            return name
    return ""


def describe_rule(rule: dict) -> str:
    """Concrete from/to summary of a rule for the Active Rules table's
    Details column: real IPs and addresses, not English paraphrasing —
    "this server"/interface names/"anyone" all resolve to actual addresses,
    since a reader cross-checking against `iptables -S` or a packet capture
    needs the real values, not a soft description of them. Deliberately IP
    only, no client name lookup — the Active Rules table has its own
    Client column for that (see rule_client_name); showing it in both
    places was redundant."""
    kind = rule["kind"]
    protocol = rule.get("protocol") or "all"

    def label(value):
        return value or "0.0.0.0/0"

    def service(dport_key="dport"):
        dport = rule.get(dport_key)
        if protocol == "all":
            return f"port {dport}" if dport else "all traffic"
        return f"{protocol}/{dport}" if dport else protocol

    if kind == "input":
        verb = "Allow" if rule["action"] == "ACCEPT" else "Block"
        src = label(rule.get("src"))
        return f"{verb} {service()} from {src} → {_server_ip()}"

    if kind == "forward":
        verb = "Allow" if rule["action"] == "ACCEPT" else "Block"
        src = label(rule.get("src"))
        dst = label(rule.get("dst"))
        return f"{verb} {service()} from {src} → {dst}"

    if kind == "portforward":
        proto = rule.get("protocol") or "tcp"
        ext_ip = _iface_ip(rule["ext_iface"]) if rule.get("ext_iface") else _server_ip()
        target = f"{rule['target_ip']}:{rule['target_port']}"
        return f"Translate {ext_ip}:{rule['ext_port']} ({proto}) → {target}"

    if kind == "masquerade":
        src = label(rule.get("src"))
        exit_ip = _iface_ip(rule["out_iface"]) if rule.get("out_iface") else _server_ip()
        return f"Translate {src} → {exit_ip}"

    if kind == "snat":
        src = label(rule.get("src"))
        return f"Translate {src} → {rule['snat_ip']}"

    if kind == "client_block":
        return f"Block all traffic from {rule['client_ip']} → 0.0.0.0/0, and to this server itself"

    return ""


def regenerate_client_script(name: str, ip: str):
    """Write (or, if the client has no forward rules left, delete) a
    read-only /etc/openvpn/scripts/firewall-<name>.sh mirroring that
    client's current enabled FORWARD rules as plain iptables commands —
    so someone on the CLI can see what's configured without opening the
    web UI. This is NOT wired into OpenVPN's client-connect; see
    deploy/pivpn-webui-client-script-helper.sh for why re-adding rules that
    way would silently strip this app's own rule tags on every reconnect.
    Best-effort: a permission/helper problem here shouldn't block whatever
    rule change triggered it, so callers should let this raise and just log
    it rather than surface it as the primary error to the user."""
    rules = [
        r for r in db.list_rules(enabled_only=True)
        if r["kind"] == "forward" and r["src"] == ip
    ]
    if not rules:
        run_root([config.CLIENT_SCRIPT_HELPER, "delete", name])
        return

    lines = [
        "#!/bin/bash",
        f"# Read-only reference — current FORWARD rules for client '{name}' ({ip}),",
        "# generated by pivpn-webui. Edit these in the web UI, not here — this file",
        "# is overwritten every time that client's rules change there, and running",
        "# it directly would duplicate rules the app already applies itself.",
        "",
    ]
    for r in rules:
        argv = ["iptables", "-A", "FORWARD", "-s", ip]
        if r.get("protocol") and r["protocol"] != "all":
            argv += ["-p", r["protocol"]]
        if r.get("dst"):
            argv += ["-d", r["dst"]]
        if r.get("dport"):
            argv += ["--dport", str(r["dport"])]
        argv += ["-j", r["action"]]
        if r.get("comment"):
            lines.append(f"# {r['comment']}")
        lines.append(" ".join(argv))
    script = "\n".join(lines) + "\n"
    run_root([config.CLIENT_SCRIPT_HELPER, "write", name], input_text=script)


def _positions_for_new_specs(anchor_info: list[tuple[bool, float | None]]) -> list[float | None]:
    """anchor_info[i] = (is_already_tracked, its_db_position_if_so). Returns,
    for each i, the position a newly-adopted rule at that live-chain slot
    should get (None for already-tracked slots — callers never insert
    those), interpolated strictly between the positions of the nearest
    already-tracked neighbors before/after it in the live order (or one
    step beyond the nearest single neighbor, or 0.0/1.0/... apart if this
    chain has no tracked rules at all yet). This is what lets
    discover_cli_rules() preserve a newly-found rule's real position
    relative to everything already known, instead of just dumping it after
    everything else in the DB the way a plain -A-based re-add would."""
    n = len(anchor_info)
    result: list[float | None] = [None] * n
    i = 0
    while i < n:
        if anchor_info[i][0]:
            i += 1
            continue
        j = i
        while j < n and not anchor_info[j][0]:
            j += 1
        left = anchor_info[i - 1][1] if i > 0 else None
        right = anchor_info[j][1] if j < n else None
        count = j - i
        if left is None and right is None:
            positions = [float(k) for k in range(count)]
        elif left is None:
            positions = [right - (count - k) for k in range(count)]
        elif right is None:
            positions = [left + k + 1 for k in range(count)]
        else:
            step = (right - left) / (count + 1)
            positions = [left + step * (k + 1) for k in range(count)]
        for k, pos in enumerate(positions):
            result[i + k] = pos
        i = j
    return result


def discover_cli_rules() -> int:
    """Find rules that exist live in iptables but aren't in our DB (i.e.
    someone ran iptables directly instead of using this app, or a previous
    database was wiped/replaced — e.g. a fresh redeploy — while these rules
    stayed live), and adopt each one: record it in the DB, delete the
    original, and re-add it carrying our own `pivpn-webui:<id>` comment so
    it becomes fully visible and manageable (toggle/delete) from the webui,
    same as anything added through a form here. Safe to call on every page
    load — a rule tagged 'pivpn-webui:<id>' is only treated as already
    tracked if that id still exists in the current DB; a tag left over from
    a database that no longer has that row is re-adopted like any other CLI
    rule rather than silently skipped, so a DB reset never leaves live rules
    invisible to the UI. 'pivpn-webui:block:<name>' / 'pivpn-webui:block-in:
    <name>' (client-block rules' FORWARD and INPUT halves, tracked by name
    via db.get_client_block rather than a numeric id) are always treated
    as already ours — checking either against known_ids would never match
    and would re-adopt the same rule as a duplicate on every single page
    load.

    Adopting a rule doesn't re-add it immediately — its DB row gets a
    `position` interpolated from where it actually sits among the chain's
    already-tracked rules (see _positions_for_new_specs), and every chain
    that gained a newly-adopted rule gets rebuilt once at the end via
    _rebuild_chain. A plain per-rule delete-then-append used to land an
    adopted rule after everything else in the chain even if, live, it
    actually sat *before* something like a catch-all DROP — silently
    breaking that rule the moment it got adopted."""
    imported = 0
    all_rules = db.list_rules()
    known_ids = {str(r["id"]) for r in all_rules}
    positions_by_id = {str(r["id"]): r["position"] for r in all_rules}
    touched_chains: set[tuple[str, str | None]] = set()

    for chain, table, kind in _DISCOVERY_TARGETS:
        try:
            specs = _list_chain_specs(chain, table)
        except PrivilegedCommandError:
            continue

        parsed_list = [_parse_rule_spec(tokens) for tokens in specs]
        anchor_info = []
        for parsed in parsed_list:
            m = _OWNED_TAG_RE.match(parsed.get("comment", ""))
            if m and m.group(1) in known_ids:
                anchor_info.append((True, positions_by_id[m.group(1)]))
            else:
                anchor_info.append((False, None))
        new_positions = _positions_for_new_specs(anchor_info)

        for idx, tokens in enumerate(specs):
            parsed = parsed_list[idx]
            comment = parsed.get("comment", "")
            if comment.startswith("pivpn-webui:block"):
                continue  # client-block rule (FORWARD "block:" or INPUT "block-in:" half) —
                          # tracked by client name (db.get_client_block), not a numeric id
            if comment.startswith("pivpn-webui:"):
                if comment[len("pivpn-webui:"):] in known_ids:
                    continue  # already ours, and still tracked
                parsed = {**parsed, "comment": ""}  # orphaned tag, not a real note
            rule = _rule_from_parsed(kind, parsed)
            if rule is None:
                continue  # a shape we don't model (e.g. REJECT, LOG) — leave it alone

            rule["position"] = new_positions[idx]
            rule_id = db.insert_rule(rule)
            try:
                del_argv = [config.IPTABLES_BIN]
                if table:
                    del_argv += ["-t", table]
                del_argv += ["-D"] + tokens[1:]  # same spec as seen, -A -> -D
                run_root(del_argv)
                imported += 1
                touched_chains.update(_chains_for(rule))
            except PrivilegedCommandError:
                db.delete_rule(rule_id)  # leave the original CLI rule untouched

    for chain, table in touched_chains:
        _rebuild_chain(chain, table)
    return imported
