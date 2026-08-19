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
    argv = [config.IPTABLES_BIN, "-D" if delete else "-I", "FORWARD"]
    argv += ["-s", rule["client_ip"]]
    argv += ["-m", "comment", "--comment", f"pivpn-webui:block:{rule['client_name']}"]
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


def _apply_idempotent(rule):
    try:
        _unapply(rule)
    except PrivilegedCommandError:
        pass  # wasn't present yet, that's fine
    _apply(rule)


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

_IMPORT_ADDERS = {
    "forward": lambda f: add_forward_rule(
        action=f.get("action"), protocol=f.get("protocol"),
        src=f.get("src"), dst=f.get("dst"), dport=f.get("dport"),
        comment=f.get("comment", ""),
    ),
    "portforward": lambda f: add_portforward_rule(
        ext_port=f.get("ext_port"), target_ip=f.get("target_ip"),
        target_port=f.get("target_port"), protocol=f.get("protocol", "tcp"),
        ext_iface=f.get("ext_iface"), comment=f.get("comment", ""),
    ),
    "snat": lambda f: add_snat_rule(
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
        raise FirewallError(f"Unknown rule kind {tokens[0]!r} (expected forward, portforward, or snat).")
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


def import_rules(text: str, client_ips: dict[str, str] | None = None) -> tuple[int, list[str]]:
    """Add one rule per non-blank, non-'#'-comment line. Every line is
    independent — one bad line doesn't stop the rest from importing.

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
                _IMPORT_ADDERS[kind](fields)
                added += 1
            except FirewallError as exc:
                errors.append(f"line {i}: {exc}")
            continue
        if tokens[0].lower() not in _IMPORT_ADDERS:
            name, eq, value = tokens[0].partition("=")
            if len(tokens) == 1 and eq and name.isidentifier():
                variables[name] = value
                continue
            errors.append(
                f"line {i}: Unknown rule kind {tokens[0]!r} "
                "(expected forward, portforward, snat, or a NAME=value variable definition)."
            )
            continue
        try:
            kind, fields = _parse_import_line(_substitute_vars(line, variables))
            for key in ("src", "dst"):
                if key in fields:
                    fields[key] = _resolve_client_name(fields[key], client_ips)
            _IMPORT_ADDERS[kind](fields)
            added += 1
        except FirewallError as exc:
            errors.append(f"line {i}: {exc}")
    return added, errors


def set_client_block(client_name: str, client_ip: str, blocked: bool):
    existing = db.get_client_block(client_name)
    if blocked:
        if existing:
            return existing["id"]
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


def toggle_rule(rule_id: int):
    rule = db.get_rule(rule_id)
    if not rule:
        raise FirewallError("Rule not found.")
    new_state = not rule["enabled"]
    if new_state:
        _apply_idempotent(rule)
    else:
        _unapply(rule)
    db.set_enabled(rule_id, new_state)


def disable_rule(rule_id: int):
    """Explicitly disable (not toggle) — used by bulk-disable, where some
    selected rules may already be disabled and a toggle would wrongly
    re-enable them."""
    rule = db.get_rule(rule_id)
    if not rule or not rule["enabled"]:
        return
    _unapply(rule)
    db.set_enabled(rule_id, False)


def delete_rule(rule_id: int):
    rule = db.get_rule(rule_id)
    if not rule:
        return
    if rule["enabled"]:
        try:
            _unapply(rule)
        except PrivilegedCommandError:
            pass
    db.delete_rule(rule_id)


def sync_all():
    """Reconcile iptables with the DB — safe to call repeatedly (e.g. on
    every app start, or after a manual iptables flush)."""
    for rule in db.list_rules(enabled_only=True):
        try:
            _apply_idempotent(rule)
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


def describe_rule(rule: dict, client_names: dict[str, str] | None = None) -> str:
    """Concrete from/to summary of a rule for the Active Rules table's
    Details column: real IPs and addresses, not English paraphrasing —
    "this server"/interface names/"anyone" all resolve to actual addresses,
    since a reader cross-checking against `iptables -S` or a packet capture
    needs the real values, not a soft description of them. client_names
    ({ip: name}) lets a src/dst/target that happens to be a known VPN
    client's exact IP show up as "name (ip)" instead of a bare address —
    optional since not every caller has that mapping to hand (e.g.
    discover_cli_rules doesn't)."""
    kind = rule["kind"]
    protocol = rule.get("protocol") or "all"

    def label(value):
        if not value:
            return "0.0.0.0/0"
        name = (client_names or {}).get(value)
        return f"{name} ({value})" if name else value

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
        who = (client_names or {}).get(rule.get("target_ip"))
        target = f"{rule['target_ip']}:{rule['target_port']}" + (f" ({who})" if who else "")
        return f"Translate {ext_ip}:{rule['ext_port']} ({proto}) → {target}"

    if kind == "masquerade":
        src = label(rule.get("src"))
        exit_ip = _iface_ip(rule["out_iface"]) if rule.get("out_iface") else _server_ip()
        return f"Translate {src} → {exit_ip}"

    if kind == "snat":
        src = label(rule.get("src"))
        return f"Translate {src} → {rule['snat_ip']}"

    if kind == "client_block":
        return f"Block all traffic from {rule['client_name']} ({rule['client_ip']}) → 0.0.0.0/0"

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
    invisible to the UI. 'pivpn-webui:block:<name>' (client-block rules,
    tracked by name via db.get_client_block rather than a numeric id) is
    always treated as already ours — checking it against known_ids would
    never match and would re-adopt the same rule as a duplicate on every
    single page load."""
    imported = 0
    known_ids = {str(r["id"]) for r in db.list_rules()}
    for chain, table, kind in _DISCOVERY_TARGETS:
        try:
            specs = _list_chain_specs(chain, table)
        except PrivilegedCommandError:
            continue
        for tokens in specs:
            parsed = _parse_rule_spec(tokens)
            comment = parsed.get("comment", "")
            if comment.startswith("pivpn-webui:block:"):
                continue  # client-block rule — tracked by client name (db.get_client_block), not a numeric id
            if comment.startswith("pivpn-webui:"):
                if comment[len("pivpn-webui:"):] in known_ids:
                    continue  # already ours, and still tracked
                parsed = {**parsed, "comment": ""}  # orphaned tag, not a real note
            rule = _rule_from_parsed(kind, parsed)
            if rule is None:
                continue  # a shape we don't model (e.g. REJECT, LOG) — leave it alone

            rule_id = db.insert_rule(rule)
            rule["id"] = rule_id
            try:
                del_argv = [config.IPTABLES_BIN]
                if table:
                    del_argv += ["-t", table]
                del_argv += ["-D"] + tokens[1:]  # same spec as seen, -A -> -D
                run_root(del_argv)
                _apply(rule)  # re-add, now tagged so we can manage it going forward
                imported += 1
            except PrivilegedCommandError:
                db.delete_rule(rule_id)  # leave the original CLI rule untouched
    return imported
