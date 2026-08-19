import shlex

from app.firewall import _parse_rule_spec, _rule_from_parsed, describe_rule


def test_input_accept(monkeypatch):
    monkeypatch.setattr("app.firewall._server_ip", lambda: "10.0.0.1")
    rule = {"kind": "input", "action": "ACCEPT", "protocol": "tcp",
            "src": "10.202.226.0/24", "dport": "443"}
    assert describe_rule(rule) == "Allow tcp/443 from 10.202.226.0/24 → 10.0.0.1"


def test_input_block_anywhere(monkeypatch):
    monkeypatch.setattr("app.firewall._server_ip", lambda: "10.0.0.1")
    rule = {"kind": "input", "action": "DROP", "protocol": "tcp",
            "src": None, "dport": "443"}
    assert describe_rule(rule) == "Block tcp/443 from 0.0.0.0/0 → 10.0.0.1"


def test_forward_resolves_client_name():
    # forward never calls _server_ip()/_iface_ip() — no mocking needed here,
    # this is testing label()'s client-name lookup instead.
    rule = {"kind": "forward", "action": "DROP", "protocol": "all",
            "src": "10.202.226.4", "dst": "192.168.100.0/24"}
    client_names = {"10.202.226.4": "macbook-phanne"}
    assert describe_rule(rule, client_names) == \
        "Block all traffic from macbook-phanne (10.202.226.4) → 192.168.100.0/24"


def test_snat():
    # No subprocess calls at all for snat — snat_ip is always a literal
    # from the rule itself, not something detected from the machine.
    rule = {"kind": "snat", "src": "10.202.226.0/24", "snat_ip": "192.168.100.12"}
    assert describe_rule(rule) == "Translate 10.202.226.0/24 → 192.168.100.12"


def test_masquerade_with_interface(monkeypatch):
    # Same mocking pattern as _server_ip(), but for the other
    # subprocess-backed helper — _iface_ip() — since out_iface is set here.
    monkeypatch.setattr("app.firewall._iface_ip", lambda iface: "203.0.113.5")
    rule = {"kind": "masquerade", "src": "10.202.226.0/24", "out_iface": "eth0"}
    assert describe_rule(rule) == "Translate 10.202.226.0/24 → 203.0.113.5"


def test_client_block():
    rule = {"kind": "client_block", "client_name": "nurak", "client_ip": "10.202.226.21"}
    assert describe_rule(rule) == "Block all traffic from nurak (10.202.226.21) → 0.0.0.0/0"


# --- the reverse direction: raw iptables -S output back into a rule dict.
# This is what discover_cli_rules() depends on, and it's the exact logic
# behind the orphaned-tag bug found earlier this project (see memory) —
# arguably more valuable to protect than describe_rule() itself.

def test_parse_rule_spec_input_accept():
    line = '-A INPUT -s 10.255.50.0/24 -p tcp -m tcp --dport 443 -m comment --comment "pivpn-webui:1" -j ACCEPT'
    parsed = _parse_rule_spec(shlex.split(line))
    assert parsed == {
        "src": "10.255.50.0/24",
        "protocol": "tcp",
        "dport": "443",
        "comment": "pivpn-webui:1",
        "action": "ACCEPT",
    }


def test_parse_rule_spec_snat():
    line = '-A POSTROUTING -s 10.202.226.0/24 -o ens19 -j SNAT --to-source 192.168.100.12'
    parsed = _parse_rule_spec(shlex.split(line))
    assert parsed == {
        "src": "10.202.226.0/24",
        "out_iface": "ens19",
        "action": "SNAT",
        "to_source": "192.168.100.12",
    }


def test_rule_from_parsed_input():
    parsed = {"src": "10.255.50.0/24", "protocol": "tcp", "dport": "443", "action": "ACCEPT"}
    rule = _rule_from_parsed("input", parsed)
    assert rule["kind"] == "input"
    assert rule["action"] == "ACCEPT"
    assert rule["src"] == "10.255.50.0/24"
    assert rule["comment"] == "(from CLI)"  # no original comment to preserve
    assert rule["source"] == "cli"


def test_rule_from_parsed_preserves_original_comment():
    parsed = {"action": "MASQUERADE", "src": "10.202.226.0/24", "out_iface": "ens18",
              "comment": "cluster access"}
    rule = _rule_from_parsed("postrouting", parsed)
    assert rule["kind"] == "masquerade"
    assert rule["comment"] == "(from CLI) cluster access"


def test_rule_from_parsed_unrecognized_shape_returns_none():
    # REJECT isn't in ALLOWED_ACTION — a shape this app doesn't model, per
    # discover_cli_rules()'s own contract: leave it alone, don't adopt it.
    parsed = {"action": "REJECT", "src": "10.0.0.0/8"}
    assert _rule_from_parsed("forward", parsed) is None
