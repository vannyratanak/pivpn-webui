import shlex

from app.firewall import (
    _parse_rule_spec,
    _positions_for_new_specs,
    _rule_from_parsed,
    _would_allow_client,
    describe_rule,
)


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


# --- _positions_for_new_specs: the fix for the real bug this project hit —
# discover_cli_rules() adopting a manually-added ACCEPT rule that lived
# *before* an existing catch-all DROP, but a plain -A re-add silently moved
# it to the end of the chain, landing it after the DROP and breaking it.

def test_positions_between_two_anchors():
    # one new rule sitting between two already-tracked ones
    anchors = [(True, 1.0), (False, None), (True, 4.0)]
    assert _positions_for_new_specs(anchors) == [None, 2.5, None]


def test_positions_multiple_between_two_anchors_stay_ordered():
    anchors = [(True, 1.0), (False, None), (False, None), (True, 4.0)]
    result = _positions_for_new_specs(anchors)
    assert result[0] is None and result[3] is None
    assert 1.0 < result[1] < result[2] < 4.0


def test_positions_new_rule_before_an_existing_accept_and_drop():
    # the actual bug scenario: ACCEPT (tracked, pos 1.0) already exists,
    # a newly-discovered ACCEPT sat between it and the catch-all DROP
    # (tracked, pos 2.0) live — it must land strictly before the DROP.
    anchors = [(True, 1.0), (False, None), (True, 2.0)]
    result = _positions_for_new_specs(anchors)
    assert 1.0 < result[1] < 2.0


def test_positions_new_rule_before_first_anchor():
    anchors = [(False, None), (True, 5.0)]
    result = _positions_for_new_specs(anchors)
    assert result[0] < 5.0
    assert result[1] is None


def test_positions_new_rule_after_last_anchor():
    anchors = [(True, 5.0), (False, None)]
    result = _positions_for_new_specs(anchors)
    assert result[0] is None
    assert result[1] > 5.0


def test_positions_no_anchors_at_all_stay_relatively_ordered():
    # a chain with nothing tracked yet — e.g. the very first discover_cli_rules() run
    anchors = [(False, None), (False, None), (False, None)]
    result = _positions_for_new_specs(anchors)
    assert result[0] < result[1] < result[2]


# --- _would_allow_client: the self-lockout guard. Simulates the same
# first-match-wins evaluation iptables itself does for the INPUT chain,
# so a reorder/disable/delete can be refused *before* it's applied if it
# would cut off the very connection making the request — the class of bug
# that caused several real outages this session.

def _rule(id, action, src=None, position=0.0, protocol="tcp", dport="443"):
    return {"id": id, "action": action, "src": src, "position": position,
            "protocol": protocol, "dport": dport}


def test_allow_client_matches_accept_before_drop():
    rules = [
        _rule(1, "ACCEPT", "10.202.226.0/24", position=1.0),
        _rule(2, "DROP", position=2.0),
    ]
    assert _would_allow_client(rules, "10.202.226.5") is True


def test_allow_client_matches_drop_when_no_earlier_accept():
    rules = [
        _rule(1, "ACCEPT", "10.202.226.0/24", position=1.0),
        _rule(2, "DROP", position=2.0),
    ]
    assert _would_allow_client(rules, "203.0.113.9") is False


def test_allow_client_order_matters_drop_before_accept_blocks_it():
    # the exact shape of today's real bug: same two rules, but DROP now
    # sorts first — the matching ACCEPT further down never gets reached.
    rules = [
        _rule(2, "DROP", position=1.0),
        _rule(1, "ACCEPT", "10.202.226.0/24", position=2.0),
    ]
    assert _would_allow_client(rules, "10.202.226.5") is False


def test_allow_client_no_match_falls_through_to_default_accept():
    rules = [_rule(1, "ACCEPT", "10.202.226.0/24", position=1.0)]
    assert _would_allow_client(rules, "203.0.113.9") is True


def test_allow_client_ignores_rules_for_other_ports():
    rules = [_rule(1, "DROP", dport="22", position=1.0)]
    assert _would_allow_client(rules, "203.0.113.9") is True


def test_allow_client_ignores_rules_for_other_protocols():
    rules = [_rule(1, "DROP", protocol="udp", position=1.0)]
    assert _would_allow_client(rules, "203.0.113.9") is True


def test_allow_client_no_src_matches_anywhere():
    rules = [_rule(1, "DROP", src=None, position=1.0)]
    assert _would_allow_client(rules, "203.0.113.9") is False


def test_allow_client_position_tie_broken_by_lower_id():
    # matches the same (position, id) tie-break used everywhere else in
    # this module (_rebuild_chain, reorder_rule's sibling sort) — lower id
    # wins a tie, regardless of which rule it is.
    rules = [_rule(2, "DROP", position=1.0), _rule(1, "ACCEPT", "203.0.113.0/24", position=1.0)]
    assert _would_allow_client(rules, "203.0.113.9") is True


def test_allow_client_malformed_src_is_ignored():
    rules = [_rule(1, "DROP", src="not-a-cidr", position=1.0)]
    assert _would_allow_client(rules, "203.0.113.9") is True


def test_allow_client_ipv6_client_vs_ipv4_only_rule_falls_through():
    rules = [_rule(1, "DROP", src="203.0.113.0/24", position=1.0)]
    assert _would_allow_client(rules, "2001:db8::5") is True


def test_allow_client_unparseable_ip_fails_open():
    assert _would_allow_client([_rule(1, "DROP")], "not-an-ip") is True
