import shlex

import pytest

from app.firewall import (
    _IMPORT_ADDERS,
    FirewallError,
    _apply,
    _check_client_block_self_lockout,
    _client_block_argv,
    _client_block_input_argv,
    _parse_import_line,
    _parse_rule_spec,
    _positions_for_new_specs,
    _require_proto_for_dport,
    _rule_from_parsed,
    _unapply,
    _would_allow_client,
    add_forward_rule,
    add_input_rule,
    describe_rule,
    import_rules,
    rule_client_name,
    toggle_rule,
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


def test_forward_shows_ip_only_no_client_name():
    # forward never calls _server_ip()/_iface_ip() — no mocking needed here.
    # describe_rule deliberately never resolves a client name (that's the
    # Active Rules table's own Client column's job, see rule_client_name) —
    # confirms it stays a bare IP even for a known client's address.
    rule = {"kind": "forward", "action": "DROP", "protocol": "all",
            "src": "10.202.226.4", "dst": "192.168.100.0/24"}
    assert describe_rule(rule) == "Block all traffic from 10.202.226.4 → 192.168.100.0/24"


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
    # client_name isn't shown here either, same reasoning as forward/
    # portforward — it's the Client column's job now, not Details'.
    rule = {"kind": "client_block", "client_name": "nurak", "client_ip": "10.202.226.21"}
    assert describe_rule(rule) == (
        "Block all traffic from 10.202.226.21 → 0.0.0.0/0, and to this server itself"
    )


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


# --- client_block: FORWARD half (stop the client reaching past this box)
# and INPUT half (stop the client reaching this box itself) are two
# independent rules, applied/removed together. See _apply/_unapply and
# discover_cli_rules' "pivpn-webui:block"-prefix skip (both "block:" and
# "block-in:" tags), and _check_client_block_self_lockout for the guard
# against blocking your own current connection's IP.

_BLOCK_RULE = {"client_name": "nurak", "client_ip": "10.202.226.21"}


def test_client_block_forward_argv_shape():
    argv = _client_block_argv(_BLOCK_RULE)
    assert argv[1:] == [
        "-I", "FORWARD", "-s", "10.202.226.21",
        "-m", "comment", "--comment", "pivpn-webui:block:nurak",
        "-j", "DROP",
    ]


def test_client_block_input_argv_shape():
    argv = _client_block_input_argv(_BLOCK_RULE)
    assert argv[1:] == [
        "-I", "INPUT", "-s", "10.202.226.21",
        "-m", "comment", "--comment", "pivpn-webui:block-in:nurak",
        "-j", "DROP",
    ]


def test_client_block_input_argv_delete_shape():
    argv = _client_block_input_argv(_BLOCK_RULE, delete=True)
    assert argv[1] == "-D"
    assert argv[2] == "INPUT"


def test_apply_client_block_touches_both_chains(monkeypatch):
    calls = []
    monkeypatch.setattr("app.firewall.run_root", lambda argv: calls.append(argv))
    _apply({"kind": "client_block", **_BLOCK_RULE})
    assert len(calls) == 2
    assert calls[0][1:3] == ["-I", "FORWARD"]
    assert calls[1][1:3] == ["-I", "INPUT"]


def test_unapply_client_block_touches_both_chains(monkeypatch):
    calls = []
    monkeypatch.setattr("app.firewall.run_root", lambda argv: calls.append(argv))
    _unapply({"kind": "client_block", **_BLOCK_RULE})
    assert len(calls) == 2
    assert calls[0][1:3] == ["-D", "FORWARD"]
    assert calls[1][1:3] == ["-D", "INPUT"]


def test_client_block_self_lockout_same_ip_raises():
    with pytest.raises(FirewallError):
        _check_client_block_self_lockout("10.202.226.21", "10.202.226.21")


def test_client_block_self_lockout_different_ip_ok():
    _check_client_block_self_lockout("203.0.113.9", "10.202.226.21")  # no raise


def test_client_block_self_lockout_no_admin_ip_skips_check():
    # None means "no real request to protect" (internal caller/tests) —
    # never raise in that case, same convention as _check_self_lockout.
    _check_client_block_self_lockout(None, "10.202.226.21")  # no raise


# --- add_input_rule: previously there was no way to add a brand-new INPUT
# rule at all (only forward/portforward/snat had an adder — "input" wasn't
# in _IMPORT_ADDERS, and a raw "-A INPUT ..." import line crashed with a
# bare KeyError since _iptables_line_to_fields does return kind="input").
# The new rule always lands last (db.insert_rule's default position), so
# unlike client_block's blanket rule this one does need the full
# position-ordered simulation — same self-lockout guard reorder_rule uses.

def _patch_insert_and_apply(monkeypatch, existing_input):
    # db.list_rules() rows always carry a "kind" — add_input_rule filters
    # on it — but the _rule() helper above (shared with the pure
    # _would_allow_client tests) doesn't set one, so inject it here rather
    # than changing that shared helper's shape.
    rows = [{"kind": "input", **r} for r in existing_input]
    monkeypatch.setattr("app.firewall.db.list_rules", lambda enabled_only=False: rows)
    inserted = []
    monkeypatch.setattr("app.firewall.db.insert_rule", lambda rule: inserted.append(rule) or 99)
    applied = []
    monkeypatch.setattr("app.firewall.run_root", lambda argv: applied.append(argv))
    return inserted, applied


def test_add_input_rule_self_lockout_raises_and_never_applies(monkeypatch):
    inserted, applied = _patch_insert_and_apply(monkeypatch, existing_input=[])
    with pytest.raises(FirewallError):
        add_input_rule(action="DROP", protocol="all", src=None, dport=None, client_ip="203.0.113.9")
    assert inserted == []  # refused before ever touching the DB or iptables
    assert applied == []


def test_add_input_rule_allowed_when_earlier_accept_still_covers_caller(monkeypatch):
    existing = [_rule(1, "ACCEPT", "203.0.113.0/24", position=1.0, dport="443")]
    inserted, applied = _patch_insert_and_apply(monkeypatch, existing_input=existing)
    # a new blanket DROP lands last (after the existing ACCEPT) — caller's
    # own connection still matches the earlier ACCEPT first, so this is safe
    add_input_rule(action="DROP", protocol="all", src=None, dport=None, client_ip="203.0.113.9")
    assert len(inserted) == 1
    assert len(applied) == 1


def test_add_input_rule_no_client_ip_skips_guard(monkeypatch):
    # None means "no real request to protect" — e.g. a script/internal
    # caller, not a browser request that could get locked out.
    inserted, applied = _patch_insert_and_apply(monkeypatch, existing_input=[])
    add_input_rule(action="DROP", protocol="all", src=None, dport=None, client_ip=None)
    assert len(inserted) == 1
    assert len(applied) == 1


def _patch_toggle(monkeypatch, rule, other_input_rules=()):
    # rule is the row toggle_rule looks up via db.get_rule; other_input_rules
    # are the rest of the currently-enabled input set db.list_rules(enabled_only=True)
    # would return, standing in for "everything else already live".
    monkeypatch.setattr("app.firewall.db.get_rule", lambda rule_id: dict(rule))
    monkeypatch.setattr(
        "app.firewall.db.list_rules",
        lambda enabled_only=False: [{"kind": "input", **r} for r in other_input_rules],
    )
    set_enabled_calls = []
    monkeypatch.setattr(
        "app.firewall.db.set_enabled",
        lambda rule_id, enabled: set_enabled_calls.append((rule_id, enabled)),
    )
    applied = []

    def _run_root(argv):
        applied.append(argv)
        return ""  # _rebuild_chain treats this as "-S <chain>" output: no owned rules live yet

    monkeypatch.setattr("app.firewall.run_root", _run_root)
    return set_enabled_calls, applied


def test_toggle_rule_enable_self_lockout_raises_and_never_applies(monkeypatch):
    # Regression test: re-enabling a disabled blanket-DROP input rule used
    # to skip the self-lockout guard entirely (only the disable direction
    # checked it) — a rule that was safe to leave off could silently cut
    # the admin off the moment it was flipped back on.
    rule = {**_rule(1, "DROP", src=None, position=1.0), "kind": "input", "enabled": 0}
    set_enabled_calls, applied = _patch_toggle(monkeypatch, rule, other_input_rules=[])
    with pytest.raises(FirewallError):
        toggle_rule(1, client_ip="203.0.113.55")
    assert set_enabled_calls == []  # refused before ever touching the DB or iptables
    assert applied == []


def test_toggle_rule_enable_allowed_when_earlier_accept_still_covers_caller(monkeypatch):
    rule = {**_rule(2, "DROP", src=None, position=2.0), "kind": "input", "enabled": 0}
    earlier_accept = _rule(1, "ACCEPT", "203.0.113.0/24", position=1.0)
    set_enabled_calls, applied = _patch_toggle(monkeypatch, rule, other_input_rules=[earlier_accept])
    toggle_rule(2, client_ip="203.0.113.55")
    assert set_enabled_calls == [(2, True)]
    assert applied  # chain rebuild actually ran


def test_toggle_rule_enable_no_client_ip_skips_guard(monkeypatch):
    rule = {**_rule(1, "DROP", src=None, position=1.0), "kind": "input", "enabled": 0}
    set_enabled_calls, applied = _patch_toggle(monkeypatch, rule, other_input_rules=[])
    toggle_rule(1, client_ip=None)
    assert set_enabled_calls == [(1, True)]


def test_import_adders_accepts_input_kind():
    assert "input" in _IMPORT_ADDERS


def test_import_rules_raw_input_line_no_longer_crashes(monkeypatch):
    # Regression test for the bug this session found: _iptables_line_to_fields
    # returns kind="input" for a raw "-A INPUT ..." line, but "input" was
    # missing from _IMPORT_ADDERS — dispatch raised a bare KeyError, not a
    # catchable FirewallError, so one bad/unexpected line crashed the whole
    # import instead of reporting "line N: ..." like every other bad line.
    _patch_insert_and_apply(monkeypatch, existing_input=[])
    added, errors = import_rules(
        'iptables -A INPUT -s 203.0.113.0/24 -p tcp -m tcp --dport 22 -j ACCEPT\n'
    )
    assert errors == []
    assert added == 1


# --- _parse_rule_spec: every recognized flag used to assume a following
# value existed (tokens[i + 1] with no bounds check) — fine for live `-S`
# output (iptables itself rejects a flag with no value at insert time),
# but this also parses arbitrary pasted 'iptables -A ...' lines from the
# rule importer, where nothing guarantees that. A line truncated right
# after a flag (a typo, a copy-paste cut short) raised a bare IndexError
# instead of being treated as an incomplete/unrecognized matcher.

@pytest.mark.parametrize("tail", [
    ["-s"], ["-d"], ["-p"], ["-i"], ["-o"], ["--dport"], ["-j"], ["-m"],
    ["-j", "DNAT", "--to-destination"], ["-j", "SNAT", "--to-source"],
])
def test_parse_rule_spec_truncated_flag_does_not_crash(tail):
    _parse_rule_spec(["-A", "FORWARD", *tail])  # must not raise IndexError


def test_parse_rule_spec_well_formed_line_still_parses_correctly():
    parsed = _parse_rule_spec(
        ["-A", "FORWARD", "-s", "10.8.0.5", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"]
    )
    assert parsed == {"src": "10.8.0.5", "protocol": "tcp", "dport": "443", "action": "ACCEPT"}


def test_import_rules_truncated_iptables_line_does_not_crash(monkeypatch):
    _patch_insert_and_apply(monkeypatch, existing_input=[])
    added, errors = import_rules("iptables -A FORWARD -s\n")
    assert added == 0
    assert errors == []  # not a recognized rule (no action) — silently skipped, like other unsupported lines


def test_import_rules_undefined_variable_in_raw_iptables_line_reports_clean_error(monkeypatch):
    # Regression test: _substitute_vars raises FirewallError (not
    # ValueError) for an undefined $VAR — the raw 'iptables ...' import
    # branch only caught ValueError around that call, so this used to
    # escape import_rules entirely (crashing the whole request) instead
    # of reporting just this one line and continuing to the next.
    inserted, applied = _patch_insert_and_apply(monkeypatch, existing_input=[])
    added, errors = import_rules(
        'iptables -A FORWARD -s $UNDEFINED -p tcp --dport 443 -j ACCEPT\n'
        'iptables -A FORWARD -s 10.8.0.5 -p tcp --dport 80 -j ACCEPT\n'
    )
    assert len(errors) == 1
    assert "$UNDEFINED" in errors[0]
    assert added == 1  # the second, valid line still imported
    assert len(inserted) == 1


# --- rule_client_name: the Active Rules table's dedicated Client column,
# decoupled from Details' inline "name (ip)" text so it's its own
# sortable/scannable field regardless of rule kind.

def test_rule_client_name_client_block_uses_stored_name_no_lookup():
    # client_block already carries client_name directly — no client_names
    # dict passed at all, confirming it's never even consulted here.
    rule = {"kind": "client_block", "client_name": "nurak", "client_ip": "10.202.226.21"}
    assert rule_client_name(rule) == "nurak"


def test_rule_client_name_forward_matches_src():
    rule = {"kind": "forward", "src": "10.202.226.4", "dst": "192.168.100.0/24"}
    assert rule_client_name(rule, {"10.202.226.4": "macbook-phanne"}) == "macbook-phanne"


def test_rule_client_name_forward_matches_dst_when_src_unmatched():
    rule = {"kind": "forward", "src": "192.168.100.0/24", "dst": "10.202.226.4"}
    assert rule_client_name(rule, {"10.202.226.4": "macbook-phanne"}) == "macbook-phanne"


def test_rule_client_name_portforward_uses_target_ip():
    rule = {"kind": "portforward", "target_ip": "10.202.226.4", "target_port": "80"}
    assert rule_client_name(rule, {"10.202.226.4": "macbook-phanne"}) == "macbook-phanne"


def test_rule_client_name_no_match_returns_empty_string():
    rule = {"kind": "forward", "src": "203.0.113.0/24", "dst": None}
    assert rule_client_name(rule, {"10.202.226.4": "macbook-phanne"}) == ""


def test_rule_client_name_no_client_names_dict_returns_empty_string():
    rule = {"kind": "input", "src": "10.202.226.4"}
    assert rule_client_name(rule) == ""


# --- _require_proto_for_dport: caught live — the Add forward/INPUT rule
# forms let you pick Protocol=Any alongside a Dest. port, which iptables
# then rejected outright at apply time ("unknown option '--dport'", since
# --dport needs -p tcp/udp loaded first) instead of a clear validation
# error. add_forward_rule/add_input_rule both call this after validating
# protocol/dport individually.

def test_require_proto_for_dport_any_with_port_raises():
    with pytest.raises(FirewallError):
        _require_proto_for_dport("all", "443")


def test_require_proto_for_dport_tcp_with_port_ok():
    _require_proto_for_dport("tcp", "443")  # no raise


def test_require_proto_for_dport_any_with_no_port_ok():
    _require_proto_for_dport("all", None)  # no raise — "any protocol, any port" is fine


def test_add_forward_rule_rejects_any_protocol_with_port():
    with pytest.raises(FirewallError):
        add_forward_rule(action="DROP", protocol="all", src=None, dst=None, dport="9991")


def test_add_input_rule_rejects_any_protocol_with_port(monkeypatch):
    inserted, applied = _patch_insert_and_apply(monkeypatch, existing_input=[])
    with pytest.raises(FirewallError):
        add_input_rule(action="ACCEPT", protocol="all", src=None, dport="9991")
    assert inserted == []  # rejected before ever touching the DB or iptables
    assert applied == []


# --- _parse_import_line: an unbalanced quote must raise FirewallError,
# never a raw ValueError from shlex.split — found live: a $VAR substituted
# into an otherwise-fine import line can introduce a stray quote that only
# breaks *after* substitution, past the caller's own pre-substitution
# shlex.split guard, and crashed the whole import request with a raw 500.

def test_parse_import_line_unbalanced_quote_raises_firewall_error():
    with pytest.raises(FirewallError):
        _parse_import_line('forward action=DROP comment="unbalanced')


def test_import_rules_variable_substitution_unbalanced_quote_is_caught():
    # COMMENT_VAL's value is fine quoted on its own definition line; only
    # once substituted into the next line (replacing the literal
    # "$COMMENT_VAL" text) does the apostrophe end up unquoted and unbalanced.
    text = (
        "COMMENT_VAL=\"john's rule\"\n"
        "forward action=DROP protocol=tcp src=198.51.100.0/24 dport=9 comment=$COMMENT_VAL\n"
    )
    added, errors = import_rules(text)
    assert added == 0
    assert len(errors) == 1
    assert "line 2" in errors[0]
