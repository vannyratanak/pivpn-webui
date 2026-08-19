from app.firewall import describe_rule


def test_input_accept():
    rule = {"kind": "input", "action": "ACCEPT", "protocol": "tcp",
            "src": "10.202.226.0/24", "dport": "443"}
    assert describe_rule(rule) == "Allow tcp/443 from 10.202.226.0/24 → this server"


def test_input_block_anywhere():
    rule = {"kind": "input", "action": "DROP", "protocol": "tcp",
            "src": None, "dport": "443"}
    assert describe_rule(rule) == "Block tcp/443 from 0.0.0.0/0 → this server"
