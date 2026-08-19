from app.firewall import describe_rule


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
