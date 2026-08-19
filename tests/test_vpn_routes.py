from app import vpn_routes


def test_list_routes_parses_managed_and_unmanaged(monkeypatch):
    """The helper script now surfaces every push-route line in server.conf,
    not just ones this app created — managed=True/False must round-trip
    correctly so the UI can tell them apart (and hide the Remove action for
    unmanaged ones, since remove_route() can't touch them anyway)."""
    monkeypatch.setattr(
        vpn_routes,
        "run_root",
        lambda argv: "192.168.100.0 255.255.255.0 unmanaged\n10.20.30.0 255.255.255.0 managed\n",
    )
    routes = vpn_routes.list_routes()
    assert routes == [
        {"network": "192.168.100.0", "netmask": "255.255.255.0", "managed": False},
        {"network": "10.20.30.0", "netmask": "255.255.255.0", "managed": True},
    ]


def test_list_routes_empty(monkeypatch):
    monkeypatch.setattr(vpn_routes, "run_root", lambda argv: "")
    assert vpn_routes.list_routes() == []
