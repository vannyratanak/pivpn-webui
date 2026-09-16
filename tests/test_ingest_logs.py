from app import db, pivpn_ctl
from deploy import ingest_logs

# Reuses the exact same real captured lines as test_vpnlog.py, since these
# are the same CONNECT_RE/DISCONNECT_RE/FLOW_RE patterns being fed through
# — just via ingest_logs's openvpn-tail/flow-tail path now, not a live
# per-request fetch.

CONNECT_LINE = (
    "2026-08-21T13:20:11+0700 vpn ovpn-server[23975]: "
    "[macbook-phanne] Peer Connection Initiated with [AF_INET]10.66.66.1:2642"
)
DISCONNECT_LINE = (
    "2026-08-21T12:47:07+0700 vpn ovpn-server[23975]: "
    "macbook-phanne/10.66.66.1:2201 SIGTERM[soft,remote-exit] received, client-instance exiting"
)
OTHER_LINE = "2026-08-21T12:00:00+0700 vpn ovpn-server[23975]: VERIFY OK: depth=1, CN=Easy-RSA CA"

TCP_FLOW_LINE = (
    "2026-09-15T10:11:14+0700 vpn kernel: VPNFLOW IN=tun0 OUT=ens18 MAC= "
    "SRC=10.202.226.2 DST=149.112.112.112 LEN=64 TOS=0x00 PREC=0x00 TTL=63 "
    "ID=0 DF PROTO=TCP SPT=52250 DPT=443 WINDOW=65535 RES=0x00 CWR ECE SYN URGP=0"
)


def test_ingest_vpn_events_stores_connect_disconnect_and_other(temp_db, monkeypatch):
    monkeypatch.setattr(
        ingest_logs, "run_root",
        lambda argv, timeout=None: "\n".join([CONNECT_LINE, DISCONNECT_LINE, OTHER_LINE]),
    )

    count = ingest_logs.ingest_vpn_events()

    assert count == 3
    events = db.list_vpn_events()
    assert [e["event"] for e in events] == ["other", "disconnected", "connected"]  # ts order
    connected = next(e for e in events if e["event"] == "connected")
    assert connected["client"] == "macbook-phanne"
    assert connected["address"] == "10.66.66.1:2642"
    other = next(e for e in events if e["event"] == "other")
    assert "VERIFY OK" in other["detail"]


def test_ingest_vpn_events_resolves_real_address_for_connects_only(temp_db, monkeypatch):
    monkeypatch.setattr(
        ingest_logs, "run_root",
        lambda argv, timeout=None: "\n".join([CONNECT_LINE, DISCONNECT_LINE]),
    )
    calls = []

    def fake_resolve_bulk(addresses):
        calls.append(addresses)
        return {addr: f"resolved:{addr}" for addr in addresses}

    monkeypatch.setattr(ingest_logs, "resolve_real_addresses_bulk", fake_resolve_bulk)

    ingest_logs.ingest_vpn_events()

    events = db.list_vpn_events()
    connected = next(e for e in events if e["event"] == "connected")
    disconnected = next(e for e in events if e["event"] == "disconnected")
    assert connected["real_address"] == "resolved:10.66.66.1:2642"
    assert disconnected["real_address"] is None  # never resolved for disconnect/other rows
    assert calls == [["10.66.66.1:2642"]]  # only the connect address was asked for


def test_ingest_vpn_events_resolves_a_burst_of_connects_in_one_bulk_call(temp_db, monkeypatch):
    # The actual regression this exists for: N clients reconnecting in the
    # same tick must resolve as one batch, not N sequential SSH calls (see
    # resolve_real_addresses_bulk's own docstring for the ~30-45s a naive
    # loop would cost at real relay latency).
    lines = [
        "2026-08-21T13:20:{:02d}+0700 vpn ovpn-server[1]: "
        "[client{n}] Peer Connection Initiated with [AF_INET]10.66.66.1:{port}".format(n, n=n, port=3000 + n)
        for n in range(5)
    ]
    monkeypatch.setattr(ingest_logs, "run_root", lambda argv, timeout=None: "\n".join(lines))
    calls = []
    monkeypatch.setattr(
        ingest_logs, "resolve_real_addresses_bulk",
        lambda addresses: calls.append(addresses) or {a: None for a in addresses},
    )

    count = ingest_logs.ingest_vpn_events()

    assert count == 5
    assert len(calls) == 1
    assert len(calls[0]) == 5


def test_ingest_vpn_events_reprocessing_same_line_is_a_noop(temp_db, monkeypatch):
    # journalctl --cursor-file can re-emit the last-seen line on the very
    # next invocation (confirmed live) — the table's UNIQUE constraint +
    # INSERT OR IGNORE must absorb that instead of duplicating the row.
    monkeypatch.setattr(ingest_logs, "run_root", lambda argv, timeout=None: CONNECT_LINE)
    ingest_logs.ingest_vpn_events()
    ingest_logs.ingest_vpn_events()
    assert len(db.list_vpn_events()) == 1


def test_ingest_vpn_events_empty_output_is_a_noop(temp_db, monkeypatch):
    monkeypatch.setattr(ingest_logs, "run_root", lambda argv, timeout=None: "")
    assert ingest_logs.ingest_vpn_events() == 0
    assert db.list_vpn_events() == []


def test_ingest_traffic_flows_resolves_client_and_org(temp_db, monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {})
    monkeypatch.setattr(
        pivpn_ctl, "list_connected_clients",
        lambda: {"mobile": {"virtual_address": "10.202.226.2"}},
    )
    monkeypatch.setattr(ingest_logs, "run_root", lambda argv, timeout=None: TCP_FLOW_LINE)
    monkeypatch.setattr(
        ingest_logs.iplookup, "get_ip_orgs_bulk",
        lambda ips: {ip: "Meta Platforms Ireland Limited" for ip in ips},
    )

    count = ingest_logs.ingest_traffic_flows()

    assert count == 1
    rows, total = db.list_traffic_flows()
    assert total == 1
    assert len(rows) == 1
    assert rows[0]["client"] == "mobile"
    assert rows[0]["dst_org"] == "Meta Platforms Ireland Limited"
    assert rows[0]["dport"] == "443"


def test_ingest_traffic_flows_handles_journalctl_no_entries_output(temp_db, monkeypatch):
    # Regression test: journalctl -g/--grep (used by flow-tail) exits 1 —
    # not 0 — when its pattern matches nothing, printing "-- No entries --"
    # to stdout. pivpn-webui-log-helper.sh's flow-tail action already
    # tolerates that exit code (see its own comment); this is the
    # Python-side half — that literal line must parse as "no flows", not
    # raise or produce a bogus row.
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {})
    monkeypatch.setattr(pivpn_ctl, "list_connected_clients", lambda: {})
    monkeypatch.setattr(ingest_logs, "run_root", lambda argv, timeout=None: "-- No entries --")

    assert ingest_logs.ingest_traffic_flows() == 0
    assert db.list_traffic_flows() == ([], 0)


def test_ingest_traffic_flows_looks_up_org_once_per_unique_destination(temp_db, monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {})
    monkeypatch.setattr(pivpn_ctl, "list_connected_clients", lambda: {})
    # Two distinct flow lines, same destination (different source port so
    # they're not identical rows and both actually get inserted).
    second_line = TCP_FLOW_LINE.replace("SPT=52250", "SPT=52251")
    monkeypatch.setattr(
        ingest_logs, "run_root",
        lambda argv, timeout=None: "\n".join([TCP_FLOW_LINE, second_line]),
    )
    calls = []

    def fake_get_ip_orgs_bulk(ips):
        calls.append(ips)
        return {ip: "Meta Platforms Ireland Limited" for ip in ips}

    monkeypatch.setattr(ingest_logs.iplookup, "get_ip_orgs_bulk", fake_get_ip_orgs_bulk)

    count = ingest_logs.ingest_traffic_flows()

    assert count == 2
    assert len(calls) == 1  # one bulk call for the whole batch, not per row


def test_main_ingests_both_and_prunes(temp_db, monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {})
    monkeypatch.setattr(pivpn_ctl, "list_connected_clients", lambda: {})
    calls = {"openvpn": 0, "flow": 0}

    def fake_run_root(argv, timeout=None):
        calls["openvpn" if argv[-1] == "openvpn-tail" else "flow"] += 1
        return CONNECT_LINE if argv[-1] == "openvpn-tail" else TCP_FLOW_LINE

    monkeypatch.setattr(ingest_logs, "run_root", fake_run_root)
    monkeypatch.setattr(ingest_logs.iplookup, "get_ip_orgs_bulk", lambda ips: {ip: None for ip in ips})

    pruned = []
    monkeypatch.setattr(db, "prune_old_logs", lambda days: pruned.append(days))

    ingest_logs.main()

    assert calls == {"openvpn": 1, "flow": 1}
    assert pruned == [ingest_logs.RETENTION_DAYS]
