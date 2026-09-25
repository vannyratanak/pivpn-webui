import asyncio

import config
import pytest
from app import db, iplookup
import hub_gateway


def _seed_online_client():
    db.replace_client_status_cache([{
        "name": "mobile", "status": "Valid", "expiration": "", "list_position": 0,
        "ip": "10.8.0.2", "session_real_address": "198.51.100.4:1234",
        "session_virtual_address": "10.8.0.2", "session_bytes_recv": "1",
        "session_bytes_sent": "2", "session_since": "2026-09-23 10:00:00",
    }])


def test_current_default_agent_disconnect_clears_online_cache(temp_db):
    _seed_online_client()
    socket = object()
    hub_gateway.live_agents[config.DEFAULT_SERVER_ID] = socket

    asyncio.run(hub_gateway._mark_agent_disconnected(config.DEFAULT_SERVER_ID, socket))

    assert config.DEFAULT_SERVER_ID not in hub_gateway.live_agents
    assert db.get_client_status_cache("mobile")["session"] is None


def test_stale_agent_socket_cannot_clear_new_connection_cache(temp_db):
    _seed_online_client()
    current, stale = object(), object()
    hub_gateway.live_agents[config.DEFAULT_SERVER_ID] = current

    asyncio.run(hub_gateway._mark_agent_disconnected(config.DEFAULT_SERVER_ID, stale))

    assert hub_gateway.live_agents[config.DEFAULT_SERVER_ID] is current
    assert db.get_client_status_cache("mobile")["session"] is not None
    hub_gateway.live_agents.pop(config.DEFAULT_SERVER_ID, None)


def test_traffic_batch_parses_kernel_event_without_live_whois(temp_db, monkeypatch):
    monkeypatch.setattr(db, "list_client_ip_name_map", lambda: {"10.8.0.2": "mobile"})
    monkeypatch.setattr(iplookup, "get_cached_ip_orgs", lambda ips: {"9.9.9.9": "Quad9"})
    events = [{
        "cursor": "s=boot;i=42;b=boot;m=1;t=2;x=3",
        "message": "IN=tun0 OUT=eth0 MAC=00 SRC=10.8.0.2 DST=9.9.9.9 LEN=60 PROTO=UDP SPT=4567 DPT=53",
        "realtime_us": "1790136182000000",
    }]

    rows, cursor = hub_gateway._traffic_batch_rows(events)

    assert cursor == events[0]["cursor"]
    assert rows == [(
        "2026-09-23 04:03:02", "10.8.0.2", "9.9.9.9", "Quad9", "mobile",
        "UDP", "4567", "53", "tun0", "eth0",
    )]


def test_traffic_batch_rejects_invalid_journal_cursor():
    with pytest.raises(ValueError):
        hub_gateway._traffic_batch_rows([{
            "cursor": "../../bad", "message": "", "realtime_us": "1",
        }])


def test_agent_traffic_batch_cursor_and_rows_are_idempotent(temp_db):
    rows = [(
        "2026-09-23 04:03:02", "10.8.0.2", "9.9.9.9", None, "mobile",
        "UDP", "4567", "53", "tun0", "eth0",
    )]
    cursor = "s=boot;i=42;b=boot;m=1;t=2;x=3"

    db.insert_agent_traffic_batch(config.DEFAULT_SERVER_ID, rows, cursor)
    db.insert_agent_traffic_batch(config.DEFAULT_SERVER_ID, rows, cursor)

    flows, total = db.list_traffic_flows()
    assert total == 1
    assert flows[0]["src"] == "10.8.0.2"
    assert db.get_traffic_flow_cursor(config.DEFAULT_SERVER_ID) == cursor
