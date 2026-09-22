from app import db, pivpn_ctl
from deploy import ingest_clients


def test_ingest_client_status_drops_non_valid_clients(temp_db, monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "list_clients", lambda: [
        {"name": "laptop-anna", "status": "Valid", "expiration": "2027-01-01"},
        {"name": "old-phone", "status": "Revoked", "expiration": "2025-01-01"},
    ])
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {})
    monkeypatch.setattr(pivpn_ctl, "list_connected_clients", lambda: {})

    count = ingest_clients.ingest_client_status()

    assert count == 1
    assert [c["name"] for c in db.list_client_status_cache()] == ["laptop-anna"]


def test_ingest_client_status_caches_ip_and_session(temp_db, monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "list_clients", lambda: [
        {"name": "laptop-anna", "status": "Valid", "expiration": "2027-01-01"},
    ])
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {"laptop-anna": "10.8.0.2"})
    monkeypatch.setattr(pivpn_ctl, "list_connected_clients", lambda: {
        "laptop-anna": {
            "real_address": "1.2.3.4:5", "virtual_address": "10.8.0.2",
            "bytes_recv": "100", "bytes_sent": "200", "since": "2026-09-16 10:00:00",
        },
    })

    ingest_clients.ingest_client_status()

    cached = db.get_client_status_cache("laptop-anna")
    assert cached["ip"] == "10.8.0.2"
    assert cached["session"] == {
        "real_address": "1.2.3.4:5", "virtual_address": "10.8.0.2",
        "bytes_recv": "100", "bytes_sent": "200", "since": "2026-09-16 10:00:00",
    }


def test_ingest_client_status_no_session_for_disconnected_client(temp_db, monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "list_clients", lambda: [
        {"name": "laptop-anna", "status": "Valid", "expiration": "2027-01-01"},
    ])
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {})
    monkeypatch.setattr(pivpn_ctl, "list_connected_clients", lambda: {})

    ingest_clients.ingest_client_status()

    assert db.get_client_status_cache("laptop-anna")["session"] is None


def test_ingest_client_status_preserves_pivpn_list_order(temp_db, monkeypatch):
    # Not alphabetical — whatever order `pivpn list` itself returned, so
    # the Clients page's display order doesn't silently change just
    # because reads now go through this cache.
    monkeypatch.setattr(pivpn_ctl, "list_clients", lambda: [
        {"name": "zebra", "status": "Valid", "expiration": ""},
        {"name": "apple", "status": "Valid", "expiration": ""},
    ])
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {})
    monkeypatch.setattr(pivpn_ctl, "list_connected_clients", lambda: {})

    ingest_clients.ingest_client_status()

    assert [c["name"] for c in db.list_client_status_cache()] == ["zebra", "apple"]


def test_ingest_client_status_duplicate_name_keeps_last_entry(temp_db, monkeypatch):
    # pivpn_ctl.list_clients() can return repeated historical certificate
    # entries for one name (see that function's own docstring) — the
    # later (current) entry must win, matching the old live-lookup's
    # _find_valid_client (matches[-1]) behavior.
    monkeypatch.setattr(pivpn_ctl, "list_clients", lambda: [
        {"name": "mobile", "status": "Valid", "expiration": "2027-01-01"},
        {"name": "mobile", "status": "Valid", "expiration": "2029-01-01"},
    ])
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {})
    monkeypatch.setattr(pivpn_ctl, "list_connected_clients", lambda: {})

    ingest_clients.ingest_client_status()

    assert db.get_client_status_cache("mobile")["expiration"] == "2029-01-01"


def test_ingest_client_status_removes_entries_no_longer_present(temp_db, monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "list_clients", lambda: [
        {"name": "keeper", "status": "Valid", "expiration": ""},
        {"name": "leaving", "status": "Valid", "expiration": ""},
    ])
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {})
    monkeypatch.setattr(pivpn_ctl, "list_connected_clients", lambda: {})
    ingest_clients.ingest_client_status()
    assert {c["name"] for c in db.list_client_status_cache()} == {"keeper", "leaving"}

    # "leaving" genuinely removed (e.g. `pivpn removeOVPN`) — the next
    # snapshot no longer mentions it at all, so it must disappear from the
    # cache too, not linger as a stale row forever.
    monkeypatch.setattr(pivpn_ctl, "list_clients", lambda: [
        {"name": "keeper", "status": "Valid", "expiration": ""},
    ])
    ingest_clients.ingest_client_status()

    assert {c["name"] for c in db.list_client_status_cache()} == {"keeper"}


def test_ingest_client_status_leaves_cache_untouched_on_pivpn_error(temp_db, monkeypatch):
    monkeypatch.setattr(pivpn_ctl, "list_clients", lambda: [
        {"name": "keeper", "status": "Valid", "expiration": ""},
    ])
    monkeypatch.setattr(pivpn_ctl, "list_client_ips", lambda: {})
    monkeypatch.setattr(pivpn_ctl, "list_connected_clients", lambda: {})
    ingest_clients.ingest_client_status()

    def _boom():
        raise pivpn_ctl.PivpnError("agent unreachable")
    monkeypatch.setattr(pivpn_ctl, "list_clients", _boom)

    count = ingest_clients.ingest_client_status()

    assert count == 0
    # Stale but present — a transient pivpn/agent failure shouldn't wipe
    # an otherwise-good cache.
    assert [c["name"] for c in db.list_client_status_cache()] == ["keeper"]
