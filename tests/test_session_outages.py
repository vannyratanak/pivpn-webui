from app import vpnlog
import pytest


@pytest.fixture(autouse=True)
def no_clock_changes(monkeypatch):
    monkeypatch.setattr(vpnlog.db, "list_clock_change_times", lambda: [])
    monkeypatch.setattr(vpnlog.db, "list_session_observation_gaps", lambda: [])


def event(ts, kind, address="10.8.0.2:1000", detail=""):
    return dict(ts=ts, event=kind, client="client1", address=address,
                detail=detail, real_address=None)


def test_restart_prevents_pairing_across_blackout(monkeypatch):
    monkeypatch.setattr(vpnlog, "_parse_openvpn_events", lambda: [
        event("2026-09-23 17:57:28", "connected"),
        event("2026-09-25 09:00:00", "other", detail="OpenVPN 2.6.12 x86_64"),
        event("2026-09-25 09:15:11", "disconnected"),
    ])
    sessions, total = vpnlog.list_client_sessions()
    assert total == 2
    old = next(s for s in sessions if s["start"])
    assert old["end"] is None
    assert old["duration"] is None
    assert not old["ongoing"]
    assert "restart" in old["status_note"]
    assert all(s["duration"] is None for s in sessions)


def test_late_disconnect_cannot_close_different_peer(monkeypatch):
    monkeypatch.setattr(vpnlog, "_parse_openvpn_events", lambda: [
        event("2026-09-25 09:00:00", "connected"),
        event("2026-09-25 09:01:00", "disconnected", address="10.8.0.2:9999"),
        event("2026-09-25 09:02:00", "disconnected"),
    ])
    sessions, _ = vpnlog.list_client_sessions()
    complete = next(s for s in sessions if s["start"])
    assert complete["end"] == "2026-09-25 09:02:00"
    assert complete["duration"] == "2m 0s"


def test_long_session_without_restart_is_preserved(monkeypatch):
    monkeypatch.setattr(vpnlog, "_parse_openvpn_events", lambda: [
        event("2026-09-23 17:00:00", "connected"),
        event("2026-09-25 09:00:00", "disconnected"),
    ])
    sessions, _ = vpnlog.list_client_sessions()
    assert len(sessions) == 1
    assert sessions[0]["duration"] == "40h 0m"


def test_initialization_boundary_closes_unmatched_sessions(monkeypatch):
    monkeypatch.setattr(vpnlog, "_parse_openvpn_events", lambda: [
        event("2026-09-23 17:00:00", "connected"),
        event("2026-09-25 09:00:00", "other", detail="Initialization Sequence Completed"),
    ])
    sessions, _ = vpnlog.list_client_sessions()
    assert len(sessions) == 1
    assert not sessions[0]["ongoing"]
    assert sessions[0]["duration"] is None


def test_vm_resume_clock_jump_does_not_become_connected_duration(monkeypatch):
    monkeypatch.setattr(vpnlog, "_parse_openvpn_events", lambda: [
        event("2026-09-23 10:57:28", "connected"),
        event("2026-09-25 02:15:11", "disconnected"),
    ])
    monkeypatch.setattr(vpnlog.db, "list_clock_change_times", lambda: ["2026-09-25 02:15:11"])
    sessions, _ = vpnlog.list_client_sessions()
    assert len(sessions) == 1
    assert sessions[0]["end"] == "2026-09-25 02:15:11"
    assert sessions[0]["duration"] is None
    assert "clock changed" in sessions[0]["duration_note"]


def test_outage_ends_old_session_and_reconnect_starts_new_session(monkeypatch):
    monkeypatch.setattr(vpnlog, "_parse_openvpn_events", lambda: [
        event("2026-09-23 10:57:28", "connected"),
        event("2026-09-25 02:15:11", "disconnected"),
        event("2026-09-25 02:15:28", "connected", address="10.8.0.2:2000"),
        event("2026-09-25 02:19:34", "disconnected", address="10.8.0.2:2000"),
    ])
    monkeypatch.setattr(vpnlog.db, "list_session_observation_gaps", lambda: [
        {"last_observed_at": "2026-09-23 11:27:15", "resumed_at": "2026-09-25 02:15:11"},
    ])
    sessions, total = vpnlog.list_client_sessions()
    assert total == 2
    old = next(s for s in sessions if s["start"].startswith("2026-09-23"))
    assert old["end"] == "2026-09-23 11:27:15"
    assert old["duration"] is None
    assert not old["ongoing"]
    assert old["last_observed_at"] == "2026-09-23 11:27:15"
    assert old["end_estimated"]
    assert "Interrupted" in old["status_note"]
    new = next(s for s in sessions if s["start"].startswith("2026-09-25"))
    assert new["duration"] == "4m 6s"
