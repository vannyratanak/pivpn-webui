from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace
from app import db
from app.overview import certificate
from app.overview_health import service_health
from tests.test_api import _admin_token, _moderator_token, _auth_header, _seed_client_status_cache


def test_certificate_boundaries():
    today = date(2026, 9, 25)
    assert certificate({'expiration': 'Oct 25 2026'}, today)['certificate_state'] == 'expiring'
    assert certificate({'expiration': 'Oct 26 2026'}, today)['certificate_state'] == 'valid'
    assert certificate({'expiration': 'Sep 24 2026'}, today)['certificate_state'] == 'expired'
    assert certificate({'expiration': 'not a date'}, today)['expiry_date'] is None


def test_overview_requires_auth(client):
    for path in ('/api/overview', '/api/overview/activity', '/api/overview/health'):
        assert client.get(path).status_code == 401
    assert client.get('/overview').status_code == 302


def test_moderator_can_read_clients_but_not_health(client):
    headers = _auth_header(_moderator_token(client))
    _seed_client_status_cache([{'name': 'office-router', 'expiration': 'Sep 25 2030'}])
    data = client.get('/api/overview', headers=headers).get_json()
    assert data['clients'][0]['name'] == 'office-router'
    assert data['clients'][0]['certificate_state'] == 'valid'
    assert client.get('/api/overview/health', headers=headers).status_code == 403


def test_activity_reports_peak_concurrency_not_connect_count(client, monkeypatch):
    headers = _auth_header(_admin_token(client))
    # 'range=1d' means the calendar day containing `now` (see overview.py's
    # activity()), not a rolling 24h window — frozen and pinned mid-day so
    # results don't depend on what wall-clock time this test actually runs.
    now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)

    class _FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr('app.overview.datetime', _FixedDatetime)
    ts = lambda d: d.strftime('%Y-%m-%d %H:%M:%S')
    # a connects 09:00, disconnects 09:20; b connects 09:15 and stays
    # online; c connects 09:25 and stays online — a+b overlap briefly,
    # then b+c overlap, but never all three at once. Peak concurrency
    # this hour is 2, not the 3 connect events a naive count would report.
    db.insert_vpn_events([
        (ts(now.replace(hour=9, minute=0)), 'connected', 'a', '10.8.0.2:1', '', None),
        (ts(now.replace(hour=9, minute=15)), 'connected', 'b', '10.8.0.2:2', '', None),
        (ts(now.replace(hour=9, minute=20)), 'disconnected', 'a', '10.8.0.2:1', '', None),
        (ts(now.replace(hour=9, minute=25)), 'connected', 'c', '10.8.0.2:3', '', None),
    ])
    # An already-ended session from the day before must not leak into
    # today's peak, only the previous period's.
    db.insert_vpn_events([
        (ts(now - timedelta(days=1)), 'connected', 'yesterday', '10.8.0.2:9', '', None),
        (ts(now - timedelta(days=1) + timedelta(minutes=5)), 'disconnected', 'yesterday', '10.8.0.2:9', '', None),
    ])
    result = client.get('/api/overview/activity?range=1d', headers=headers)
    assert result.status_code == 200
    data = result.get_json()
    bucket9 = data['buckets'][9]
    assert bucket9['start'] == '2026-09-25 09:00:00'
    assert bucket9['peak'] == 2
    assert data['total'] == 2
    assert data['previous_total'] == 1
    assert not data['coverage_complete']
    assert len(data['buckets']) == 24
    assert client.get('/api/overview/activity?range=invalid', headers=headers).status_code == 400


def test_activity_range_1d_uses_viewer_local_calendar_day(client, monkeypatch):
    headers = _auth_header(_admin_token(client))
    now = datetime(2026, 9, 25, 2, 0, 0, tzinfo=timezone.utc)  # 09:00 in UTC+7

    class _FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr('app.overview.datetime', _FixedDatetime)

    utc_result = client.get('/api/overview/activity?range=1d', headers=headers).get_json()
    assert utc_result['start'] == '2026-09-25 00:00:00'
    assert utc_result['end'] == '2026-09-26 00:00:00'

    # tz_offset uses JS Date.getTimezoneOffset()'s sign convention — -420
    # is UTC+7 (Phnom Penh). Local time is already 09:00 on the 25th, so
    # local midnight is still the previous UTC calendar day.
    local_result = client.get('/api/overview/activity?range=1d&tz_offset=-420', headers=headers).get_json()
    assert local_result['start'] == '2026-09-24 17:00:00'
    assert local_result['end'] == '2026-09-25 17:00:00'


def test_health_unknown_for_missing_unit(monkeypatch):
    monkeypatch.setattr('app.overview_health.subprocess.run', lambda *a, **kw: SimpleNamespace(returncode=0, stdout='LoadState=not-found\nActiveState=inactive\n'))
    assert service_health()['state'] == 'Unknown'


def test_health_running_only_for_loaded_active_service(monkeypatch):
    monkeypatch.setattr('app.overview_health.subprocess.run', lambda *a, **kw: SimpleNamespace(returncode=0, stdout='LoadState=loaded\nActiveState=active\n'))
    assert service_health()['state'] == 'Running'
