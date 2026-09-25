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


def test_activity_aggregates_beyond_log_page_and_does_not_claim_coverage(client, monkeypatch):
    headers = _auth_header(_admin_token(client))
    # 'range=1d' means the calendar day containing `now` (see overview.py's
    # activity()), not a rolling 24h window — frozen and pinned mid-day so
    # "25 hours ago" unambiguously lands in yesterday regardless of what
    # wall-clock time this test actually runs at.
    now = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)

    class _FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr('app.overview.datetime', _FixedDatetime)
    ts = lambda d: d.strftime('%Y-%m-%d %H:%M:%S')
    db.insert_vpn_events([(ts(now-timedelta(hours=1)), 'connected', f'client{i}', '10.8.0.2:1', '', None) for i in range(125)])
    db.insert_vpn_events([(ts(now-timedelta(hours=25)), 'connected', 'earlier', '10.8.0.2:1', '', None)])
    result = client.get('/api/overview/activity?range=1d', headers=headers)
    assert result.status_code == 200
    data = result.get_json()
    assert data['total'] == 125
    assert sum(b['count'] for b in data['buckets']) == 125
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
