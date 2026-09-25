"""Read-only dashboard projections. No VPN mutations run on this page."""
from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt, jwt_required
from app import db, hub_client, vpnlog
import config

bp = Blueprint('overview_api', __name__, url_prefix='/api/overview')


def stamp(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def certificate(client, today):
    expiry = None
    for fmt in ('%b %d %Y', '%Y-%m-%d', '%b %d %H:%M:%S %Y GMT'):
        try:
            expiry = datetime.strptime(client.get('expiration') or '', fmt).date()
            break
        except ValueError:
            pass
    status = (client.get('status') or '').lower()
    if status == 'expired' or (expiry and expiry < today):
        state = 'expired'
    elif expiry and (expiry - today).days <= 30:
        state = 'expiring'
    else:
        state = 'valid' if expiry else 'unknown'
    return {'expiry_date': expiry.isoformat() if expiry else None, 'certificate_state': state}


@bp.get('')
@jwt_required()
def snapshot():
    now = datetime.now(timezone.utc)
    clients = db.list_client_status_cache()
    blocks = db.list_client_blocks()
    for client in clients:
        client['blocked'] = client['name'] in blocks
        client.update(certificate(client, now.date()))
    conn = db.get_conn()
    try:
        updated = conn.execute('SELECT MAX(updated_at) AS updated FROM client_status_cache').fetchone()['updated']
        server = conn.execute('SELECT name FROM servers WHERE id=%s', (config.DEFAULT_SERVER_ID,)).fetchone() if config.HUB_MODE else None
    finally:
        conn.close()
    return jsonify(clients=clients, fetched_at=stamp(now), last_client_update=updated,
                   server_name=server['name'] if server else 'PiVPN server',
                   freshness_note='Cached client data. A recent row update does not confirm a complete snapshot.')


@bp.get('/activity')
@jwt_required()
def activity():
    key = request.args.get('range', '1d')
    if key not in ('1d', '7d'):
        return jsonify(error='Range must be 1d or 7d.'), 400
    now = datetime.now(timezone.utc).replace(microsecond=0)
    if key == '1d':
        # Today, midnight-to-midnight in the *viewer's* timezone — not a
        # rolling 24h window — so the chart matches what "today" means to
        # whoever's looking at it, not whatever hour the page happens to
        # load at. tz_offset is minutes, same sign convention as JS's
        # Date.getTimezoneOffset() (positive means local time is behind
        # UTC), sent by overview-page.js on every request.
        tz_offset = request.args.get('tz_offset', 0, type=int)
        local_midnight = (now - timedelta(minutes=tz_offset)).replace(hour=0, minute=0, second=0, microsecond=0)
        start = local_midnight + timedelta(minutes=tz_offset)
        end = start + timedelta(days=1)
        step = 3600
    else:
        end = now
        start = now - timedelta(days=7)
        step = 86400
    now_s = stamp(now)
    # Peak concurrent online clients per bucket, not a connect-event count
    # — a client that's been online since before `start` (or stays online
    # past `end`) has to count in every bucket it spans, not just the one
    # holding its connect event.
    peaks = vpnlog.peak_concurrency_by_bucket(stamp(start), stamp(end), step, now_s)
    conn = db.get_conn()
    try:
        earliest = conn.execute('SELECT MIN(ts) AS earliest FROM vpn_events').fetchone()['earliest']
    finally:
        conn.close()
    buckets = [{'start': stamp(start + timedelta(seconds=i * step)),
                'end': stamp(start + timedelta(seconds=(i + 1) * step)), 'peak': peaks[i]}
               for i in range(len(peaks))]
    return jsonify(range=key, start=stamp(start), end=stamp(end),
                   buckets=buckets, total=max(peaks, default=0),
                   earliest_record=earliest, coverage_complete=False,
                   coverage_note='Recorded events only; collection gaps may exist. Zero means no clients online.')


@bp.get('/health')
@jwt_required()
def health():
    if get_jwt().get('role') != 'admin':
        return jsonify(error='Admin access required.'), 403
    from app.overview_health import service_health
    checked = stamp(datetime.now(timezone.utc))
    if not config.HUB_MODE:
        return jsonify(agent='Local deployment', service=service_health(), checked_at=checked)
    try:
        result = hub_client.call(config.DEFAULT_SERVER_ID, 'overview_health', timeout=3)
    except hub_client.HubClientError:
        return jsonify(agent='Unknown', service={'state': 'Unknown'}, checked_at=checked,
                       note='Could not reach the gateway or agent. Retry to check again.')
    if result.get('ok'):
        return jsonify(agent='Connected', service=result['result'], checked_at=checked)
    disconnected = result.get('error') == f'server #{config.DEFAULT_SERVER_ID} is not connected'
    return jsonify(agent='Disconnected' if disconnected else 'Unknown', service={'state': 'Unknown'},
                   checked_at=checked, note='Health check unavailable. Ensure the agent runs the updated version.')
