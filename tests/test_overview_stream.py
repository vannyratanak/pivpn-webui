import asyncio
import contextlib
import select

from aiohttp.test_utils import TestClient, TestServer

from app import db
from app.overview_notify import install
from overview_stream import Broker, auth_app, create_stream_app
from tests.test_api import _admin_token, _moderator_token, _seed_client_status_cache


def listen():
    conn = db._connect()
    conn.autocommit = True
    conn.cursor().execute('LISTEN overview_changes')
    return conn


def notifications(conn, timeout=.15):
    select.select([conn], [], [], timeout)
    conn.poll()
    topics = [n.payload for n in conn.notifies]
    conn.notifies.clear()
    return topics


def test_notifications_after_commit_not_counters_or_rollback(temp_db):
    install()
    listener = listen()
    writer = db.get_conn()
    try:
        _seed_client_status_cache([{'name': 'one'}])
        assert notifications(listener) == ['snapshot']
        writer.execute("UPDATE client_status_cache SET session_bytes_recv='123', updated_at='later'")
        writer.commit()
        assert notifications(listener) == []
        writer.execute("UPDATE client_status_cache SET session_since='2026-09-25 10:00:00'")
        assert notifications(listener) == []
        writer.rollback()
        assert notifications(listener) == []
        writer.execute("UPDATE client_status_cache SET session_since='2026-09-25 10:00:00'")
        writer.commit()
        assert notifications(listener) == ['snapshot']
        db.insert_vpn_events([('2026-09-25 10:00:00', 'connected', 'one', '', '', None)])
        assert notifications(listener) == ['activity']
        db.insert_vpn_events([('2026-09-25 10:00:01', 'other', '', '', 'ordinary diagnostic', None)])
        assert notifications(listener) == []
        db.insert_system_log_lines([('2026-09-25 10:00:02', 'systemd', 'ordinary diagnostic')])
        assert notifications(listener) == []
        db.insert_system_log_lines([('2026-09-25 10:00:03', 'systemd-resolved', 'Clock change detected. Flushing caches.')])
        assert notifications(listener) == ['activity']
    finally:
        listener.close()
        writer.close()


def test_broker_bounds_slow_browser_backlog():
    broker = Broker()
    queue = asyncio.Queue(maxsize=16)
    broker.subscribers.add(queue)
    for _ in range(1000):
        broker.publish('snapshot')
    assert queue.qsize() <= 16
    assert 'resync' in list(queue._queue)
    broker.publish('auth')
    for _ in range(1000):
        broker.publish('snapshot')
    assert 'auth' in list(queue._queue)


def test_stream_auth_coalescing_health_permissions_and_disconnect(client):
    admin = _admin_token(client)
    moderator = _moderator_token(client)
    flask_app = auth_app()

    async def check():
        broker = Broker()
        broker.ready = True
        broker.health = {'agent': 'Connected', 'service': {'state': 'Running'}, 'checked_at': '2026-09-25 10:00:00'}
        async with TestClient(TestServer(create_stream_app(broker, flask_app))) as http:
            assert (await http.get('/api/overview/events')).status == 401
            assert (await http.get('/api/overview/events', headers={'Authorization': 'Bearer invalid'})).status == 401
            async def event(response):
                return (await asyncio.wait_for(response.content.readuntil(b'\n\n'), 3)).decode()
            a = await http.get('/api/overview/events', headers={'Authorization': f'Bearer {admin}'})
            m = await http.get('/api/overview/events', headers={'Authorization': f'Bearer {moderator}'})
            assert 'event: ready' in await event(a)
            assert 'event: ready' in await event(m)
            for _ in range(5):
                broker.publish('snapshot')
            assert 'event: changed' in await event(a)
            assert 'event: health' in await event(a)
            assert 'event: changed' in await event(m)
            # Health never reaches the moderator; auth invalidation ends both streams.
            broker.publish('auth')
            assert await asyncio.wait_for(m.content.read(), 3) == b''
            assert await asyncio.wait_for(a.content.read(), 3) == b''
            assert not broker.subscribers
            broker.ready = False
            assert (await http.get('/api/overview/events', headers={'Authorization': f'Bearer {admin}'})).status == 503
    asyncio.run(check())


def test_listener_wakes_on_committed_change_and_cleans_up(temp_db):
    install()
    async def check():
        broker = Broker()
        queue = asyncio.Queue(maxsize=16)
        broker.subscribers.add(queue)
        task = asyncio.create_task(broker.listen())
        try:
            assert await asyncio.wait_for(queue.get(), 3) == 'resync'
            await asyncio.to_thread(_seed_client_status_cache, [{'name': 'one'}])
            assert await asyncio.wait_for(queue.get(), 3) == 'snapshot'
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        assert not broker.ready
    asyncio.run(check())
