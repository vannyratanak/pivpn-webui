#!/usr/bin/env python3
"""Async Overview SSE endpoint. One PostgreSQL LISTEN socket for all viewers.

Run behind nginx on loopback; intentionally separate from gunicorn's finite
request-thread pool. Events invalidate only the affected dashboard projection.
"""
import asyncio
import contextlib
import json
import logging
import time
from datetime import datetime, timezone

from aiohttp import web
from flask import Flask
from flask_jwt_extended import get_jwt, verify_jwt_in_request

import config
from app import db, jwt, hub_client
from app.overview_health import service_health
from app.overview_notify import install

log = logging.getLogger(__name__)


def auth_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = config.JWT_SECRET_KEY
    jwt.init_app(app)  # Includes the normal session-generation revocation check.
    return app


def authenticate(app, authorization):
    with app.test_request_context(headers={'Authorization': authorization}):
        verify_jwt_in_request()
        return dict(get_jwt())


def read_health():
    result = {'agent': 'Local deployment', 'service': {'state': 'Unknown'}}
    if config.HUB_MODE:
        try:
            reply = hub_client.call(config.DEFAULT_SERVER_ID, 'overview_health', timeout=3)
            if reply.get('ok'):
                result = {'agent': 'Connected', 'service': reply['result']}
            else:
                disconnected = reply.get('error') == f'server #{config.DEFAULT_SERVER_ID} is not connected'
                result = {'agent': 'Disconnected' if disconnected else 'Unknown', 'service': {'state': 'Unknown'}}
        except hub_client.HubClientError:
            result = {'agent': 'Unknown', 'service': {'state': 'Unknown'}}
    else:
        result['service'] = service_health()
    result['checked_at'] = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    return result


class Broker:
    def __init__(self):
        self.subscribers = set()
        self.health = None
        self.ready = False

    def publish(self, topic):
        for queue in tuple(self.subscribers):
            # A slow browser gets a bounded resync signal, never an event backlog.
            if queue.full():
                pending = set()
                while not queue.empty():
                    pending.add(queue.get_nowait())
                queue.put_nowait('auth' if 'auth' in pending else 'offline' if 'offline' in pending else 'resync')
            if not queue.full():
                queue.put_nowait(topic)

    async def listen(self):
        loop = asyncio.get_running_loop()
        while True:
            conn = None
            fd = None
            try:
                conn = await asyncio.to_thread(db._connect)
                conn.autocommit = True
                await asyncio.to_thread(conn.cursor().execute, 'LISTEN overview_changes')
                wake = asyncio.Event()
                fd = conn.fileno()
                loop.add_reader(fd, wake.set)
                self.ready = True
                self.publish('resync')  # Covers changes missed during DB reconnect.
                while True:
                    await wake.wait()
                    wake.clear()
                    conn.poll()
                    topics = {n.payload for n in conn.notifies}
                    conn.notifies.clear()
                    for topic in topics:
                        if topic in {'snapshot', 'activity', 'auth', 'vpn_logs', 'traffic_logs', 'system_logs', 'activity_logs', 'auth_logs'}:
                            self.publish(topic)
            except Exception:
                log.exception('Overview notification listener disconnected')
            finally:
                self.ready = False
                self.publish('offline')
                if fd is not None:
                    loop.remove_reader(fd)
                if conn is not None:
                    conn.close()
            await asyncio.sleep(3)

    async def health_loop(self):
        while True:
            try:
                self.health = await asyncio.to_thread(read_health)
                self.publish('health')
            except Exception:
                log.exception('Overview health check failed')
            await asyncio.sleep(30)  # One probe shared by every viewer.


def frame(event, data):
    return f'event: {event}\ndata: {json.dumps(data)}\n\n'.encode()


def create_stream_app(broker=None, flask_app=None):
    broker = broker or Broker()
    flask_app = flask_app or auth_app()
    app = web.Application()

    async def events(request):
        try:
            claims = await asyncio.to_thread(authenticate, flask_app, request.headers.get('Authorization', ''))
        except Exception:
            raise web.HTTPUnauthorized()
        if not broker.ready:
            raise web.HTTPServiceUnavailable()
        queue = asyncio.Queue(maxsize=16)
        broker.subscribers.add(queue)
        response = web.StreamResponse(headers={'Content-Type': 'text/event-stream',
                                               'Cache-Control': 'no-cache, no-store',
                                               'X-Accel-Buffering': 'no'})
        try:
            await response.prepare(request)
            await response.write(frame('ready', {}))
            queue.put_nowait('health')
            while time.time() < claims['exp']:
                try:
                    topic = await asyncio.wait_for(queue.get(), timeout=min(15, max(.01, claims['exp'] - time.time())))
                except asyncio.TimeoutError:
                    await asyncio.wait_for(response.write(b': keepalive\n\n'), timeout=5)
                    continue
                topics = {topic}
                await asyncio.sleep(.5)  # Coalesce bursts across transactions.
                while not queue.empty():
                    topics.add(queue.get_nowait())
                if topics & {'auth', 'offline'}:
                    break  # Reconnect must authenticate and resync.
                if 'resync' in topics:
                    topics.update(('snapshot', 'activity'))
                changed = topics & {'snapshot', 'activity', 'vpn_logs', 'traffic_logs', 'system_logs', 'activity_logs', 'auth_logs'}
                if claims.get('role') != 'admin':
                    # Moderators may see client status, VPN client sessions,
                    # and auth events, but no admin-only system/traffic/audit
                    # activity signal side channel.
                    changed &= {'snapshot', 'activity', 'vpn_logs', 'auth_logs'}
                changed = sorted(changed)
                if changed:
                    await asyncio.wait_for(response.write(frame('changed', changed)), timeout=5)
                if 'health' in topics and claims.get('role') == 'admin' and broker.health:
                    await asyncio.wait_for(response.write(frame('health', broker.health)), timeout=5)
        except (ConnectionError, asyncio.TimeoutError):
            pass
        finally:
            broker.subscribers.discard(queue)
        return response

    app.router.add_get('/api/overview/events', events)
    return app


async def run():
    config.require_secrets()
    await asyncio.to_thread(install)
    broker = Broker()
    tasks = [asyncio.create_task(broker.listen()), asyncio.create_task(broker.health_loop())]
    runner = web.AppRunner(create_stream_app(broker), shutdown_timeout=5)
    await runner.setup()
    await web.TCPSite(runner, '127.0.0.1', 8766).start()
    try:
        await asyncio.Event().wait()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await runner.cleanup()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(run())
