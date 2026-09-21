#!/usr/bin/env python3
"""Hub-side gateway process for the hub/agent split (see config.py's
HUB_MODE docstring and app/hub_client.py).

Runs as its own long-lived process on the hub machine, separate from the
Flask app (gunicorn) — the one thing this app has that couldn't stay a
per-request WSGI call: something has to hold a live WebSocket connection
per remote box between requests. Two listeners, one asyncio event loop:

- A WebSocket server remote agents dial into (agent.py, running on each
  PiVPN box) and authenticate against the `servers` table (see
  app/db.py's create_server/verify_server_token).
- A Unix-domain-socket server the Flask app's (possibly several, one per
  gunicorn worker) processes connect to per call, via app/hub_client.py —
  one request in, one response out, this process does the actual
  agent-routing and request/response correlation in between.

db.py's functions are all blocking psycopg2 calls; every one used here
goes through asyncio.to_thread so it can't stall the event loop (and,
transitively, every other agent's connection) while waiting on Postgres.
"""
import asyncio
import json
import logging
import os
import ssl
import sys
import uuid
from pathlib import Path

import websockets

import config
from app import db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("hub_gateway")

AGENT_HOST = os.environ.get("GATEWAY_AGENT_HOST", "0.0.0.0")
AGENT_PORT = int(os.environ.get("GATEWAY_AGENT_PORT", "8765"))
HELLO_TIMEOUT = 10  # seconds to wait for an agent's first (hello) message
MAX_MESSAGE_BYTES = 64 * 1024 * 1024  # see websockets.serve() call in main()

# {server_id: websocket} — only ever one live entry per server_id; a
# second agent connecting with the same id (e.g. the box restarted its
# agent while the old TCP connection hadn't timed out yet) replaces it.
live_agents: dict[int, "websockets.WebSocketServerProtocol"] = {}

# {request_id: asyncio.Future} — resolved by handle_agent's read loop
# when the matching response arrives, awaited by handle_flask.
pending: dict[str, asyncio.Future] = {}


async def handle_agent(websocket):
    try:
        hello_raw = await asyncio.wait_for(websocket.recv(), timeout=HELLO_TIMEOUT)
    except (asyncio.TimeoutError, websockets.ConnectionClosed):
        log.warning("agent connection dropped before sending hello")
        return
    try:
        hello = json.loads(hello_raw)
        server_id = int(hello["server_id"])
        token = hello["token"]
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        await websocket.close(code=4000, reason="malformed hello")
        return

    valid = await asyncio.to_thread(db.verify_server_token, server_id, token)
    if not valid:
        log.warning("agent for server #%s rejected: bad token", server_id)
        await websocket.send(json.dumps({"type": "hello_ack", "ok": False, "error": "invalid server_id/token"}))
        await websocket.close(code=4001, reason="unauthorized")
        return

    live_agents[server_id] = websocket
    await asyncio.to_thread(db.touch_server_last_seen, server_id)
    await websocket.send(json.dumps({"type": "hello_ack", "ok": True}))
    log.info("agent for server #%s connected", server_id)

    try:
        async for raw in websocket:
            try:
                message = json.loads(raw)
                request_id = message["id"]
            except (json.JSONDecodeError, KeyError, TypeError):
                log.warning("server #%s sent an unparseable response: %r", server_id, raw)
                continue
            future = pending.pop(request_id, None)
            if future is not None and not future.done():
                future.set_result(message)
    except websockets.ConnectionClosed:
        pass
    finally:
        if live_agents.get(server_id) is websocket:
            del live_agents[server_id]
        log.info("agent for server #%s disconnected", server_id)


async def handle_flask(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        raw = await reader.read()
        request = json.loads(raw)
        server_id = int(request.pop("server_id"))
        timeout = request.get("timeout", 15)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        await _respond(writer, {"ok": False, "error": f"malformed request: {exc}"})
        return

    agent_ws = live_agents.get(server_id)
    if agent_ws is None:
        await _respond(writer, {"ok": False, "error": f"server #{server_id} is not connected"})
        return

    request_id = uuid.uuid4().hex
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    pending[request_id] = future
    try:
        await agent_ws.send(json.dumps({**request, "id": request_id}))
        response = await asyncio.wait_for(future, timeout=timeout + 5)
    except (asyncio.TimeoutError, websockets.ConnectionClosed) as exc:
        pending.pop(request_id, None)
        await _respond(writer, {"ok": False, "error": f"no response from server #{server_id}: {exc}"})
        return
    await _respond(writer, response)


async def _respond(writer: asyncio.StreamWriter, payload: dict):
    try:
        writer.write(json.dumps(payload).encode())
        await writer.drain()
    finally:
        writer.close()


def _build_tls_context() -> ssl.SSLContext | None:
    """None means plain ws:// (both GATEWAY_TLS_CERT/KEY unset — the
    default, matching every deployment that predates this). Refuses to
    start with only one of the two set, rather than silently falling back
    to plain ws:// on what's almost certainly a config typo."""
    if not config.GATEWAY_TLS_CERT and not config.GATEWAY_TLS_KEY:
        log.warning(
            "GATEWAY_TLS_CERT/GATEWAY_TLS_KEY not set — serving agent connections over "
            "plain ws://, unencrypted. See setup-hub-tls.sh to turn TLS on."
        )
        return None
    if not (config.GATEWAY_TLS_CERT and config.GATEWAY_TLS_KEY):
        log.error("Set both GATEWAY_TLS_CERT and GATEWAY_TLS_KEY, or neither — not just one.")
        sys.exit(1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(config.GATEWAY_TLS_CERT, config.GATEWAY_TLS_KEY)
    if config.GATEWAY_CLIENT_CA:
        # Mutual TLS: require every connecting agent to present a
        # certificate signed by this hub's own CA (see setup-hub-tls.sh
        # and manage_servers.py's register()) before the connection even
        # completes — a stolen hello token alone is no longer enough to
        # open a new connection, since forging an acceptable cert needs
        # the CA's private key too, which never leaves this hub.
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(config.GATEWAY_CLIENT_CA)
        # TLS 1.3 session tickets let a later connection resume an
        # earlier session without redoing the full handshake — in some
        # server/library combinations, that resumed handshake skips
        # re-verifying the client certificate rather than re-checking it.
        # Disabling tickets on this context removes that ambiguity
        # entirely: every connection goes through a full handshake with
        # real client-cert verification, every time. (The actual
        # enforcement was verified directly, repeatedly, with a real
        # WebSocket client — see the mTLS rollout notes.)
        ctx.options |= ssl.OP_NO_TICKET
    return ctx


async def main():
    socket_path = Path(config.GATEWAY_SOCKET_PATH)
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists():
        socket_path.unlink()  # stale socket from a previous, uncleanly-stopped run

    tls_ctx = _build_tls_context()

    await asyncio.start_unix_server(handle_flask, path=str(socket_path))
    # websockets' own default max_size (1 MiB) silently closes the whole
    # connection on anything bigger — real payloads here can badly exceed
    # that (e.g. a 7-day System log pull is genuinely several MB of raw
    # text), and a message that's merely large, from an already-
    # authenticated agent, isn't the kind of thing this cap is meant to
    # guard against. Bounded, not disabled (max_size=None) — still a real
    # ceiling against a truly pathological payload, just one sized for
    # this app's actual traffic instead of the library's generic default.
    await websockets.serve(handle_agent, AGENT_HOST, AGENT_PORT, max_size=MAX_MESSAGE_BYTES, ssl=tls_ctx)
    mtls = tls_ctx is not None and tls_ctx.verify_mode == ssl.CERT_REQUIRED
    log.info("listening for agents on %s:%s (%s%s), for Flask on %s",
              AGENT_HOST, AGENT_PORT, "wss://" if tls_ctx else "ws://",
              " mTLS-required" if mtls else "", socket_path)

    await asyncio.Future()  # run forever — cleanup is just process exit


if __name__ == "__main__":
    asyncio.run(main())
