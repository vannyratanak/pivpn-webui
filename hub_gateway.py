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
import re
import ssl
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import websockets

import config
from app import db, iplookup, vpnlog

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
_BATCH_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_FLOW_CURSOR_RE = re.compile(r"^[A-Za-z0-9_:=;.-]{1,2048}$")


def _traffic_batch_rows(events: list[dict]) -> tuple[list[tuple], str]:
    """Validate journal events and convert recognized kernel flow lines."""
    parsed = []
    last_cursor = None
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("invalid traffic event")
        cursor = event.get("cursor")
        message = event.get("message")
        realtime_us = event.get("realtime_us")
        if (not isinstance(cursor, str) or not _FLOW_CURSOR_RE.fullmatch(cursor)
                or not isinstance(message, str) or len(message) > 8192
                or not isinstance(realtime_us, str) or not realtime_us.isdigit()
                or len(realtime_us) > 20):
            raise ValueError("invalid traffic event fields")
        last_cursor = cursor
        match = vpnlog.FLOW_RE.search(message)
        if not match:
            continue
        try:
            ts = datetime.fromtimestamp(int(realtime_us) / 1_000_000, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OverflowError, OSError):
            continue
        parsed.append((ts, match))
    if not last_cursor:
        raise ValueError("empty traffic batch")

    ip_to_name = db.list_client_ip_name_map()
    orgs = iplookup.get_cached_ip_orgs([match.group("dst") for _, match in parsed])
    rows = []
    for ts, match in parsed:
        src, dst = match.group("src"), match.group("dst")
        rows.append((
            ts, src, dst, orgs.get(dst), ip_to_name.get(src), match.group("proto"),
            match.group("sport"), match.group("dport"), match.group("in_if"), match.group("out_if"),
        ))
    return rows, last_cursor


def _vpn_event_batch_rows(events: list[dict]) -> tuple[list[tuple], str]:
    """Convert OpenVPN journal events to the shared VPN Sessions rows."""
    rows = []
    last_cursor = None
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("invalid VPN event")
        cursor = event.get("cursor")
        message = event.get("message")
        realtime_us = event.get("realtime_us")
        if (not isinstance(cursor, str) or not _FLOW_CURSOR_RE.fullmatch(cursor)
                or not isinstance(message, str) or len(message) > 8192
                or not isinstance(realtime_us, str) or not realtime_us.isdigit()
                or len(realtime_us) > 20):
            raise ValueError("invalid VPN event fields")
        last_cursor = cursor
        try:
            ts = datetime.fromtimestamp(int(realtime_us) / 1_000_000, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OverflowError, OSError):
            continue
        match = vpnlog.CONNECT_RE.search(message)
        if match:
            rows.append((ts, "connected", match.group("name"),
                         f"{match.group('addr')}:{match.group('port')}", "", None))
            continue
        match = vpnlog.DISCONNECT_RE.search(message)
        if match:
            rows.append((ts, "disconnected", match.group("name"),
                         f"{match.group('addr')}:{match.group('port')}", "", None))
            continue
        rows.append((ts, "other", "", "", message, None))
    if not last_cursor:
        raise ValueError("empty VPN event batch")
    return rows, last_cursor


def _peer_cert_cn(websocket) -> str | None:
    """The verified TLS client certificate's Common Name, or None when
    mutual TLS is off (GATEWAY_CLIENT_CA unset — no client cert was ever
    required or requested) or the connection somehow has no cert. Unlike
    the hello message's fields, this can't be lied about — the transport
    already cryptographically verified whoever's holding this connection
    really does possess the private key matching a cert this hub's own
    CA signed, before this function ever runs."""
    transport = getattr(websocket, "transport", None)
    peercert = transport.get_extra_info("peercert") if transport else None
    if not peercert:
        return None
    for rdn in peercert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


async def _reject_hello(websocket, actor: str, server_id, reason: str, detail: str):
    log.warning("agent hello rejected (server_id=%s): %s", server_id, detail)
    await asyncio.to_thread(db.add_audit, actor, "agent_hello_rejected", f"server_id={server_id}", "error", detail)
    await websocket.send(json.dumps({"type": "hello_ack", "ok": False, "error": reason}))
    await websocket.close(code=4001, reason="unauthorized")


async def _mark_agent_disconnected(server_id: int, websocket):
    """Forget only the current socket and clear its cached live sessions."""
    if live_agents.get(server_id) is not websocket:
        return
    del live_agents[server_id]
    if server_id == config.DEFAULT_SERVER_ID:
        try:
            await asyncio.to_thread(db.apply_client_connection_snapshot, {})
        except Exception:
            log.exception("could not clear cached client sessions after agent disconnect")


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

    # Cross-check the certificate's identity (proven by the TLS handshake
    # itself) against what the hello *claims* to be — without this, mTLS
    # and the token check are two independent locks that happen to both
    # need to pass, but nothing ties them to the *same* claimed identity.
    # A cert for agent A plus a leaked token for agent B, presented
    # together, would otherwise still get through. Only runs at all when
    # mTLS is actually on (cert_cn is None otherwise, same as before this
    # existed).
    cert_cn = _peer_cert_cn(websocket)
    actor = cert_cn or f"server_id={server_id}"
    if cert_cn:
        cert_server = await asyncio.to_thread(db.get_server_by_name, cert_cn)
        if not cert_server or cert_server["id"] != server_id:
            await _reject_hello(
                websocket, actor, server_id, "identity mismatch",
                f"cert CN {cert_cn!r} doesn't match claimed server_id {server_id}",
            )
            return

    status = await asyncio.to_thread(db.verify_server_token, server_id, token)
    if status != "ok":
        await _reject_hello(
            websocket, actor, server_id, f"invalid server_id/token ({status})",
            f"{status} token",
        )
        return

    live_agents[server_id] = websocket
    await asyncio.to_thread(db.touch_server_last_seen, server_id)
    traffic_cursor = await asyncio.to_thread(db.get_traffic_flow_cursor, server_id)
    vpn_cursor = await asyncio.to_thread(db.get_vpn_event_cursor, server_id)
    await websocket.send(json.dumps({
        "type": "hello_ack", "ok": True, "traffic_cursor": traffic_cursor,
        "vpn_cursor": vpn_cursor,
        "traffic_enabled": server_id == config.DEFAULT_SERVER_ID,
    }))
    log.info("agent for server #%s connected", server_id)

    try:
        async for raw in websocket:
            try:
                message = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                log.warning("server #%s sent an unparseable response: %r", server_id, raw)
                continue
            if not isinstance(message, dict):
                log.warning("server #%s sent a non-object message", server_id)
                continue
            if message.get("type") == "client_status_snapshot":
                sessions = message.get("sessions")
                if (
                    server_id == config.DEFAULT_SERVER_ID
                    and isinstance(sessions, dict)
                    and len(sessions) <= 4096
                ):
                    safe_sessions = {
                        name: {
                            key: value for key, value in session.items()
                            if key in {
                                "real_address", "virtual_address", "bytes_recv",
                                "bytes_sent", "since",
                            }
                            and (value is None or isinstance(value, str))
                            and (value is None or len(value) <= 256)
                        }
                        for name, session in sessions.items()
                        if isinstance(name, str)
                        and 1 <= len(name) <= 32
                        and all(ch.isalnum() or ch in "_-" for ch in name)
                        and isinstance(session, dict)
                    }
                    await asyncio.to_thread(db.apply_client_connection_snapshot, safe_sessions)
                continue
            if message.get("type") == "traffic_flow_batch":
                batch_id = message.get("batch_id")
                events = message.get("events")
                ok = False
                if (server_id == config.DEFAULT_SERVER_ID
                        and isinstance(batch_id, str) and _BATCH_ID_RE.fullmatch(batch_id)
                        and isinstance(events, list) and 1 <= len(events) <= 50):
                    try:
                        rows, cursor = await asyncio.to_thread(_traffic_batch_rows, events)
                        await asyncio.to_thread(db.insert_agent_traffic_batch, server_id, rows, cursor)
                        ok = True
                    except (ValueError, TypeError):
                        log.warning("rejected invalid traffic batch from server #%s", server_id)
                    except Exception:
                        log.exception("failed to persist traffic batch from server #%s", server_id)
                await websocket.send(json.dumps({
                    "type": "traffic_flow_ack", "batch_id": batch_id, "ok": ok,
                }))
                continue
            if message.get("type") == "vpn_event_batch":
                batch_id = message.get("batch_id")
                events = message.get("events")
                ok = False
                if (server_id == config.DEFAULT_SERVER_ID
                        and isinstance(batch_id, str) and _BATCH_ID_RE.fullmatch(batch_id)
                        and isinstance(events, list) and 1 <= len(events) <= 50):
                    try:
                        rows, cursor = await asyncio.to_thread(_vpn_event_batch_rows, events)
                        await asyncio.to_thread(db.insert_agent_vpn_event_batch, server_id, rows, cursor)
                        ok = True
                    except (ValueError, TypeError):
                        log.warning("rejected invalid VPN event batch from server #%s", server_id)
                    except Exception:
                        log.exception("failed to persist VPN event batch from server #%s", server_id)
                await websocket.send(json.dumps({
                    "type": "vpn_event_ack", "batch_id": batch_id, "ok": ok,
                }))
                continue
            request_id = message.get("id")
            if not isinstance(request_id, str):
                log.warning("server #%s sent a message without a request id", server_id)
                continue
            future = pending.pop(request_id, None)
            if future is not None and not future.done():
                future.set_result(message)
    except websockets.ConnectionClosed:
        pass
    finally:
        # A lost agent cannot send a final empty-session snapshot. Clear
        # cached online state once this socket is known dead; an old
        # websocket closing after a reconnect must not clear the newer
        # connection's state.
        await _mark_agent_disconnected(server_id, websocket)
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
    await websockets.serve(
        handle_agent, AGENT_HOST, AGENT_PORT, max_size=MAX_MESSAGE_BYTES,
        ssl=tls_ctx, ping_interval=5, ping_timeout=5,
    )
    mtls = tls_ctx is not None and tls_ctx.verify_mode == ssl.CERT_REQUIRED
    log.info("listening for agents on %s:%s (%s%s), for Flask on %s",
              AGENT_HOST, AGENT_PORT, "wss://" if tls_ctx else "ws://",
              " mTLS-required" if mtls else "", socket_path)

    await asyncio.Future()  # run forever — cleanup is just process exit


if __name__ == "__main__":
    asyncio.run(main())
