#!/usr/bin/env python3
"""Agent-side process for the hub/agent split (see config.py's HUB_MODE
docstring and hub_gateway.py's module docstring for the full picture).

Runs on the PiVPN box itself, as the same non-root sudo user setup.sh
already creates — this doesn't change that box's privilege-separation
model at all, only *how* a command gets triggered: a WebSocket message
from the hub instead of an inbound Flask request. Dials OUT to the hub
(so no inbound port ever needs opening on this box) and, for every
request the hub sends, calls the exact same local-execution functions
(app/privileged.py's run_root, app/pivpn_ctl.py's _run_pivpn/
read_client_ovpn) a standalone (non-hub) deployment of this app already
uses — they naturally take their local-subprocess branch here since this
process's own .env has no reason to ever set HUB_MODE=true.
"""
import asyncio
import base64
import json
import logging
import re
import ssl
import subprocess
import sys

import websockets

import config
from app import pivpn_ctl, privileged

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("agent")

MIN_BACKOFF_SECONDS = 2
MAX_BACKOFF_SECONDS = 60
MAX_MESSAGE_BYTES = 64 * 1024 * 1024  # match hub_gateway.py's own max_size — see its comment


def _list_interfaces_local() -> list[str]:
    """Same logic as app/firewall.py's _list_interfaces_local — duplicated
    here (a few lines, stdlib only) rather than importing app.firewall,
    which pulls in app.db/psycopg2 for a function that itself never
    touches the database; agent.py's whole point is staying independent
    of anything the hub-side Flask app needs. Same reasoning applies to
    _server_ip_local/_iface_ip_local below."""
    try:
        out = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True, timeout=3,
        ).stdout
        names = re.findall(r"^\d+:\s+([^:@]+)[:@]", out, re.MULTILINE)
        return sorted(n for n in names if n != "lo")
    except (OSError, subprocess.SubprocessError):
        return []


def _server_ip_local() -> str:
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            capture_output=True, text=True, timeout=3,
        ).stdout
        m = re.search(r"\bsrc (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else "this server"
    except (OSError, subprocess.SubprocessError):
        return "this server"


def _iface_ip_local(iface: str) -> str:
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=3,
        ).stdout
        m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else iface
    except (OSError, subprocess.SubprocessError):
        return iface


def _resolve_real_address_local(address: str) -> str | None:
    """Same logic as app/vpnlog.py's _resolve_real_address_local —
    duplicated for the same reason as the other _local helpers above.
    This one specifically needs to run here rather than on the hub: the
    relay only trusts the forced-command SSH key generated for (and
    living only on) this box, not the hub's."""
    if not config.RELAY_HOST or not config.RELAY_TUNNEL_IP:
        return None
    ip, _, port = address.rpartition(":")
    if ip != config.RELAY_TUNNEL_IP or not port.isdigit():
        return None
    try:
        result = subprocess.run(
            [
                "ssh", "-o", "ConnectTimeout=3", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                f"{config.RELAY_SSH_USER}@{config.RELAY_HOST}",
                config.RELAY_LOOKUP_SCRIPT, port,
            ],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = result.stdout.strip()
    return out if result.returncode == 0 and out else None


async def _dispatch(message: dict) -> dict:
    action = message.get("action")
    try:
        if action == "run_root":
            result = await asyncio.to_thread(
                privileged.run_root, message["argv"], message.get("input_text"), message.get("timeout", 15)
            )
            return {"ok": True, "result": result}
        if action == "run_pivpn":
            result = await asyncio.to_thread(
                pivpn_ctl._run_pivpn, message["argv"], message.get("timeout", 30)
            )
            return {"ok": True, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        if action == "read_client_ovpn":
            data = await asyncio.to_thread(pivpn_ctl.read_client_ovpn, message["name"])
            return {"ok": True, "result": base64.b64encode(data).decode()}
        if action == "list_interfaces":
            names = await asyncio.to_thread(_list_interfaces_local)
            return {"ok": True, "result": names}
        if action == "server_ip":
            ip = await asyncio.to_thread(_server_ip_local)
            return {"ok": True, "result": ip}
        if action == "iface_ip":
            ip = await asyncio.to_thread(_iface_ip_local, message["iface"])
            return {"ok": True, "result": ip}
        if action == "resolve_real_address":
            addr = await asyncio.to_thread(_resolve_real_address_local, message["address"])
            return {"ok": True, "result": addr}
        return {"ok": False, "error": f"unknown action: {action!r}"}
    except (privileged.PrivilegedCommandError, pivpn_ctl.PivpnError) as exc:
        return {"ok": False, "error": str(exc)}
    except FileNotFoundError as exc:
        return {"ok": False, "error": f"not found: {exc}"}
    except Exception as exc:  # one bad/unexpected request must never kill the agent loop
        log.exception("unexpected error handling action %r", action)
        return {"ok": False, "error": f"unexpected agent error: {exc}"}


def _build_tls_context() -> ssl.SSLContext | None:
    """None for a plain ws:// HUB_URL (websockets.connect ignores ssl=None
    and just doesn't use TLS at all). For wss://, HUB_TLS_CERT pins trust
    to hub_gateway.py's own (self-signed) cert specifically, rather than
    the system's default CA trust store — a self-signed cert was never
    signed by anything in that store, so without this every connection
    attempt would fail verification. Left unset, falls back to the
    default trust store, which is correct the day hub_gateway.py ever
    gets a real CA-signed cert instead."""
    if not config.HUB_URL.startswith("wss://"):
        return None
    ctx = ssl.create_default_context()
    if config.HUB_TLS_CERT:
        ctx = ssl.create_default_context(cafile=config.HUB_TLS_CERT)
    return ctx


async def _run_until_disconnected():
    tls_ctx = _build_tls_context()
    async with websockets.connect(config.HUB_URL, max_size=MAX_MESSAGE_BYTES, ssl=tls_ctx) as websocket:
        await websocket.send(json.dumps(
            {"type": "hello", "server_id": config.AGENT_SERVER_ID, "token": config.AGENT_TOKEN}
        ))
        ack = json.loads(await websocket.recv())
        if not ack.get("ok"):
            log.error("hub rejected this agent (%s) — check AGENT_SERVER_ID/AGENT_TOKEN in .env", ack.get("error"))
            sys.exit(1)
        log.info("connected to hub as server #%s", config.AGENT_SERVER_ID)

        async for raw in websocket:
            try:
                message = json.loads(raw)
                request_id = message["id"]
            except (json.JSONDecodeError, KeyError, TypeError):
                log.warning("hub sent an unparseable request: %r", raw)
                continue
            response = await _dispatch(message)
            await websocket.send(json.dumps({**response, "id": request_id}))


async def main():
    if not (config.HUB_URL and config.AGENT_SERVER_ID and config.AGENT_TOKEN):
        log.error("HUB_URL, AGENT_SERVER_ID, and AGENT_TOKEN must all be set in the environment (.env).")
        sys.exit(1)
    if config.HUB_MODE:
        log.error("HUB_MODE must NOT be set on this box — this process IS the local executor.")
        sys.exit(1)

    backoff = MIN_BACKOFF_SECONDS
    while True:
        try:
            await _run_until_disconnected()
            backoff = MIN_BACKOFF_SECONDS  # a connection that worked, then later dropped — reset the backoff
        except Exception as exc:  # SystemExit (fatal auth rejection above) is not an Exception — propagates
            log.warning("hub connection lost (%s) — retrying in %ss", exc, backoff)
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
