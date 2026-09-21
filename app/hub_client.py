"""Flask-process side of the hub/agent split (see config.py's HUB_MODE).

Talks to hub_gateway.py — the separate process that actually holds the
live WebSocket connections to remote agents — over a local Unix domain
socket. One request per connection: connect, write one JSON line, read
until the gateway closes its end, parse the response. No persistent
connection/multiplexing needed here since gunicorn already gives each
worker its own OS process making its own short-lived calls; all the
actual multiplexing (routing a call to the right agent, matching replies
by request id) lives in hub_gateway.py, not here.
"""
import json
import socket

import config


class HubClientError(RuntimeError):
    pass


def call(server_id: int, action: str, timeout: int = 15, **params) -> dict:
    """Sends {"server_id", "action", **params} to hub_gateway.py and
    returns its parsed JSON response (an {"ok": True, ...} or
    {"ok": False, "error": ...} dict) — callers (app/privileged.py,
    app/pivpn_ctl.py) interpret those two shapes themselves, same as they
    already interpret a local subprocess.CompletedProcess.

    Raises HubClientError (never lets a raw socket/JSON exception escape)
    for anything that means the request never got a real answer at all —
    gateway not running, agent not connected, timeout, malformed
    response — as distinct from an {"ok": False} response, which means
    the agent *did* run the command and it failed."""
    request = json.dumps({"server_id": server_id, "action": action, **params}) + "\n"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout + 5)  # gateway enforces `timeout` itself; a little slack for its own overhead
        try:
            sock.connect(config.GATEWAY_SOCKET_PATH)
        except (FileNotFoundError, ConnectionRefusedError) as exc:
            raise HubClientError(
                f"hub_gateway.py isn't reachable at {config.GATEWAY_SOCKET_PATH} — is it running?"
            ) from exc
        sock.sendall(request.encode())
        sock.shutdown(socket.SHUT_WR)

        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    except socket.timeout as exc:
        raise HubClientError(f"Timed out waiting for server #{server_id} to respond.") from exc
    except OSError as exc:
        raise HubClientError(f"hub_gateway.py connection failed: {exc}") from exc
    finally:
        sock.close()

    try:
        return json.loads(b"".join(chunks))
    except json.JSONDecodeError as exc:
        raise HubClientError(f"hub_gateway.py returned a malformed response: {exc}") from exc
