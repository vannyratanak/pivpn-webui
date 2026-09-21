"""The only place in this app that shells out as root.

Everything here goes through `sudo -n` against a short, explicit allowlist
of binaries (see deploy/sudoers-pivpn-webui.template). Callers must build
argv as a list — never string-interpolate user input into a shell command.
"""
import subprocess

import config
from app import hub_client


class PrivilegedCommandError(RuntimeError):
    pass


def run_root(argv: list[str], input_text: str | None = None, timeout: int = 15) -> str:
    if config.HUB_MODE:
        return _run_root_remote(argv, input_text, timeout)
    return _run_root_local(argv, input_text, timeout)


def _run_root_local(argv: list[str], input_text: str | None, timeout: int) -> str:
    cmd = ["sudo", "-n", *argv]
    try:
        result = subprocess.run(
            cmd, input=input_text, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError as exc:
        raise PrivilegedCommandError(f"command not found: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise PrivilegedCommandError(f"command timed out: {' '.join(argv)}") from exc
    if result.returncode != 0:
        raise PrivilegedCommandError(
            f"command failed ({' '.join(argv)}): {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


def _run_root_remote(argv: list[str], input_text: str | None, timeout: int) -> str:
    """Same contract as _run_root_local, but the sudo/subprocess call
    actually happens on agent.py, running on config.DEFAULT_SERVER_ID's
    box — see app/hub_client.py and hub_gateway.py for the round trip."""
    try:
        response = hub_client.call(
            config.DEFAULT_SERVER_ID, "run_root", argv=argv, input_text=input_text, timeout=timeout
        )
    except hub_client.HubClientError as exc:
        raise PrivilegedCommandError(str(exc)) from exc
    if not response.get("ok"):
        raise PrivilegedCommandError(response.get("error") or "remote run_root failed")
    return response.get("result", "")
