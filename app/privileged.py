"""The only place in this app that shells out as root.

Everything here goes through `sudo -n` against a short, explicit allowlist
of binaries (see deploy/sudoers-pivpn-webui.template). Callers must build
argv as a list — never string-interpolate user input into a shell command.
"""
import subprocess


class PrivilegedCommandError(RuntimeError):
    pass


def run_root(argv: list[str], input_text: str | None = None, timeout: int = 15) -> str:
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
