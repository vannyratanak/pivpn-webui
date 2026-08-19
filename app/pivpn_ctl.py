"""Wrapper around the `pivpn` CLI (OpenVPN mode).

Verified against a real PiVPN install (OpenVPN, PiVPN scripts installed
2026-08-17): `pivpn add [nopass|-p <pass>] -n <name>`, `pivpn revoke -y
<name>`, `pivpn list`. Two things about `pivpn list`'s output that aren't
obvious from a quick glance: it always emits ANSI color codes even when
stdout isn't a tty, and its columns are Status/Name/Expiration — not
Name/Status/whatever you'd guess — with the first data row always being the
server's own certificate, not a client.

There is no built-in "renew" for OpenVPN certs in PiVPN — renew_client()
implements the standard community workaround (revoke + reissue under the
same name). The client must install the new .ovpn file; the old one stops
working the moment revoke happens.

Per-client static tunnel IPs (client-config-dir / ccd) are assigned and
cleaned up by PiVPN's own add/revoke scripts — this module only ever reads
that state (see get_client_ip), never writes it.

Still worth a sanity check on a different install: PiVPN's scripts have
drifted across releases/forks before. If something here doesn't match,
`pivpn -h` and `pivpn add -h` on the box will show the current syntax.
"""
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import config
from app.privileged import PrivilegedCommandError, run_root

CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class PivpnError(RuntimeError):
    pass


def validate_name(name: str) -> str:
    name = (name or "").strip()
    if not CLIENT_NAME_RE.match(name):
        raise PivpnError(
            f"Invalid client name '{name}': use letters, digits, '-' or '_' only (max 32 chars)."
        )
    return name


_validate_name = validate_name  # internal alias, kept short at call sites below


def _require_pivpn_binary() -> None:
    if shutil.which("pivpn") is None:
        raise PivpnError("`pivpn` command not found on PATH. Is PiVPN installed?")


def _run_pivpn(argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise PivpnError("`pivpn` command not found on PATH. Is PiVPN installed?") from exc
    except subprocess.TimeoutExpired as exc:
        raise PivpnError(f"`{' '.join(argv)}` timed out.") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise PivpnError(f"Failed to run `{' '.join(argv)}`: {exc}") from exc


def client_ovpn_path(name: str) -> Path:
    return Path(config.OVPN_DIR).expanduser() / f"{name}.ovpn"


def list_clients() -> list[dict]:
    """Parse `pivpn list`'s table into client rows, excluding the server's
    own certificate (always the first data row — see module docstring).

    Always fetched fresh, no caching — `pivpn list` itself is slow (PiVPN's
    own listOVPN.sh spawns ~5 subprocesses per line of the PKI cert index,
    valid and revoked both, so it scales with total certs ever issued —
    ~0.9s measured with ~20 clients, not something this app's code
    controls), but that cost is the tradeoff for this always reflecting the
    true current state — including a client added a different way, e.g.
    `pivpn add` run directly via SSH — rather than being up to a cache TTL
    stale."""
    result = _run_pivpn(["pivpn", "list"], timeout=20)
    if result.returncode != 0:
        raise PivpnError(result.stderr.strip() or "pivpn list failed")

    rows = []
    for raw_line in result.stdout.splitlines():
        line = _ANSI_RE.sub("", raw_line).strip()
        if not line or line.startswith(":"):
            continue
        if line.lower().startswith("status") and "name" in line.lower():
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        rows.append(
            {
                "status": parts[0],
                "name": parts[1],
                "expiration": parts[2] if len(parts) > 2 else "",
                "raw": line,
            }
        )
    return rows[1:]


def add_client(name: str, passphrase: str | None = None) -> Path:
    name = _validate_name(name)
    _require_pivpn_binary()
    if client_ovpn_path(name).exists():
        raise PivpnError(f"A client named '{name}' already exists.")

    if passphrase:
        argv = ["pivpn", "add", "-p", passphrase, "-n", name, "-d", config.PIVPN_CERT_DAYS]
    else:
        argv = ["pivpn", "add", "nopass", "-n", name, "-d", config.PIVPN_CERT_DAYS]

    result = _run_pivpn(argv)
    if result.returncode != 0:
        raise PivpnError((result.stdout + result.stderr).strip() or "pivpn add failed")

    if not client_ovpn_path(name).exists():
        raise PivpnError(
            f"pivpn add reported success but {client_ovpn_path(name)} was not found — "
            "check PIVPN_OVPN_DIR in your .env."
        )
    return client_ovpn_path(name)


def import_clients(text: str) -> tuple[int, list[str]]:
    """Add one client per non-blank, non-'#'-comment line: 'name=<name>
    passphrase=<optional>' (same key=value style as the firewall rule
    importer). Every line is independent — one bad line (duplicate name,
    invalid characters, etc.) doesn't stop the rest from importing.
    Returns (number added, list of 'line N: <error>' messages for the rest)."""
    added = 0
    errors = []
    for i, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line)
            fields = {}
            for tok in tokens:
                if "=" not in tok:
                    raise PivpnError(f"Expected key=value, got {tok!r}.")
                key, _, value = tok.partition("=")
                fields[key] = value
            name = fields.get("name", "")
            if not name:
                raise PivpnError("Missing name=... .")
            add_client(name, passphrase=fields.get("passphrase") or None)
            added += 1
        except PivpnError as exc:
            errors.append(f"line {i}: {exc}")
    return added, errors


def remove_client(name: str) -> None:
    name = _validate_name(name)
    _require_pivpn_binary()
    result = _run_pivpn(["pivpn", "revoke", "-y", name])
    if result.returncode != 0:
        raise PivpnError((result.stdout + result.stderr).strip() or "pivpn revoke failed")


def renew_client(name: str) -> Path:
    """Revoke + reissue under the same name (see module docstring)."""
    name = _validate_name(name)
    remove_client(name)
    return add_client(name)


def _parse_status_log(out: str) -> dict:
    """Parse one `status-version 3` OpenVPN status log (tab-separated,
    'CLIENT_LIST\t<name>\t<real addr>\t<virtual addr>\t<virtual ipv6>\t
    <bytes recv>\t<bytes sent>\t<connected since>\t...' rows — see the
    matching HEADER line for the full column list). This is the format
    PiVPN's `status-version 3` directive actually produces; the CSV-style
    'OpenVPN CLIENT LIST' format this used to look for is status-version 1
    and doesn't appear in a real install's log at all, so that old parser
    silently matched nothing, ever.
    """
    connected = {}
    for raw_line in out.splitlines():
        parts = raw_line.rstrip("\n").split("\t")
        if len(parts) < 8 or parts[0] != "CLIENT_LIST":
            continue
        name, real_addr = parts[1], parts[2]
        bytes_recv, bytes_sent, since = parts[5], parts[6], parts[7]
        connected[name] = {
            "real_address": real_addr,
            "bytes_recv": bytes_recv,
            "bytes_sent": bytes_sent,
            "since": since,
        }
    return connected


def list_connected_clients() -> dict:
    """Merge of clients connected right now, across every OpenVPN instance
    this box runs (production + the throwaway TCP-test instance used for
    the Cloudflare Tunnel reachability test — see status-tcp-test in
    deploy/pivpn-webui-ccd-helper.sh; remove that source once that instance
    is torn down).

    Returns {common_name: {"real_address", "bytes_recv", "bytes_sent", "since"}}.
    Empty dict (not an error) if a log is unreadable or nothing's connected —
    this is a "best effort" status view, not something client add/remove
    depends on. STATUS_LOG in deploy/pivpn-webui-ccd-helper.sh is verified
    against a real install's `grep '^status ' /etc/openvpn/server.conf`, but
    that path isn't guaranteed identical across PiVPN versions.
    """
    connected = {}
    for action in ("status", "status-tcp-test"):
        try:
            out = run_root([config.CCD_HELPER, action])
        except PrivilegedCommandError:
            continue
        connected.update(_parse_status_log(out))
    return connected


def list_client_ips() -> dict[str, str]:
    """Every client's static VPN IP in one call — {name: ip}. Use this
    instead of get_client_ip() when looking up more than one client, since
    the underlying CCD helper always lists everyone regardless; calling
    get_client_ip() per client in a loop re-runs that same privileged
    subprocess once per client for no reason (measured: ~2s each, so an
    N-client list page took ~2s * N instead of ~2s total)."""
    try:
        out = run_root([config.CCD_HELPER, "list"])
    except PrivilegedCommandError:
        return {}
    ips = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2:
            ips[parts[0]] = parts[1]
    return ips


def get_client_ip(name: str) -> str | None:
    """Static VPN IP PiVPN pinned for this client via client-config-dir
    (written by pivpn's own add script), or None if it hasn't connected/been
    assigned one yet. For looking up more than one client, use
    list_client_ips() instead — see its docstring."""
    return list_client_ips().get(name)
