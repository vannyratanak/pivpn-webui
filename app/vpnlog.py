"""Read-only journal access for the Logs page (Sessions + System tabs).

Goes through the pivpn-webui-log-helper.sh root helper (see deploy/ and
app/privileged.py) — three fixed journalctl invocations, no user input
reaches the shell.

IMPORTANT — verify before relying on this in production: OpenVPN's log
line format isn't strictly standardized across versions/configs. The
CONNECT_RE / DISCONNECT_RE patterns below match the commonly-seen
"Peer Connection Initiated" / "SIGTERM ... client-instance exiting"
messages, but if your server's `verb` level or log format differs, session
parsing may fall back to raw/unparsed rows rather than raise an error —
this is a "best effort" view, not something else depends on it.
"""
import re
from datetime import datetime

import config
from app.privileged import run_root

CONNECT_RE = re.compile(
    r"\[(?P<name>[^\]]+)\] Peer Connection Initiated with \[AF_INET6?\](?P<addr>[0-9a-fA-F:.]+):(?P<port>\d+)"
)
DISCONNECT_RE = re.compile(
    r"^(?P<name>[^/\s]+)/(?P<addr>[0-9a-fA-F:.]+):(?P<port>\d+) SIGTERM"
)

# journalctl -o short-iso lines look like: "2026-08-17T10:22:31+0700 host proc[pid]: message"
JOURNAL_LINE_RE = re.compile(r"^(?P<ts>\S+)\s+\S+\s+\S+?(?:\[\d+\])?:\s?(?P<msg>.*)$")


def _format_ts(ts: str) -> str:
    """journalctl -o short-iso gives '2026-08-17T10:22:31+0700' — reformat
    to the same 'YYYY-MM-DD HH:MM:SS' style used elsewhere in the app (see
    db.add_audit). The offset is dropped rather than shown, since it's just
    the box's own local timezone repeated on every single row."""
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ts


def _split_journal_line(raw_line: str) -> tuple[str, str]:
    m = JOURNAL_LINE_RE.match(raw_line)
    if not m:
        return "", raw_line
    return _format_ts(m.group("ts")), m.group("msg")


def _parse_openvpn_events() -> list[dict]:
    """Every connect/disconnect/other event from the OpenVPN service
    journal, oldest first (the order they actually happened in) — shared by
    list_sessions (raw event log) and list_client_sessions (paired into
    per-client sessions with a duration), so pairing always sees the full,
    correctly-ordered event stream rather than an already-reversed/truncated
    view."""
    out = run_root([config.LOG_HELPER, "openvpn"])
    events = []
    for raw_line in out.splitlines():
        ts, msg = _split_journal_line(raw_line.strip())
        if not msg:
            continue
        m = CONNECT_RE.search(msg)
        if m:
            events.append({
                "ts": ts, "event": "connected", "client": m.group("name"),
                "address": f"{m.group('addr')}:{m.group('port')}", "detail": "",
            })
            continue
        m = DISCONNECT_RE.search(msg)
        if m:
            events.append({
                "ts": ts, "event": "disconnected", "client": m.group("name"),
                "address": f"{m.group('addr')}:{m.group('port')}", "detail": "",
            })
            continue
        events.append({"ts": ts, "event": "other", "client": "", "address": "", "detail": msg})
    return events


def list_sessions(limit: int = 300) -> list[dict]:
    """Best-effort connect/disconnect events parsed from the OpenVPN
    service journal, most recent first."""
    events = _parse_openvpn_events()
    events.reverse()
    return events[:limit]


def _format_duration(start: str, end: str) -> str | None:
    try:
        start_dt = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
        end_dt = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None
    seconds = int((end_dt - start_dt).total_seconds())
    if seconds < 0:
        return None
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def list_client_sessions(limit: int = 300) -> list[dict]:
    """Per-client login sessions — each a paired connect+disconnect (or
    still-open connect with no disconnect yet), most recent first. Answers
    "how many sessions, when, how long" per client, as opposed to
    list_sessions' flat raw event log.

    A client reconnecting mid-window is handled by tracking one "currently
    open" connect per client name and closing it against that same client's
    next disconnect — correct for PiVPN's one-cert-per-client-name model,
    but would misattribute session boundaries if two devices ever shared a
    common name (not supported by pivpn add anyway).
    """
    events = _parse_openvpn_events()
    open_sessions: dict[str, dict] = {}
    sessions = []
    for e in events:
        if e["event"] == "connected":
            open_sessions[e["client"]] = {"start": e["ts"], "address": e["address"]}
        elif e["event"] == "disconnected":
            pending = open_sessions.pop(e["client"], None)
            start = pending["start"] if pending else None
            address = pending["address"] if pending else e["address"]
            sessions.append({
                "client": e["client"], "start": start, "end": e["ts"], "address": address,
                "duration": _format_duration(start, e["ts"]) if start else None,
                "ongoing": False,
            })
    for client, pending in open_sessions.items():
        sessions.append({
            "client": client, "start": pending["start"], "end": None,
            "address": pending["address"], "duration": None, "ongoing": True,
        })
    sessions.sort(key=lambda s: s["start"] or "", reverse=True)
    return sessions[:limit]


def list_webui_log(limit: int = 300) -> list[str]:
    out = run_root([config.LOG_HELPER, "webui"])
    lines = [ln for ln in out.splitlines() if ln.strip()]
    lines.reverse()
    return lines[:limit]


def list_system_log(limit: int = 300) -> list[str]:
    out = run_root([config.LOG_HELPER, "system"])
    lines = [ln for ln in out.splitlines() if ln.strip()]
    lines.reverse()
    return lines[:limit]
