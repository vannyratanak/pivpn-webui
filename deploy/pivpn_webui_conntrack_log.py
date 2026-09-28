#!/usr/bin/env python3
"""Normalize conntrack NEW events into the VPNFLOW format consumed by the hub."""
import re
import sys


EVENT_RE = re.compile(r"^\[(?P<epoch>\d+(?:\.\d+)?)\]\s+\[NEW\]\s+ipv\d+\s+\d+\s+\S+\s+\d+\s+.*?\bsrc=(?P<src>[0-9a-fA-F:.]+)\s+dst=(?P<dst>[0-9a-fA-F:.]+)(?:\s+sport=(?P<sport>\d+)\s+dport=(?P<dport>\d+))?(?:\s|$)")
PROTO_RE = re.compile(r"^\[\d+(?:\.\d+)?\]\s+\[NEW\]\s+ipv\d+\s+\d+\s+(?P<proto>\S+)")


def normalize(line: str) -> str | None:
    match = EVENT_RE.search(line.strip())
    proto = PROTO_RE.search(line.strip())
    if not match or not proto:
        return None
    try:
        realtime_us = str(round(float(match.group("epoch")) * 1_000_000))
    except (ValueError, OverflowError):
        return None
    ports = ""
    if match.group("sport") and match.group("dport"):
        ports = f" SPT={match.group('sport')} DPT={match.group('dport')}"
    return (
        "VPNFLOW IN= OUT= "
        f"SRC={match.group('src')} DST={match.group('dst')} "
        f"PROTO={proto.group('proto').upper()}{ports} HOST_REALTIME_US={realtime_us}"
    )


def main() -> None:
    for line in sys.stdin:
        event = normalize(line)
        if event:
            print(event, flush=True)


if __name__ == "__main__":
    main()
