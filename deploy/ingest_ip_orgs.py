#!/usr/bin/env python3
"""Resolve organizations for traffic flows without slowing log ingestion.

Flow rows are committed with any already-cached organization value by
ingest_logs.py. This bounded worker fills cold cache misses separately so
new traffic appears immediately even when a WHOIS server is slow.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db, iplookup

BATCH_SIZE = 8  # matches iplookup's bounded WHOIS worker pool


def ingest_ip_orgs() -> int:
    ips = db.list_traffic_destinations_for_org_lookup(limit=BATCH_SIZE)
    if not ips:
        return 0
    orgs = iplookup.get_ip_orgs_bulk(ips)
    db.update_traffic_flow_orgs(orgs)
    return len(ips)


def main():
    count = ingest_ip_orgs()
    print(f"resolved organizations for {count} traffic destination(s)")


if __name__ == "__main__":
    main()
