"""Best-effort destination-IP -> organization lookup for the Traffic log
(see vpnlog.list_traffic_flows).

Shells out to the system `whois` client rather than hand-rolling WHOIS's
own referral-chasing (a query to whois.iana.org typically just points you
at the real regional registry — ARIN/RIPE/APNIC/LACNIC/AFRINIC — each with
its own response format) since a mature client already handles that far
more reliably than a from-scratch implementation would. Needs the `whois`
package installed on the server (see README) — a missing binary degrades
to "no organization found" for everything, same as any other lookup
failure, never an error.

Every result is cached in the DB (db.ip_org_cache), including a failed
lookup (as NULL) — org-to-IP-block ownership essentially never changes, a
live WHOIS query is a real network round-trip, and the Traffic tab can
have hundreds of rows that are mostly repeats of a handful of
destinations. Without this, a busy Traffic tab would mean a burst of WHOIS
queries on every single page load, both slow and a good way to get
rate-limited by a WHOIS server.
"""
import concurrent.futures
import ipaddress
import re
import subprocess

from app import db

# Bounds how many `whois` processes list_traffic_flows() can have in flight
# at once for a single page render's batch of never-before-seen
# destinations — high enough that a normal miss batch (a handful to a few
# dozen IPs, per vpnlog's own dedup) finishes in roughly one timeout period
# instead of N, low enough not to fire off hundreds of processes/sockets at
# once if a page render ever hits an unusually large miss batch.
_MAX_CONCURRENT_WHOIS = 8

# Priority order matters: a raw `whois <ip>` on an ARIN-referred address
# includes both the IANA referral stub's generic 'organisation:' line and
# ARIN's own, more specific 'OrgName:' line further down — searching for
# specific field names (never the bare word "organisation") and stopping
# at the first one found in this order picks the most specific value
# regardless of which order they appear in the raw text.
_ORG_FIELDS = ("OrgName", "org-name", "descr", "owner", "netname")


def _run_whois(ip: str) -> str | None:
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 and result.stdout else None


def extract_org(whois_text: str) -> str | None:
    for field in _ORG_FIELDS:
        m = re.search(rf"^{re.escape(field)}:\s*(.+)$", whois_text, re.IGNORECASE | re.MULTILINE)
        if m:
            value = m.group(1).strip()
            if value:
                return value
    return None


def get_ip_org(ip: str) -> str | None:
    """None means either "private/reserved address" (not worth a WHOIS
    query at all) or "looked up, nothing usable came back" — both cases
    the Traffic tab just shows as a blank Organization cell."""
    try:
        if ipaddress.ip_address(ip).is_private:
            return "Private network"
    except ValueError:
        return None

    found, cached = db.get_cached_ip_org(ip)
    if found:
        return cached

    whois_text = _run_whois(ip)
    org = extract_org(whois_text) if whois_text else None
    db.cache_ip_org(ip, org)
    return org


def get_ip_orgs_bulk(ips: list[str]) -> dict[str, str | None]:
    """Same lookup/caching rules as get_ip_org, one call per unique IP in
    `ips`, but resolves every not-yet-cached address's WHOIS query
    concurrently instead of one at a time.

    get_ip_org's subprocess.run has a 5s timeout, and a slow/unreachable
    registry hits that timeout in full rather than failing fast — called
    in a loop (as vpnlog.list_traffic_flows originally did), a batch of N
    never-before-seen destinations pays up to N*5s serially in the request
    thread. Real-world traffic tabs regularly see batches like this: CDN
    edges (Fastly, Akamai, Google, etc.) hand out many distinct IPs that
    are each individually rare, so the DB cache doesn't shield a given page
    render as much as the per-destination repeat rate might suggest.
    Running the misses through a bounded thread pool instead means the
    whole batch takes roughly as long as its single slowest lookup."""
    result: dict[str, str | None] = {}
    to_query: list[str] = []
    for ip in dict.fromkeys(ips):
        try:
            if ipaddress.ip_address(ip).is_private:
                result[ip] = "Private network"
                continue
        except ValueError:
            result[ip] = None
            continue
        found, cached = db.get_cached_ip_org(ip)
        if found:
            result[ip] = cached
        else:
            to_query.append(ip)

    if to_query:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(_MAX_CONCURRENT_WHOIS, len(to_query))
        ) as pool:
            future_to_ip = {pool.submit(_run_whois, ip): ip for ip in to_query}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                whois_text = future.result()
                org = extract_org(whois_text) if whois_text else None
                db.cache_ip_org(ip, org)
                result[ip] = org

    return result
