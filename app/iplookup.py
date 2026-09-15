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
import ipaddress
import re
import subprocess

from app import db

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
    """None means "looked up, nothing usable came back" — the Traffic tab
    shows that as a blank Organization cell. A private/reserved address
    isn't worth a WHOIS query at all (there's no public registry entry to
    find) — its own IP is returned instead, so the column is never blank
    for internal traffic, just not an "organization" in the WHOIS sense."""
    try:
        if ipaddress.ip_address(ip).is_private:
            return ip
    except ValueError:
        return None

    found, cached = db.get_cached_ip_org(ip)
    if found:
        return cached

    whois_text = _run_whois(ip)
    org = extract_org(whois_text) if whois_text else None
    db.cache_ip_org(ip, org)
    return org
