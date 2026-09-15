import subprocess
import threading

import config
from app import db, iplookup

# Real `whois <ip>` output, captured live for three real destinations seen
# in .10's Traffic tab (see app/iplookup.py's docstring for why the system
# client is used instead of a hand-rolled implementation) — not synthetic,
# since the exact field layout (an early IANA-referral 'organisation:'
# stub, followed by the real registry's block further down) is easy to get
# wrong by hand and only obvious from a real capture.

WHOIS_QUAD9 = """\
% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

refer:        whois.arin.net

inetnum:      9.0.0.0 - 9.255.255.255
organisation: Administered by ARIN
status:       LEGACY

whois:        whois.arin.net

changed:      1992-08
source:       IANA

# whois.arin.net

NetRange:       9.9.9.0 - 9.9.9.255
CIDR:           9.9.9.0/24
NetName:        CLEAN-97
NetHandle:      NET-9-9-9-0-1
Parent:         NET9 (NET-9-0-0-0-0)
NetType:        Direct Allocation
Organization:   Quad9 (CLEAN-97)
RegDate:        2017-09-13
Updated:        2025-10-21

OrgName:        Quad9
OrgId:          CLEAN-97
Address:        1442A Walnut Street, Suite 501
City:           Berkeley
StateProv:      CA
Country:        US
"""

WHOIS_APPLE = """\
% IANA WHOIS server

refer:        whois.arin.net

inetnum:      17.0.0.0 - 17.255.255.255
organisation: Apple Computer Inc.
status:       LEGACY

# whois.arin.net

NetRange:       17.0.0.0 - 17.255.255.255
CIDR:           17.0.0.0/8
NetName:        APPLE-WWNET
Organization:   Apple Inc. (APPLEC-1-Z)
RegDate:        1990-04-16

OrgName:        Apple Inc.
OrgId:          APPLEC-1-Z
Address:        One Apple Park Way
City:           Cupertino
Country:        US
"""

# RIPE-registered blocks (Meta's) never have an OrgName field at all —
# org-name (hyphenated) is the RIPE equivalent, and it sits *after*
# netname in the raw text, which is exactly the ordering the priority
# list in iplookup._ORG_FIELDS has to get right.
WHOIS_META = """\
% IANA WHOIS server

refer:        whois.ripe.net

inetnum:      57.0.0.0 - 57.255.255.255
organisation: Administered by RIPE NCC
status:       LEGACY

# whois.ripe.net

inetnum:        57.141.0.0 - 57.149.255.255
netname:        FB-BLOCK
country:        IE
org:            ORG-FIL7-RIPE
source:         RIPE

organisation:   ORG-FIL7-RIPE
org-name:       Meta Platforms Ireland Limited
country:        IE
address:        Merrion Road Dublin 4
source:         RIPE # Filtered
"""


def test_extract_org_prefers_orgname_over_ripe_stub():
    assert iplookup.extract_org(WHOIS_QUAD9) == "Quad9"


def test_extract_org_prefers_orgname_over_organisation_stub():
    # 'organisation: Apple Computer Inc.' appears earlier in the text but
    # isn't one of the targeted field names — OrgName (a different, later
    # field) should win.
    assert iplookup.extract_org(WHOIS_APPLE) == "Apple Inc."


def test_extract_org_falls_back_to_org_name_when_no_orgname_field():
    # RIPE responses have no 'OrgName:' at all — org-name (hyphenated)
    # must be found even though netname appears earlier in the text.
    assert iplookup.extract_org(WHOIS_META) == "Meta Platforms Ireland Limited"


def test_extract_org_no_match_returns_none():
    assert iplookup.extract_org("nothing usable here\njust noise\n") is None


def _use_temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()


def test_get_ip_org_private_address_skips_whois_entirely(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)

    def fail_if_called(*a, **k):
        raise AssertionError("whois should never be invoked for a private address")

    monkeypatch.setattr(subprocess, "run", fail_if_called)
    assert iplookup.get_ip_org("192.168.100.10") == "Private network"


def test_get_ip_org_malformed_address_returns_none(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    assert iplookup.get_ip_org("not-an-ip") is None


def test_get_ip_org_live_lookup_then_cached(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    calls = []

    def run(argv, capture_output, text, timeout):
        calls.append(argv)
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout=WHOIS_QUAD9, stderr="")

    monkeypatch.setattr(subprocess, "run", run)

    assert iplookup.get_ip_org("9.9.9.9") == "Quad9"
    assert iplookup.get_ip_org("9.9.9.9") == "Quad9"
    # second call must be served from db.ip_org_cache, not a second WHOIS query
    assert len(calls) == 1


def test_get_ip_org_failed_lookup_cached_as_none_not_retried(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    calls = []

    def run(argv, capture_output, text, timeout):
        calls.append(argv)
        raise subprocess.TimeoutExpired(cmd="whois", timeout=5)

    monkeypatch.setattr(subprocess, "run", run)

    assert iplookup.get_ip_org("1.1.1.1") is None
    assert iplookup.get_ip_org("1.1.1.1") is None
    assert len(calls) == 1  # cached failure, not retried on every call


def test_get_ip_org_whois_binary_missing_returns_none_not_raise(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)

    def raise_oserror(*a, **k):
        raise OSError("whois: command not found")

    monkeypatch.setattr(subprocess, "run", raise_oserror)
    assert iplookup.get_ip_org("1.1.1.1") is None


def test_get_ip_orgs_bulk_dedups_private_cached_and_malformed_without_whois(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    db.cache_ip_org("9.9.9.9", "Quad9")  # pre-warm one entry, as if a prior request cached it

    def fail_if_called(*a, **k):
        raise AssertionError("whois should never be invoked for private/cached/malformed addresses")

    monkeypatch.setattr(subprocess, "run", fail_if_called)

    result = iplookup.get_ip_orgs_bulk(
        ["192.168.100.10", "192.168.100.10", "9.9.9.9", "not-an-ip"]
    )

    assert result == {
        "192.168.100.10": "Private network",
        "9.9.9.9": "Quad9",
        "not-an-ip": None,
    }


def test_get_ip_orgs_bulk_looks_up_each_unique_miss_once_and_caches(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    calls = []
    lock = threading.Lock()

    def run(argv, capture_output, text, timeout):
        with lock:
            calls.append(argv[-1])
        stdout = WHOIS_QUAD9 if argv[-1] == "9.9.9.9" else WHOIS_APPLE
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(subprocess, "run", run)

    result = iplookup.get_ip_orgs_bulk(["9.9.9.9", "17.0.0.1", "9.9.9.9"])

    assert result == {"9.9.9.9": "Quad9", "17.0.0.1": "Apple Inc."}
    assert sorted(calls) == ["17.0.0.1", "9.9.9.9"]  # each unique miss queried exactly once
    # both now served from cache, same as a subsequent page render would see
    assert iplookup.get_ip_org("9.9.9.9") == "Quad9"
    assert iplookup.get_ip_org("17.0.0.1") == "Apple Inc."


def test_get_ip_orgs_bulk_runs_misses_concurrently_not_serially(tmp_path, monkeypatch):
    # Two never-before-seen IPs, each blocking until both lookups are
    # in flight at once — proves the batch doesn't serialize N subprocess
    # timeouts in the request thread (the exact slowness this function
    # exists to fix). Would deadlock/timeout under the old one-at-a-time
    # get_ip_org loop.
    both_started = threading.Barrier(2, timeout=5)

    def run(argv, capture_output, text, timeout):
        both_started.wait()
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout=WHOIS_QUAD9, stderr="")

    _use_temp_db(tmp_path, monkeypatch)
    monkeypatch.setattr(subprocess, "run", run)

    result = iplookup.get_ip_orgs_bulk(["9.9.9.9", "8.8.8.8"])

    assert result == {"9.9.9.9": "Quad9", "8.8.8.8": "Quad9"}
