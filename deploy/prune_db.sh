#!/usr/bin/env bash
# Daily retention prune for the Postgres tables that are actual
# time-series logs. Run via pivpn-webui-prune-db.timer (see setup-
# prune-db.sh) — not on any request path, same reasoning as
# ingest_logs.py running on its own timer instead of per-page-load.
#
# vpn_events/traffic_flows/system_log_lines/audit_log: 30 days — nothing
# in the UI looks back further than that (Logs' own range filter tops out
# at 7 days).
# login_failures: 1 day — it exists purely to count *recent* failed
# logins for rate-limiting, so a day-old row is already doing nothing
# there regardless of retention policy elsewhere.
#
# ip_org_cache and firewall_rules/users are deliberately excluded: the
# first is a permanent lookup cache (see its own CREATE TABLE comment —
# a cached "found nothing" result is meant to never expire), the other
# two are current-state tables, not logs — rows leave them when a rule/
# account is actually deleted, not on a timer.
#
# Every ts column here is TEXT (see app/db.py's migration notes — storing
# the exact same 'YYYY-MM-DD HH:MM:SS' strings the Python app itself
# formats/compares as strings), not TIMESTAMPTZ — `ts < now() - interval
# ...` alone is comparing text to a timestamptz, which Postgres refuses
# outright ("operator does not exist: text < timestamp with time zone"),
# not a type it silently coerces. Confirmed live: every DELETE below
# errored out under ON_ERROR_STOP, so this prune had never actually
# succeeded once — all five tables grew unbounded instead of being
# trimmed daily. ts::timestamp casts it back to a real timestamp for the
# comparison; the app's own local-time convention for these columns
# (see add_audit's docstring) makes the cast's implicit-timezone
# interpretation match what wrote them in the first place, and being off
# by a few hours either way is irrelevant at 30-day/1-day granularity.
set -euo pipefail

export PGPASSWORD="${PIVPN_WEBUI_DB_PASSWORD:?PIVPN_WEBUI_DB_PASSWORD not set — see .env}"

psql \
  -h "${PIVPN_WEBUI_DB_HOST:?PIVPN_WEBUI_DB_HOST not set — see .env}" \
  -U "${PIVPN_WEBUI_DB_USER:?PIVPN_WEBUI_DB_USER not set — see .env}" \
  -d "${PIVPN_WEBUI_DB_NAME:?PIVPN_WEBUI_DB_NAME not set — see .env}" \
  -v ON_ERROR_STOP=1 <<'SQL'
DELETE FROM vpn_events       WHERE ts::timestamp < now() - interval '30 days';
DELETE FROM traffic_flows    WHERE ts::timestamp < now() - interval '30 days';
DELETE FROM system_log_lines WHERE ts::timestamp < now() - interval '30 days';
DELETE FROM audit_log        WHERE ts::timestamp < now() - interval '30 days';
DELETE FROM login_failures   WHERE ts::timestamp < now() - interval '1 day';
SQL
