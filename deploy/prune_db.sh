#!/usr/bin/env bash
# Daily retention prune for the Postgres tables that are actual
# time-series logs. Run via pivpn-webui-prune-db.timer (see setup-
# prune-db.sh) — not on any request path, same reasoning as
# ingest_logs.py running on its own timer instead of per-page-load.
#
# vpn_events/traffic_flows/audit_log: 30 days — nothing in the UI looks
# back further than that (Logs' own range filter tops out at 7 days).
# login_failures: 1 day — it exists purely to count *recent* failed
# logins for rate-limiting, so a day-old row is already doing nothing
# there regardless of retention policy elsewhere.
#
# ip_org_cache and firewall_rules/users are deliberately excluded: the
# first is a permanent lookup cache (see its own CREATE TABLE comment —
# a cached "found nothing" result is meant to never expire), the other
# two are current-state tables, not logs — rows leave them when a rule/
# account is actually deleted, not on a timer.
set -euo pipefail

export PGPASSWORD="${PIVPN_WEBUI_DB_PASSWORD:?PIVPN_WEBUI_DB_PASSWORD not set — see .env}"

psql \
  -h "${PIVPN_WEBUI_DB_HOST:?PIVPN_WEBUI_DB_HOST not set — see .env}" \
  -U "${PIVPN_WEBUI_DB_USER:?PIVPN_WEBUI_DB_USER not set — see .env}" \
  -d "${PIVPN_WEBUI_DB_NAME:?PIVPN_WEBUI_DB_NAME not set — see .env}" \
  -v ON_ERROR_STOP=1 <<'SQL'
DELETE FROM vpn_events     WHERE ts < now() - interval '30 days';
DELETE FROM traffic_flows  WHERE ts < now() - interval '30 days';
DELETE FROM audit_log      WHERE ts < now() - interval '30 days';
DELETE FROM login_failures WHERE ts < now() - interval '1 day';
SQL
