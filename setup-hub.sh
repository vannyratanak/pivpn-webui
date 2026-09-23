#!/usr/bin/env bash
# One-time setup for the HUB in a hub/agent deployment — the machine that
# runs the Flask app + Postgres + hub_gateway.py, and that every agent box
# dials into. Run this ONCE on whatever machine will *permanently* be the
# hub — not a laptop that closes/sleeps/changes networks; every agent's
# HUB_URL points at this machine's address and expects it reachable at
# all times. See README's "Hub/agent deployment" section for the full
# manual walkthrough this automates.
#
# Wraps setup.sh (base install: venv/Postgres/admin account/standalone
# systemd unit — still needed here, since the Flask app itself runs on
# the hub), passing HUB_ONLY_INSTALL=1 so it skips the 4 privileged
# helper scripts + their sudoers grant + the CRL permission watcher —
# all local-PiVPN-only concerns a hub with no PiVPN installed never
# exercises (see setup.sh's own comment on why). Then everything
# hub-specific on top: HUB_MODE config, TLS for the agent-facing
# WebSocket, hub_gateway.py's own systemd unit, the background
# log/client ingestion timers, and (optionally) registering the first
# agent box.
#
# Safe to re-run: every step either already no-ops on a second run
# (setup.sh's own DB role handling, the systemd/TLS installs below all
# check for existing files/config first) or explicitly asks before doing
# anything that isn't (agent registration always creates a brand new
# server_id — see manage_servers.py's own docstring on why there's no
# "re-register the same box" case).
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
  echo "Run this as your normal user, not root/sudo." >&2
  exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

echo "======================================================"
echo " PiVPN Web UI — one-time HUB setup"
echo "======================================================"
echo
echo "This machine will run the web UI, the database, and the always-on"
echo "connection every agent box dials into. It does NOT need PiVPN/"
echo "OpenVPN installed locally — this app never touches this machine's"
echo "own firewall/VPN config, only whichever agent(s) you register below."
echo

if [[ ! -x venv/bin/python3 || ! -f .env ]]; then
  echo "== Step 1/6: base install (venv, Postgres, admin account) =="
  echo "(The OpenVPN-related prompts below don't matter for a hub — this"
  echo " box has no local PiVPN install — defaults are fine.)"
  echo
  HUB_ONLY_INSTALL=1 ./setup.sh
else
  echo "== Step 1/6: base install already done (venv/.env exist) — skipping setup.sh =="
  echo "   (remove venv/ and .env first if you want to redo it from scratch)"
fi

echo
echo "== Ensuring WHOIS is installed on the hub (organization lookups run here) =="
./deploy/install-whois.sh

# shellcheck disable=SC1091
source venv/bin/activate

echo
echo "== Step 2/6: turning on HUB_MODE =="
if grep -q '^HUB_MODE=' .env 2>/dev/null; then
  echo "HUB_MODE already set in .env — leaving it as-is."
else
  read -rp "DEFAULT_SERVER_ID for this hub's primary agent [1]: " DEFAULT_SERVER_ID
  DEFAULT_SERVER_ID="${DEFAULT_SERVER_ID:-1}"
  {
    echo ""
    echo "HUB_MODE=true"
    echo "DEFAULT_SERVER_ID=${DEFAULT_SERVER_ID}"
  } >> .env
  echo "Added HUB_MODE=true and DEFAULT_SERVER_ID=${DEFAULT_SERVER_ID} to .env"
fi

echo
echo "== Step 3/6: TLS for the agent-facing connection (mutual TLS) =="
if [[ -f instance/hub-gateway.crt && -f instance/hub-ca.crt ]]; then
  echo "Certs already exist at instance/hub-gateway.crt and instance/hub-ca.crt — skipping."
else
  ./setup-hub-tls.sh
fi

# Wire GATEWAY_TLS_CERT/KEY + GATEWAY_CLIENT_CA into .env automatically —
# setup-hub-tls.sh only prints these (it's also meant to be runnable
# standalone/re-run without assuming a specific .env layout); this script
# can safely append them since it just confirmed/created .env itself.
if ! grep -q '^GATEWAY_TLS_CERT=' .env 2>/dev/null; then
  {
    echo ""
    echo "GATEWAY_TLS_CERT=${APP_DIR}/instance/hub-gateway.crt"
    echo "GATEWAY_TLS_KEY=${APP_DIR}/instance/hub-gateway.key"
    echo "GATEWAY_CLIENT_CA=${APP_DIR}/instance/hub-ca.crt"
  } >> .env
  echo "Added GATEWAY_TLS_CERT/GATEWAY_TLS_KEY/GATEWAY_CLIENT_CA to .env"
fi

echo
echo "== Step 4/6: installing hub systemd services =="
CURRENT_USER="$(whoami)"

SERVICE_TMP="$(mktemp)"
sed -e "s#__APP_DIR__#${APP_DIR}#g" -e "s/__USER__/${CURRENT_USER}/g" \
  deploy/pivpn-webui-hub-gateway.service.template > "$SERVICE_TMP"
sudo install -m 0644 "$SERVICE_TMP" /etc/systemd/system/pivpn-webui-hub-gateway.service
rm -f "$SERVICE_TMP"

sudo systemctl daemon-reload
sudo systemctl enable --now pivpn-webui-hub-gateway
sudo systemctl enable --now pivpn-webui
echo "hub_gateway.py and the Flask app are both running as systemd services now."

echo
echo "== Step 5/6: background ingestion (Clients/Logs pages read from the"
echo "             DB instead of a live agent round-trip on every load) =="
./deploy/setup-log-ingest.sh
./deploy/setup-client-ingest.sh

echo
echo "== Step 6/6: register the first agent box =="
read -rp "Register an agent now? Give it a name (blank to skip and do this later): " AGENT_NAME
if [[ -n "$AGENT_NAME" ]]; then
  python3 manage_servers.py register "$AGENT_NAME"
else
  echo "Skipped — run 'python3 manage_servers.py register <name>' any time later to add one."
fi

echo
echo "======================================================"
echo " Hub setup complete."
echo "======================================================"
echo
echo "Web UI is up on this machine at http://127.0.0.1:8443 (bound to"
echo "localhost by default — see README's 'Accessing it remotely' section"
echo "for putting nginx + a real TLS cert in front of it: ./setup-nginx.sh)."
echo
echo "Now run ./setup-agent.sh on each real PiVPN box, using the"
echo "server_id/token (and cert paths, if printed above) from step 6."
echo "Already have an agent box's name from before? Run this again any"
echo "time: python3 manage_servers.py register <name>"
