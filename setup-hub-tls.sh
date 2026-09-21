#!/usr/bin/env bash
# Run this ON THE HUB, as the same user hub_gateway.py runs as (no sudo —
# unlike setup-nginx.sh's cert, this one only needs to be readable by that
# one process, not by a system service like nginx). Generates a
# self-signed certificate for the agent-facing WebSocket (hub_gateway.py)
# and prints the .env changes needed on the hub and on every agent.
#
# Only the .crt (public half) ever needs to leave this machine — copy it
# to each agent box's HUB_TLS_CERT path. The .key stays here.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"
mkdir -p instance

CERT="instance/hub-gateway.crt"
KEY="instance/hub-gateway.key"

read -rp "Hub's address (IP or hostname agents will dial into) [$(hostname)]: " HUB_NAME
HUB_NAME="${HUB_NAME:-$(hostname)}"

# Modern TLS verification (Python's ssl module included) checks the
# connection target against the certificate's SAN (Subject Alternative
# Name), not just its CN — a CN-only cert fails hostname verification
# even though the name is right, since CN-based fallback matching was
# deprecated. An IP address specifically needs an "IP:" SAN entry, not a
# "DNS:" one, or it fails the same way even with SAN present.
if [[ "$HUB_NAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  SAN="IP:${HUB_NAME}"
else
  SAN="DNS:${HUB_NAME}"
fi

if [[ -f "$CERT" && -f "$KEY" ]]; then
  echo "Existing cert found at $CERT / $KEY — leaving it as-is."
  echo "(Delete both files first if you want this script to regenerate them.)"
else
  echo "== Generating a self-signed certificate for '${HUB_NAME}' =="
  openssl req -x509 -nodes -days 1095 \
    -newkey rsa:2048 \
    -keyout "$KEY" \
    -out "$CERT" \
    -subj "/CN=${HUB_NAME}" \
    -addext "subjectAltName=${SAN}"
  chmod 600 "$KEY"
fi

echo
echo "Add to THIS hub's .env, then restart hub_gateway.py:"
echo "  GATEWAY_TLS_CERT=${APP_DIR}/${CERT}"
echo "  GATEWAY_TLS_KEY=${APP_DIR}/${KEY}"
echo
echo "For EVERY agent box already registered against this hub:"
echo "  1. Copy just the .crt (not the .key) to it, e.g.:"
echo "       scp ${CERT} <agent-user>@<agent-host>:~/pivpn-webui/instance/hub-gateway.crt"
echo "  2. In that agent's own .env, change HUB_URL from ws:// to wss://"
echo "     and add:"
echo "       HUB_TLS_CERT=<path where you copied it>/hub-gateway.crt"
echo "  3. Restart that agent's agent.py."
