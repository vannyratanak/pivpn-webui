#!/usr/bin/env bash
# Run this ON THE HUB, as the same user hub_gateway.py runs as (no sudo —
# unlike setup-nginx.sh's cert, this one only needs to be readable by that
# one process, not by a system service like nginx). Generates two things:
#
#  1. A self-signed certificate for the agent-facing WebSocket itself
#     (hub_gateway.py) — agents pin this one exact file to verify "is
#     this really the hub".
#  2. This hub's own small private CA, used to sign each agent's own
#     client certificate (see manage_servers.py's register()) for mutual
#     TLS — the hub verifies "is this really an agent we issued a cert
#     to" instead of relying purely on the hello token, which by itself
#     is just a string that could be copied.
#
# Only .crt files (public halves) ever need to leave this machine — the
# hub's own .crt goes to each agent's HUB_TLS_CERT; the CA's .crt is used
# locally by hub_gateway.py itself (GATEWAY_CLIENT_CA) and never needs to
# leave. Both .key files stay here, always.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"
mkdir -p instance

CERT="instance/hub-gateway.crt"
KEY="instance/hub-gateway.key"
CA_CERT="instance/hub-ca.crt"
CA_KEY="instance/hub-ca.key"

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

if [[ -f "$CA_CERT" && -f "$CA_KEY" ]]; then
  echo "Existing agent-signing CA found at $CA_CERT / $CA_KEY — leaving it as-is."
  echo "(Delete both files first if you want this script to regenerate it — note that"
  echo " doing so invalidates every agent cert manage_servers.py has already issued.)"
else
  echo "== Generating this hub's own CA (signs each agent's client certificate) =="
  openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout "$CA_KEY" \
    -out "$CA_CERT" \
    -subj "/CN=pivpn-webui-hub-ca" \
    -addext "basicConstraints=critical,CA:true"
  chmod 600 "$CA_KEY"
fi

echo
echo "Add to THIS hub's .env, then restart hub_gateway.py:"
echo "  GATEWAY_TLS_CERT=${APP_DIR}/${CERT}"
echo "  GATEWAY_TLS_KEY=${APP_DIR}/${KEY}"
echo
echo "To also require agents to prove their identity with a signed"
echo "certificate (mutual TLS — recommended, closes the gap where a"
echo "stolen hello token alone is enough to open a new connection),"
echo "additionally add:"
echo "  GATEWAY_CLIENT_CA=${APP_DIR}/${CA_CERT}"
echo "Every agent must then also be registered with"
echo "'python3 manage_servers.py register <name>' (or re-registered, for"
echo "ones set up before this existed) to get a cert signed by this CA —"
echo "an agent with no client cert will fail to connect at all once this"
echo "is set."
echo
echo "For EVERY agent box already registered against this hub:"
echo "  1. Copy just the .crt (not the .key) to it, e.g.:"
echo "       scp ${CERT} <agent-user>@<agent-host>:~/pivpn-webui/instance/hub-gateway.crt"
echo "  2. In that agent's own .env, change HUB_URL from ws:// to wss://"
echo "     and add:"
echo "       HUB_TLS_CERT=<path where you copied it>/hub-gateway.crt"
echo "  3. Restart that agent's agent.py."
