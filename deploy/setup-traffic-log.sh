#!/usr/bin/env bash
# Install the CT-local conntrack NEW-event collector for traffic history.
# Safe to run inside the PiVPN agent CT: it does not restart OpenVPN or
# change forwarding behavior, and requires no Proxmox host configuration.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run this with sudo." >&2
  exit 1
fi

SERVER_CONF="/etc/openvpn/server.conf"
FLOW_UNIT="pivpn-webui-conntrack.service"
COMMENT="pivpn-webui-trafficlog"
if [[ ! -r "$SERVER_CONF" ]]; then
  echo "Can't read $SERVER_CONF — is PiVPN/OpenVPN installed on this box?" >&2
  exit 1
fi

netmask_to_cidr() {
  local netmask="$1" bits=0 octet
  IFS='.' read -r -a octets <<< "$netmask"
  for octet in "${octets[@]}"; do
    case "$octet" in
      255) bits=$((bits + 8)) ;;
      254) bits=$((bits + 7)) ;; 252) bits=$((bits + 6)) ;;
      248) bits=$((bits + 5)) ;; 240) bits=$((bits + 4)) ;;
      224) bits=$((bits + 3)) ;; 192) bits=$((bits + 2)) ;;
      128) bits=$((bits + 1)) ;; 0) ;;
      *) echo "Unrecognized netmask octet '$octet' in '$netmask'" >&2; exit 1 ;;
    esac
  done
  echo "$bits"
}

read -r NET MASK <<< "$(awk '/^server / {print $2, $3; exit}' "$SERVER_CONF")"
if [[ -z "${NET:-}" || -z "${MASK:-}" ]]; then
  echo "Couldn't find a 'server <net> <mask>' line in $SERVER_CONF." >&2
  exit 1
fi
CIDR="$NET/$(netmask_to_cidr "$MASK")"
echo "Detected VPN client subnet: $CIDR"

CONNTRACK="$(command -v conntrack || true)"
if [[ -z "$CONNTRACK" ]]; then
  echo "conntrack is missing. Install it inside this CT (for Debian/Ubuntu: sudo apt install conntrack), then rerun." >&2
  exit 1
fi
CONNTRACK="$(readlink -f "$CONNTRACK")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install -m 0755 "$SCRIPT_DIR/pivpn_webui_conntrack_log.py" /usr/local/sbin/pivpn-webui-conntrack-log.py

cat > "/etc/systemd/system/$FLOW_UNIT" <<UNIT
[Unit]
Description=PiVPN Web UI VPN connection event collector (conntrack)
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -o pipefail -c '$CONNTRACK -E --event-mask NEW --orig-src $CIDR --output timestamp,extended | /usr/bin/python3 /usr/local/sbin/pivpn-webui-conntrack-log.py'
Restart=always
RestartSec=2
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pivpn-webui-conntrack
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT

# Remove only the previous non-terminating LOG rule added by this project.
# It is no longer needed. This does not alter ACCEPT/DROP/NAT rules.
while iptables -t mangle -C FORWARD -s "$CIDR" -m conntrack --ctstate NEW \
    -m comment --comment "$COMMENT" -j LOG --log-prefix "VPNFLOW " --log-level 6 \
    2>/dev/null; do
  iptables -t mangle -D FORWARD -s "$CIDR" -m conntrack --ctstate NEW \
    -m comment --comment "$COMMENT" -j LOG --log-prefix "VPNFLOW " --log-level 6
done
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save
fi

systemctl daemon-reload
systemctl enable --now "$FLOW_UNIT"
systemctl restart "$FLOW_UNIT"

echo
echo "Collector running inside this CT. No Proxmox change or OpenVPN restart was made."
echo "After a client opens a new connection, verify with:"
echo "  journalctl -u '$FLOW_UNIT' --since '2 min ago' --no-pager"
