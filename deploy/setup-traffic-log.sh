#!/usr/bin/env bash
# Run this on the PiVPN server (with sudo) to enable per-destination VPN
# traffic logging: which client connected to which destination IP/port,
# and when.
#
# Deliberately NOT wired through the app's own Firewall page / DB-tracked
# rule system: this app's discover_cli_rules() (app/firewall.py) adopts any
# untagged rule it finds in filter/FORWARD, filter/INPUT, nat/PREROUTING and
# nat/POSTROUTING into a managed ACCEPT/DROP/DNAT rule the next time the
# Firewall page loads — it has no concept of a LOG-target rule, so a LOG
# rule placed in one of those chains/tables would get silently mangled the
# first time an admin opens that page. The mangle table's FORWARD chain
# carries the exact same forwarded packets but is never touched by
# discover_cli_rules(), so a plain LOG rule there is genuinely safe from
# adoption — same "intentionally unmanaged" pattern already used for a
# hand-added route (see project memory / README).
#
# Logs one line per NEW connection from the VPN client subnet (via
# `-m conntrack --ctstate NEW`), not every packet — logging every packet on
# an already-busy link would be both useless (one connection is one row
# either way) and a real syslog/journal volume problem.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run this with sudo." >&2
  exit 1
fi

SERVER_CONF="/etc/openvpn/server.conf"
LOG_PREFIX="VPNFLOW "
COMMENT="pivpn-webui-trafficlog"

if [[ ! -r "$SERVER_CONF" ]]; then
  echo "Can't read $SERVER_CONF — is PiVPN/OpenVPN installed on this box?" >&2
  exit 1
fi

# netmask -> CIDR prefix length, e.g. 255.255.255.0 -> 24. Needed because
# server.conf's `server` line gives a network + dotted-quad netmask, not
# CIDR, and iptables -s wants CIDR.
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
if [[ -z "$NET" || -z "$MASK" ]]; then
  echo "Couldn't find a 'server <net> <mask>' line in $SERVER_CONF." >&2
  exit 1
fi
CIDR="$NET/$(netmask_to_cidr "$MASK")"
echo "Detected VPN client subnet: $CIDR"

if iptables -t mangle -C FORWARD -s "$CIDR" -m conntrack --ctstate NEW \
    -m comment --comment "$COMMENT" -j LOG --log-prefix "$LOG_PREFIX" --log-level 6 \
    2>/dev/null; then
  echo "Rule already present, nothing to do."
else
  iptables -t mangle -A FORWARD -s "$CIDR" -m conntrack --ctstate NEW \
    -m comment --comment "$COMMENT" -j LOG --log-prefix "$LOG_PREFIX" --log-level 6
  echo "Rule added."
fi

if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save
  echo "Saved via netfilter-persistent (survives reboot)."
else
  echo "netfilter-persistent not found — this rule will NOT survive a reboot until you persist it another way." >&2
fi

echo
echo "Verify with a real connection from a connected client, then:"
echo "  journalctl -k -g '$LOG_PREFIX' --since '10 min ago' --no-pager -o short-iso"
