# PiVPN Web UI handoff — 2026-09-28

## VPN and traffic event streaming

The hub/agent WebSocket streams VPN events and traffic-flow events in acknowledged batches. The hub commits rows and their journal cursor together. After reconnect the agent resumes after its last acknowledged cursor. A one-minute recovery timer catches missed events; WHOIS enrichment is asynchronous.

VPN Sessions and Client Sessions share the same VPN-event stream/table. Traffic and VPN events have separate cursor tables. The five-second timer ingests whole-system logs only; organization enrichment remains on its ten-second timer.

## CT-local traffic flow capture

The agent CT's conntrack listener test succeeded. The user ran `sudo conntrack -E --event-mask NEW --orig-src 10.8.0.0/24 --output timestamp,extended` and received events including original source/destination IPs, protocol, and ports. This avoids the Proxmox host journal entirely. Earlier records showed `10.152.217.0/24`; verify the actual subnet in `/etc/openvpn/server.conf` on the agent CT. The installer reads the subnet automatically.

Implemented locally, not deployed: `deploy/setup-traffic-log.sh` installs/enables `pivpn-webui-conntrack.service`, normalizes conntrack events into `VPNFLOW` messages, and removes only this project's old tagged LOG rule. The agent log helper follows the service journal, and the existing WebSocket moves events to the hub. The hub and fallback ingestion preserve the conntrack event timestamp. This does not restart OpenVPN or alter Proxmox. Existing stored traffic rows remain; conntrack cannot recreate missing historical rows.

To deploy/update on the agent CT from the updated checkout:

1. Run `sudo ./deploy/setup-traffic-log.sh`.
2. Install `deploy/pivpn-webui-log-helper.sh` as `/usr/local/sbin/pivpn-webui-log-helper.sh` with root ownership and executable permissions.
3. Restart only `pivpn-webui-agent` so it follows the new journal source.
4. Verify with `sudo journalctl -u pivpn-webui-conntrack.service --since '2 min ago' --no-pager` after a client starts a new connection, then confirm rows arrive in the hub UI.

No production server has been changed by this local implementation. No Proxmox action is needed. No hub update is needed for this agent-side collector change.

## Current network notes

Proxmox node `ITS-CN3`; agent CT `10.255.1.239`; route to the CT is `via 172.16.255.1 dev vmbr0 src 172.16.255.5`. Proxmox's separate management address `172.16.255.3` is not on `vmbr0`. The old `nf_log_all_netns` sysctl was set at runtime during debugging; this implementation does not rely on it.

## Verification

Previous baseline after VPN event streaming: 448 Python tests and 11 JavaScript tests passed. Verify the new focused tests, Python compilation, shell syntax, and `git diff --check` before deployment.
