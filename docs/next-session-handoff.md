# PiVPN Web UI handoff — 2026-09-25

## VPN and traffic WebSocket work

Implemented locally, not deployed. The default agent follows new `VPNFLOW` kernel journal records and OpenVPN service journal records with `journalctl --follow`, sends batches over the existing authenticated WebSocket, and waits for hub acknowledgments. The hub parses and stores each stream with its journal cursor atomically. After reconnect, the agent resumes after the last committed cursor. Existing database uniqueness deduplicates recovery-timer rows. WHOIS remains asynchronous.

VPN Sessions and Client Sessions share the same VPN-event stream/table. Traffic and VPN events have separate cursor tables. The five-second timer now ingests whole-system logs only; a new one-minute fallback timer recovers missed VPN and traffic events; organization enrichment remains on its ten-second timer.

Files for this path: `agent.py`, `hub_gateway.py`, `app/db.py`, `deploy/pivpn-webui-log-helper.sh`, `deploy/ingest_logs.py`, and the updated/new systemd service and timer templates. `setup-log-ingest.sh` installs the timers. README documents the paths.

## Deployment notes

- Hub `.52` needs updated application source, `./deploy/setup-log-ingest.sh` (installs the five-second system-log timer and one-minute event fallback timer), and restarts of `pivpn-webui` (schema initialization) and `pivpn-webui-hub-gateway` (new WebSocket protocol).
- Agent `.51` needs the updated `agent.py` and the updated log helper installed at `/usr/local/sbin/pivpn-webui-log-helper.sh`, then restart `pivpn-webui-agent`. `setup-agent.sh` installs that helper and the agent service; review its effects before rerunning the full setup script.
- No server has been changed by this local implementation.
- The working tree contains other uncommitted changes from the ongoing bug/performance work. Review `git status` and diffs; preserve unrelated/user-owned files.

## Verification

Verification after the VPN event streaming additions: 448 Python tests and 11 JavaScript tests passed; Python compilation, shell syntax, and `git diff --check` passed.
