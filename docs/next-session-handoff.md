# PiVPN Web UI handoff — 2026-09-25

## Traffic-over-WebSocket work

Implemented locally, not deployed. The default agent follows new `VPNFLOW` kernel journal records with `journalctl --follow`, sends batches over the existing authenticated WebSocket, and waits for a hub acknowledgment. The hub parses and stores the flow rows plus the journal cursor atomically. After reconnect, the agent resumes after the last committed cursor. Existing flow uniqueness deduplicates timer fallback/backfill rows. WHOIS remains asynchronous.

Files for this path: `agent.py`, `hub_gateway.py`, `app/db.py`, and `deploy/pivpn-webui-log-helper.sh`. Hub schema initialization creates `traffic_flow_cursors`. The existing `deploy/ingest_logs.py` timer remains enabled as fallback and backfill. `README.md` now documents both paths.

## Deployment notes

- Hub `.52` needs the updated application source and a restart of `pivpn-webui-hub-gateway` (for the new WebSocket protocol) and `pivpn-webui` (for schema initialization and the current local fixes).
- Agent `.51` needs the updated `agent.py` and the updated log helper installed at `/usr/local/sbin/pivpn-webui-log-helper.sh`, then restart `pivpn-webui-agent`. `setup-agent.sh` installs that helper and the agent service; review its effects before rerunning the full setup script.
- Do not disable the five-second log-ingest timer; it provides history recovery and fallback. No server has been changed by this local implementation.
- The working tree contains other uncommitted changes from the ongoing bug/performance work. Review `git status` and diffs; preserve unrelated/user-owned files.

## Verification

Added gateway tests for flow parsing, bad cursor rejection, and idempotent row/cursor storage. Verification: 438 Python tests passed; 9 JavaScript tests passed; Python compilation, shell syntax, and `git diff --check` passed.
