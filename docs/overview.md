# Overview dashboard

Open **Overview** in the navigation or visit `/overview` after signing in. Both admins and moderators can view client summaries and activity. The existing sign-in destination remains Clients.

Implemented features:

- Connected, total, blocked, and expiring-certificate summary cards.
- Recorded connection starts for the last 24 hours or 7 days, aggregated across the full database range rather than one log page.
- Connected/offline donut with exact counts and filter controls.
- Connected, Needs attention, All clients, and Offline views with search, pagination, and URL state.
- Explicit certificate expiry parsing, including expired and unknown dates.
- Independent admin-only VPN service and agent checks.
- Automatic refresh every 30 seconds while visible, manual refresh, and preserved data with an error notice when refresh fails.
- A frozen print preview with chart data tables; use Print / Save as PDF in the preview. All client aggregates appear regardless of the client-table filter.
- Light/dark themes and mobile layouts.

## Data meaning

Client counts come from the existing client cache. “Last row update” is the most recent cached row update, not proof of a complete fresh snapshot. An empty cache has no update timestamp.

Activity bars count recorded connection starts, including reconnects. Chart bucket times are UTC; the selected rolling range ends when the API request is evaluated. A zero bucket means no recorded events, not verified absence of activity. The previous equal-length period is shown as a recorded count. Percentage changes are withheld because uninterrupted collection coverage is not tracked. With seven-day retention, the previous period for a seven-day view will generally be incomplete.

Expired and expiring certificate labels use UTC calendar dates; an expiry date today is included in the next-30-days group. Unknown formats remain unknown. Blocked access is independent of the cached connection state.

Bandwidth and historical concurrent-client charts require a future metrics collector and are not implemented.

## Deployment

The hub needs the updated application and a web service restart. The new read-only health action also requires the updated `agent.py` and `app/overview_health.py` on the agent and an agent service restart. Until then, the page still loads client data and charts, with health shown as unknown. No database migration is required by Overview.

The service check runs `systemctl show` without sudo, with a two-second timeout, for `OPENVPN_UNIT` (default `openvpn@server`). Set that environment variable on the agent, or on the application host for local deployments, if the OpenVPN service uses a different unit. This check reports unit state; it does not test end-to-end VPN connectivity. Agent Connected means the authenticated agent answered the health request at the displayed check time.

API routes use the existing bearer-token authentication:

- `GET /api/overview`: client snapshot and normalized certificate information.
- `GET /api/overview/activity?range=1d|7d`: recorded activity and previous-period count.
- `GET /api/overview/health`: admin-only bounded service/agent observation.

## Live updates

Overview, `/clients`, and `/logs` load their current view, then share the
Bearer-authenticated SSE endpoint at `/api/overview/events`. PostgreSQL commit notifications invalidate only the affected view: client
snapshot, activity chart, VPN sessions, traffic, system, activity, or auth logs.
Browser refreshes are coalesced and bounded; log views refresh at most once per
two seconds, and only the selected log tab is fetched. Traffic
rows, unchanged client snapshots, byte counters, and routine VPN diagnostics do
not refresh the Overview or Clients views. Log-table notifications are emitted
once per database transaction. Reconnecting resynchronizes both sections, so notifications
need not be stored or replayed. Hidden tabs disconnect and resync on return.

The **Now, HH:mm** label uses the browser's local clock and makes no network
request. It continues to advance even if the server is unavailable; the separate
live-update status reports the connection. Charts refresh at hour boundaries to
account for continuing sessions and midnight, even without a connect/disconnect.
The seven-day view is a rolling snapshot, recalculated on events/hour boundaries.

The async `overview_stream.py` service listens on loopback port 8766. nginx routes
only the SSE endpoint to it, with buffering disabled; ordinary API requests stay
on gunicorn. One PostgreSQL LISTEN connection serves every viewer. Health is
checked once every 30 seconds on the hub and shared with admin viewers. A silent
heartbeat every 15 seconds detects broken streams; reconnect uses backoff up to
30 seconds. Failed projection requests retry after 30 seconds. JWT expiry and
account changes close streams and require authentication again. Slow viewers have
bounded queues and receive a resync signal rather than an unbounded backlog.

On an existing hub, run `./deploy/setup-overview-stream.sh` and update the nginx
site using the SSE location in `deploy/nginx-pivpn-webui.conf.template` (or rerun
`./setup-nginx.sh`). Restart the web service to load the updated template. Fresh
hub setup installs the stream service automatically. Direct gunicorn access does
not provide SSE; use the nginx HTTPS address. The agent protocol is unchanged.

Operational tradeoff: this adds a service and long-lived connection per visible
tab. Monitor `systemctl status pivpn-webui-overview-stream` and its journal. A
stream outage leaves the last received data visible with a reconnect message;
manual Refresh remains available. Ordinary snapshot/chart API reads still occur
per viewer when a relevant change arrives, rather than continuously while idle.

The Clients and Logs pages use this same hub stream; they do not start separate
connections. Client connection changes update `/clients` and the client summary.
VPN, traffic, system, activity, and auth log changes refresh only their selected
Logs tab, with a two-second minimum between automatic table fetches.


Next review: compare the browser Network panel on Overview, Clients, client
detail, and each Logs tab against actual updates; confirm connected-client
snapshots don't trigger extra fetches immediately after a manual client action;
check stream recovery while the PostgreSQL listener is restarted; and review
any remaining periodic refreshes on pages outside those covered here.
