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
