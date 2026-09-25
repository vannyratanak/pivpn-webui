# Overview design proposal

Status: proposal, updated September 25, 2026.

## Purpose

Give the operator a quick answer to three questions: who is connected, which clients need attention, and where to investigate next. Add **Overview** before Clients in the shared desktop and mobile navigation, at `/overview`. Keep the existing Clients page for client management.

The project currently has no Overview route or template. This proposal follows PRODUCT.md, DESIGN.md, and the current console.css components. The client API reads an ingested snapshot; a successful request alone does not prove the VPN server is healthy.

## Layout

```text
PiVPN   Overview  Clients  Firewall Rules  VPN Routes  Logs  Users

Overview                              [Print report]  [Refresh]
Connections and access across your VPN.
Snapshot updated: Sep 23, 14:32:08 · Refresh every 30 seconds

VPN service: Running · Agent: Connected · Client data: Fresh
Last checked: Sep 23, 14:32:08

┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│ Connected       │ Total clients   │ Blocked         │ Certificates    │
│ 12              │ 38              │ 2               │ 3               │
│ Current sessions│ Registered      │ Access restricted│ Expire in 30 days│
└─────────────────┴─────────────────┴─────────────────┴─────────────────┘

┌─────────────────────────────────────────┬─────────────────────────────┐
│ Connection activity     [24h] [7d] [30d] │ Client status               │
│ Recorded session starts                 │                             │
│       ▂ ▄     ▆ █ ▅                     │       ◯ 38 clients          │
│   ▁ ▃ █ █ ▂ ▄ █ █ █ ▃                  │ 12 connected · 26 offline   │
│ 00:00          12:00             23:00   │ Based on cached snapshot    │
└─────────────────────────────────────────┴─────────────────────────────┘
Session starts: 148 · Previous 24h: 132 · +12.1%

Connected (12)    Needs attention (5)    All clients (38)
━━━━━━━━━━━━━━

Connected clients                              [Search clients…]
Client          VPN IP       Remote address    Connected since
office-router   10.8.0.2     203.0.113.8:51820  Sep 23, 08:14
laptop          10.8.0.3     203.0.113.9:49210  Sep 23, 09:26
…
                                        Show 10   Prev  1 of 2   Next

[Manage clients]  [View session history]
```

Numbers and addresses above are illustrative, not readings from the deployment.

## Charts

Make charts a prominent part of Overview, directly below the summary cards. On desktop, use a two-thirds-width activity chart and a one-third-width status chart. Stack them on phones. Keep the client table beneath them so the operator can move from a visual summary to individual records.

| Chart | What it answers | Data and delivery |
| --- | --- | --- |
| Connection activity — vertical bars | When are clients starting VPN sessions? | Aggregate recorded connect events from existing VPN event history on the backend. Offer 24h, 7d, and 30d ranges, subject to available retention. Label the measure “Recorded session starts”; repeated connections count separately. |
| Client status — donut | How much of the client inventory is connected? | Use `/api/clients`: connected versus offline, with total clients in the center and exact counts in a visible legend. Available immediately. |
| Connected clients over time — line, later phase | When does concurrent usage peak? | Persist timestamped connection-count snapshots. Show gaps when collection is unavailable. Existing current-state data alone cannot supply this history. |
| VPN bandwidth — two lines, later phase | How much traffic is moving through the VPN? | Collect numeric receive/send counter samples and calculate rates using elapsed time. Handle session restarts and counter resets; current cumulative counters are not bandwidth rates. |

Ship the activity bars and status donut as the initial chart pair. The activity chart requires a small aggregation endpoint, but can use existing recorded events without a new metrics collector. Aggregate the full authorized time range, not one page of the Logs API. Verify event classification and retention before enabling each range. Incomplete history must be labeled with its available coverage; missing collection must not be drawn as confirmed zero activity.

The donut has exactly two mutually exclusive slices: connected and offline. Show blocking separately in the summary and table because blocked clients may also have cached sessions. For zero inventory, replace the donut with “No client records available.” Clicking a segment filters the client table; provide equivalent labeled buttons for keyboard users.

Use green for connected and neutral slate for offline. Activity bars use a single theme-aware neutral tone; selected bars use the existing blue accent. Both line charts, when introduced, use distinct line styles and direct labels as well as color. This extends the design system with functional data visualization while retaining its restrained palette.

Every chart includes a title, unit, time range when relevant, snapshot or coverage note, and a “View data” control exposing an accessible table. Show values on hover and keyboard focus. Start bar-chart axes at zero; show integer session counts, explicit timezone labels, and date-aware ticks. Avoid 3D effects and animated redraws during refresh. Respect reduced-motion preferences.

Range controls affect only historical charts; the donut and summary cards remain labeled as the current cached snapshot. Preserve the chosen range in the URL. Chart failures are independent: show Retry within the failed chart while leaving successful cards and tables usable. Keep the previous chart visible with a stale-data note if a later refresh fails.

## Period comparisons

Place a concise comparison beneath Connection activity: **148 session starts · Previous 24h: 132 · +12.1%**. These example values are illustrative. The selected chart range controls the comparison. Compare the selected trailing interval with the immediately preceding interval of equal duration, using one fixed end timestamp per response. Include exact start/end dates and timezone in the detail view and printed report.

Calculate percentage change as `(current - previous) / previous × 100`, rounded to one decimal place. When both counts are zero, show “No change.” When only the previous count is zero, show the absolute increase and “No percentage baseline.” When either interval lacks confirmed collection coverage, show “Comparison unavailable — incomplete history” with the known counts and coverage notes. Event timestamps alone cannot establish uninterrupted collection.

Use neutral text and explicit Increase/Decrease labels: more connections are not inherently good or bad. Reconnects count as additional recorded session starts. Do not apply a historical percentage to the current connected-client total without historical snapshots. Preserve the comparison range in the URL and aggregate both periods on the backend using the same event classification and access scope.

## Server health strip

Add a compact strip below the page description with separate **VPN service**, **Agent connection**, and **Client data** indicators. Give each indicator its own observation timestamp and text label; avoid one overall green badge that could hide a failed component.

| Indicator | States | Evidence required |
| --- | --- | --- |
| VPN service | Running, Stopped, Unknown | A bounded, read-only check of the configured OpenVPN systemd unit on the VPN host |
| Agent connection, hub mode | Connected, Disconnected, Unknown | Current gateway connection state for the configured server, with observation time; a historical last-seen timestamp is insufficient |
| Agent connection, local mode | Local deployment | Agent connectivity is not applicable |
| Client data | Fresh, Delayed, Unknown | Last successful complete client ingest, including empty snapshots, and the expected ingest cadence |

Proposed freshness rule: Fresh through three expected ingest intervals, Delayed after that, Unknown when no trustworthy completion timestamp exists. Return the threshold and timestamps from the backend so the browser does not guess. Re-evaluate age as time passes even when refresh requests fail. A failed service check means Unknown, with its previous successful observation shown separately if available.

Fetch health independently of charts and client lists. Cache checks briefly and use bounded timeouts so an unreachable agent cannot delay the rest of Overview. Never invoke service restarts from this strip. Keep detailed service and gateway checks admin-only to match existing operational access; moderators see client-data freshness. Enforce this on the API as well as in the template. The printed report follows the same role scope.

## Printable report

Add **Print report** beside Refresh. Open an authenticated print preview with a frozen copy of the loaded overview data and a **Print / Save as PDF** action using the browser print dialog. Freeze the report timestamp, range, counts, comparisons, and chart data together so polling cannot change a report midway through printing.

The report includes:

- Server display name, selected period with exact boundaries and timezone, and report generation time.
- Available health indicators with their observation times and any stale or unknown labels.
- Client summary cards, activity chart, status donut, and period comparison.
- Certificate/blocked attention totals when those features are available, plus data-coverage notes.
- A compact table of the activity chart's bucket values as an appendix, so exact values remain readable in print.

Keep the default report an aggregate overview. The client table's search and pagination do not change report totals. State this scope in the preview as “All clients · Selected activity period.” Include no credentials or client configuration downloads. Reports are generated on demand; emailing and scheduled delivery are outside this proposal.

Use a white print background, dark text, visible chart labels, and patterns or line styles that survive grayscale printing. Hide navigation and interactive controls. Fit both A4 and Letter paper, repeat table headers across pages, and keep chart cards together. Render printable chart graphics rather than relying on hover tooltips. Display unavailable sections explicitly; a report may contain partial data, but must retain every stale-data and coverage note visible in its preview.

## Tabs

| Tab | Content | Next action |
| --- | --- | --- |
| Connected | Client name, VPN IP, remote address, connected since; a Blocked label when applicable | Open the client detail page |
| Needs attention | Client name, reason, certificate expiration, VPN IP; reasons include blocked, expired, or expiring within 30 days | Open client details to investigate or renew |
| All clients | Client name, connection status, access status, certificate status, VPN IP | Open client details or the Clients management page |

Connected is the default. Summary cards link to the relevant view; Certificates filters Needs attention to certificate issues. Attention counts represent unique clients, even when one client has several reasons. The certificate card counts certificates expiring in the next 30 days; already expired certificates appear in Needs attention separately. Blocking is an intentional access policy and uses a neutral label; it does not imply a fault. A cached session can still exist for a blocked client, so show both facts.

Store view and search state in the URL, such as `/overview?tab=attention&reason=certificate&q=laptop`. Support browser Back and shareable links. Use the existing linked-tab convention with `aria-current="page"`; search has a persistent accessible label. Changing tabs resets pagination and retains the search query. Counts describe the full snapshot; the table separately reports filtered results.

## Visual treatment

- Use the existing system font, 27px page heading, 13px table text, 14px card corners, and shared spacing and color tokens.
- Render summary values at 30px with tabular numerals. Keep their labels visible; color supplements the text.
- Use green for connected, amber for approaching expiry, red for expired, and neutral for blocked/offline. Reserve blue for links, focus, and selected tabs.
- Support both themes through existing variables. The runtime currently defaults to light despite the older dark-first language in PRODUCT.md.
- At narrow widths, use a two-column summary grid, a horizontally scrollable tab strip, and a table scroll region. Allow the page to scroll vertically so summary content cannot hide pagination. At 320px, stack the page actions and search.
- Retain visible focus rings, the mobile navigation drawer, and reduced-motion behavior. Refresh must preserve focus and must not announce every table cell.

## Loading and refresh

Load the page shell immediately, then fetch data through ApiClient. Refresh every 30 seconds while the page is visible, avoid overlapping requests, and fetch again when a hidden page becomes visible. Manual Refresh shows a busy state.

Display placeholders during the first fetch. An empty connected view says “No clients are connected in this snapshot.” An empty attention view says “No client access or certificate issues in this snapshot.” A search with no matches offers Clear search. If no inventory exists, say “No client records available” and link to Clients; an empty cache alone cannot distinguish a new installation from missing ingest data.

On refresh failure, retain existing rows with a visible “Could not refresh; showing the previous snapshot” message and Retry. On initial failure, show an error state rather than zero totals. Distinguish **snapshot updated** from **page fetched**. Until the API supplies an ingest timestamp, show only the latter, with “Cached client data.”

## Data and implementation

| Information | Current source | Work needed |
| --- | --- | --- |
| Client inventory, sessions, blocking | `GET /api/clients` | Reuse; available to both roles |
| Remote address and connection start | `clients[].session` | Format existing fields |
| Certificate expiry | `clients[].expiration` and `status` | Normalize date on the backend; return an ISO date or null to avoid browser-dependent parsing |
| Snapshot freshness | `client_status_cache.updated_at` exists but is omitted from the response | Expose completed-ingest metadata, including successful empty snapshots; do not infer whole-snapshot freshness from a single row |
| Client status chart | `GET /api/clients` | Derive connected/offline counts from the same snapshot as the cards |
| Connection activity chart | Recorded VPN events in `app/db.py`, interpreted by `app/vpnlog.py` | Add an authenticated aggregation endpoint with validated ranges, time buckets, coverage metadata, and the same access scope as client session history |
| Period comparison | Recorded VPN events plus collection-coverage metadata | Aggregate adjacent equal-duration intervals; suppress percentages with missing coverage or a zero baseline |
| VPN service / agent health | No dedicated overview health response | Add bounded service checks and current gateway connection observations; enforce admin access |
| Printable report | Loaded overview datasets and observation metadata | Build an authenticated frozen preview with print styles and a chart-data appendix |
| Traffic rates and historical charts | No overview time series | Future work: collect timestamped counter samples before introducing bandwidth charts |

Start with the existing API for Connected, Blocked, and All clients. Upgrade Blocked to Needs attention once normalized certificate dates are available. This keeps the initial page useful while avoiding guessed expiration dates. Do not label a page-fetch timestamp as a snapshot timestamp.

Add `app/templates/overview.html`, `app/static/js/overview-page.js`, and page-scoped styles. Add a login-protected route in app/routes.py and a link in base.html's shared navigation macro. Both admin and moderator can see client summaries; privileged navigation continues to use the existing role checks. Keep login redirects unchanged for the initial release. The client-snapshot view needs no database migration; trustworthy ingest freshness and historical coverage may require persisted metadata.

Implement in this order: client summaries and status donut; activity aggregation and coverage tracking; period comparison; independent health checks; printable preview using those datasets. Historical concurrency and bandwidth charts remain a later phase requiring a metrics collector.

## Acceptance criteria

- Counts and filtered tables agree for empty, mixed, and blocked-but-connected snapshots.
- URLs restore tab, search, and pagination state; browser Back restores the previous view.
- Both roles can use Overview, and existing API authorization remains in force.
- Failed requests never appear as zero clients or a healthy server.
- Keyboard navigation, light/dark themes, and 320px/390px/desktop layouts remain usable.
- Refresh preserves the active view and focus; hidden pages stop polling.
- Certificate enhancements handle unknown dates, already expired certificates, and the 30-day boundary explicitly.
- Donut counts sum to total inventory; blocked-but-connected clients are counted once.
- Activity bars agree with recorded connect events across the complete selected range, including timezone and bucket boundaries.
- Chart data is available by keyboard and as a table; missing history and request failures remain distinguishable from zero activity.
- Comparisons handle equal-duration boundaries, zero baselines, and partial retention without misleading percentage changes.
- Health checks distinguish a stopped service from an unreachable host; cached observations age correctly and privileged health details remain admin-only.
- Print preview freezes all loaded values, preserves incomplete-data notes, and produces legible charts and tables on A4 and Letter paper in grayscale.
