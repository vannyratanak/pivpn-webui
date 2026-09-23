// Every 'YYYY-MM-DD HH:MM:SS' timestamp this app's API returns is UTC (see
// app/vpnlog.py's _format_ts and app/db.py's various
// datetime.now(timezone.utc) call sites) — never the server's own local
// wall-clock time. That matters because this app can manage boxes in
// different timezones: found live, a test agent's system clock was UTC
// while the admin viewing the page was +07, and displaying the raw string
// as-is made a session started this morning look like it started in the
// middle of the night, and inflated a chart's duration math by exactly
// that offset.
//
// This converts one of those strings to the *viewer's own* local time,
// still in the same 'YYYY-MM-DD HH:MM:SS' shape the rest of this app's
// tables already use everywhere, so it's a drop-in replacement for
// displaying a raw ts/start/end field.
function formatServerTs(ts) {
  if (!ts) return ts;
  const date = new Date(ts.replace(' ', 'T') + 'Z');
  if (Number.isNaN(date.getTime())) return ts;
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} `
    + `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

window.formatServerTs = formatServerTs;
