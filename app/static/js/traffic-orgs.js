// Fills in the Traffic tab's Organization column after the page has
// already rendered, instead of before — see vpnlog.list_traffic_flows'
// "Cache-only on purpose" comment and the /logs/traffic/orgs route. A
// never-before-seen destination's WHOIS lookup can take a few seconds even
// with the server's own concurrency, and there's no reason the rest of the
// (already fully loaded) table should wait on that.
function attachTrafficOrgFill(tbodySelector) {
  const tbody = document.querySelector(tbodySelector);
  if (!tbody) return;
  const pending = tbody.querySelectorAll('.org-pending');
  if (!pending.length) return;

  const dsts = [...new Set(Array.from(pending, (el) => el.dataset.dst))];
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.content : '';

  fetch('/logs/traffic/orgs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
    body: JSON.stringify({ ips: dsts }),
  })
    .then((resp) => (resp.ok ? resp.json() : Promise.reject(resp)))
    .then((data) => {
      if (!data.ok) return Promise.reject(data);
      // Re-query rather than reuse the `pending` NodeList capture above —
      // the pagination/filter scripts that ran earlier in this same block
      // don't remove rows from the DOM, but this stays correct even if
      // that ever changes.
      tbody.querySelectorAll('.org-pending').forEach((el) => {
        el.textContent = data.orgs[el.dataset.dst] || '—';
        // Drop both classes, not just the pending marker — once resolved
        // this is an ordinary value, same as one that was already cached
        // at render time (see the plain-text branch in logs.html), not a
        // muted/italic "note" anymore.
        el.classList.remove('org-pending', 'cell-note');
      });
    })
    .catch(() => {
      // Best-effort, same as every lookup in this feature — leave the "…"
      // placeholder rather than show something that reads like a real
      // (empty) result. A page reload retries from scratch.
    });
}
