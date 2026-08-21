// Drag-and-drop reordering for the Firewall page's rules table. Native
// HTML5 drag-and-drop (no library, matching this app's no-dependencies-if-
// avoidable stance) — each reorderable <tr draggable="true"> can be dragged
// onto another row; dropping sends which rule it landed before/after to
// POST /firewall/<id>/reorder via fetch. Unlike every other mutation in
// this app (see nav-loading.js's comment on why: plain form posts, no AJAX
// page loads), this one deliberately doesn't redirect/reload — the row is
// already in its new spot in the DOM the moment it's dropped, so a full
// reload would just be flicker and a scroll-position jump for a change
// that's already visible.
function attachFirewallReorder(tbodySelector) {
  const tbody = document.querySelector(tbodySelector);
  if (!tbody) return;
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.content : '';
  let draggingRow = null;

  tbody.addEventListener('dragstart', (e) => {
    const row = e.target.closest('tr[draggable="true"]');
    if (!row) { e.preventDefault(); return; }
    draggingRow = row;
    e.dataTransfer.effectAllowed = 'move';
    // Firefox requires setData to be called for drag to actually start.
    e.dataTransfer.setData('text/plain', row.dataset.ruleId || '');
    row.classList.add('dragging-row');
  });

  tbody.addEventListener('dragend', () => {
    if (draggingRow) draggingRow.classList.remove('dragging-row');
    draggingRow = null;
  });

  tbody.addEventListener('dragover', (e) => {
    if (!draggingRow) return;
    const overRow = e.target.closest('tr');
    if (!overRow || overRow === draggingRow || overRow.getAttribute('draggable') !== 'true') return;
    e.preventDefault(); // only allow drop once we know the target is a valid reorderable row
    const rect = overRow.getBoundingClientRect();
    const before = (e.clientY - rect.top) < rect.height / 2;
    overRow.parentNode.insertBefore(draggingRow, before ? overRow : overRow.nextSibling);
  });

  tbody.addEventListener('drop', (e) => {
    if (!draggingRow) return;
    e.preventDefault();
    const row = draggingRow;
    const ruleId = row.dataset.ruleId;
    const prevRow = row.previousElementSibling;
    const nextRow = row.nextElementSibling;
    const body = prevRow
      ? { target_id: prevRow.dataset.ruleId, place: 'after' }
      : nextRow
        ? { target_id: nextRow.dataset.ruleId, place: 'before' }
        : null;
    if (!body) return; // dropped in the only slot it could already be in

    fetch(`/firewall/${ruleId}/reorder`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
      body: JSON.stringify(body),
    })
      .then((resp) => resp.ok ? resp.json() : Promise.reject(resp))
      .then((data) => {
        if (!data.ok) return Promise.reject(data);
      })
      .catch(() => {
        // DB and DOM have now disagreed — reload is the honest recovery,
        // not worth reimplementing "undo this drag" for a rare failure.
        alert('Could not save that order — reloading to show the real order.');
        window.location.reload();
      });
  });
}
