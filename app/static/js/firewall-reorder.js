// Reordering for the Firewall page's rules table, two ways: native HTML5
// drag-and-drop (no library, matching this app's no-dependencies-if-
// avoidable stance) for the mouse, and ↑/↓ on a focused drag-handle for
// the keyboard (drag-and-drop has no keyboard equivalent of its own —
// found by an /impeccable audit, since without this the whole feature was
// mouse-only). Both send which rule it landed before/after to POST
// /firewall/<id>/reorder via fetch. Unlike every other mutation in this
// app (see nav-loading.js's comment on why: plain form posts, no AJAX page
// loads), this one deliberately doesn't redirect/reload — the row is
// already in its new spot in the DOM the moment it's dropped/moved, so a
// full reload would just be flicker and a scroll-position jump for a
// change that's already visible.
function attachFirewallReorder(tbodySelector) {
  const tbody = document.querySelector(tbodySelector);
  if (!tbody) return;
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.content : '';
  let draggingRow = null;

  // Shared by the mouse-drag drop handler and the keyboard handler below —
  // both just need "tell the server the new before/after, then recover if
  // it disagrees."
  function sendReorder(ruleId, body, onSuccess) {
    fetch(`/firewall/${ruleId}/reorder`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
      body: JSON.stringify(body),
    })
      .then((resp) => resp.ok ? resp.json() : Promise.reject(resp))
      .then((data) => {
        if (!data.ok) return Promise.reject(data);
        onSuccess();
      })
      .catch(() => {
        // DB and DOM have now disagreed — reload is the honest recovery,
        // not worth reimplementing "undo this drag" for a rare failure.
        alert('Could not save that order — reloading to show the real order.');
        window.location.reload();
      });
  }

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

  tbody.addEventListener('dragenter', (e) => {
    if (draggingRow) e.preventDefault(); // some browsers also gate 'drop' on this, not just dragover
  });

  tbody.addEventListener('dragover', (e) => {
    if (!draggingRow) return;
    // Always claim the dragover, even over a gap/border/padding pixel that
    // isn't exactly over a row — the browser only allows 'drop' to fire at
    // all if the *last* dragover before mouse-up called preventDefault, and
    // a real mouse (unlike a scripted single-point test) is never pixel-
    // perfect over row centers. Missing this meant drop silently never
    // fired on real drags: the row still looked reordered (from earlier
    // dragovers that did land on a row), but nothing ever got saved.
    e.preventDefault();
    const overRow = e.target.closest('tr');
    if (!overRow || overRow === draggingRow || overRow.getAttribute('draggable') !== 'true') return;
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

    sendReorder(ruleId, body, () => {});
  });

  // Keyboard equivalent of the mouse drag above — focus a row's handle,
  // press ↑/↓ to swap it with the neighbor in that direction. Skips over
  // (and never lands on) a client_block row, same as dragover already
  // does, since those aren't reorderable at all (always -I to the front).
  tbody.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return;
    const handle = e.target.closest('.drag-handle');
    if (!handle) return;
    const row = handle.closest('tr[draggable="true"]');
    if (!row) return;

    const neighbor = e.key === 'ArrowUp' ? row.previousElementSibling : row.nextElementSibling;
    if (!neighbor || neighbor.getAttribute('draggable') !== 'true') return; // already at that end
    e.preventDefault();

    const ruleId = row.dataset.ruleId;
    const body = e.key === 'ArrowUp'
      ? { target_id: neighbor.dataset.ruleId, place: 'before' }
      : { target_id: neighbor.dataset.ruleId, place: 'after' };

    // Move immediately (optimistic, same as dragover's live preview above)
    // instead of waiting for the response — a held-down arrow key's
    // browser-repeat can fire the next keydown before the previous
    // request's response comes back, so reading the row's position from
    // the DOM only *after* the response used to see a stale, not-yet-moved
    // position and recompute the same neighbor instead of the next one:
    // the row moved fewer slots than keys pressed. sendReorder's existing
    // catch()-and-reload already recovers if the server ever disagrees,
    // same safety net drag-and-drop already relies on.
    row.parentNode.insertBefore(row, e.key === 'ArrowUp' ? neighbor : neighbor.nextSibling);
    handle.focus(); // keep focus on the same handle so repeated ↑/↓ keeps working

    sendReorder(ruleId, body, () => {});
  });
}
