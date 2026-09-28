// Wires a text input to show/hide matching rows/lines in a log or table
// view (whole-row/line text match, case-insensitive substring). Debounced
// so it doesn't re-scan every row on every single keystroke.
//
// If headerSelector is given, clicking (or pressing Enter/Space on, via
// keyboard) a <th> sorts the table by that column instead — activate again
// to reverse direction, activate a different header to sort by that one.
// Each header gets role="button"/tabindex so it's keyboard-reachable, and
// aria-sort reflects the current state for screen readers. Only meaningful
// for table rows (a log-line has no columns), so headerSelector is only
// passed for actual tables.
//
// onChange, if given, fires after every filter pass and every sort — for
// callers (e.g. pagination) that need to react to the new match/order state
// without re-implementing the matching or sorting logic themselves.
function attachLogFilter(inputId, containerSelector, itemSelector, headerSelector, onChange) {
  const input = document.getElementById(inputId);
  const container = document.querySelector(containerSelector);
  if (!input || !container) return;

  let debounceTimer = null;
  input.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      const term = input.value.trim().toLowerCase();
      container.querySelectorAll(itemSelector).forEach((item) => {
        const match = !term || item.textContent.toLowerCase().includes(term);
        item.dataset.filterMatch = match ? '1' : '0';
        item.style.display = match ? '' : 'none';
      });
      onChange && onChange();
    }, 120);
  });

  if (!headerSelector) return;
  const headers = Array.from(document.querySelectorAll(headerSelector));
  let sortColumn = null;
  let sortDir = null; // null (unsorted) | 'asc' | 'desc' — a 3-state cycle per column
  // Snapshot of row order, taken the moment a column *starts* a new sort
  // cycle (not once at page load) — restored verbatim as that cycle's
  // third click ("back to normal"). Taking it lazily like this means a
  // table whose rows changed since the page loaded (Clients' insert/
  // remove, Firewall Rules' Add Rule, etc.) still restores to how things
  // actually looked right before this column started sorting, not a
  // stale page-load-time layout. A row removed from the table before the
  // restore is skipped (isConnected check) rather than resurrected.
  let originalOrder = null;

  // th.cellIndex (its actual position among ALL cells in its row) rather
  // than its position within the filtered `headers` array — headerSelector
  // can exclude any subset of columns (leading, trailing, or in the middle,
  // e.g. a checkbox column up front plus an Actions column at the end), and
  // cellIndex is the only thing that still correctly maps back to
  // a.children[...] regardless of what got excluded.
  function activate(th) {
    const index = th.cellIndex;
    if (sortColumn !== index) {
      originalOrder = Array.from(container.querySelectorAll(itemSelector));
      sortColumn = index;
      sortDir = 'asc';
    } else if (sortDir === 'asc') {
      sortDir = 'desc';
    } else if (sortDir === 'desc') {
      sortDir = null;
    } else {
      originalOrder = Array.from(container.querySelectorAll(itemSelector));
      sortDir = 'asc';
    }

    headers.forEach((h) => {
      h.classList.remove('sort-asc', 'sort-desc');
      h.setAttribute('aria-sort', 'none');
    });

    if (sortDir === null) {
      originalOrder.forEach((row) => { if (row.isConnected) container.appendChild(row); });
      sortColumn = null;
      onChange && onChange();
      return;
    }

    th.classList.add(sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
    th.setAttribute('aria-sort', sortDir === 'asc' ? 'ascending' : 'descending');

    const rows = Array.from(container.querySelectorAll(itemSelector));
    rows.sort((a, b) => {
      const at = (a.children[index]?.textContent || '').trim();
      const bt = (b.children[index]?.textContent || '').trim();
      const cmp = at.localeCompare(bt, undefined, { numeric: true, sensitivity: 'base' });
      return sortDir === 'asc' ? cmp : -cmp;
    });
    rows.forEach((row) => container.appendChild(row));
    onChange && onChange();
  }

  headers.forEach((th) => {
    th.classList.add('sort-header');
    th.setAttribute('role', 'button');
    th.setAttribute('tabindex', '0');
    th.setAttribute('aria-sort', 'none');
    th.addEventListener('click', () => activate(th));
    th.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        activate(th);
      }
    });
  });
}
