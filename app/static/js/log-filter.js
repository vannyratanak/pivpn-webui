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
  let sortAsc = true;

  // th.cellIndex (its actual position among ALL cells in its row) rather
  // than its position within the filtered `headers` array — headerSelector
  // can exclude any subset of columns (leading, trailing, or in the middle,
  // e.g. a checkbox column up front plus an Actions column at the end), and
  // cellIndex is the only thing that still correctly maps back to
  // a.children[...] regardless of what got excluded.
  function activate(th) {
    const index = th.cellIndex;
    sortAsc = sortColumn === index ? !sortAsc : true;
    sortColumn = index;
    headers.forEach((h) => {
      h.classList.remove('sort-asc', 'sort-desc');
      h.setAttribute('aria-sort', 'none');
    });
    th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
    th.setAttribute('aria-sort', sortAsc ? 'ascending' : 'descending');

    const rows = Array.from(container.querySelectorAll(itemSelector));
    rows.sort((a, b) => {
      const at = (a.children[index]?.textContent || '').trim();
      const bt = (b.children[index]?.textContent || '').trim();
      const cmp = at.localeCompare(bt, undefined, { numeric: true, sensitivity: 'base' });
      return sortAsc ? cmp : -cmp;
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
