// A <select> that narrows a table/list to rows containing its selected value
// (empty value = show all) — composes with attachLogFilter's text search the
// same way pagination.js does: reads item.dataset.filterMatch (set by the
// search pass) as the "does this row match the search" signal, independent
// of item.style.display, so this filter and the search filter don't fight
// over the same property. Wire attachLogFilter's onChange to call refresh()
// so typing in the search box re-applies this filter on top.
function attachSelectFilter(selectId, containerSelector, itemSelector) {
  const select = document.getElementById(selectId);
  const container = document.querySelector(containerSelector);
  if (!select || !container) return null;

  function refresh() {
    const value = select.value;
    // Plain .includes() would let "10.202.226.2" match inside
    // "10.202.226.21" too — bound the match so a digit/dot on either side
    // (i.e. it being a prefix of a longer IP) doesn't count.
    const pattern = value
      ? new RegExp('(?<![\\d.])' + value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![\\d.])')
      : null;
    container.querySelectorAll(itemSelector).forEach((item) => {
      const searchOk = item.dataset.filterMatch !== '0';
      const selectOk = !pattern || pattern.test(item.textContent);
      item.style.display = (searchOk && selectOk) ? '' : 'none';
    });
  }

  select.addEventListener('change', refresh);
  refresh();
  return { refresh };
}
