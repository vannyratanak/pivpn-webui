// A <select> that narrows a table/list to rows containing its selected value
// (empty value = show all) — composes with attachLogFilter's text search the
// same way pagination.js does: reads item.dataset.filterMatch (set by the
// search pass) as the "does this row match the search" signal, independent
// of item.style.display, so this filter and the search filter don't fight
// over the same property. Also writes item.dataset.selectMatch (this
// filter's own verdict, search excluded) so pagination.js — which composes
// with this on the Firewall Rules table — can read it separately: reading
// only style.display or only filterMatch here would either double up or
// silently discard whichever of search/select this filter doesn't directly
// own. Wire attachLogFilter's onChange to call refresh() so typing in the
// search box re-applies this filter on top; pass onChange to also re-run
// pagination on this filter's own change event, not just the search box's.
function attachSelectFilter(selectId, containerSelector, itemSelector, onChange) {
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
      item.dataset.selectMatch = selectOk ? '1' : '0';
      item.style.display = (searchOk && selectOk) ? '' : 'none';
    });
    onChange && onChange();
  }

  select.addEventListener('change', refresh);
  refresh();
  return { refresh };
}
