// Client-side pagination layered on top of attachLogFilter (log-filter.js).
// Reads item.dataset.filterMatch (set by log-filter.js's filter pass) as the
// authoritative "does this row match the current search" signal, independent
// of item.style.display — which this file also writes to, to slice the
// matching set into pages. Keeping those two concerns on separate signals is
// what lets filtering, sorting, and paging compose correctly instead of
// fighting over the same style.display property.
function attachPagination(containerSelector, itemSelector, pageSizeId, controlsId) {
  const container = document.querySelector(containerSelector);
  const pageSizeSelect = document.getElementById(pageSizeId);
  const controls = document.getElementById(controlsId);
  if (!container || !pageSizeSelect || !controls) return null;

  const prevBtn = controls.querySelector('[data-page-prev]');
  const nextBtn = controls.querySelector('[data-page-next]');
  const status = controls.querySelector('[data-page-status]');
  // A screen reader user paging/searching gets no signal that "Page 2 of 5"
  // changed unless something announces it — set here once, so every page
  // that calls attachPagination gets it for free instead of needing the
  // attribute repeated in each page's own template markup.
  if (status) status.setAttribute('aria-live', 'polite');

  let currentPage = 1;

  function refresh() {
    const pageSize = parseInt(pageSizeSelect.value, 10) || 25;
    const allItems = Array.from(container.querySelectorAll(itemSelector));
    const matching = allItems.filter((item) => item.dataset.filterMatch !== '0');
    const totalPages = Math.max(1, Math.ceil(matching.length / pageSize));
    currentPage = Math.min(Math.max(1, currentPage), totalPages);

    const start = (currentPage - 1) * pageSize;
    const end = start + pageSize;
    matching.forEach((item, i) => {
      item.style.display = (i >= start && i < end) ? '' : 'none';
    });

    // Stays visible (not hidden) even with nothing to page through — Prev/Next
    // just go disabled, same as any other control with nothing to do, rather
    // than the whole row disappearing and shifting the layout around it.
    prevBtn.disabled = currentPage <= 1;
    nextBtn.disabled = currentPage >= totalPages;
    status.textContent = matching.length === 0
      ? 'No results'
      : `Page ${currentPage} of ${totalPages} (${matching.length} total)`;
  }

  prevBtn.addEventListener('click', () => { currentPage -= 1; refresh(); });
  nextBtn.addEventListener('click', () => { currentPage += 1; refresh(); });
  pageSizeSelect.addEventListener('change', () => { currentPage = 1; refresh(); });

  refresh();
  return { refresh };
}
