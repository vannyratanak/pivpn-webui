// Logs page — same JWT/fetch() pattern as clients-page.js, extended to a
// page with six different tabs and real server-side search/range/
// pagination (GET /api/logs), not the "fetch everything, page client-side"
// shape Clients/Users use.
//
// Every allowed tab's <section> (see logs.html's data-logs-section) exists
// in the DOM at once now, hidden except the active one — switching tabs
// just toggles visibility and refetches, no page reload, no plain GET
// navigation left anywhere on this page. Search/range/page-size/Prev/Next/
// Refresh are all wired to state + fetch, never a form submission.
(function () {
  function escapeHtml(value) {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
  }

  function sessionsRow(e) {
    const badge = e.event === 'connected'
      ? '<span class="badge badge-connected">connected</span>'
      : e.event === 'disconnected'
        ? '<span class="badge badge-inactive">disconnected</span>'
        : '<span class="badge badge-inactive">other</span>';
    return `<tr><td>${escapeHtml(e.ts)}</td><td>${badge}</td><td>${escapeHtml(e.client)}</td><td>${escapeHtml(e.address)}</td><td>${escapeHtml(e.detail)}</td></tr>`;
  }

  function clientSessionsRow(s) {
    const endCell = s.ongoing
      ? '<span class="badge badge-connected">ongoing</span>'
      : s.status_note
        ? `<span class="cell-note">${escapeHtml(s.status_note)}</span>`
        : escapeHtml(s.end || '—');
    const addressCell = s.real_address
      ? `${escapeHtml(s.real_address)}<span class="cell-note hint-block">via relay (${escapeHtml(s.address)})</span>`
      : escapeHtml(s.address || '—');
    return `<tr><td>${escapeHtml(s.client)}</td><td>${escapeHtml(s.start || '—')}</td><td>${endCell}</td><td>${escapeHtml(s.duration || '—')}</td><td>${addressCell}</td></tr>`;
  }

  function trafficRow(f) {
    const src = escapeHtml(f.src) + (f.sport ? ':' + escapeHtml(f.sport) : '');
    const dst = escapeHtml(f.dst) + (f.dport ? ':' + escapeHtml(f.dport) : '');
    return `<tr><td>${escapeHtml(f.ts)}</td><td>${escapeHtml(f.client)}</td><td>${src}</td><td>${dst}</td><td>${escapeHtml(f.dst_org || '—')}</td><td>${escapeHtml(f.proto)}</td><td>${escapeHtml(f.dport || '—')}</td></tr>`;
  }

  function systemRow(e) {
    return `<tr><td>${escapeHtml(e.ts)}</td><td>${escapeHtml(e.process || '—')}</td><td>${escapeHtml(e.message)}</td></tr>`;
  }

  function activityRow(e) {
    const cls = e.result === 'error' ? ' class="blocked-row"' : '';
    return `<tr${cls}><td>${escapeHtml(e.ts)}</td><td>${escapeHtml(e.actor)}</td><td>${escapeHtml(e.action)}</td><td>${escapeHtml(e.target || '')}</td><td>${escapeHtml(e.result)}</td><td>${escapeHtml(e.detail || '')}</td></tr>`;
  }

  function authRow(e) {
    const cls = e.result === 'error' ? ' class="blocked-row"' : '';
    return `<tr${cls}><td>${escapeHtml(e.ts)}</td><td>${escapeHtml(e.actor)}</td><td>${escapeHtml(e.action)}</td><td>${escapeHtml(e.result)}</td><td>${escapeHtml(e.detail || '')}</td></tr>`;
  }

  // Mirrors the exact empty-state text + colspan each tab's own template
  // used to render server-side.
  const TAB_CONFIG = {
    sessions: { tbodyId: 'sessions-tbody', colCount: 5, rowHtml: sessionsRow, emptyMessage: (q) => (q ? 'No sessions match that search.' : 'No session events found.') },
    client_sessions: { tbodyId: 'client-sessions-tbody', colCount: 5, rowHtml: clientSessionsRow, emptyMessage: (q) => (q ? 'No sessions match that search.' : 'No session events found.') },
    traffic: { tbodyId: 'traffic-tbody', colCount: 7, rowHtml: trafficRow, emptyMessage: (q) => (q ? 'No flows match that search.' : 'No traffic flow events found.') },
    system: { tbodyId: 'system-log-tbody', colCount: 3, rowHtml: systemRow, emptyMessage: (q) => (q ? 'No log lines match that search.' : 'No log lines found yet.') },
    activity: { tbodyId: 'activity-tbody', colCount: 6, rowHtml: activityRow, emptyMessage: (q) => (q ? 'No activity matches that search.' : 'No activity yet.') },
    auth: { tbodyId: 'auth-tbody', colCount: 5, rowHtml: authRow, emptyMessage: (q) => (q ? 'No auth activity matches that search.' : 'No auth activity yet.') },
  };

  document.addEventListener('DOMContentLoaded', () => {
    const root = document.getElementById('logs-tabs');
    if (!root) return;

    const searchInput = document.getElementById('logs-search');
    const rangeSelect = document.getElementById('logs-range');
    const pageSizeSelect = document.getElementById('logs-page-size');
    const prevBtn = document.querySelector('[data-logs-page-nav="prev"]');
    const nextBtn = document.querySelector('[data-logs-page-nav="next"]');
    const statusEl = document.querySelector('[data-logs-page-status]');
    const refreshBtn = document.querySelector('[data-logs-refresh]');
    const tabLinks = Array.from(document.querySelectorAll('[data-logs-tab-link]'));
    if (!searchInput || !rangeSelect || !pageSizeSelect || !prevBtn || !nextBtn) return;

    let tab = root.dataset.tab;
    let page = parseInt(root.dataset.page, 10) || 1;

    function activeSection() {
      return document.querySelector(`[data-logs-section="${tab}"]`);
    }

    function skeletonRowHtml(colCount) {
      const cells = Array(colCount).fill('<td><span class="skeleton-bar"></span></td>').join('');
      return `<tr class="skeleton-row">${cells}</tr>`.repeat(6);
    }

    function apiUrl() {
      const params = new URLSearchParams({ tab, range: rangeSelect.value, page: String(page), page_size: pageSizeSelect.value });
      const q = searchInput.value.trim();
      if (q) params.set('q', q);
      return '/api/logs?' + params.toString();
    }

    // Keeps the URL bookmarkable/refreshable at the current tab/search/
    // range/page — nothing here ever triggers a real navigation itself.
    function syncUrl() {
      const url = new URL(window.location.href);
      url.searchParams.set('tab', tab);
      url.searchParams.set('page', String(page));
      url.searchParams.set('page_size', pageSizeSelect.value);
      url.searchParams.set('range', rangeSelect.value);
      const q = searchInput.value.trim();
      if (q) url.searchParams.set('q', q); else url.searchParams.delete('q');
      window.history.replaceState(null, '', url);
    }

    function showLoadError(cfg, message) {
      const tbody = document.getElementById(cfg.tbodyId);
      tbody.innerHTML = `<tr class="empty-row"><td colspan="${cfg.colCount}" class="empty">${escapeHtml(message)}</td></tr>`;
    }

    function loadLogs(showSkeletonWhileLoading) {
      const cfg = TAB_CONFIG[tab];
      const tbody = document.getElementById(cfg.tbodyId);
      if (showSkeletonWhileLoading) tbody.innerHTML = skeletonRowHtml(cfg.colCount);
      const q = searchInput.value.trim();
      return ApiClient.call(apiUrl())
        .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data })))
        .then(({ ok, data }) => {
          if (!ok) { showLoadError(cfg, data.error || 'Could not load this tab.'); return; }
          const entries = data.entries || [];
          tbody.innerHTML = entries.length
            ? entries.map(cfg.rowHtml).join('')
            : `<tr class="empty-row"><td colspan="${cfg.colCount}" class="empty">${cfg.emptyMessage(q)}</td></tr>`;

          const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
          if (statusEl) statusEl.textContent = `Page ${data.page} of ${totalPages} (${data.total} total)`;
          prevBtn.disabled = data.page <= 1;
          nextBtn.disabled = data.page >= totalPages;
          page = data.page;
          syncUrl();
        });
    }

    // Tab switching never preserves search/range across tabs (matches the
    // old plain-<a>-navigation behavior, which never carried q/range
    // forward either) — only *which tab* survives via the URL now.
    function switchTab(newTab, newTabLabel) {
      if (newTab === tab || !TAB_CONFIG[newTab]) return;
      const oldSection = activeSection();
      if (oldSection) oldSection.hidden = true;
      tab = newTab;
      page = 1;
      searchInput.value = '';
      rangeSelect.value = '1h';
      searchInput.placeholder = 'Search…';
      searchInput.setAttribute('aria-label', `Search ${newTabLabel}`);
      const newSection = activeSection();
      if (newSection) newSection.hidden = false;
      tabLinks.forEach((a) => {
        const isActive = a.dataset.logsTabLink === newTab;
        a.classList.toggle('active', isActive);
        if (isActive) a.setAttribute('aria-current', 'page');
        else a.removeAttribute('aria-current');
      });
      loadLogs(true);
    }

    tabLinks.forEach((a) => {
      a.addEventListener('click', (e) => {
        e.preventDefault();
        switchTab(a.dataset.logsTabLink, a.dataset.logsTabLabel || '');
      });
    });

    // Enter-to-search, matching the old form's "submits on Enter"
    // behavior — a real query per keystroke would be wasteful given this
    // is a server-side search, not client-side filtering.
    searchInput.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter') return;
      e.preventDefault();
      page = 1;
      loadLogs(false);
    });

    rangeSelect.addEventListener('change', () => { page = 1; loadLogs(false); });
    pageSizeSelect.addEventListener('change', () => { page = 1; loadLogs(false); });
    prevBtn.addEventListener('click', () => { page = Math.max(1, page - 1); loadLogs(false); });
    nextBtn.addEventListener('click', () => { page += 1; loadLogs(false); });
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        ApiClient.withBusy(refreshBtn, ApiClient.call('/api/logs/refresh', { method: 'POST' })
          .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data }))))
          .then(({ ok, data }) => {
            if (!ok) { showLoadError(TAB_CONFIG[tab], data.error || 'Could not refresh.'); return; }
            loadLogs(false);
          });
      });
    }

    loadLogs(true);
  });
})();
