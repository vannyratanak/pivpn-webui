document.addEventListener('DOMContentLoaded', () => {
  const root = document.getElementById('overview-root');
  if (!root) return;
  const el = (id) => document.getElementById(`ov-${id}`);
  const escape = (value) => { const node = document.createElement('span'); node.textContent = value == null ? '' : String(value); return node.innerHTML; };
  const text = (id, value) => { if (el(id)) el(id).textContent = value; };
  const parseServerUtc = (ts) => new Date(ts.replace(' ', 'T') + 'Z').getTime();
  let snapshot = null;
  let state;
  let activityRange = null;
  let chartWindow = null;
  const nowTimeFormat = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
  function updateNowMarker() {
    const marker = el('now-marker');
    if (!marker) return;
    const now = new Date();
    const fraction = activityRange === '7d' && chartWindow ? 1 : chartWindow ? (now.getTime() - chartWindow.start) / (chartWindow.end - chartWindow.start) : NaN;
    marker.hidden = !Number.isFinite(fraction) || fraction < 0 || fraction > 1;
    if (marker.hidden) return;
    marker.style.left = `${fraction * 100}%`;
    marker.classList.toggle('near-start', fraction < 0.12);
    marker.classList.toggle('near-end', fraction > 0.88);
    marker.querySelector('.ov-now-marker-label').textContent = `Now, ${nowTimeFormat.format(now)}`;
  }
  const busy = new Set();
  const views = ['connected', 'attention', 'all', 'offline'];
  function readState() {
    const p = new URLSearchParams(location.search);
    state = { tab: views.includes(p.get('tab')) ? p.get('tab') : 'connected',
      q: p.get('q') || '', reason: ['certificate', 'blocked'].includes(p.get('reason')) ? p.get('reason') : '',
      page: Math.max(1, Number.parseInt(p.get('page'), 10) || 1), range: p.get('range') === '7d' ? '7d' : '1d' };
    el('search').value = state.q;
    el('range').value = state.range;
    el('range').dispatchEvent(new Event('change', { bubbles: false }));
  }
  function save(replace = false) {
    const p = new URLSearchParams({ tab: state.tab, range: state.range });
    if (state.q) p.set('q', state.q);
    if (state.reason) p.set('reason', state.reason);
    if (state.page > 1) p.set('page', state.page);
    history[replace ? 'replaceState' : 'pushState']({}, '', `${location.pathname}?${p}`);
  }
  function filterClients(clients) {
    return clients.filter((c) => {
      const attention = c.blocked || ['expired', 'expiring'].includes(c.certificate_state);
      if (state.tab === 'connected' && !c.session) return false;
      if (state.tab === 'offline' && c.session) return false;
      if (state.tab === 'attention' && !attention) return false;
      if (state.reason === 'certificate' && !['expired', 'expiring'].includes(c.certificate_state)) return false;
      if (state.reason === 'blocked' && !c.blocked) return false;
      return [c.name, c.ip, c.status, c.expiration].join(' ').toLowerCase().includes(state.q.toLowerCase());
    });
  }
  function renderTable() {
    root.querySelectorAll('#ov-tabs a').forEach((a) => {
      const active = a.dataset.view === state.tab;
      a.classList.toggle('active', active);
      if (active) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    if (!snapshot) return;
    const matches = filterClients(snapshot.clients);
    const pages = Math.max(1, Math.ceil(matches.length / 10));
    state.page = Math.min(state.page, pages);
    const rows = matches.slice((state.page - 1) * 10, state.page * 10);
    const focusedLink = el('clients-body').contains(document.activeElement) ? document.activeElement.getAttribute('href') : null;
    el('clients-body').innerHTML = rows.length ? rows.map((c) => {
      let certificate = c.certificate_state === 'expired' ? 'Certificate expired' : c.certificate_state === 'expiring' ? `Expires ${c.expiry_date}` : c.certificate_state === 'unknown' ? 'Expiry unknown' : `Expires ${c.expiry_date}`;
      return `<tr><td><a href="/clients/${encodeURIComponent(c.name)}">${escape(c.name)}</a></td><td><span class="badge ${c.session ? 'badge-connected' : 'badge-inactive'}">${c.session ? 'Connected' : 'Offline'}</span></td><td><code>${escape(c.ip || '—')}</code></td><td>${c.blocked ? '<span class="badge badge-inactive">Blocked</span> ' : ''}${escape(certificate)}</td><td>${escape(c.session ? c.session.since || 'Unknown' : '—')}</td></tr>`;
    }).join('') : `<tr><td class="empty" colspan="5">${state.q ? 'No clients match your search.' : !snapshot.clients.length ? 'No client records available.' : state.tab === 'connected' ? 'No clients connected in this snapshot.' : state.tab === 'attention' ? 'No access or certificate issues in this snapshot.' : 'No clients in this view.'} <button class="btn btn-sm" type="button" data-clear>Clear filters</button></td></tr>`;
    text('page', `${matches.length} clients · Page ${state.page} of ${pages}`);
    text('filter-note', state.reason ? `Filtered by ${state.reason === 'certificate' ? 'expired or expiring certificates' : 'blocked access'}. Select a tab to reset.` : 'Connection status reflects the last cached observation.');
    el('prev').disabled = state.page <= 1;
    el('next').disabled = state.page >= pages;
    if (focusedLink) {
      const replacement = [...el('clients-body').querySelectorAll('a')].find((a) => a.getAttribute('href') === focusedLink);
      (replacement || el('search')).focus({ preventScroll: true });
    }
  }
  function renderSnapshot(data) {
    snapshot = data;
    const clients = data.clients;
    const connected = clients.filter((c) => c.session).length;
    const counts = { total: clients.length, connected, blocked: clients.filter((c) => c.blocked).length, expiring: clients.filter((c) => c.certificate_state === 'expiring').length };
    Object.entries(counts).forEach(([key, value]) => text(`count-${key}`, value));
    text('feedback', '');
    text('freshness', data.last_client_update ? `Last row update: ${formatServerTs(data.last_client_update)}` : 'No update timestamp available');
    el('freshness').title = data.freshness_note;
    text('legend-connected', connected);
    text('legend-offline', clients.length - connected);
    text('donut-total', `${connected}/${clients.length}`);
    el('donut-active').setAttribute('stroke-dasharray', `${clients.length ? connected / clients.length * 490.09 : 0} 490.09`);
    root.querySelector('.ov-donut').setAttribute('aria-label', `${connected} connected, ${clients.length - connected} offline, ${clients.length} total clients`);
    text('status-note', clients.length ? 'Blocked access is tracked separately from connection status.' : 'No client records available.');
    renderTable();
  }
  async function json(path) {
    const response = await ApiClient.call(path);
    if (!response.ok) throw new Error('Request failed');
    return response.json();
  }
  function controls() {
    el('refresh').disabled = busy.size > 0;
  }
  // Push-triggered refreshes keep controls stable and preserve the last data
  // while a request runs. Manual Refresh uses the same single-flight guard.
  const failedRefreshTimers = {};
  function retryFailedRefresh(topic) {
    text('feedback', 'Some data could not refresh. Showing the last received data; retrying…');
    if (!failedRefreshTimers[topic]) failedRefreshTimers[topic] = setTimeout(() => {
      delete failedRefreshTimers[topic]; invalidate([topic]);
    }, 30000);
  }
  function clearFailedRefresh(topic) {
    clearTimeout(failedRefreshTimers[topic]); delete failedRefreshTimers[topic];
  }
  let snapshotPolling = false, activityPolling = false;
  async function loadSnapshot(silent) {
    if (snapshotPolling || busy.has('snapshot')) return;
    if (silent) snapshotPolling = true; else { busy.add('snapshot'); controls(); }
    try { renderSnapshot(await json('/api/overview')); clearFailedRefresh('snapshot'); }
    catch {
      if (silent) retryFailedRefresh('snapshot');
      if (!silent) { text('feedback', snapshot ? 'Could not refresh clients. Showing the previous snapshot; use Refresh to retry.' : 'Could not load clients. Use Refresh to retry.'); if (!snapshot) el('clients-body').innerHTML = '<tr><td colspan="5" class="empty">Client data unavailable.</td></tr>'; }
    }
    finally { if (silent) snapshotPolling = false; else { busy.delete('snapshot'); controls(); } }
  }
  function pollSnapshotSilently() { return loadSnapshot(true); }
  async function loadActivity(silent) {
    if (activityPolling || busy.has('activity')) return;
    if (silent) activityPolling = true; else { busy.add('activity'); controls(); }
    const requested = state.range;
    try {
      const data = await json(`/api/overview/activity?range=${requested}&tz_offset=${new Date().getTimezoneOffset()}`);
      if (requested !== state.range) return;
      clearFailedRefresh('activity');
      activityRange = requested;
      text('activity-error', '');
      text('activity-total', data.total);
      const period = requested === '7d' ? 'this week' : 'today';
      text('activity-total-label', `${data.total === 1 ? 'client' : 'clients'} online at peak ${period}`);
      text('coverage', data.coverage_note);
      const max = Math.max(1, data.total);
      const focusedBar = [...el('bars').children].indexOf(document.activeElement);
      el('bars').innerHTML = data.buckets.map((b) => `<div class="ov-bar-column" tabindex="0" role="img" aria-label="${escape(formatServerTs(b.start))} to ${escape(formatServerTs(b.end))}: peak of ${b.peak} online"><span class="ov-bar" style="height:${b.peak / max * 100}%"></span><span class="ov-bar-tooltip">${escape(formatServerTs(b.start).slice(5, 16))} · ${b.peak}</span></div>`).join('');
      text('axis-start', `${formatServerTs(data.start).slice(5, 16)}`);
      text('axis-end', `${formatServerTs(data.end).slice(5, 16)} · Peak ${data.total}`);
      el('chart-data').innerHTML = data.buckets.map((b) => `<tr><td>${escape(formatServerTs(b.start))}</td><td>${escape(formatServerTs(b.end))}</td><td>${b.peak}</td></tr>`).join('');
      // Where "now" actually falls within [start, end) — data.start/end are
      // UTC strings from the server, compared against the viewer's own
      // clock (not a server timestamp) so the line tracks in real time
      // between data updates, not just at the moment this response arrived.
      chartWindow = { start: parseServerUtc(data.start), end: parseServerUtc(data.end) };
      updateNowMarker();
      if (focusedBar >= 0) (el('bars').children[Math.min(focusedBar, data.buckets.length - 1)]).focus({ preventScroll: true });
    } catch {
      if (silent) retryFailedRefresh('activity');
      if (!silent) {
        if (activityRange !== requested) {
          el('bars').replaceChildren(); el('chart-data').replaceChildren();
          chartWindow = null;
          if (el('now-marker')) el('now-marker').hidden = true;
          ['activity-total', 'activity-total-label', 'coverage', 'axis-start', 'axis-end'].forEach((id) => text(id, '—'));
          text('activity-error', 'Could not refresh activity. Use Refresh to retry.');
        } else text('activity-error', 'Could not refresh activity. Showing the previous chart; use Refresh to retry.');
      }
    } finally {
      if (silent) activityPolling = false; else { busy.delete('activity'); controls(); }
      if (requested !== state.range) loadActivity();
    }
  }
  function pollActivitySilently() { return loadActivity(true); }
  function renderHealth(data) {
    if (root.dataset.admin !== 'true') return;
    text('service', data.service.state); text('unit', data.service.unit || 'Service check unavailable');
    text('agent', data.agent); text('health-time', `Checked ${formatServerTs(data.checked_at)}`);
    text('health-note', data.note || '');
  }
  function refresh() { loadSnapshot(); loadActivity(); }
  // Invalidation events are bounded and coalesced. If an event arrives during
  // a fetch, run again after it finishes so an old response can't lose a change.
  const dirty = new Set();
  let dirtyTimer = null;
  function invalidate(topics) {
    topics.filter(topic => ['snapshot', 'activity'].includes(topic)).forEach(topic => dirty.add(topic));
    if (dirtyTimer !== null) return;
    dirtyTimer = setTimeout(flushChanges, 500);
  }
  function flushChanges() {
    dirtyTimer = null;
    if (document.hidden) return;
    if (dirty.has('snapshot') && !snapshotPolling && !busy.has('snapshot')) {
      dirty.delete('snapshot'); pollSnapshotSilently();
    }
    if (dirty.has('activity') && !activityPolling && !busy.has('activity')) {
      dirty.delete('activity'); pollActivitySilently();
    }
    if (dirty.size) dirtyTimer = setTimeout(flushChanges, 500);
  }
  const stream = OverviewStream((event, data) => {
    if (event === 'ready') invalidate(['snapshot', 'activity']);
    if (event === 'changed') invalidate(data);
    if (event === 'health') renderHealth(data);
  }, message => text('live-status', message));
  root.addEventListener('click', (event) => {
    const control = event.target.closest('[data-view], [data-clear]');
    if (!control) return;
    event.preventDefault();
    state.tab = control.dataset.view || 'all'; state.reason = control.dataset.reason || ''; state.page = 1;
    if (control.hasAttribute('data-clear')) { state.q = ''; el('search').value = ''; }
    save(); renderTable();
  });
  el('search').addEventListener('input', () => { state.q = el('search').value; state.page = 1; save(true); renderTable(); });
  el('prev').addEventListener('click', () => { state.page = Math.max(1, state.page - 1); save(); renderTable(); });
  el('next').addEventListener('click', () => { state.page++; save(); renderTable(); });
  readState();
  el('range').addEventListener('change', () => { if (state.range === el('range').value) return; state.range = el('range').value; save(); loadActivity(); });
  window.addEventListener('popstate', () => { readState(); renderTable(); if (activityRange !== state.range) loadActivity(); });
  el('refresh').addEventListener('click', refresh);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      stream.stop(); clearTimeout(dirtyTimer); dirtyTimer = null;
    } else {
      updateNowMarker(); refresh(); stream.start();
    }
  });
  window.addEventListener('pagehide', () => stream.stop());
  window.addEventListener('pageshow', () => { if (!document.hidden) stream.start(); });
  // This timer only moves the clock label. Data changes arrive over SSE.
  // A new hour needs a chart refresh even if an existing session stays online.
  let hour = new Date().toDateString() + ':' + new Date().getHours();
  setInterval(() => {
    if (document.hidden) return;
    updateNowMarker();
    const now = new Date();
    const nextHour = now.toDateString() + ':' + now.getHours();
    if (nextHour !== hour) {
      hour = nextHour;
      setTimeout(() => invalidate(['snapshot', 'activity']), 1100);
    }
  }, 1000);
  refresh();
  if (!document.hidden) stream.start();
});
