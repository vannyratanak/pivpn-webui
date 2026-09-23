// Client detail page — same fetch()-driven pattern as clients-page.js/
// firewall-page.js (see clients-page.js's own top comment), but the
// first page converted with NO "left on old form-POST" carve-outs: the
// header meta strip, the Renew/Block/Remove actions dropdown, Download,
// the rules table (list/toggle/delete/add), and Apply Rules/Save Rules/
// bulk-disable/bulk-delete all go through /api/... here. The client-
// scoped rule endpoints this depends on (resync/persist/bulk-disable/
// bulk-delete) are new — see app/api.py's own comments on them.
document.addEventListener('DOMContentLoaded', () => {
  const metaRow = document.getElementById('client-meta-row');
  if (!metaRow) return;
  const name = metaRow.dataset.clientName;

  const rulesTbody = document.getElementById('client-rules-tbody');
  const ruleActions = document.getElementById('client-rule-actions');
  const noIpMessage = document.getElementById('client-no-ip-message');
  const saveRulesBtn = document.getElementById('client-save-rules-btn');
  const blockToggleBtn = document.getElementById('client-block-toggle-btn');
  const addRuleDialog = document.getElementById('add-client-rule-dialog');
  const addRuleForm = document.getElementById('add-client-rule-form');
  const addRuleSrcOption = document.getElementById('client-add-rule-src-option');
  let rulesPager = null;
  let clientIp = null;
  let clientBlocked = false;

  function escapeHtml(value) {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
  }

  function showToast(message) {
    const notice = document.createElement('div');
    notice.className = 'reorder-error-toast';
    notice.setAttribute('role', 'alert');
    notice.textContent = message;
    document.body.appendChild(notice);
    setTimeout(() => notice.remove(), 3200);
  }

  // --- client meta (status/cert/expiry/ip/session) + actions dropdown

  function metaSkeletonHtml() {
    return '<span class="skeleton-bar"></span><span class="skeleton-bar"></span><span class="skeleton-bar"></span>';
  }

  // clients-page.js's own GET /api/clients response already has
  // everything this page's own GET /api/clients/<name> would return —
  // reading what it cached in sessionStorage right before this
  // navigation (see that file's own comment on DETAIL_CACHE_KEY) skips
  // this page's skeleton-then-fetch entirely for the common "clicked a
  // client's name from the list" path, without ever trusting it as the
  // final answer — loadClient() below still always fetches fresh right
  // after, this only affects what's on screen for that first moment.
  const DETAIL_CACHE_KEY = 'pivpn_webui_client_cache';
  function getCachedClient() {
    try {
      const raw = sessionStorage.getItem(DETAIL_CACHE_KEY);
      return raw ? JSON.parse(raw)[name] || null : null;
    } catch (e) {
      return null;
    }
  }

  function renderMeta(c) {
    clientIp = c.ip;
    clientBlocked = !!c.blocked;
    const validSvg = '<svg class="cert-icon cert-icon-valid" aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11.5 14.5 15.5 10"/></svg>';
    const blockedSvg = '<svg class="cert-icon cert-icon-blocked" aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="9.5" y1="9.5" x2="14.5" y2="14.5"/><line x1="14.5" y1="9.5" x2="9.5" y2="14.5"/></svg>';
    const sep = '<span class="meta-sep" aria-hidden="true">&middot;</span>';
    const parts = [
      `<span class="status-indicator ${c.session ? 'status-indicator-connected' : ''}"><span class="status-dot ${c.session ? 'status-dot-connected' : ''}" aria-hidden="true"></span>${c.session ? 'Online' : 'Offline'}</span>`,
      `<span class="cert-status">${c.blocked ? blockedSvg : validSvg}${escapeHtml(c.status)}${c.blocked ? ' (blocked)' : ''}</span>`,
      `<span>Expires ${escapeHtml(c.expiration || '—')}</span>`,
      `<span>${escapeHtml(c.ip || '—')}</span>`,
    ];
    if (c.session) parts.push(`<span>Connected since ${escapeHtml(c.session.since || '—')}</span>`);
    metaRow.innerHTML = parts.join(sep);

    blockToggleBtn.textContent = clientBlocked ? 'Unblock' : 'Block';

    if (clientIp) {
      ruleActions.hidden = false;
      noIpMessage.hidden = true;
      addRuleSrcOption.textContent = `${name} (${clientIp})`;
    } else {
      ruleActions.hidden = true;
      noIpMessage.hidden = false;
    }
  }

  function loadClient(showSkeletonWhileLoading) {
    // Only on the very first load, not the background poll below — that
    // one already has real content on screen, and flashing it back to
    // skeleton bars every 10 seconds would read as far more disruptive
    // than the thing it's meant to fix.
    if (showSkeletonWhileLoading) {
      const cached = getCachedClient();
      if (cached) renderMeta(cached);
      else metaRow.innerHTML = metaSkeletonHtml();
    }
    return ApiClient.call(`/api/clients/${encodeURIComponent(name)}`)
      .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) {
          metaRow.innerHTML = `<span class="empty">${escapeHtml(data.error || 'Client not found.')}</span>`;
          ruleActions.hidden = true;
          noIpMessage.hidden = true;
          return;
        }
        renderMeta(data);
      });
  }

  document.getElementById('client-download-btn').addEventListener('click', (e) => {
    const btn = e.currentTarget;
    ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/download`)
      .then((resp) => (resp.ok ? resp.blob() : Promise.reject()))
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${name}.ovpn`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      }))
      .catch(() => showToast(`Could not download ${name}'s profile.`));
  });

  document.getElementById('client-actions-menu').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;

    if (action === 'renew') {
      window.askConfirm(
        `Renew ${name}? This revokes the current cert and issues a new one — the old .ovpn will stop working immediately.`,
        'Renew',
        () => {
          ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/renew`, { method: 'POST' })
            .then((resp) => (resp.ok ? loadClient() : resp.json().then((d) => Promise.reject(d)))))
            .catch((d) => showToast((d && d.error) || `Could not renew ${name}.`));
        },
      );
      return;
    }

    if (action === 'block') {
      const nowBlocked = !clientBlocked;
      ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ blocked: nowBlocked }),
      })
        .then((resp) => (resp.ok ? loadClient() : Promise.reject())))
        .catch(() => showToast(`Could not ${nowBlocked ? 'block' : 'unblock'} ${name}.`));
      return;
    }

    if (action === 'remove') {
      window.askConfirm(`Permanently remove ${name}? This cannot be undone.`, 'Remove', () => {
        ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}`, { method: 'DELETE' })
          .then((resp) => {
            if (!resp.ok) return Promise.reject();
            window.location.href = '/clients';
          }))
          .catch(() => showToast(`Could not remove ${name}.`));
      });
    }
  });

  // --- rules table

  function rowHtml(r) {
    return `
      <tr class="${r.enabled ? '' : 'disabled-row'}" draggable="true" data-rule-id="${r.id}">
        <td><input type="checkbox" class="client-rule-select-checkbox" data-rule-id="${r.id}" aria-label="Select rule ${r.id}"></td>
        <td>${escapeHtml(r.kind)}</td>
        <td>${escapeHtml(r.action)}</td>
        <td>${escapeHtml(r.detail)}</td>
        <td>${escapeHtml(r.comment || '')}</td>
        <td><span class="${r.persisted ? 'saved-yes' : 'saved-no'}">${r.persisted ? 'Saved' : 'Unsaved'}</span></td>
        <td><span class="drag-handle" title="Drag to reorder, or focus and press ↑/↓" tabindex="0" role="button" aria-label="Reorder rule — press up or down arrow to move it">&#9776;</span></td>
        <td>
          <div class="actions">
            <button type="button" class="btn btn-sm ${r.enabled ? 'btn-warn' : 'btn-ok'}" data-action="toggle" data-rule-id="${r.id}">${r.enabled ? 'Disable' : 'Enable'}</button>
            <button type="button" class="btn btn-sm btn-danger" data-action="delete" data-rule-id="${r.id}">Delete</button>
          </div>
        </td>
      </tr>`;
  }

  function skeletonRowHtml() {
    const cells = '<td></td>' + Array(4).fill('<td><span class="skeleton-bar"></span></td>').join('') + '<td></td><td></td><td></td>';
    return `<tr class="skeleton-row">${cells}</tr>`.repeat(4);
  }

  function updateBulkUi() {
    const checkboxes = Array.from(document.querySelectorAll('#client-rules-tbody .client-rule-select-checkbox'));
    const checked = checkboxes.filter((cb) => cb.checked);
    const bulkGroup = document.getElementById('client-bulk-actions-group');
    const disableBtn = document.getElementById('client-bulk-disable-btn');
    const deleteBtn = document.getElementById('client-bulk-delete-btn');
    bulkGroup.hidden = checked.length === 0;
    document.getElementById('client-bulk-disable-count').textContent = checked.length;
    document.getElementById('client-bulk-delete-count').textContent = checked.length;
    disableBtn.disabled = checked.length === 0;
    deleteBtn.disabled = checked.length === 0;
  }

  function render(rules) {
    if (!rules.length) {
      rulesTbody.innerHTML = '<tr class="empty-row"><td colspan="8" class="empty">No rules scoped to this client yet.</td></tr>';
    } else {
      rulesTbody.innerHTML = rules.map(rowHtml).join('');
    }
    saveRulesBtn.hidden = rules.every((r) => r.persisted);

    if (rulesPager) {
      rulesPager.refresh();
    } else {
      rulesPager = attachPagination('#client-rules-tbody', 'tr:not(.empty-row)', 'client-rules-page-size', 'client-rules-pagination');
      attachLogFilter('client-rules-filter', '#client-rules-tbody', 'tr:not(.empty-row)', null, () => rulesPager && rulesPager.refresh());
      // Shared with the main Firewall page (firewall-reorder.js, loaded
      // globally via base.html) — only the endpoint differs, scoped to
      // this client's own rules (see api.py's client_reorder_rule).
      if (window.attachFirewallReorder) {
        window.attachFirewallReorder('#client-rules-tbody', (ruleId) => `/api/clients/${encodeURIComponent(name)}/rules/${ruleId}/reorder`);
      }
    }
    document.getElementById('client-rules-select-all').checked = false;
    updateBulkUi();
  }

  // Optimistic in-place patch for a toggle — same reasoning as
  // firewall-page.js's own updateRuleRowInPlace: no GET for just this
  // one rule exists, so this uses what's already known (enabled flips,
  // toggling always makes a rule Unsaved relative to disk) rather than
  // re-fetching and rebuilding the whole table for a single row.
  function updateRuleRowInPlace(row, enabled) {
    row.classList.toggle('disabled-row', !enabled);
    const toggleBtn = row.querySelector('[data-action="toggle"]');
    if (toggleBtn) {
      toggleBtn.textContent = enabled ? 'Disable' : 'Enable';
      toggleBtn.classList.toggle('btn-warn', enabled);
      toggleBtn.classList.toggle('btn-ok', !enabled);
    }
    const savedCell = row.querySelector('.saved-yes, .saved-no');
    if (savedCell) {
      savedCell.textContent = 'Unsaved';
      savedCell.classList.remove('saved-yes');
      savedCell.classList.add('saved-no');
    }
    saveRulesBtn.hidden = false;
  }

  function removeRuleRow(row) {
    row.remove();
    if (!rulesTbody.querySelector('tr:not(.empty-row)')) {
      rulesTbody.innerHTML = '<tr class="empty-row"><td colspan="8" class="empty">No rules scoped to this client yet.</td></tr>';
    }
    if (rulesPager) rulesPager.refresh();
    saveRulesBtn.hidden = !rulesTbody.querySelector('.saved-no');
    updateBulkUi();
  }

  function loadRules(showSkeletonWhileLoading) {
    if (showSkeletonWhileLoading) rulesTbody.innerHTML = skeletonRowHtml();
    return ApiClient.call(`/api/clients/${encodeURIComponent(name)}/rules`)
      .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data })))
      .then(({ ok, data }) => {
        // An error body has no "rules" key, so `data.rules || []` used to
        // silently render "No rules scoped to this client yet." instead
        // of the real error — technically not a crash (unlike the other
        // pages' version of this gap), but just as misleading: it looks
        // like a normal empty state, not a failure.
        if (!ok) {
          rulesTbody.innerHTML = `<tr class="empty-row"><td colspan="8" class="empty">${escapeHtml(data.error || 'Could not load rules.')}</td></tr>`;
          return;
        }
        render(data.rules || []);
      });
  }

  rulesTbody.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const ruleId = btn.dataset.ruleId;

    const row = btn.closest('tr');
    if (btn.dataset.action === 'toggle') {
      const currentlyEnabled = !row.classList.contains('disabled-row');
      ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/rules/${ruleId}/toggle`, { method: 'POST' })
        .then((resp) => (resp.ok ? updateRuleRowInPlace(row, !currentlyEnabled) : Promise.reject())))
        .catch(() => showToast(`Could not toggle rule #${ruleId}.`));
      return;
    }
    if (btn.dataset.action === 'delete') {
      window.askConfirm('Delete this rule?', 'Delete', () => {
        ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/rules/${ruleId}`, { method: 'DELETE' })
          .then((resp) => (resp.ok ? removeRuleRow(row) : Promise.reject())))
          .catch(() => showToast(`Could not delete rule #${ruleId}.`));
      });
    }
  });

  document.getElementById('client-rules-select-all').addEventListener('change', (e) => {
    document.querySelectorAll('#client-rules-tbody .client-rule-select-checkbox').forEach((cb) => {
      if (cb.closest('tr').style.display !== 'none') cb.checked = e.target.checked;
    });
    updateBulkUi();
  });
  rulesTbody.addEventListener('change', (e) => {
    if (e.target.classList.contains('client-rule-select-checkbox')) updateBulkUi();
  });

  function selectedRuleIds() {
    return Array.from(document.querySelectorAll('#client-rules-tbody .client-rule-select-checkbox'))
      .filter((cb) => cb.checked)
      .map((cb) => Number(cb.dataset.ruleId));
  }

  document.getElementById('client-bulk-disable-btn').addEventListener('click', (e) => {
    const ids = selectedRuleIds();
    if (!ids.length) return;
    ApiClient.withBusy(e.currentTarget, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/rules/bulk-disable`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rule_ids: ids }),
    })
      .then((resp) => (resp.ok ? loadRules() : Promise.reject())))
      .catch(() => showToast('Could not disable the selected rule(s).'));
  });

  document.getElementById('client-bulk-delete-btn').addEventListener('click', (e) => {
    const ids = selectedRuleIds();
    if (!ids.length) return;
    const btn = e.currentTarget;
    window.askConfirm(`Delete ${ids.length} selected rule(s)? This cannot be undone.`, 'Delete', () => {
      ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/rules/bulk-delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule_ids: ids }),
      })
        .then((resp) => (resp.ok ? loadRules() : Promise.reject())))
        .catch(() => showToast('Could not delete the selected rule(s).'));
    });
  });

  document.getElementById('client-apply-rules-btn').addEventListener('click', (e) => {
    ApiClient.withBusy(e.currentTarget, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/rules/resync`, { method: 'POST' })
      .then((resp) => (resp.ok ? loadRules() : Promise.reject())))
      .catch(() => showToast('Could not reapply firewall rules.'));
  });

  saveRulesBtn.addEventListener('click', (e) => {
    ApiClient.withBusy(e.currentTarget, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/rules/persist`, { method: 'POST' })
      .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data }))))
      .then(({ ok, data }) => {
        if (!ok) { showToast(data.error || 'Could not save firewall rules.'); return; }
        loadRules();
      })
      .catch(() => showToast('Could not save firewall rules.'));
  });

  // --- Add Rule dialog

  document.getElementById('client-add-rule-open-btn').addEventListener('click', () => addRuleDialog.showModal());

  addRuleForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const submitBtn = addRuleForm.querySelector('[type="submit"]');
    const action = addRuleForm.querySelector('[name="action"]').value;
    const protocol = addRuleForm.querySelector('[name="protocol"]').value;
    const dport = addRuleForm.querySelector('[name="dport"]').value;
    const comment = addRuleForm.querySelector('[name="comment"]').value;
    const rawDsts = Array.from(addRuleForm.querySelectorAll('[name="dst"]')).map((el) => el.value.trim());
    const filledDsts = rawDsts.filter((d) => d);
    const dsts = filledDsts.length ? filledDsts : [''];

    ApiClient.withBusy(submitBtn, Promise.all(dsts.map((dst) =>
      ApiClient.call(`/api/clients/${encodeURIComponent(name)}/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, protocol, dst, dport, comment }),
      }).then((resp) => resp.json().then((data) => ({ ok: resp.ok, data, dst }))),
    ))).then((results) => {
      const added = results.filter((r) => r.ok).length;
      const skipped = results.filter((r) => !r.ok).map((r) => `${r.dst || 'any'}: ${r.data.error}`);
      if (added) showToast(added > 1 ? `Added ${added} forward rule(s).` : 'Forward rule added.');
      if (skipped.length) showToast('Skipped: ' + skipped.join('; '));
      if (added) {
        addRuleDialog.close();
        addRuleForm.reset();
        // Drop any extra destination rows added via "+ Destination",
        // back down to the one permanent row the dialog opens with.
        document.querySelectorAll('.client-add-rule-dst-row').forEach((row, i) => { if (i > 0) row.remove(); });
        loadRules();
      }
    });
  });

  // --- Import Rules dialog

  const importRuleDialog = document.getElementById('client-import-rules-dialog');
  const importRuleForm = document.getElementById('client-import-rules-form');
  document.getElementById('client-import-rule-open-btn').addEventListener('click', () => importRuleDialog.showModal());

  importRuleForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const submitBtn = importRuleForm.querySelector('[type="submit"]');
    ApiClient.withBusy(submitBtn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/rules/import`, {
      method: 'POST',
      body: new FormData(importRuleForm),
    }).then((resp) => resp.json().then((data) => ({ ok: resp.ok, data }))))
      .then(({ ok, data }) => {
        if (!ok) { showToast(data.error || 'Could not import rules.'); return; }
        let message = data.added ? `Imported ${data.added} rule(s).` : 'No rules were added.';
        if (data.errors && data.errors.length) message += ` ${data.errors.length} failed: ${data.errors.slice(0, 10).join('; ')}`;
        showToast(message);
        if (data.added) {
          importRuleDialog.close();
          importRuleForm.reset();
          loadRules();
        }
      })
      .catch(() => showToast('Could not import rules.'));
  });

  // Same reasoning as clients-page.js's own poll: this client's Online/
  // Offline status can change with no action on this page at all (they
  // connect/disconnect their own VPN client), so it shouldn't need a
  // manual reload to show current — the meta strip is small enough that
  // loadClient()'s existing full-refresh is fine to reuse here (unlike
  // the rules table, there's no pagination/filter state a rebuild could
  // clobber).
  const POLL_INTERVAL_MS = 10 * 1000;
  setInterval(() => {
    if (document.visibilityState === 'hidden') return;
    loadClient();
  }, POLL_INTERVAL_MS);

  // --- Activity (session log + traffic), scoped to this client only —
  // reuses the same GET /api/logs endpoint the Logs page itself uses,
  // with a client=<name> filter pushed down server-side (see
  // vpnlog.py/db.py) so this never has to filter a mixed-client page's
  // worth of rows out in JS.
  const activityTabs = Array.from(document.querySelectorAll('[data-activity-tab]'));
  const activityRangeSelect = document.getElementById('client-activity-range');
  const activityPageSizeSelect = document.getElementById('client-activity-page-size');
  const activityPrevBtn = document.querySelector('[data-activity-page-prev]');
  const activityNextBtn = document.querySelector('[data-activity-page-next]');
  const activityStatusEl = document.querySelector('[data-activity-page-status]');
  let activityTab = 'client_sessions';
  let activityPage = 1;

  function activitySection(tab) {
    return document.querySelector(`[data-activity-section="${tab}"]`);
  }

  // Same row shape as logs-page.js's own clientSessionsRow/trafficRow,
  // minus the Client/Source columns those need (always this client here,
  // so showing it again on every row would be pure noise).
  function clientSessionRowHtml(s) {
    const endCell = s.ongoing
      ? '<span class="badge badge-connected">ongoing</span>'
      : s.status_note
        ? `<span class="cell-note">${escapeHtml(s.status_note)}</span>`
        : escapeHtml(s.end || '—');
    const addressCell = s.real_address
      ? `${escapeHtml(s.real_address)}<span class="cell-note hint-block">via relay (${escapeHtml(s.address)})</span>`
      : escapeHtml(s.address || '—');
    return `<tr><td>${escapeHtml(s.start || '—')}</td><td>${endCell}</td><td>${escapeHtml(s.duration || '—')}</td><td>${addressCell}</td></tr>`;
  }

  function trafficRowHtml(f) {
    const dst = escapeHtml(f.dst) + (f.dport ? ':' + escapeHtml(f.dport) : '');
    return `<tr><td>${escapeHtml(f.ts)}</td><td>${dst}</td><td>${escapeHtml(f.dst_org || '—')}</td><td>${escapeHtml(f.proto)}</td></tr>`;
  }

  const ACTIVITY_CONFIG = {
    client_sessions: { tbodyId: 'client-activity-sessions-tbody', colCount: 4, rowHtml: clientSessionRowHtml, emptyMessage: 'No session events found for this client yet.' },
    traffic: { tbodyId: 'client-activity-traffic-tbody', colCount: 4, rowHtml: trafficRowHtml, emptyMessage: 'No traffic flows found for this client yet.' },
  };

  // --- Charts: a quick visual read of the same data the tables below
  // already show — not a replacement for them (no exact values on hover,
  // no pagination). Plain divs sized with inline %, no charting library
  // (matches this app's existing no-dependencies-if-avoidable stance —
  // see firewall-reorder.js's own comment on the same point) — each is
  // small enough that a library would cost more than it saves here.
  //
  // Fetched independently of the table's own paginated request, always at
  // CHART_PAGE_SIZE regardless of the table's page/page size, so the
  // chart reflects the whole selected range rather than whatever page the
  // table happens to be showing right now.
  const CHART_PAGE_SIZE = 100;
  const RANGE_HOURS = { '1h': 1, '6h': 6, '12h': 12, '1d': 24, '7d': 24 * 7 };

  function chartFetch(tab) {
    const params = new URLSearchParams({
      tab, client: name, range: activityRangeSelect.value, page: '1', page_size: String(CHART_PAGE_SIZE),
    });
    return ApiClient.call(`/api/logs?${params.toString()}`)
      .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data })))
      .then(({ ok, data }) => (ok ? (data.entries || []) : []));
  }

  // Server timestamps are plain 'YYYY-MM-DD HH:MM:SS' strings (no
  // timezone) — parsed here as if they're in the browser's own local
  // timezone, same assumption the rest of this app already makes by just
  // displaying them as-is (a self-hosted admin tool where the server and
  // the admin viewing it are typically in the same timezone anyway). Fine
  // for a rough visual chart; not meant to be millisecond-precise.
  function parseServerTs(ts) {
    if (!ts) return null;
    const ms = new Date(ts.replace(' ', 'T')).getTime();
    return Number.isNaN(ms) ? null : ms;
  }

  const DAY_LABELS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

  function formatDurationMs(ms) {
    const totalSeconds = Math.max(0, Math.round(ms / 1000));
    const h = Math.floor(totalSeconds / 3600);
    const m = Math.floor((totalSeconds % 3600) / 60);
    const s = totalSeconds % 60;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  // One row per calendar day covering the selected range (Last 7 days ->
  // 7 rows, oldest at top through today at the bottom) — each row's bar is
  // the total time this client was connected that day, summed across every
  // session that started on it. A session is attributed whole to the day
  // it *started* rather than split across midnight — real sessions here
  // are seconds to a few hours, so that simplification never meaningfully
  // changes which day looks busiest, and this chart isn't meant to be
  // to-the-second precise anyway. Same horizontal label/bar/value row
  // style as the destinations chart below (renderDestChart).
  function renderSessionTimeline(sessions) {
    const container = document.getElementById('client-session-timeline');
    if (!container) return;
    const rangeEnd = Date.now();
    const rangeHours = RANGE_HOURS[activityRangeSelect.value] || RANGE_HOURS['7d'];

    // Exactly N calendar-day rows ending today (7d -> 7 rows, today plus
    // the 6 days before it) — not "floor(rangeStart) through today", which
    // adds a stray extra day up front whenever rangeStart itself falls
    // partway through a day rather than exactly on a midnight boundary
    // (always, for a rolling "last N days" window).
    const dayMs = 24 * 3600 * 1000;
    const numDays = Math.max(1, Math.ceil(rangeHours / 24));
    const today = new Date(rangeEnd);
    today.setHours(0, 0, 0, 0);
    const buckets = [];
    for (let i = numDays - 1; i >= 0; i--) {
      const d = today.getTime() - i * dayMs;
      buckets.push({ dayStart: d, dayEnd: d + dayMs, ms: 0 });
    }

    sessions.forEach((s) => {
      const start = parseServerTs(s.start);
      if (start == null) return;
      // A session with no `end` is one of two very different things (see
      // vpnlog.py's list_client_sessions): genuinely still connected right
      // now (ongoing: true) — that one legitimately counts toward "now" —
      // or a stale reconnect where no matching disconnect event was ever
      // logged (ongoing: false, status_note "Ended (exact time unknown)").
      // The second one already ended; we just don't know exactly when, so
      // it contributes nothing to the total rather than being guessed as
      // "ran until right now" (that guess was inflating today's total by
      // however many hours ago it actually started).
      if (!s.ongoing && !s.end) return;
      const end = s.ongoing ? rangeEnd : parseServerTs(s.end);
      if (end == null || end <= start) return;
      const bucket = buckets.find((b) => start >= b.dayStart && start < b.dayEnd);
      if (bucket) bucket.ms += (end - start);
    });

    if (!buckets.some((b) => b.ms > 0)) {
      container.innerHTML = '<p class="chart-empty">No sessions in this range to chart.</p>';
      return;
    }
    const max = Math.max(...buckets.map((b) => b.ms), 1);
    const rows = buckets.map((b) => {
      const date = new Date(b.dayStart);
      // A day with real connected time still gets a visible sliver even
      // when it's tiny next to the range's busiest day — 0% would look
      // indistinguishable from a day with no sessions at all.
      const pct = b.ms > 0 ? Math.max((b.ms / max) * 100, 2) : 0;
      return `
        <div class="dest-chart-row">
          <span class="dest-chart-label">${DAY_LABELS[date.getDay()]} ${date.getDate()}</span>
          <span class="dest-chart-bar-wrap"><span class="dest-chart-bar" style="width:${pct}%"></span></span>
          <span class="dest-chart-count">${b.ms > 0 ? escapeHtml(formatDurationMs(b.ms)) : '—'}</span>
        </div>`;
    }).join('');
    container.innerHTML = rows;
  }

  function renderDestChart(flows) {
    const container = document.getElementById('client-dest-chart');
    if (!container) return;
    if (!flows.length) {
      container.innerHTML = '<p class="chart-empty">No traffic in this range to chart.</p>';
      return;
    }
    const counts = new Map();
    flows.forEach((f) => {
      const key = f.dst_org || f.dst || 'Unknown';
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    // Top 6 destinations by flow count — a full breakdown of every
    // distinct destination belongs to the table below this chart, not
    // squeezed into a bar for each one.
    const top = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const max = top[0][1];
    container.innerHTML = top.map(([label, count]) => `
      <div class="dest-chart-row">
        <span class="dest-chart-label" title="${escapeHtml(label)}">${escapeHtml(label)}</span>
        <span class="dest-chart-bar-wrap"><span class="dest-chart-bar" style="width:${(count / max) * 100}%"></span></span>
        <span class="dest-chart-count">${count}</span>
      </div>`).join('');
  }

  const CHART_LOADERS = {
    client_sessions: () => chartFetch('client_sessions').then(renderSessionTimeline),
    traffic: () => chartFetch('traffic').then(renderDestChart),
  };

  function loadActivityChart() {
    const loader = CHART_LOADERS[activityTab];
    if (loader) loader();
  }

  function activitySkeletonRowHtml(colCount) {
    const cells = Array(colCount).fill('<td><span class="skeleton-bar"></span></td>').join('');
    return `<tr class="skeleton-row">${cells}</tr>`.repeat(4);
  }

  function loadActivity(showSkeletonWhileLoading) {
    const cfg = ACTIVITY_CONFIG[activityTab];
    const tbody = document.getElementById(cfg.tbodyId);
    if (showSkeletonWhileLoading) tbody.innerHTML = activitySkeletonRowHtml(cfg.colCount);
    const params = new URLSearchParams({
      tab: activityTab, client: name, range: activityRangeSelect.value,
      page: String(activityPage), page_size: activityPageSizeSelect.value,
    });
    return ApiClient.call(`/api/logs?${params.toString()}`)
      .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) {
          tbody.innerHTML = `<tr class="empty-row"><td colspan="${cfg.colCount}" class="empty">${escapeHtml(data.error || 'Could not load this tab.')}</td></tr>`;
          return;
        }
        const entries = data.entries || [];
        tbody.innerHTML = entries.length
          ? entries.map(cfg.rowHtml).join('')
          : `<tr class="empty-row"><td colspan="${cfg.colCount}" class="empty">${cfg.emptyMessage}</td></tr>`;
        const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
        if (activityStatusEl) activityStatusEl.textContent = `Page ${data.page} of ${totalPages} (${data.total} total)`;
        activityPrevBtn.disabled = data.page <= 1;
        activityNextBtn.disabled = data.page >= totalPages;
        activityPage = data.page;
      });
  }

  activityTabs.forEach((btn) => {
    btn.addEventListener('click', () => {
      const newTab = btn.dataset.activityTab;
      if (newTab === activityTab) return;
      const oldSection = activitySection(activityTab);
      if (oldSection) oldSection.hidden = true;
      activityTabs.forEach((t) => {
        t.classList.toggle('active', t === btn);
        t.setAttribute('aria-selected', String(t === btn));
      });
      activityTab = newTab;
      activityPage = 1;
      const newSection = activitySection(activityTab);
      if (newSection) newSection.hidden = false;
      loadActivity(true);
      loadActivityChart();
    });
  });

  // Chart only reloads on a tab switch or a range change — not on Prev/
  // Next/page-size, which only affect which slice of the same range the
  // *table* below is currently showing; the chart already covers the
  // whole range every time regardless of the table's own pagination.
  activityRangeSelect.addEventListener('change', () => { activityPage = 1; loadActivity(false); loadActivityChart(); });
  activityPageSizeSelect.addEventListener('change', () => { activityPage = 1; loadActivity(false); });
  activityPrevBtn.addEventListener('click', () => { activityPage = Math.max(1, activityPage - 1); loadActivity(false); });
  activityNextBtn.addEventListener('click', () => { activityPage += 1; loadActivity(false); });

  loadClient(true);
  loadRules(true);
  loadActivity(true);
  loadActivityChart();
});
