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

  function renderMeta(c) {
    clientIp = c.ip;
    clientBlocked = !!c.blocked;
    const validSvg = '<svg class="cert-icon cert-icon-valid" aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11.5 14.5 15.5 10"/></svg>';
    const blockedSvg = '<svg class="cert-icon cert-icon-blocked" aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="9.5" y1="9.5" x2="14.5" y2="14.5"/><line x1="14.5" y1="9.5" x2="9.5" y2="14.5"/></svg>';
    const sep = '<span class="meta-sep" aria-hidden="true">&middot;</span>';
    const parts = [
      `<span class="status-indicator ${c.session ? 'status-indicator-connected' : ''}"><span class="status-dot ${c.session ? 'status-dot-connected' : ''}" aria-hidden="true"></span>${c.session ? 'Active' : 'Inactive'}</span>`,
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

  function loadClient() {
    metaRow.innerHTML = metaSkeletonHtml();
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
      <tr class="${r.enabled ? '' : 'disabled-row'}">
        <td><input type="checkbox" class="client-rule-select-checkbox" data-rule-id="${r.id}" aria-label="Select rule ${r.id}"></td>
        <td>${escapeHtml(r.kind)}</td>
        <td>${escapeHtml(r.action)}</td>
        <td>${escapeHtml(r.detail)}</td>
        <td>${escapeHtml(r.comment || '')}</td>
        <td><span class="${r.persisted ? 'saved-yes' : 'saved-no'}">${r.persisted ? 'Saved' : 'Unsaved'}</span></td>
        <td>
          <div class="actions">
            <button type="button" class="btn btn-sm ${r.enabled ? 'btn-warn' : 'btn-ok'}" data-action="toggle" data-rule-id="${r.id}">${r.enabled ? 'Disable' : 'Enable'}</button>
            <button type="button" class="btn btn-sm btn-danger" data-action="delete" data-rule-id="${r.id}">Delete</button>
          </div>
        </td>
      </tr>`;
  }

  function skeletonRowHtml() {
    const cells = '<td></td>' + Array(4).fill('<td><span class="skeleton-bar"></span></td>').join('') + '<td></td><td></td>';
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
      rulesTbody.innerHTML = '<tr class="empty-row"><td colspan="7" class="empty">No rules scoped to this client yet.</td></tr>';
    } else {
      rulesTbody.innerHTML = rules.map(rowHtml).join('');
    }
    saveRulesBtn.hidden = rules.every((r) => r.persisted);

    if (rulesPager) {
      rulesPager.refresh();
    } else {
      rulesPager = attachPagination('#client-rules-tbody', 'tr:not(.empty-row)', 'client-rules-page-size', 'client-rules-pagination');
      attachLogFilter('client-rules-filter', '#client-rules-tbody', 'tr:not(.empty-row)', null, () => rulesPager && rulesPager.refresh());
    }
    document.getElementById('client-rules-select-all').checked = false;
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
          rulesTbody.innerHTML = `<tr class="empty-row"><td colspan="7" class="empty">${escapeHtml(data.error || 'Could not load rules.')}</td></tr>`;
          return;
        }
        render(data.rules || []);
      });
  }

  rulesTbody.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const ruleId = btn.dataset.ruleId;

    if (btn.dataset.action === 'toggle') {
      ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/rules/${ruleId}/toggle`, { method: 'POST' })
        .then((resp) => (resp.ok ? loadRules() : Promise.reject())))
        .catch(() => showToast(`Could not toggle rule #${ruleId}.`));
      return;
    }
    if (btn.dataset.action === 'delete') {
      window.askConfirm('Delete this rule?', 'Delete', () => {
        ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/rules/${ruleId}`, { method: 'DELETE' })
          .then((resp) => (resp.ok ? loadRules() : Promise.reject())))
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

  loadClient();
  loadRules(true);
});
