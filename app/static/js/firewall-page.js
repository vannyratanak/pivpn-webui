// Firewall Rules: load data and submit every action through the JWT API.
document.addEventListener('DOMContentLoaded', () => {
  const tbody = document.getElementById('rules-tbody');
  if (!tbody) return;

  const KIND_DISPLAY_ORDER = { forward: 0, input: 1, masquerade: 2, snat: 3, portforward: 4, client_block: 5 };
  const KIND_DISPLAY_LABEL = {
    forward: 'FORWARD — traffic passing through this server',
    input: 'INPUT — traffic to this server itself',
    masquerade: 'NAT — outbound address translation',
    snat: 'NAT — outbound address translation',
    portforward: 'PORT FORWARDS',
    client_block: 'CLIENT BLOCKS',
  };

  const emptyClientRow = document.getElementById('rules-empty-client');
  const saveRulesForm = document.querySelector('form[action$="/firewall/persist"]');
  let rulesPager = null;
  let rulesClientFilter = null;

  function escapeHtml(value) {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
  }

  function rowHtml(r) {
    const rowClasses = [r.enabled ? '' : 'disabled-row'].filter(Boolean).join(' ');
    const draggable = r.kind !== 'client_block' ? ` draggable="true" data-rule-id="${r.id}"` : '';
    const orderCell = r.kind === 'client_block'
      ? '<span class="hint" title="Client blocks always take priority over other rules and can’t be reordered">—</span>'
      : '<span class="drag-handle" title="Drag to reorder, or focus and press ↑/↓" tabindex="0" role="button" aria-label="Reorder rule — press up or down arrow to move it">&#9776;</span>';
    return `
      <tr class="${rowClasses}"${draggable} data-kind="${escapeHtml(r.kind)}">
        <td><input type="checkbox" class="rule-select-checkbox" data-rule-id="${r.id}" aria-label="Select rule ${r.id}"></td>
        <td>${escapeHtml(r.client_name || '')}</td>
        <td>${escapeHtml(r.kind)}</td>
        <td>${escapeHtml(r.action)}</td>
        <td>${escapeHtml(r.detail)}</td>
        <td>${escapeHtml(r.comment || '')}</td>
        <td>${r.source === 'cli' ? 'CLI' : 'webui'}</td>
        <td><span class="${r.persisted ? 'saved-yes' : 'saved-no'}">${r.persisted ? 'Saved' : 'Unsaved'}</span></td>
        <td>${orderCell}</td>
        <td>
          <div class="actions">
            <button type="button" class="btn btn-sm ${r.enabled ? 'btn-warn' : 'btn-ok'}" data-action="toggle" data-rule-id="${r.id}">${r.enabled ? 'Disable' : 'Enable'}</button>
            <button type="button" class="btn btn-sm btn-danger" data-action="delete" data-rule-id="${r.id}">Delete</button>
          </div>
        </td>
      </tr>`;
  }

  function skeletonRowHtml() {
    const cells = '<td></td>' + Array(7).fill('<td><span class="skeleton-bar"></span></td>').join('') + '<td></td><td></td>';
    return `<tr class="skeleton-row">${cells}</tr>`.repeat(6);
  }

  function render(rules) {
    if (!rules.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="10" class="empty">No rules yet.</td></tr>';
    } else {
      const sorted = rules.slice().sort((a, b) => (KIND_DISPLAY_ORDER[a.kind] ?? 99) - (KIND_DISPLAY_ORDER[b.kind] ?? 99));
      let html = '';
      let prevLabel = null;
      for (const r of sorted) {
        const label = KIND_DISPLAY_LABEL[r.kind] || r.kind;
        if (label !== prevLabel) {
          html += `<tr class="kind-divider-row"><td colspan="10">${escapeHtml(label)}</td></tr>`;
          prevLabel = label;
        }
        html += rowHtml(r);
      }
      tbody.innerHTML = html;
    }
    if (emptyClientRow) tbody.appendChild(emptyClientRow); // keep it in the DOM, re-shown by the client filter as needed

    if (saveRulesForm) saveRulesForm.hidden = rules.every((r) => r.persisted);

    if (rulesPager) {
      rulesPager.refresh();
    } else {
      const rowSelector = 'tr:not(.empty-row):not(.kind-divider-row)';
      rulesPager = attachPagination('#rules-tbody', rowSelector, 'rules-page-size', 'rules-pagination', updateDividerVisibility);
      rulesClientFilter = attachSelectFilter('rules-client-filter', '#rules-tbody', rowSelector, () => {
        rulesPager && rulesPager.refresh();
        updateEmptyClientMessage();
      });
      attachLogFilter('rules-filter', '#rules-tbody', rowSelector, '#rules-table thead th:not(:first-child):not(:last-child)', () => {
        rulesClientFilter && rulesClientFilter.refresh();
        rulesPager && rulesPager.refresh();
        updateEmptyClientMessage();
      });
      attachFirewallReorder('#rules-tbody');
    }
    updateDividerVisibility();
    updateEmptyClientMessage();
    tbody.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function updateEmptyClientMessage() {
    if (!emptyClientRow) return;
    const clientSelect = document.getElementById('rules-client-filter');
    const clientSelected = !!clientSelect && clientSelect.value !== '';
    const clientHasRules = Array.from(document.querySelectorAll('#rules-tbody tr:not(.empty-row):not(.kind-divider-row)'))
      .some((row) => row.dataset.selectMatch !== '0');
    emptyClientRow.style.display = (clientSelected && !clientHasRules) ? '' : 'none';
  }

  function updateDividerVisibility() {
    let currentDivider = null;
    let groupHasVisibleRow = false;
    function closeGroup() {
      if (currentDivider) currentDivider.style.display = groupHasVisibleRow ? '' : 'none';
    }
    Array.from(document.querySelectorAll('#rules-tbody > tr')).forEach((row) => {
      if (row.classList.contains('kind-divider-row')) {
        closeGroup();
        currentDivider = row;
        groupHasVisibleRow = false;
      } else if (!row.classList.contains('empty-row') && row.style.display !== 'none') {
        groupHasVisibleRow = true;
      }
    });
    closeGroup();
  }

  function loadRules(showSkeletonWhileLoading) {
    if (showSkeletonWhileLoading) tbody.innerHTML = skeletonRowHtml();
    return ApiClient.call('/api/firewall/rules')
      .then(async (resp) => {
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Could not load rules.');
        render(data.rules);
      });
  }

  function showRowError(el, message) {
    const notice = document.createElement('div');
    notice.className = 'reorder-error-toast';
    notice.setAttribute('role', 'alert');
    notice.textContent = message;
    document.body.appendChild(notice);
    setTimeout(() => notice.remove(), 3200);
  }

  function loadOptions() {
    return ApiClient.call('/api/firewall/options')
      .then(async (resp) => {
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Could not load firewall options.');
        const clients = data.clients || [];
        const filter = document.getElementById('rules-client-filter');
        clients.forEach((c) => {
          const option = new Option(`${c.name} (${c.ip})`, c.ip);
          filter && filter.appendChild(option);
        });
        ['fwd-src-select', 'input-src-select'].forEach((id) => {
          const select = document.getElementById(id);
          if (!select) return;
          const custom = select.querySelector('option[value="__custom__"]');
          clients.forEach((c) => select.insertBefore(new Option(`${c.name} (${c.ip})`, c.ip), custom));
          select.dispatchEvent(new Event('change'));
        });
        const iface = document.querySelector('#add-snat-form select[name="out_iface"]');
        (data.interfaces || []).forEach((name) => iface && iface.appendChild(new Option(name, name)));
        (data.warnings || []).forEach((warning) => showRowError(tbody, warning));
      });
  }

  tbody.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const ruleId = btn.dataset.ruleId;

    if (btn.dataset.action === 'toggle') {
      ApiClient.call(`/api/firewall/rules/${ruleId}/toggle`, { method: 'POST' })
        .then((resp) => resp.ok ? loadRules() : Promise.reject())
        .catch(() => showRowError(btn.closest('tr'), `Could not toggle rule #${ruleId}.`));
      return;
    }
    if (btn.dataset.action === 'delete') {
      window.askConfirm('Delete this rule?', 'Delete', () => {
        ApiClient.call(`/api/firewall/rules/${ruleId}`, { method: 'DELETE' })
          .then((resp) => resp.ok ? loadRules() : Promise.reject())
          .catch(() => showRowError(btn.closest('tr'), `Could not delete rule #${ruleId}.`));
      });
    }
  });

  // Shared by the 4 Add Rule forms (see firewall.html's own inline
  // scripts, right next to each form) — called directly once any warning
  // has already been confirmed (or never applied). fieldNames drives
  // which named fields become the JSON body; a hidden input (e.g. the
  // Forward/Input forms' src field, kept in sync with their custom-
  // source dropdown) works exactly like any other named field here.
  window.submitFirewallAddForm = function (form, endpoint, fieldNames) {
    const body = {};
    fieldNames.forEach((name) => {
      const el = form.querySelector(`[name="${name}"]`);
      if (el) body[name] = el.value;
    });
    ApiClient.call(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
      .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) { showRowError(form, data.error || 'Could not add that rule.'); return; }
        document.getElementById('add-rule-dialog').close();
        form.reset();
        // form.reset() doesn't fire change/input, so the Forward/Input
        // forms' custom-source select+hidden-field sync (see their own
        // inline scripts) never re-runs on its own — nudge it back in
        // sync with the now-reset <select>. No-ops for Portforward/SNAT,
        // which have no such element.
        const srcSelect = form.querySelector('[id$="-src-select"]');
        if (srcSelect) srcSelect.dispatchEvent(new Event('change'));
        return loadRules();
      }).catch((error) => showRowError(form, error.message || 'Could not add that rule.'));
  };

  window.runFirewallAction = async function (form, endpoint, body) {
    const buttons = Array.from(form.querySelectorAll('button[type="submit"]'));
    buttons.forEach((button) => { button.disabled = true; });
    try {
      const options = { method: 'POST' };
      if (body instanceof FormData) options.body = body;
      else if (body !== undefined) {
        options.headers = { 'Content-Type': 'application/json' };
        options.body = JSON.stringify(body);
      }
      const resp = await ApiClient.call(endpoint, options);
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Could not apply that change.');
      const failures = data.errors || data.skipped || [];
      let message = data.persisted ? 'Firewall rules saved for reboot.'
        : data.resynced ? 'Firewall rules reapplied.'
        : data.added !== undefined ? `Imported ${data.added} rule(s).`
        : `Changed ${data.changed} rule(s).`;
      if (failures.length) message += ` ${failures.length} failed: ${failures.slice(0, 10).join('; ')}`;
      showRowError(form, message);
      if (endpoint.endsWith('/import') && !failures.length) {
        document.getElementById('import-rules-dialog').close();
        form.reset();
      }
      await loadRules();
    } catch (error) {
      showRowError(form, error.message || 'Could not apply that change.');
    } finally {
      buttons.forEach((button) => { button.disabled = false; });
      tbody.dispatchEvent(new Event('change', { bubbles: true }));
    }
  };

  ['resync', 'persist', 'import'].forEach((action) => {
    const form = document.querySelector(`form[action$="/firewall/${action}"]`);
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      window.runFirewallAction(form, `/api/firewall/${action}`, action === 'import' ? new FormData(form) : undefined);
    });
  });

  Promise.all([loadRules(true), loadOptions()]).catch((error) => {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="10" class="empty">Could not load rules. Reload to retry.</td></tr>';
    showRowError(tbody, error.message);
  });
});
