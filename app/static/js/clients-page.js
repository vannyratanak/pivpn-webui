// Clients page — fetches/mutates data via /api/... (see api-client.js)
// instead of a server-rendered table + plain form POSTs. Every action on
// this page (list/add/renew/remove/block/download/import/bulk-remove)
// goes through the JSON API now — see window.bulkRemoveClients and the
// Import Clients form handling below for the last two.
document.addEventListener('DOMContentLoaded', () => {
  const tbody = document.getElementById('clients-tbody');
  if (!tbody) return;

  const countHint = document.querySelector('.card-header-title-group .hint');
  const addForm = document.querySelector('#add-client-dialog form');
  let clientsPager = null;

  function escapeHtml(value) {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
  }

  function rowHtml(c) {
    const blockedClass = c.blocked ? ' class="blocked-row"' : '';
    const sessionBadge = c.session
      ? '<span class="badge badge-connected">connected</span>'
      : '<span class="badge badge-inactive">inactive</span>';
    const blockLabel = c.blocked ? 'Unblock' : 'Block';
    const blockBtnClass = c.blocked ? 'btn-ok' : 'btn-warn';
    const name = escapeHtml(c.name);
    return `
      <tr${blockedClass} data-client-name="${name}">
        <td><input type="checkbox" name="client_names" value="${name}" form="bulk-remove-form" class="client-select-checkbox" aria-label="Select client ${name}"></td>
        <td><a href="/clients/${encodeURIComponent(c.name)}">${name}</a></td>
        <td>${escapeHtml(c.status)}</td>
        <td>${escapeHtml(c.expiration)}</td>
        <td>${c.ip ? escapeHtml(c.ip) : '—'}</td>
        <td>${sessionBadge}</td>
        <td>
          <div class="actions">
            <button type="button" class="btn btn-sm" data-action="download">Download</button>
            <button type="button" class="btn btn-sm btn-secondary" data-action="renew">Renew</button>
            <button type="button" class="btn btn-sm ${blockBtnClass}" data-action="block">${blockLabel}</button>
            <button type="button" class="btn btn-sm btn-danger" data-action="remove">Remove</button>
          </div>
        </td>
      </tr>`;
  }

  function skeletonRowHtml() {
    // Six cells worth of pulsing bars, matching the real row shape below
    // minus the checkbox/action buttons (nothing meaningful to fake
    // there) — six rows is just a reasonable guess at "about a page's
    // worth", not tied to any real count, since the real count isn't
    // known until the fetch this is standing in for actually resolves.
    const cells = '<td></td>' + Array(5).fill('<td><span class="skeleton-bar"></span></td>').join('') + '<td></td>';
    return `<tr class="skeleton-row">${cells}</tr>`.repeat(6);
  }

  function render(clients, connectedCount) {
    if (!clients.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="7" class="empty">No clients found (or `pivpn list` returned nothing parseable — check the server logs).</td></tr>';
    } else {
      tbody.innerHTML = clients.map(rowHtml).join('');
    }
    if (countHint) countHint.textContent = `${connectedCount} connected / ${clients.length} total`;

    if (clientsPager) {
      clientsPager.refresh();
    } else {
      clientsPager = attachPagination('#clients-tbody', 'tr:not(.empty-row)', 'clients-page-size', 'clients-pagination');
      attachLogFilter('clients-filter', '#clients-tbody', 'tr:not(.empty-row)', '#clients-table thead th:not(:first-child):not(:last-child)', () => clientsPager && clientsPager.refresh());
    }
  }

  function loadClients(showSkeletonWhileLoading) {
    // Only on the very first load, not on a post-action refresh (after
    // Renew/Block/Remove) — those already have real rows on screen, and
    // replacing them with a skeleton for what's usually a sub-second
    // refresh would read as more disruptive flicker, not a loading cue.
    if (showSkeletonWhileLoading) tbody.innerHTML = skeletonRowHtml();
    return ApiClient.call('/api/clients')
      .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data })))
      .then(({ ok, data }) => {
        // Without this check, a non-2xx body (e.g. {"error": "..."}, no
        // "clients" key) hit render()'s clients.length straight on,
        // throwing and leaving the skeleton spinning forever with no
        // visible explanation — caught live against a dev environment
        // whose hub/agent link was down. Same failure mode this whole
        // change is about: no reaction at all reads as broken, not as
        // "something went wrong, here's why."
        if (!ok) {
          tbody.innerHTML = `<tr class="empty-row"><td colspan="7" class="empty">${escapeHtml(data.error || 'Could not load clients.')}</td></tr>`;
          return;
        }
        render(data.clients, data.connected_count);
      });
  }

  function showRowError(row, message) {
    // A styled toast (matching firewall-reorder.js's reorder-error-toast
    // pattern) rather than alert() — see that file's own comment for why.
    const notice = document.createElement('div');
    notice.className = 'reorder-error-toast';
    notice.setAttribute('role', 'alert');
    notice.textContent = message;
    document.body.appendChild(notice);
    setTimeout(() => notice.remove(), 3200);
  }

  tbody.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const row = btn.closest('tr');
    const name = row.dataset.clientName;
    const action = btn.dataset.action;

    if (action === 'download') {
      ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/download`)
        .then((resp) => {
          if (!resp.ok) return Promise.reject();
          return resp.blob();
        })
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
        .catch(() => showRowError(row, `Could not download ${name}'s profile.`));
      return;
    }

    if (action === 'renew') {
      window.askConfirm(
        `Renew ${name}? This revokes the current cert and issues a new one — the old .ovpn will stop working immediately.`,
        'Renew',
        () => {
          ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/renew`, { method: 'POST' })
            .then((resp) => resp.ok ? loadClients() : Promise.reject()))
            .catch(() => showRowError(row, `Could not renew ${name}.`));
        },
      );
      return;
    }

    if (action === 'block') {
      const nowBlocked = !row.classList.contains('blocked-row');
      ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ blocked: nowBlocked }),
      })
        .then((resp) => resp.ok ? loadClients() : Promise.reject()))
        .catch(() => showRowError(row, `Could not ${nowBlocked ? 'block' : 'unblock'} ${name}.`));
      return;
    }

    if (action === 'remove') {
      window.askConfirm(`Permanently remove ${name}? This cannot be undone.`, 'Remove', () => {
        ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}`, { method: 'DELETE' })
          .then((resp) => resp.ok ? loadClients() : Promise.reject()))
          .catch(() => showRowError(row, `Could not remove ${name}.`));
      });
    }
  });

  if (addForm) {
    addForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const submitBtn = addForm.querySelector('[type="submit"]');
      const name = addForm.querySelector('[name="name"]').value.trim();
      const passphrase = addForm.querySelector('[name="passphrase"]').value;
      ApiClient.withBusy(submitBtn, ApiClient.call('/api/clients', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, passphrase: passphrase || undefined }),
      })
        .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data }))))
        .then(({ ok, data }) => {
          if (!ok) { showRowError(tbody, data.error || `Could not create ${name}.`); return; }
          document.getElementById('add-client-dialog').close();
          addForm.reset();
          loadClients();
        });
    });
  }

  // Import Clients — a real multipart file upload (FormData built straight
  // from the form, so the file input's contents come along for free), not
  // a JSON body. ApiClient.call still works unchanged: it only ever adds
  // the Authorization header, and deliberately sets no Content-Type of its
  // own, leaving fetch() to set the multipart boundary itself the same way
  // it would for any other FormData body.
  const importForm = document.querySelector('#import-clients-dialog form');
  if (importForm) {
    importForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const submitBtn = importForm.querySelector('[type="submit"]');
      const fileInput = importForm.querySelector('[name="clients_file"]');
      if (!fileInput.files.length) return;
      ApiClient.withBusy(submitBtn, ApiClient.call('/api/clients/import', { method: 'POST', body: new FormData(importForm) })
        .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data }))))
        .then(({ ok, data }) => {
          if (!ok) { showRowError(tbody, data.error || 'Could not import that file.'); return; }
          if (data.errors && data.errors.length) {
            showRowError(tbody, `${data.errors.length} line(s) failed: ${data.errors.slice(0, 10).join('; ')}`);
          }
          document.getElementById('import-clients-dialog').close();
          importForm.reset();
          loadClients();
        });
    });
  }

  // Bulk-remove — invoked from clients.html's own inline script (the
  // checkbox-selection/confirm-message logic lives there, unrelated to
  // this page's data layer) once the user confirms. Exposed on window
  // for that same reason window.askConfirm is (a fetch()-driven page
  // action reused from outside this closure).
  window.bulkRemoveClients = function (names) {
    ApiClient.call('/api/clients/bulk-remove', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ names }),
    })
      .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) { showRowError(tbody, data.error || 'Could not remove the selected clients.'); return; }
        if (data.errors && data.errors.length) {
          showRowError(tbody, `${data.errors.length} failed: ${data.errors.slice(0, 10).join('; ')}`);
        }
        loadClients();
      });
  };

  loadClients(true);
});
