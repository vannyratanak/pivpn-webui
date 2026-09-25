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
  const renewDialog = document.getElementById('renew-client-dialog');
  const renewForm = document.getElementById('renew-client-form');
  let clientsPager = null;
  let totalCount = 0;
  let connectedCount = 0;
  // Set right before renewDialog.showModal(), read by renewForm's own
  // submit handler below — a plain closure variable rather than a DOM
  // dataset, since what's actually needed (the row, for refreshRow())
  // is an element reference, not a serializable string. The dialog's own
  // submit button gets the busy state, not the row's Renew button —
  // opening the dialog isn't itself a request.
  let pendingRenewRow = null;

  function escapeHtml(value) {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
  }

  function rowHtml(c) {
    const blockedClass = c.blocked ? ' class="blocked-row"' : '';
    const sessionBadge = c.session
      ? '<span class="badge badge-connected">online</span>'
      : '<span class="badge badge-inactive">offline</span>';
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

  function updateCountHint() {
    if (countHint) countHint.textContent = `${connectedCount} connected / ${totalCount} total`;
  }

  // Clicking a client's name here full-page-navigates to /clients/<name>
  // — a real browser navigation, not an in-app route change, so nothing
  // in memory survives it. This is how client-detail-page.js still gets
  // an instant first render instead of showing its own skeleton and
  // re-fetching data this page already just fetched: sessionStorage
  // (survives the navigation, cleared with the tab) carries the last
  // list response over; the detail page still confirms it with its own
  // background fetch right after, this is only for the *first* paint.
  const DETAIL_CACHE_KEY = 'pivpn_webui_client_cache';
  function cacheForDetailPage(clients) {
    try {
      const byName = {};
      clients.forEach((c) => { byName[c.name] = c; });
      sessionStorage.setItem(DETAIL_CACHE_KEY, JSON.stringify(byName));
    } catch (e) {
      // Private-browsing quota or storage disabled — the detail page
      // just falls back to its own fetch+skeleton, same as before this
      // existed. Never worth failing the actual page load over.
    }
  }

  // Applies fresh data to an existing row's cells in place, rather than
  // replacing the <tr> node — outerHTML-replacing (or a full tbody
  // rebuild) would discard whatever inline style attachPagination/
  // attachLogFilter had already set on it (they hide rows by toggling
  // style.display, not by removing them), silently breaking pagination/
  // search state on that row until the next full reload.
  function updateRowInPlace(row, c) {
    row.classList.toggle('blocked-row', !!c.blocked);
    const cells = row.children;
    cells[2].textContent = c.status;
    cells[3].textContent = c.expiration;
    cells[4].textContent = c.ip || '—';
    cells[5].innerHTML = c.session
      ? '<span class="badge badge-connected">online</span>'
      : '<span class="badge badge-inactive">offline</span>';
    const blockBtn = row.querySelector('[data-action="block"]');
    if (blockBtn) {
      blockBtn.textContent = c.blocked ? 'Unblock' : 'Block';
      blockBtn.classList.toggle('btn-ok', !!c.blocked);
      blockBtn.classList.toggle('btn-warn', !c.blocked);
    }
  }

  // Re-fetches just this one client (not the whole list) and patches its
  // row in place — see updateRowInPlace's own comment for why a full
  // loadClients() after every Renew/Block used to make the entire table
  // flicker on every single-row action, which is what this whole change
  // exists to avoid.
  function refreshRow(row, name) {
    return ApiClient.call(`/api/clients/${encodeURIComponent(name)}`)
      .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data })))
      .then(({ ok, data }) => {
        if (ok) updateRowInPlace(row, data);
      });
  }

  function removeRow(row) {
    const wasConnected = !!row.querySelector('.badge-connected');
    row.remove();
    totalCount = Math.max(0, totalCount - 1);
    if (wasConnected) connectedCount = Math.max(0, connectedCount - 1);
    updateCountHint();
    if (!totalCount) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="7" class="empty">No clients found (or `pivpn list` returned nothing parseable — check the server logs).</td></tr>';
    }
    if (clientsPager) clientsPager.refresh();
  }

  // Inserts a newly-added client's row without touching any existing
  // row — same "don't refresh the whole table for a single change"
  // reasoning as updateRowInPlace/removeRow above.
  function insertRow(c) {
    const emptyRow = tbody.querySelector('.empty-row');
    if (emptyRow) emptyRow.remove();
    tbody.insertAdjacentHTML('beforeend', rowHtml(c));
    totalCount += 1;
    if (c.session) connectedCount += 1;
    updateCountHint();
    if (clientsPager) {
      clientsPager.refresh();
    } else {
      clientsPager = attachPagination('#clients-tbody', 'tr:not(.empty-row)', 'clients-page-size', 'clients-pagination');
      attachLogFilter('clients-filter', '#clients-tbody', 'tr:not(.empty-row)', '#clients-table thead th:not(:first-child):not(:last-child)', () => clientsPager && clientsPager.refresh());
    }
  }

  function render(clients, connectedCountArg) {
    totalCount = clients.length;
    connectedCount = connectedCountArg;
    if (!clients.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="7" class="empty">No clients found (or `pivpn list` returned nothing parseable — check the server logs).</td></tr>';
    } else {
      tbody.innerHTML = clients.map(rowHtml).join('');
    }
    updateCountHint();
    cacheForDetailPage(clients);

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
      })
      .catch((error) => {
        // Keep a failed initial/API refresh visible instead of leaving the
        // loading skeleton indefinitely when auth, network, or rendering fails.
        tbody.innerHTML = `<tr class="empty-row"><td colspan="7" class="empty">Could not load clients: ${escapeHtml(error.message || 'request failed')}. <button type="button" class="btn btn-sm" data-clients-retry>Retry</button></td></tr>`;
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
    const retry = e.target.closest('button[data-clients-retry]');
    if (retry) { loadClients(true); return; }
    const btn = e.target.closest('button[data-action]');
    if (!btn) {
      // Row-to-detail navigation — anywhere in the row except the
      // Actions cell (handled above, via the early return once `btn` is
      // found) and the checkbox (its own click target, for bulk-select)
      // or the name <a> itself (already a real link — leaving its click
      // alone means Cmd/Ctrl/middle-click still open a new tab the
      // normal way, which a synthetic navigate-on-click here would break).
      if (e.target.closest('input[type="checkbox"]') || e.target.closest('a')) return;
      const navRow = e.target.closest('tr[data-client-name]');
      if (navRow) window.location.href = `/clients/${encodeURIComponent(navRow.dataset.clientName)}`;
      return;
    }
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
      if (!renewDialog || !renewForm) {
        // Same stale-template gap as the guard on renewForm's own submit
        // handler below — falls back to the old plain-confirm behavior
        // (passwordless renew only) instead of being stuck with a
        // half-broken button.
        window.askConfirm(
          `Renew ${name}? This revokes the current cert and issues a new one — the old .ovpn will stop working immediately.`,
          'Renew',
          () => {
            ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/renew`, { method: 'POST' })
              .then((resp) => resp.ok ? refreshRow(row, name) : Promise.reject()))
              .catch(() => showRowError(row, `Could not renew ${name}.`));
          },
        );
        return;
      }
      pendingRenewRow = row;
      renewForm.reset();
      document.getElementById('renew-client-name').textContent = name;
      renewDialog.showModal();
      return;
    }

    if (action === 'block') {
      const nowBlocked = !row.classList.contains('blocked-row');
      ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ blocked: nowBlocked }),
      })
        .then((resp) => resp.ok ? refreshRow(row, name) : Promise.reject()))
        .catch(() => showRowError(row, `Could not ${nowBlocked ? 'block' : 'unblock'} ${name}.`));
      return;
    }

    if (action === 'remove') {
      window.askConfirm(`Permanently remove ${name}? This cannot be undone.`, 'Remove', () => {
        ApiClient.withBusy(btn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}`, { method: 'DELETE' })
          .then((resp) => resp.ok ? removeRow(row) : Promise.reject()))
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
          ApiClient.call(`/api/clients/${encodeURIComponent(name)}`)
            .then((resp) => (resp.ok ? resp.json() : Promise.reject()))
            .then((c) => insertRow(c))
            // The add itself already succeeded — this second fetch is
            // just to render its row without a full reload; if it fails
            // (e.g. a slow hub round-trip), fall back to the one case
            // that still needs a full list refresh rather than leaving
            // the new client invisible until the next manual reload.
            .catch(() => loadClients());
        });
    });
  }

  // Guarded like addForm/importForm below — real crash caught live: a
  // stale gunicorn worker still serving the pre-Renew-dialog template
  // (Jinja templates need a full restart to pick up changes; static JS
  // reloads immediately from disk on its own, so the two can briefly
  // disagree right after a deploy) meant this element didn't exist yet,
  // and an unguarded renewForm.addEventListener() threw on page load —
  // taking the *entire* Clients page's init down with it, not just Renew.
  if (renewForm) {
    renewForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const row = pendingRenewRow;
      const name = row.dataset.clientName;
      const passphrase = renewForm.querySelector('[name="passphrase"]').value;
      const submitBtn = renewForm.querySelector('[type="submit"]');
      ApiClient.withBusy(submitBtn, ApiClient.call(`/api/clients/${encodeURIComponent(name)}/renew`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase: passphrase || undefined }),
      })
        .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data }))))
        .then(({ ok, data }) => {
          if (!ok) { showRowError(row, data.error || `Could not renew ${name}.`); return; }
          renewDialog.close();
          renewForm.reset();
          refreshRow(row, name);
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

  // Status changes arrive through the hub's shared live update stream.
  let initialLoaded = false;
  let hadStream = false;
  let pendingClientChange = false;
  let fallbackTimer;
  const clientStream = OverviewStream((event, topics) => {
    if (event === 'ready') {
      if (hadStream) loadClients(false); // reconnect: resynchronize
      hadStream = true;
      if (pendingClientChange) { pendingClientChange = false; loadClients(false); }
    } else if (event === 'changed' && topics.includes('snapshot')) {
      if (initialLoaded) loadClients(false); else pendingClientChange = true;
    }
  }, () => {});
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) clientStream.stop(); else clientStream.start();
  });
  window.addEventListener('pagehide', () => clientStream.stop());
  window.addEventListener('pageshow', () => { if (!document.hidden) clientStream.start(); });

  loadClients(true).finally(() => { initialLoaded = true; clearTimeout(fallbackTimer); });
  clientStream.start();
  // Preserve initial page rendering if the live service is temporarily down.
  fallbackTimer = setTimeout(() => {
    if (!initialLoaded) loadClients(true).finally(() => { initialLoaded = true; clearTimeout(fallbackTimer); });
  }, 3000);
});
