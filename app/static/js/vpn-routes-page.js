// VPN Routes page — same fetch()-driven pattern as clients-page.js (see
// that file's top comment for the full reasoning). Simpler than Clients:
// no bulk actions, no confirm-on-add, just list + add + remove.
document.addEventListener('DOMContentLoaded', () => {
  const tbody = document.getElementById('routes-tbody');
  if (!tbody) return;

  const addForm = document.querySelector('#add-route-dialog form');
  let routesPager = null;

  function escapeHtml(value) {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
  }

  function rowHtml(r) {
    const network = escapeHtml(r.network);
    const netmask = escapeHtml(r.netmask);
    const actionCell = r.managed
      ? `<button type="button" class="btn btn-sm btn-danger" data-action="remove">Remove</button>`
      : `<span class="hint">Edit server.conf directly to change</span>`;
    return `
      <tr data-network="${network}" data-netmask="${netmask}">
        <td>${network}</td>
        <td>${netmask}</td>
        <td>${r.managed ? 'Web UI' : 'server.conf (unmanaged)'}</td>
        <td><div class="actions">${actionCell}</div></td>
      </tr>`;
  }

  function skeletonRowHtml() {
    const cells = Array(3).fill('<td><span class="skeleton-bar"></span></td>').join('') + '<td></td>';
    return `<tr class="skeleton-row">${cells}</tr>`.repeat(4);
  }

  function render(routes) {
    if (!routes.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="4" class="empty">No extra routes pushed yet (VPN clients only reach the VPN’s own subnet).</td></tr>';
    } else {
      tbody.innerHTML = routes.map(rowHtml).join('');
    }
    if (routesPager) {
      routesPager.refresh();
    } else {
      routesPager = attachPagination('#routes-tbody', 'tr:not(.empty-row)', 'routes-page-size', 'routes-pagination');
      attachLogFilter('routes-filter', '#routes-tbody', 'tr:not(.empty-row)', '#routes-table thead th:not(:last-child)', () => routesPager && routesPager.refresh());
    }
  }

  function loadRoutes(showSkeletonWhileLoading) {
    if (showSkeletonWhileLoading) tbody.innerHTML = skeletonRowHtml();
    return ApiClient.call('/api/vpn-routes')
      .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data })))
      .then(({ ok, data }) => {
        // Without this check, a non-2xx body throws inside render()
        // (data.routes is undefined, .length on that throws) and leaves
        // the skeleton spinning forever with no visible explanation —
        // same failure mode as clients-page.js's own version of this.
        if (!ok) {
          tbody.innerHTML = `<tr class="empty-row"><td colspan="4" class="empty">${escapeHtml(data.error || 'Could not load routes.')}</td></tr>`;
          return;
        }
        render(data.routes);
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

  // Removing/adding one route never changes any *other* row's own data
  // (unlike Clients' Renew/Block, nothing here needs a re-fetch to know
  // what changed) — direct DOM removal/insertion avoids rebuilding the
  // whole table (and the pagination/filter flicker that comes with it)
  // for a single-row change.
  function removeRow(row) {
    row.remove();
    if (!tbody.querySelector('tr:not(.empty-row)')) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="4" class="empty">No extra routes pushed yet (VPN clients only reach the VPN’s own subnet).</td></tr>';
    }
    if (routesPager) routesPager.refresh();
  }

  function insertRow(r) {
    const emptyRow = tbody.querySelector('.empty-row');
    if (emptyRow) emptyRow.remove();
    tbody.insertAdjacentHTML('beforeend', rowHtml(r));
    if (routesPager) {
      routesPager.refresh();
    } else {
      routesPager = attachPagination('#routes-tbody', 'tr:not(.empty-row)', 'routes-page-size', 'routes-pagination');
      attachLogFilter('routes-filter', '#routes-tbody', 'tr:not(.empty-row)', '#routes-table thead th:not(:last-child)', () => routesPager && routesPager.refresh());
    }
  }

  tbody.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-action="remove"]');
    if (!btn) return;
    const row = btn.closest('tr');
    const { network, netmask } = row.dataset;
    window.askConfirm(
      'Remove this route? Connected clients will stop routing this network into the tunnel.',
      'Remove',
      () => {
        ApiClient.withBusy(btn, ApiClient.call('/api/vpn-routes', {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ network, netmask }),
        })
          .then((resp) => resp.ok ? removeRow(row) : Promise.reject()))
          .catch(() => showRowError(row, `Could not remove ${network}/${netmask}.`));
      },
    );
  });

  if (addForm) {
    addForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const submitBtn = addForm.querySelector('[type="submit"]');
      const network = addForm.querySelector('[name="network"]').value.trim();
      const netmask = addForm.querySelector('[name="netmask"]').value.trim();
      ApiClient.withBusy(submitBtn, ApiClient.call('/api/vpn-routes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ network, netmask }),
      })
        .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data }))))
        .then(({ ok, data }) => {
          if (!ok) { showRowError(tbody, data.error || `Could not push ${network}/${netmask}.`); return; }
          document.getElementById('add-route-dialog').close();
          addForm.reset();
          insertRow({ network, netmask, managed: true });
        });
    });
  }

  loadRoutes(true);
});
