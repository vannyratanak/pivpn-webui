// Users page — same JWT/fetch() pattern as clients-page.js (see that
// file's own top comment for the general approach this app is
// incrementally moving every page toward). Row data comes from
// GET /api/users; add/delete/reset-password/change-own-password go
// through the matching /api/... endpoints in app/api.py.
//
// is_admin and the current user's own id are still server-rendered
// (data-is-admin/data-current-user-id on #users-table, from Flask-Login's
// current_user) rather than pulled from the API response — they gate
// which controls even exist on the page (the whole Actions column,
// the Add User button), not just how a row's own data is displayed.
document.addEventListener('DOMContentLoaded', () => {
  const table = document.getElementById('users-table');
  const tbody = document.getElementById('users-tbody');
  if (!table || !tbody) return;

  const isAdmin = table.dataset.isAdmin === 'true';
  const currentUserId = table.dataset.currentUserId;
  const colCount = isAdmin ? 4 : 3;
  let usersPager = null;

  function escapeHtml(value) {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
  }

  function rowHtml(u) {
    const youTag = String(u.id) === String(currentUserId) ? ' <span class="hint">(you)</span>' : '';
    const roleClass = u.role !== 'admin' ? ' badge-role-moderator' : '';
    const username = escapeHtml(u.username);
    const actionsTd = isAdmin ? `
        <td>
          <div class="actions">
            <button type="button" class="btn btn-sm btn-secondary" data-action="reset-password" data-user-id="${u.id}" data-username="${username}">Reset password</button>
            <button type="button" class="btn btn-sm btn-danger" data-action="delete" data-user-id="${u.id}" data-username="${username}">Delete</button>
          </div>
        </td>` : '';
    return `
      <tr data-user-id="${u.id}">
        <td>${username}${youTag}</td>
        <td><span class="badge badge-role${roleClass}">${escapeHtml(u.role)}</span></td>
        <td>${escapeHtml(u.created_at)}</td>
        ${actionsTd}
      </tr>`;
  }

  function skeletonRowHtml() {
    const cells = Array(colCount).fill('<td><span class="skeleton-bar"></span></td>').join('');
    return `<tr class="skeleton-row">${cells}</tr>`.repeat(6);
  }

  function render(users) {
    if (!users.length) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="${colCount}" class="empty">No users found.</td></tr>`;
    } else {
      tbody.innerHTML = users.map(rowHtml).join('');
    }
    if (usersPager) {
      usersPager.refresh();
    } else {
      usersPager = attachPagination('#users-tbody', 'tr:not(.empty-row)', 'users-page-size', 'users-pagination');
      attachLogFilter('users-filter', '#users-tbody', 'tr:not(.empty-row)', '#users-table thead th:not(:last-child)', () => usersPager && usersPager.refresh());
    }
  }

  function loadUsers(showSkeletonWhileLoading) {
    if (showSkeletonWhileLoading) tbody.innerHTML = skeletonRowHtml();
    return ApiClient.call('/api/users')
      .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data })))
      .then(({ ok, data }) => {
        // Without this check, a non-2xx body throws inside render() and
        // leaves the skeleton spinning forever with no explanation —
        // same fix already applied to clients-page.js/vpn-routes-page.js.
        if (!ok) {
          tbody.innerHTML = `<tr class="empty-row"><td colspan="${colCount}" class="empty">${escapeHtml(data.error || 'Could not load users.')}</td></tr>`;
          return;
        }
        render(data.users);
      });
  }

  // Styled toast, matching clients-page.js's showRowError/
  // firewall-reorder.js's reorder-error-toast pattern rather than alert().
  function showError(message) {
    const notice = document.createElement('div');
    notice.className = 'reorder-error-toast';
    notice.setAttribute('role', 'alert');
    notice.textContent = message;
    document.body.appendChild(notice);
    setTimeout(() => notice.remove(), 3200);
  }

  function postJson(path, options, body) {
    return ApiClient.call(path, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      body: JSON.stringify(body),
    }).then((resp) => resp.json().then((data) => ({ ok: resp.ok, data })));
  }

  const addForm = document.querySelector('#add-user-dialog form');
  if (addForm) {
    addForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const submitBtn = addForm.querySelector('[type="submit"]');
      const username = addForm.querySelector('[name="username"]').value.trim();
      const password = addForm.querySelector('[name="password"]').value;
      const confirm = addForm.querySelector('[name="confirm"]').value;
      const role = addForm.querySelector('[name="role"]').value;
      if (password !== confirm) { showError('Passwords did not match.'); return; }
      ApiClient.withBusy(submitBtn, postJson('/api/users', { method: 'POST' }, { username, password, role })).then(({ ok, data }) => {
        if (!ok) { showError(data.error || `Could not create ${username}.`); return; }
        document.getElementById('add-user-dialog').close();
        addForm.reset();
        loadUsers();
      });
    });
  }

  const changeForm = document.querySelector('#change-password-dialog form');
  if (changeForm) {
    changeForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const submitBtn = changeForm.querySelector('[type="submit"]');
      const current_password = changeForm.querySelector('[name="current_password"]').value;
      const password = changeForm.querySelector('[name="password"]').value;
      const confirm = changeForm.querySelector('[name="confirm"]').value;
      if (password !== confirm) { showError('Passwords did not match.'); return; }
      ApiClient.withBusy(submitBtn, postJson('/api/account/password', { method: 'POST' }, { current_password, password })).then(({ ok, data }) => {
        if (!ok) { showError(data.error || 'Could not change password.'); return; }
        document.getElementById('change-password-dialog').close();
        changeForm.reset();
      });
    });
  }

  // Shared reset-password dialog (see users.html's own comment) — reused
  // for whichever row's button was clicked, since rows no longer exist at
  // Jinja-render time for a per-row <dialog> to be generated alongside.
  const resetDialog = document.getElementById('reset-pw-dialog');
  const resetForm = resetDialog ? resetDialog.querySelector('form') : null;
  const resetHeading = resetDialog ? resetDialog.querySelector('[data-reset-heading]') : null;

  tbody.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const userId = btn.dataset.userId;
    const username = btn.dataset.username;

    if (btn.dataset.action === 'reset-password' && resetDialog) {
      resetForm.reset();
      resetForm.dataset.userId = userId;
      if (resetHeading) resetHeading.textContent = `Reset password for ${username}`;
      resetDialog.showModal();
      return;
    }

    if (btn.dataset.action === 'delete') {
      window.askConfirm(`Permanently remove ${username}? This cannot be undone.`, 'Delete', () => {
        ApiClient.withBusy(btn, ApiClient.call(`/api/users/${userId}`, { method: 'DELETE' })
          .then((resp) => resp.json().then((data) => ({ ok: resp.ok, data }))))
          .then(({ ok, data }) => {
            if (!ok) { showError(data.error || `Could not remove ${username}.`); return; }
            loadUsers();
          });
      });
    }
  });

  if (resetForm) {
    resetForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const submitBtn = resetForm.querySelector('[type="submit"]');
      const userId = resetForm.dataset.userId;
      const password = resetForm.querySelector('[name="password"]').value;
      const confirm = resetForm.querySelector('[name="confirm"]').value;
      if (password !== confirm) { showError('Passwords did not match.'); return; }
      ApiClient.withBusy(submitBtn, postJson(`/api/users/${userId}/reset-password`, { method: 'POST' }, { password })).then(({ ok, data }) => {
        if (!ok) { showError(data.error || 'Could not reset password.'); return; }
        resetDialog.close();
      });
    });
  }

  loadUsers(true);
});
