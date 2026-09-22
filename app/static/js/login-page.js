(() => {
  const form = document.getElementById('login-form');
  if (!form) return;
  if (form.dataset.locked !== 'true') {
    try {
      localStorage.removeItem('pivpn_webui_api_token');
      localStorage.removeItem('pivpn_webui_last_activity');
    } catch (_) { /* Signing in still works when storage is unavailable. */ }
  }
  const fields = Array.from(form.querySelectorAll('input[required]'));
  const password = document.getElementById('login-password');
  const toggle = document.getElementById('password-toggle');
  const submit = form.querySelector('[type="submit"]');
  const submitLabel = submit.firstElementChild;
  const originalLabel = submitLabel.textContent;
  const caps = document.getElementById('caps-lock-hint');
  let submitting = false;

  function validate(field) {
    const empty = field.name === 'username' ? !field.value.trim() : !field.value;
    const error = document.getElementById(`${field.name}-error`);
    field.setAttribute('aria-invalid', String(empty));
    error.textContent = empty ? `Enter your ${field.name}.` : '';
    error.hidden = !empty;
    return !empty;
  }
  // Native required validation remains available without JavaScript.
  form.noValidate = true;
  fields.forEach(field => {
    field.addEventListener('blur', () => validate(field));
    field.addEventListener('input', () => {
      if (field.getAttribute('aria-invalid') === 'true') validate(field);
    });
  });
  toggle.hidden = false;
  toggle.addEventListener('click', () => {
    const show = password.type === 'password';
    password.type = show ? 'text' : 'password';
    toggle.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    toggle.setAttribute('aria-pressed', String(show));
  });
  for (const event of ['keydown', 'keyup']) {
    password.addEventListener(event, e => {
      caps.hidden = !e.getModifierState?.('CapsLock');
    });
  }
  password.addEventListener('blur', () => { caps.hidden = true; });
  form.addEventListener('submit', e => {
    if (submitting) { e.preventDefault(); return; }
    const invalid = fields.filter(field => !validate(field));
    if (invalid.length) {
      e.preventDefault();
      invalid[0].focus();
      return;
    }
    submitting = true;
    submit.disabled = true;
    submitLabel.textContent = form.dataset.locked === 'true' ? 'Resuming…' : 'Signing in…';
    form.setAttribute('aria-busy', 'true');
  });
  window.addEventListener('pageshow', () => {
    submitting = false;
    submit.disabled = false;
    submitLabel.textContent = originalLabel;
    form.removeAttribute('aria-busy');
  });
  const error = document.getElementById('login-error');
  if (error) error.focus();
  else fields.find(field => field.getAttribute('aria-invalid') === 'true')?.focus();
})();
