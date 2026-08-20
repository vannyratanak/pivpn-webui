// Persists the light/dark choice in localStorage. The initial application
// (before first paint, to avoid a flash of the wrong theme) happens via
// the inline script in base.html's <head>, which runs synchronously
// before this file is even fetched — this only handles the click and
// keeps aria state in sync with whatever that inline script already set.
document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('theme-toggle');
  const label = document.getElementById('theme-toggle-label');
  if (!btn) return;

  function isLight() {
    return document.documentElement.getAttribute('data-theme') === 'light';
  }

  function sync(light) {
    btn.setAttribute('aria-pressed', String(light));
    btn.setAttribute('aria-label', light ? 'Switch to dark mode' : 'Switch to light mode');
    if (label) label.textContent = light ? 'Light' : 'Dark';
  }

  sync(isLight());

  btn.addEventListener('click', () => {
    const next = !isLight();
    if (next) {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    localStorage.setItem('pivpn-webui-theme', next ? 'light' : 'dark');
    sync(next);
  });
});
