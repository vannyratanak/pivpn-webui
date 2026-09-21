// Warn before the inactivity deadline, not the silently refreshed API token.
(function () {
  const meta = document.querySelector('meta[name="idle-timeout-minutes"]');
  if (!meta) return;
  const IDLE_MS = Number(meta.content) * 60 * 1000;
  const WARN_AT_SECONDS = 10;
  const TICK_MS = 1000;

  let toastEl = null;
  function showCountdown(secondsLeft) {
    if (!toastEl) {
      toastEl = document.createElement('div');
      toastEl.className = 'flash-toast flash-warning jwt-expiry-toast';
      let container = document.querySelector('.flash-toasts');
      if (!container) {
        container = document.createElement('div');
        container.className = 'flash-toasts';
        container.setAttribute('aria-live', 'polite');
        document.body.appendChild(container);
      }
      container.appendChild(toastEl);
    }
    toastEl.textContent = `This session will log out in ${secondsLeft}s`;
  }

  function hideCountdown() {
    if (toastEl) {
      toastEl.remove();
      toastEl = null;
    }
  }

  function tick() {
    const lastActivity = Number(localStorage.getItem('pivpn_webui_last_activity'));
    if (!lastActivity) return;
    const secondsLeft = Math.ceil((lastActivity + IDLE_MS - Date.now()) / 1000);
    if (secondsLeft <= 0) {
      hideCountdown();
      return;
    }
    if (secondsLeft <= WARN_AT_SECONDS) {
      showCountdown(secondsLeft);
    } else {
      hideCountdown();
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    tick();
    setInterval(tick, TICK_MS);
  });
})();
