// Auto-dismissing toast behavior for flash messages — the message text
// and category come from the server (base.html renders one .flash-toast
// per get_flashed_messages() entry, everywhere except the login page,
// which keeps the plain inline banner); this only handles the show-for-
// a-bit-then-go-away part client-side, plus a manual close button and
// pausing the timer while the pointer's over one, so a message someone's
// actually reading doesn't vanish out from under them.
(function() {
  const DISMISS_MS = { 'flash-success': 4000, 'flash-warning': 8000, 'flash-error': 6000 };
  const DEFAULT_MS = 4000;

  function dismiss(toast) {
    if (toast.dataset.closing) return;
    toast.dataset.closing = '1';
    toast.classList.add('closing');
    toast.addEventListener('animationend', () => toast.remove(), { once: true });
    // Belt-and-suspenders for prefers-reduced-motion, where the closing
    // animation never runs (and animationend never fires) at all.
    setTimeout(() => toast.remove(), 250);
  }

  function initToast(toast) {
    const category = Array.from(toast.classList).find((c) => c.startsWith('flash-') && c !== 'flash-toast');
    const ms = DISMISS_MS[category] || DEFAULT_MS;
    let remaining = ms;
    let startedAt = Date.now();
    let timer = setTimeout(() => dismiss(toast), ms);

    toast.addEventListener('mouseenter', () => {
      clearTimeout(timer);
      remaining -= (Date.now() - startedAt);
    });
    toast.addEventListener('mouseleave', () => {
      startedAt = Date.now();
      timer = setTimeout(() => dismiss(toast), Math.max(remaining, 1000));
    });

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'flash-toast-close';
    closeBtn.setAttribute('aria-label', 'Dismiss');
    closeBtn.textContent = '×';
    closeBtn.addEventListener('click', () => { clearTimeout(timer); dismiss(toast); });
    toast.appendChild(closeBtn);
  }

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.flash-toast').forEach(initToast);
  });
})();
