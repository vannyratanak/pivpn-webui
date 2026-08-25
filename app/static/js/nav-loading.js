// Thin top-of-page progress bar shown while navigating to a new page or
// submitting a form. This app is server-rendered (no AJAX page loads), so
// there's no "data fetched" event to hook — the only meaningful loading
// signal is "the browser is about to load a new page".
//
// A plain click/submit isn't enough on its own: the browser doesn't
// guarantee it paints a JS style change before it starts tearing the page
// down for navigation, so on a fast/local connection the whole thing can
// happen with nothing ever actually reaching the screen. So this
// intercepts the click/submit, shows the bar, waits a real paint (double
// requestAnimationFrame — the standard way to guarantee at least one frame
// was rendered), then performs the navigation itself.
document.addEventListener('DOMContentLoaded', () => {
  const bar = document.createElement('div');
  bar.id = 'nav-loading-bar';
  document.body.appendChild(bar);

  function afterPaint(fn) {
    requestAnimationFrame(() => requestAnimationFrame(fn));
  }

  function start(navigate) {
    bar.style.transition = 'none';
    bar.style.width = '0%';
    bar.style.opacity = '1';
    void bar.offsetWidth; // force reflow so the transition below animates from 0
    bar.style.transition = 'width 1.2s ease-out, opacity 0.3s ease 1.7s';
    bar.style.width = '85%';
    afterPaint(navigate);
  }

  document.addEventListener('click', (e) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const link = e.target.closest('a[href]');
    if (!link) return;
    if (link.target === '_blank' || link.hasAttribute('download')) return;
    const href = link.getAttribute('href');
    if (href.startsWith('#') || href.startsWith('javascript:')) return;
    e.preventDefault();
    start(() => { window.location.href = link.href; });
  });

  // Custom confirm dialog (see base.html for the shared markup) instead of
  // the browser's native confirm() — styleable to match the app, and lets
  // a destructive action's button say "Delete"/"Renew"/"Remove" instead of
  // a generic "OK". One dialog, reused for every data-confirm form on the
  // page, rather than one per form.
  const confirmModal = document.getElementById('confirm-modal');
  const confirmMessage = document.getElementById('confirm-modal-message');
  const confirmBtn = document.getElementById('confirm-modal-confirm-btn');
  let confirmHandler = null;

  function askConfirm(message, label, onConfirm) {
    if (!confirmModal) { onConfirm(); return; } // markup missing somehow — fail open rather than block every destructive action
    confirmMessage.textContent = message;
    confirmBtn.textContent = label || 'Confirm';
    // Drop any previous listener before adding a new one — {once: true}
    // alone only cleans up *after* it fires; if the last confirm was
    // dismissed via Cancel/Escape/backdrop instead of the button, that
    // listener is still attached, and without this it'd fire a second
    // time (for the wrong form) alongside the new one on the next confirm.
    if (confirmHandler) confirmBtn.removeEventListener('click', confirmHandler);
    confirmHandler = () => {
      confirmModal.close();
      onConfirm();
    };
    confirmBtn.addEventListener('click', confirmHandler, { once: true });
    confirmModal.showModal();
  }

  document.addEventListener('submit', (e) => {
    if (e.defaultPrevented) return;
    const form = e.target;
    // A destructive form (delete/remove/renew) sets data-confirm — read via
    // .dataset, so the value is only ever used as a JS *string argument*
    // (to askConfirm below), never compiled as JS source the way the old
    // inline onsubmit="return confirm('...')" pattern was: that broke the
    // moment interpolated dynamic content (e.g. a username) contained a
    // single quote, since the browser decodes the HTML entity back to a
    // literal ' before compiling the attribute as JS — a syntax error that
    // silently no-opped the whole handler instead of throwing, so the form
    // just submitted with no prompt at all.
    if (form.dataset.confirm) {
      e.preventDefault();
      askConfirm(form.dataset.confirm, form.dataset.confirmLabel, () => {
        start(() => { form.submit(); });
      });
      return;
    }
    e.preventDefault();
    start(() => { form.submit(); });
  });
});
