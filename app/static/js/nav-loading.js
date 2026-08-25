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

  document.addEventListener('submit', (e) => {
    if (e.defaultPrevented) return;
    const form = e.target;
    // A destructive form (delete/remove/renew) sets data-confirm instead of
    // the classic inline onsubmit="return confirm('...')" — that pattern
    // breaks the moment interpolated dynamic content (e.g. a username)
    // contains a single quote: the browser decodes the HTML entity back to
    // a literal ' before compiling the attribute as JS, so the confirm()
    // call's own string literal gets cut short — a syntax error that
    // silently no-ops the whole handler rather than throwing, so the form
    // just submits with no prompt at all. Reading data-confirm via
    // .dataset instead means the value is only ever used as a JS *string
    // argument* to confirm(), never compiled as JS source, so any
    // character in it — quotes included — is just harmless data.
    if (form.dataset.confirm && !confirm(form.dataset.confirm)) {
      e.preventDefault();
      return;
    }
    e.preventDefault();
    start(() => { form.submit(); });
  });
});
