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
    e.preventDefault();
    start(() => { form.submit(); });
  });
});
