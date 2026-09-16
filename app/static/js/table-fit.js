// Caps each .table-scroll's height at whatever vertical space is actually
// left below it on the page, so a long table scrolls internally instead of
// pushing the header/title off the top of the screen — without a plain CSS
// max-height, which would need to know the height of everything above it
// (page title, card header, hint text, etc.), and that varies per page and
// per screen size. Measuring the real rendered position (getBoundingClientRect)
// sidesteps that entirely; it's already correct for whatever's actually there.
//
// Only ever a cap: .table-scroll's own CSS min-height (style.css) is what
// keeps a near-empty table from collapsing to a sliver, and always wins over
// this if the two conflict (CSS spec: min-height beats max-height) — so a
// short viewport still shows the floor amount, letting the page scroll to
// reach the rest, rather than crushing the table down to fit.
function fitTableScrollHeights() {
  document.querySelectorAll('.table-scroll').forEach((el) => {
    // Clear first so getBoundingClientRect().top reflects natural position
    // — otherwise a previous run's own max-height would shrink-then-measure
    // against itself, ratcheting smaller on every resize instead of
    // re-measuring fresh each time.
    el.style.maxHeight = '';
    const top = el.getBoundingClientRect().top;
    const bottomBuffer = 24; // card's own bottom padding/border, roughly
    const available = window.innerHeight - top - bottomBuffer;
    el.style.maxHeight = `${available}px`;
  });
}

window.addEventListener('resize', fitTableScrollHeights);
document.addEventListener('DOMContentLoaded', fitTableScrollHeights);
