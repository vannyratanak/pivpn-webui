// Caps each .table-scroll's height at whatever vertical space is actually
// left below it on the page, so a long table scrolls internally instead of
// pushing the header/title off the top of the screen — without a plain CSS
// max-height, which would need to know the height of everything above it
// (page title, card header, hint text, etc.), and that varies per page and
// per screen size. Measuring the real rendered position (getBoundingClientRect)
// sidesteps that entirely; it's already correct for whatever's actually there.
//
// Only ever a cap, never a floor — a table with just 2-3 rows stays that
// short (no CSS min-height forcing it taller), this only ever kicks in
// once a table's real content would exceed the space actually left on
// screen.
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
    // A page whose own fixed chrome (title, hint text, dialogs' triggers,
    // etc.) already eats most of a short viewport can push `available`
    // to near zero or negative — clamp to a small floor so the table
    // never fully collapses; the page itself still scrolls to reach the
    // rest, same fallback as everywhere else in this layout.
    el.style.maxHeight = `${Math.max(available, 120)}px`;
  });
}

window.addEventListener('resize', fitTableScrollHeights);
document.addEventListener('DOMContentLoaded', fitTableScrollHeights);
