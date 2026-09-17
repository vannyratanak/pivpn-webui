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
    // Clear first so getBoundingClientRect() reflects natural position/
    // size — otherwise a previous run's own max-height would shrink-then-
    // measure against itself, ratcheting smaller on every resize instead
    // of re-measuring fresh each time.
    el.style.maxHeight = '';
    const rect = el.getBoundingClientRect();
    // Whatever sits after this element but still inside the same card
    // (pagination's Prev/Next row, the card's own bottom padding/border)
    // has to stay on screen too — a flat guessed number here previously
    // ignored pagination's real height entirely, letting the table claim
    // space that pagination actually needed, so the page overflowed by
    // roughly however tall that row was. Measuring the card's own natural
    // bottom edge against this element's natural bottom edge gets the
    // exact figure regardless of what a given page's card has after its
    // table (or doesn't).
    const card = el.closest('.card');
    const spaceBelowWithinCard = card ? card.getBoundingClientRect().bottom - rect.bottom : 0;
    const pageBottomMargin = 24; // .content's own bottom padding, roughly
    const available = window.innerHeight - rect.top - spaceBelowWithinCard - pageBottomMargin;
    // A page whose own fixed chrome (title, hint text, dialogs' triggers,
    // etc.) already eats most of a short viewport can push `available`
    // to near zero or negative — most acute on mobile, where the topbar,
    // page header, card header, and hint text alone can leave almost
    // nothing below. Clamping to a floor this small only ever showed
    // ~1 row (th/td is 10px vertical padding + ~19.5px line-height +
    // 1px border ≈ 41px/row; 120px barely clears the header). 300px
    // guarantees at least 5-6 real rows before the *table's own* scroll
    // kicks in — on a short viewport this deliberately makes the table
    // taller than the visually "available" space, so the page scrolls
    // to reach the rest of it instead of cramming rows into a tiny box.
    el.style.maxHeight = `${Math.max(available, 300)}px`;
  });
}

window.addEventListener('resize', fitTableScrollHeights);
document.addEventListener('DOMContentLoaded', fitTableScrollHeights);
