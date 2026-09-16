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
    // to near zero or negative — clamp to a small floor so the table
    // never fully collapses; the page itself still scrolls to reach the
    // rest, same fallback as everywhere else in this layout.
    el.style.maxHeight = `${Math.max(available, 120)}px`;
  });
}

window.addEventListener('resize', fitTableScrollHeights);
document.addEventListener('DOMContentLoaded', fitTableScrollHeights);
