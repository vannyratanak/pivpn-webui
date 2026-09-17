// Generic button-triggered overflow menu — full keyboard support (arrow
// keys between items, Escape closes and returns focus, click-outside
// closes). Any page can call attachDropdown(triggerId, menuId) for its
// own trigger/menu pair; each call is independent (its own closure, own
// listeners), so multiple dropdowns on one page don't interfere.
function attachDropdown(triggerId, menuId) {
  const trigger = document.getElementById(triggerId);
  const menu = document.getElementById(menuId);
  if (!trigger || !menu) return null;

  const items = () => Array.from(menu.querySelectorAll('[data-dropdown-item]'));

  function openMenu() {
    menu.hidden = false;
    trigger.setAttribute('aria-expanded', 'true');
    items()[0] && items()[0].focus();
  }

  function closeMenu(returnFocus) {
    if (menu.hidden) return;
    menu.hidden = true;
    trigger.setAttribute('aria-expanded', 'false');
    if (returnFocus) trigger.focus();
  }

  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    menu.hidden ? openMenu() : closeMenu(false);
  });

  // Each item still does its own thing (submit its own form, open its
  // own dialog) via the markup's existing onclick/submit — this just
  // closes the menu afterward so it doesn't sit open behind whatever
  // that triggers.
  items().forEach((item, i) => {
    item.addEventListener('click', () => closeMenu(false));
    item.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') { e.preventDefault(); items()[(i + 1) % items().length].focus(); }
      if (e.key === 'ArrowUp') { e.preventDefault(); items()[(i - 1 + items().length) % items().length].focus(); }
      if (e.key === 'Escape') { e.preventDefault(); closeMenu(true); }
    });
  });

  document.addEventListener('click', (e) => {
    if (!trigger.contains(e.target) && !menu.contains(e.target)) closeMenu(false);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeMenu(true);
  });

  return { closeMenu };
}
