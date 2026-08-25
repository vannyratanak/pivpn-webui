// Wraps a native <select> with a fully custom-rendered dropdown, so the open menu looks
// identical in every browser (a native select's open popup is OS-drawn and can't be styled).
// The original <select> stays in the DOM (hidden) as the source of truth: its .value stays
// in sync, and it still dispatches 'change' events — so any existing code that reads
// select.value or listens for 'change' keeps working with zero other changes.
//
// Ported from a reference project's select-enhance.js + its app.js label-linking helper,
// combined into one file since pivpn-webui has no shared app.js of its own.
function enhanceSelect(select) {
  if (!select || select.dataset.enhanced === 'true') return;
  select.dataset.enhanced = 'true';

  const wrapper = document.createElement('div');
  wrapper.className = 'custom-select-wrapper';
  select.parentNode.insertBefore(wrapper, select);
  wrapper.appendChild(select);

  const trigger = document.createElement('button');
  trigger.type = 'button';
  trigger.className = 'custom-select-trigger';
  trigger.setAttribute('role', 'combobox');
  trigger.setAttribute('aria-haspopup', 'listbox');
  trigger.setAttribute('aria-expanded', 'false');
  if (select.disabled) trigger.disabled = true;
  linkTriggerToOwnLabel(select, trigger);

  select.classList.add('custom-select-native');

  wrapper.appendChild(trigger);

  const menu = document.createElement('div');
  menu.className = 'custom-select-menu hidden';
  menu.setAttribute('role', 'listbox');
  const menuId = select.id ? `${select.id}-listbox` : `custom-select-listbox-${Math.random().toString(36).slice(2)}`;
  menu.id = menuId;
  trigger.setAttribute('aria-controls', menuId);
  wrapper.appendChild(menu);

  let activeIndex = -1;
  // Typeahead: buffer of recently-typed characters, and the timer that
  // clears it after a pause — the same shape a native <select> uses so
  // typing "sy" quickly reaches "System" rather than each keystroke
  // restarting the search from "s".
  let typeaheadBuffer = '';
  let typeaheadTimer = null;

  function optionId(i) {
    return `${menuId}-option-${i}`;
  }

  function renderMenu() {
    menu.innerHTML = '';
    Array.from(select.options).forEach((opt, i) => {
      const item = document.createElement('div');
      item.id = optionId(i);
      item.className = 'custom-select-option' + (i === select.selectedIndex ? ' selected' : '');
      item.textContent = opt.textContent;
      item.setAttribute('role', 'option');
      item.setAttribute('aria-selected', i === select.selectedIndex ? 'true' : 'false');
      item.addEventListener('click', (e) => {
        e.stopPropagation();
        chooseIndex(i);
      });
      item.addEventListener('mouseenter', () => setActive(i));
      menu.appendChild(item);
    });
  }

  function setActive(i) {
    if (i < 0 || i >= select.options.length) return;
    activeIndex = i;
    Array.from(menu.children).forEach((el, idx) => el.classList.toggle('active', idx === i));
    trigger.setAttribute('aria-activedescendant', optionId(i));
    menu.children[i]?.scrollIntoView({ block: 'nearest' });
  }

  function chooseIndex(i) {
    const opt = select.options[i];
    if (!opt) return;
    select.value = opt.value;
    select.dispatchEvent(new Event('change', { bubbles: true }));
    closeMenu();
  }

  function syncTrigger() {
    const selected = select.options[select.selectedIndex];
    trigger.textContent = selected ? selected.textContent : '';
  }

  function openMenu() {
    closeAllCustomSelects();
    renderMenu();
    menu.classList.remove('hidden');
    trigger.classList.add('open');
    trigger.setAttribute('aria-expanded', 'true');
    setActive(select.selectedIndex >= 0 ? select.selectedIndex : 0);

    menu.classList.remove('menu-flip-up');
    const boundary = findClippingAncestor(wrapper);
    const boundaryRect = boundary ? boundary.getBoundingClientRect() : { top: 0, bottom: window.innerHeight };
    const triggerRect = trigger.getBoundingClientRect();
    const menuHeight = menu.getBoundingClientRect().height;
    const spaceBelow = boundaryRect.bottom - triggerRect.bottom;
    const spaceAbove = triggerRect.top - boundaryRect.top;

    if (spaceBelow < menuHeight && spaceAbove > spaceBelow) {
      menu.classList.add('menu-flip-up');
    }
  }

  function closeMenu() {
    menu.classList.add('hidden');
    trigger.classList.remove('open');
    trigger.setAttribute('aria-expanded', 'false');
    trigger.removeAttribute('aria-activedescendant');
    activeIndex = -1;
    syncTrigger();
  }

  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    if (trigger.disabled) return;
    menu.classList.contains('hidden') ? openMenu() : closeMenu();
  });

  trigger.addEventListener('keydown', (e) => {
    const isOpen = !menu.classList.contains('hidden');
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        isOpen ? setActive(Math.min(activeIndex + 1, select.options.length - 1)) : openMenu();
        break;
      case 'ArrowUp':
        e.preventDefault();
        isOpen ? setActive(Math.max(activeIndex - 1, 0)) : openMenu();
        break;
      case 'Home':
        if (isOpen) { e.preventDefault(); setActive(0); }
        break;
      case 'End':
        if (isOpen) { e.preventDefault(); setActive(select.options.length - 1); }
        break;
      case 'Enter':
      case ' ':
        if (isOpen) {
          e.preventDefault();
          chooseIndex(activeIndex);
        }
        break;
      case 'Escape':
        if (isOpen) { e.preventDefault(); closeMenu(); }
        break;
      case 'Tab':
        if (isOpen) closeMenu();
        break;
      default:
        // Single printable character (letters/digits/etc, no modifier held)
        // — everything else (arrows/Home/End/Enter/Escape/Tab) is handled
        // above already, and a modified keystroke (e.g. Cmd+R) shouldn't
        // be swallowed as a typeahead character.
        if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
          e.preventDefault();
          clearTimeout(typeaheadTimer);
          typeaheadBuffer += e.key.toLowerCase();
          typeaheadTimer = setTimeout(() => { typeaheadBuffer = ''; }, 600);

          const options = Array.from(select.options);
          // Search starting just after the current active option (native
          // <select> behavior) so repeating the same starting letter cycles
          // through every match instead of always landing on the first one.
          const startAt = isOpen ? (activeIndex + 1) % options.length : 0;
          const ordered = options.slice(startAt).concat(options.slice(0, startAt));
          const match = ordered.find((opt) => opt.textContent.trim().toLowerCase().startsWith(typeaheadBuffer));
          if (!match) break;
          const matchIndex = options.indexOf(match);
          if (isOpen) {
            setActive(matchIndex);
          } else {
            // Matches this component's own precedent: a closed trigger's
            // arrow keys open the menu rather than silently changing the
            // value, so typeahead does the same instead of committing a
            // selection the user never saw highlighted first.
            openMenu();
            setActive(matchIndex);
          }
        }
    }
  });

  select.addEventListener('change', syncTrigger);

  syncTrigger();
}

// Re-points an existing <label for="select.id"> at the new visible trigger (via
// aria-labelledby, since the trigger is a synthetic element the template never wrote a
// matching <label for> for), and forwards label clicks to it. pivpn-webui's forms mostly
// use implicit wrapping labels (<label>Text <select>...) rather than <label for>, in which
// case there's nothing to look up here and this is a no-op — the trigger still ends up
// inside the same <label>, so a click on the label still reaches it via the DOM's own
// default click-forwarding, just without an explicit ARIA name.
function linkTriggerToOwnLabel(nativeControl, trigger) {
  const ariaLabel = nativeControl.getAttribute('aria-label');
  if (ariaLabel) {
    trigger.setAttribute('aria-label', ariaLabel);
    return;
  }
  const existingLabelledby = nativeControl.getAttribute('aria-labelledby');
  if (existingLabelledby) {
    trigger.setAttribute('aria-labelledby', existingLabelledby);
    return;
  }
  if (!nativeControl.id) return;
  const ownLabel = document.querySelector(`label[for="${CSS.escape(nativeControl.id)}"]`);
  if (!ownLabel) return;
  if (!ownLabel.id) ownLabel.id = `${nativeControl.id}-label`;
  trigger.setAttribute('aria-labelledby', ownLabel.id);
  ownLabel.addEventListener('click', (e) => {
    e.preventDefault();
    trigger.focus();
  });
}

// Nearest ancestor that would actually clip an overflowing absolutely-positioned child
// (e.g. .table-scroll, which sets overflow-y: auto).
function findClippingAncestor(el) {
  let node = el.parentElement;
  while (node && node !== document.body) {
    const style = getComputedStyle(node);
    if (style.overflowX !== 'visible' || style.overflowY !== 'visible') {
      return node;
    }
    node = node.parentElement;
  }
  return null;
}

function closeAllCustomSelects() {
  document.querySelectorAll('.custom-select-menu').forEach((m) => m.classList.add('hidden'));
  document.querySelectorAll('.custom-select-trigger').forEach((t) => {
    t.classList.remove('open');
    t.setAttribute('aria-expanded', 'false');
    t.removeAttribute('aria-activedescendant');
  });
}

document.addEventListener('click', closeAllCustomSelects);
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeAllCustomSelects();
});

// pivpn-webui has no per-page opt-in list like the reference project's callers
// (add-tab.js/users.js) — just enhance every <select> on the page.
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('select').forEach(enhanceSelect);
});
