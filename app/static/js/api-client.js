// Shared by any page that fetches its own data from /api/... (see
// clients-page.js) instead of getting it server-rendered. Manages the
// Bearer token those calls need: /api/... only ever accepts
// Authorization: Bearer, never this browser's own httpOnly session
// cookie — so a page's own JavaScript has to hold a token itself, in
// localStorage, to be able to call /api/... at all.
//
// That's a real, deliberate tradeoff, not an oversight: unlike the
// httpOnly session cookie, anything in localStorage is readable by any
// JavaScript that runs on this page, including an XSS bug if one is ever
// found. This mechanism exists because the app explicitly chose "some
// pages call the JSON API directly" over "everything is a plain form
// POST" for those pages — see the app's own docs for the reasoning.
const ApiClient = (() => {
  const STORAGE_KEY = 'pivpn_webui_api_token';

  function getToken() {
    return localStorage.getItem(STORAGE_KEY);
  }

  function setToken(token) {
    localStorage.setItem(STORAGE_KEY, token);
  }

  function clearToken() {
    localStorage.removeItem(STORAGE_KEY);
  }

  // Mints a fresh token via the *cookie*-authenticated /account/api-token
  // — this is how a page gets its first token without ever handling a
  // password itself, and how it recovers after one expires (15 minutes
  // by default) without forcing a full re-login, as long as the cookie
  // session itself is still good.
  async function mintToken() {
    const resp = await fetch('/account/api-token', { method: 'POST' });
    if (resp.redirected || resp.status === 401) {
      clearToken();
      window.location.href = '/login';
      throw new Error('not authenticated');
    }
    if (!resp.ok) throw new Error('could not obtain an API token');
    const data = await resp.json();
    setToken(data.access_token);
    return data.access_token;
  }

  async function ensureToken() {
    const existing = getToken();
    if (existing) return existing;
    return mintToken();
  }

  // Wraps fetch() with the Authorization header, and handles the token
  // being missing, expired, or superseded (see single-active-session —
  // logging in elsewhere invalidates this one): one silent retry with a
  // freshly-minted token, then a redirect to /login if that still fails,
  // since at that point the *cookie* session itself must be the problem,
  // not just this token.
  async function call(path, options = {}) {
    let token = await ensureToken();
    const withAuth = (t) => ({
      ...options,
      headers: { ...(options.headers || {}), Authorization: `Bearer ${t}` },
    });

    let resp = await fetch(path, withAuth(token));
    if (resp.status === 401) {
      clearToken();
      try {
        token = await mintToken();
      } catch {
        window.location.href = '/login';
        throw new Error('not authenticated');
      }
      resp = await fetch(path, withAuth(token));
    }
    if (resp.status === 401) {
      clearToken();
      window.location.href = '/login';
      throw new Error('not authenticated');
    }
    return resp;
  }

  // Disables `el` and marks it visually busy for the life of `promise` —
  // a click here often kicks off a hub/agent round-trip that can take
  // several real seconds (see the app's own notes on that), and with
  // nothing changing on screen in the meantime it reads as "did that even
  // register?", not "still working" — caught live: a real click landing
  // twice on Block because the first one looked like it did nothing.
  // Restoring in .finally() (not just the success path) means a failed
  // request still leaves the button clickable again, and running this on
  // a button that a subsequent re-render replaced/detached is harmless —
  // it just sets properties nothing is looking at anymore.
  function withBusy(el, promise) {
    if (el.disabled) return Promise.reject(new Error('busy'));
    // Only safe to rewrite textContent on a button that's plain text —
    // an icon-only button (Download's bare <svg>, no text) would have its
    // icon replaced by a literal "…", and a button with a live child
    // element (the bulk-action buttons' own rule-count <span>, updated
    // elsewhere via getElementById) would have that element silently
    // deleted and never come back. Every button still gets disabled +
    // the .is-busy dimmed/cursor:progress look either way — the "…"
    // suffix is an enhancement, not the whole fix.
    const canRewriteText = el.children.length === 0 && el.textContent.trim();
    const original = el.textContent;
    const busyText = original + '…';
    el.disabled = true;
    el.classList.add('is-busy');
    if (canRewriteText) el.textContent = busyText;
    return promise.finally(() => {
      el.disabled = false;
      el.classList.remove('is-busy');
      // Only strip the "…" back off if nothing else changed the label
      // while the request was in flight. Some success handlers relabel
      // the very button that's busy — Block becoming "Unblock", Disable
      // becoming "Enable" — and that runs *before* this finally(), so a
      // blind restore-to-the-pre-click text would silently clobber that
      // legitimate change back to the wrong, stale label. Caught live:
      // Block succeeded, the row correctly showed blocked, but the
      // button still read "Block" instead of "Unblock" afterward.
      if (canRewriteText && el.textContent === busyText) el.textContent = original;
    });
  }

  return { call, clearToken, withBusy };
})();
