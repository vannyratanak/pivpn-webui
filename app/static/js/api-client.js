// Shared by any page that fetches its own data from /api/... (see
// clients-page.js) instead of getting it server-rendered. Manages the
// Bearer token those calls need: /api/... only ever accepts
// Authorization: Bearer, never this browser's own httpOnly session
// cookie (see app/__init__.py's csrf.exempt(api_bp) comment for why that
// separation matters) — so a page's own JavaScript has to hold a token
// itself, in localStorage, to be able to call /api/... at all.
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
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const resp = await fetch('/account/api-token', {
      method: 'POST',
      headers: { 'X-CSRFToken': csrfMeta ? csrfMeta.content : '' },
    });
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

  return { call, clearToken };
})();
