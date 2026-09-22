// Cisco/Huawei-style idle session lock: after IDLE_TIMEOUT_MINUTES of no
// genuine user activity (click/keypress/scroll/touch/mouse-move) this script
// POSTs to /account/lock, which clears the html_jwt auth cookie and sets an
// idle_lock cookie naming the locked user, then redirects to /login.  The
// login page detects the lock cookie and shows a "resume session" screen
// (just a password prompt — the username is already known from the cookie)
// instead of a full login form.  Unlike /logout, /account/lock does NOT bump
// session_generation, so the API bearer token in localStorage and any other
// open tabs stay valid: the user only needs to re-enter their password, not
// sign in from scratch.
// See config.py's IDLE_TIMEOUT_MINUTES and auth.py's idle_timed_out for
// the server-side half of this: the enforcement lives there (a cookie
// whose "la" claim goes stale stops authenticating, full stop) — this
// script is what keeps that claim fresh during real use of the
// fetch()-driven pages (Clients/Firewall/etc.) that otherwise never
// touch this cookie-authenticated side of the app again after their
// first load, plus what proactively sends an idle tab to /login instead
// of waiting for its next click to discover the cookie's already dead.
(function () {
  const meta = document.querySelector('meta[name="idle-timeout-minutes"]');
  if (!meta) return; // login page, or not logged in — nothing to time out

  const IDLE_MS = Number(meta.content) * 60 * 1000;
  const TICK_MS = 20 * 1000;
  // Rate limit — real activity keeps happening far more often than this;
  // pinging the server on every click would be pure waste. Scaled to a
  // fraction of IDLE_MS, not a fixed constant: a fixed interval close to
  // (or, at a short configured timeout, equal to) IDLE_MS leaves no
  // safety margin, so ordinary setInterval/network jitter can land a
  // heartbeat just past the server's own deadline — caught live during
  // testing with a 1-minute IDLE_MS, where a fixed 60s interval lost
  // that race outright. Floored so a very short timeout doesn't
  // heartbeat needlessly often; capped so a long one doesn't go
  // surprisingly long between heartbeats either.
  const HEARTBEAT_MIN_INTERVAL_MS = Math.min(Math.max(IDLE_MS / 3, 15 * 1000), 5 * 60 * 1000);

  const ACTIVITY_KEY = 'pivpn_webui_last_activity';
  let lastActivity = Date.now();
  localStorage.setItem(ACTIVITY_KEY, String(lastActivity));
  // Page load itself already refreshed the cookie's "la" claim server-side
  // (this very GET went through the after_request hook), so the first
  // heartbeat is only due once real activity happens AND the rate limit
  // below has since elapsed.
  let lastHeartbeatSent = Date.now();
  let done = false;

  function markActivity() {
    // A suspended tab must expire before its first new input can revive it.
    lastActivity = Math.max(lastActivity, Number(localStorage.getItem(ACTIVITY_KEY)) || 0);
    if (Date.now() - lastActivity >= IDLE_MS) { tick(); return; }
    lastActivity = Date.now();
    localStorage.setItem(ACTIVITY_KEY, String(lastActivity));
  }

  ["click", "keydown", "scroll", "touchstart", "mousemove"].forEach((evt) => {
    document.addEventListener(evt, markActivity, { passive: true });
  });

  function sendHeartbeat() {
    lastHeartbeatSent = Date.now();
    fetch("/account/heartbeat", {
      method: "POST",
      credentials: "same-origin",
    }).then((resp) => {
      // fetch() follows redirects transparently, so a session that's
      // already idle-timed-out server-side (login_required's own
      // redirect to /login) still comes back as an ok-looking response
      // — resp.redirected is what actually reveals it. Without this
      // check that case is silent: the page just sits there looking
      // authenticated until whatever the user clicks next unexpectedly
      // bounces to /login. Caught live in testing (see
      // HEARTBEAT_MIN_INTERVAL_MS's own comment on the race that causes
      // it) — this is the fail-safe for that race, not the fix itself.
      if (resp.redirected && !done) {
        done = true;
        window.location.href = "/login";
      }
    }).catch(() => {
      // Best-effort — a dropped heartbeat just means the idle clock isn't
      // extended this round; the next tick tries again, and a hard
      // network outage will show up as the idle timeout firing, which is
      // the correct fallback here, not a bug to handle specially.
    });
  }

  function tick() {
    if (done) return;
    const now = Date.now();
    lastActivity = Math.max(lastActivity, Number(localStorage.getItem(ACTIVITY_KEY)) || 0);
    if (now - lastActivity >= IDLE_MS) {
      done = true;
      // Cisco/Huawei-style idle lock: POST /account/lock clears the html_jwt
      // cookie and sets an idle_lock cookie with the username, then redirects
      // the server-side response to /login.  We do NOT remove the API bearer
      // token from localStorage so a resumed session can keep using it — the
      // token stays valid because /account/lock (unlike /logout) never bumps
      // session_generation.  If the lock POST itself fails (network down,
      // already logged out), fall back to a plain redirect to /login anyway.
      fetch("/account/lock", {
        method: "POST",
        credentials: "same-origin",
        redirect: "follow",
      })
        .then((resp) => {
          window.location.href = resp.url || "/login";
        })
        .catch(() => {
          window.location.href = "/login";
        });
      return;
    }
    if (lastActivity > lastHeartbeatSent && now - lastHeartbeatSent >= HEARTBEAT_MIN_INTERVAL_MS) {
      sendHeartbeat();
    }
  }

  setInterval(tick, TICK_MS);
})();
