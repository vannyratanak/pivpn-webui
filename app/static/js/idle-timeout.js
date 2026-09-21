// Forces a real logout after IDLE_TIMEOUT_MINUTES of no genuine user
// activity (click/keypress/scroll/touch/mouse-move) — a separate, much
// shorter clock than the 8h "since your last *request*" cookie window
// and the 15m API-token silent refresh, both of which stay unaffected.
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
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    fetch("/account/heartbeat", {
      method: "POST",
      headers: { "X-CSRFToken": csrfMeta ? csrfMeta.content : "" },
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
      localStorage.removeItem("pivpn_webui_api_token");
      window.location.href = "/logout";
      return;
    }
    if (lastActivity > lastHeartbeatSent && now - lastHeartbeatSent >= HEARTBEAT_MIN_INTERVAL_MS) {
      sendHeartbeat();
    }
  }

  setInterval(tick, TICK_MS);
})();
