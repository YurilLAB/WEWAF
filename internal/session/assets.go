package session

// Client-side JS served at /api/browser-challenge.js and /api/browser-beacon.js.
//
// Both scripts are written as a single minification-friendly IIFE with no
// external dependencies. They're small enough (under 2 KB each uncompressed)
// to be inlined in a <script> tag, though the admin API serves them with
// Cache-Control so CDNs can long-cache them.
//
// Design constraints:
//   - Never block the page. Everything runs on idle / after-load.
//   - Never throw in the main thread. Any unsupported API is try/catch'd.
//   - No UX friction: no visible CAPTCHA, no UI, no redirects.
//   - navigator.sendBeacon is preferred over fetch so we never delay
//     document.unload.
//   - The verify endpoint is POSTed with application/x-www-form-urlencoded
//     so it works even if CSP blocks JSON.

// ChallengeJS is the browser-integrity probe. The signals it collects are
// deliberately boring: known-brittle fingerprints (canvas/audio/webgl) are
// left out — they false-positive across GPU drivers and ad blockers. The
// six checks below are the highest-signal, lowest-noise flags that
// distinguish real desktop/mobile Chromium/Firefox/Safari from Puppeteer,
// Playwright, Selenium, and friends.
const ChallengeJS = `(function(){
  'use strict';
  try {
    if (document.cookie.indexOf('__wewaf_bc=') !== -1) return; // already passed
    var n = navigator, w = window;
    var signals = {
      // navigator.webdriver === true is the WebDriver spec's required
      // giveaway. Puppeteer/Playwright default to true; users who've
      // patched it will fail differently below.
      wd: !!(n.webdriver === true),
      // navigator.plugins is empty in headless Chrome by default; real
      // browsers have at least 2 (PDF viewer, etc.).
      pl: (n.plugins && n.plugins.length) | 0,
      // navigator.languages is missing or [''] in old headless; real
      // browsers report the accept-language list.
      lg: (n.languages && n.languages.length) | 0,
      // window.chrome object exists in real Chrome; undefined in Firefox
      // and in Chrome-headless < v109.
      ch: typeof w.chrome !== 'undefined' ? 1 : 0,
      // Permissions API returns 'prompt' for notifications on real
      // browsers; headless returns 'denied' immediately.
      ua: n.userAgent.length,
      // Hardware concurrency 0 is a strong headless signal; real devices
      // report 2-16.
      hc: (n.hardwareConcurrency | 0),
      // DeviceMemory is optional but real mobile/desktop reports a value.
      dm: ((n.deviceMemory || 0) | 0),
      // Screen dims of 0x0 or 800x600 default are headless defaults.
      sw: (screen.width | 0),
      sh: (screen.height | 0),
      // Timing: a human-interactive session takes >150 ms to first touch
      // the challenge; the script fires on DOMContentLoaded.
      tn: (performance && performance.now) ? Math.round(performance.now()) : 0,
      // Touch detection — headless typically reports 0.
      tp: (n.maxTouchPoints | 0)
    };
    var send = function() {
      var body = '';
      for (var k in signals) {
        if (body) body += '&';
        body += encodeURIComponent(k) + '=' + encodeURIComponent(signals[k]);
      }
      try {
        if (n.sendBeacon) {
          var blob = new Blob([body], {type: 'application/x-www-form-urlencoded'});
          n.sendBeacon('/api/browser-challenge/verify', blob);
          return;
        }
      } catch(_) {}
      try {
        var x = new XMLHttpRequest();
        x.open('POST', '/api/browser-challenge/verify', true);
        x.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        x.send(body);
      } catch(_) {}
    };
    // Fire after the page settles so we're measuring a real session, not
    // the pre-hydration millisecond.
    if (document.readyState === 'complete') {
      setTimeout(send, 150 + Math.floor(Math.random() * 250));
    } else {
      w.addEventListener('load', function(){ setTimeout(send, 150 + Math.floor(Math.random() * 250)); });
    }
  } catch(_) { /* never throw */ }
})();`

// BeaconJS reports human-input signals back to the server. Deliberately
// coarse — we count events and time-on-page rather than recording every
// event, so payloads stay tiny and there's nothing of value to log even
// if intercepted. Reports every 10 seconds OR on pagehide, whichever
// first. Sends zero-value reports too so "quiet tab" looks different
// from "never loaded" on the backend.
const BeaconJS = `(function(){
  'use strict';
  try {
    var w = window, d = document;
    var state = { mouse: 0, keys: 0, visibleMs: 0, lastTick: Date.now(), sent: 0 };
    var capture = function() {
      try {
        d.addEventListener('mousemove', function(){ state.mouse++; }, { passive: true, capture: true });
        d.addEventListener('keydown', function(){ state.keys++; }, { passive: true, capture: true });
        d.addEventListener('touchstart', function(){ state.mouse++; }, { passive: true, capture: true });
      } catch(_) {}
    };
    var flush = function(viaBeacon) {
      var now = Date.now();
      var dt = Math.min(600000, Math.max(0, now - state.lastTick));
      if (!d.hidden) state.visibleMs += dt;
      state.lastTick = now;
      var body = 'm=' + state.mouse + '&k=' + state.keys + '&t=' + state.visibleMs;
      state.mouse = 0; state.keys = 0; state.visibleMs = 0; state.sent++;
      try {
        if (viaBeacon && navigator.sendBeacon) {
          var blob = new Blob([body], {type: 'application/x-www-form-urlencoded'});
          navigator.sendBeacon('/api/session/beacon', blob);
          return;
        }
        var x = new XMLHttpRequest();
        x.open('POST', '/api/session/beacon', true);
        x.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        x.send(body);
      } catch(_) {}
    };
    capture();
    // Tick every 10 s; browsers throttle timers on hidden tabs, which is
    // fine — we want signals from active sessions.
    setInterval(function(){ flush(false); }, 10000);
    // Flush on pagehide / visibilitychange (the correct "unload" events
    // per WHATWG; plain 'unload' is unreliable on mobile Safari).
    w.addEventListener('pagehide', function(){ flush(true); });
    d.addEventListener('visibilitychange', function(){
      if (d.hidden) flush(true);
    });
  } catch(_) {}
})();`
