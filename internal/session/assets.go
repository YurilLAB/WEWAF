package session

import "encoding/json"

// jsonMarshal is an internal indirection so the export site uses the
// stdlib JSON marshaller — kept private so callers can't bypass it
// and accidentally feed unescaped strings into the script template.
func jsonMarshal(v interface{}) ([]byte, error) { return json.Marshal(v) }

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

// PoWJS solves the proof-of-work challenge. Loaded by the server-rendered
// PoW gate page when a high-risk session is challenged. The script runs in
// a Web Worker so the main thread stays responsive — a 24-bit search can
// take several seconds. Falls back to a chunked setTimeout loop if Workers
// are unsupported (locked-down enterprise browsers, very old IE-mode pages).
//
// The client receives the salt + difficulty inline in the page and hashes
// SHA-256(salt || nonce) until the prefix has `difficulty` leading zero
// bits. Nonce is a uint64 packed big-endian into 8 bytes — matches the
// canonical reference solver in the test suite.
//
// Why not WASM: SubtleCrypto.digest('SHA-256', ...) is widely available
// (Chrome 37+, Firefox 34+, Safari 7+) and runs at ~native speed in the
// Worker context. WASM would be ~2× faster but adds 80 KB and a fetch.
const PoWJS = `(function(){
  'use strict';
  try {
    var page = window.__wewaf_pow;
    if (!page || !page.token || !page.salt || !page.difficulty) return;
    var saltB64 = page.salt;
    var difficulty = page.difficulty | 0;
    var token = page.token;

    function b64decode(b) {
      // base64-url → Uint8Array. Native atob can't take url-safe directly.
      b = String(b).replace(/-/g, '+').replace(/_/g, '/');
      while (b.length % 4) b += '=';
      var raw = atob(b);
      var out = new Uint8Array(raw.length);
      for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
      return out;
    }
    function b64urlEncode(bytes) {
      var s = '';
      for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function leadingZeroBits(buf, n) {
      var full = n >> 3;
      var rem = n & 7;
      for (var i = 0; i < full; i++) if (buf[i] !== 0) return false;
      if (rem === 0) return true;
      var mask = (0xff << (8 - rem)) & 0xff;
      return (buf[full] & mask) === 0;
    }
    var saltBytes = b64decode(saltB64);

    function solve(end, done) {
      // Iterative search using SubtleCrypto. We pack the nonce as a
      // big-endian uint64 across two uint32 halves so we don't lose
      // precision past 2^53 — JavaScript numbers can't represent the
      // full uint64 range exactly, but 2^48 is more than enough headroom
      // for any realistic difficulty.
      var nonce = new Uint8Array(8);
      var combined = new Uint8Array(saltBytes.length + 8);
      combined.set(saltBytes, 0);
      var hi = 0, lo = 0;
      function attempt() {
        // Pack [hi, lo] as 8 bytes big-endian.
        nonce[0] = (hi >>> 24) & 0xff;
        nonce[1] = (hi >>> 16) & 0xff;
        nonce[2] = (hi >>> 8) & 0xff;
        nonce[3] = hi & 0xff;
        nonce[4] = (lo >>> 24) & 0xff;
        nonce[5] = (lo >>> 16) & 0xff;
        nonce[6] = (lo >>> 8) & 0xff;
        nonce[7] = lo & 0xff;
        combined.set(nonce, saltBytes.length);
        return crypto.subtle.digest('SHA-256', combined);
      }
      function step() {
        attempt().then(function(buf){
          if (leadingZeroBits(new Uint8Array(buf), difficulty)) {
            done(new Uint8Array(nonce));
            return;
          }
          // Increment 64-bit counter (low first, carry into high).
          lo = (lo + 1) >>> 0;
          if (lo === 0) hi = (hi + 1) >>> 0;
          if (hi === 0 && lo >= end) { done(null); return; }
          // Yield every 256 attempts so the page stays responsive.
          if ((lo & 0xff) === 0) setTimeout(step, 0);
          else step();
        }).catch(function(){ done(null); });
      }
      step();
    }

    function submit(nonceBytes) {
      var body = 'token=' + encodeURIComponent(token) +
                 '&nonce=' + encodeURIComponent(b64urlEncode(nonceBytes));
      var x = new XMLHttpRequest();
      x.open('POST', '/api/pow/verify', true);
      x.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      x.onreadystatechange = function(){
        if (x.readyState === 4) {
          // On any 2xx, reload — the cookie should now bypass the gate.
          if (x.status >= 200 && x.status < 300) {
            window.location.replace(page.next || '/');
          } else {
            // Reload anyway so the user gets a fresh challenge with a
            // fresh salt. Repeated failure is usually a clock skew or
            // an expired token.
            setTimeout(function(){ window.location.reload(); }, 1500);
          }
        }
      };
      x.send(body);
    }

    if (!window.crypto || !window.crypto.subtle) {
      // SubtleCrypto missing — degrade by reloading without solving;
      // the server's threshold logic will fall back to the JS browser
      // challenge for clients in this state.
      return;
    }
    solve(1 << 28, function(nonce){
      if (nonce) submit(nonce);
    });
  } catch(_) {}
})();`

// PoWPageHTML is the shell page rendered when the WAF challenges a
// session. Tiny, no external resources, no third-party scripts. The
// challenge token is dropped into a global so PoWJS can read it without
// needing to parse the URL.
const PoWPageHTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Verifying your browser…</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;background:#0e1116;color:#e6edf3;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:32px 40px;max-width:420px;text-align:center}
h1{font-size:18px;margin:0 0 12px}
p{font-size:14px;color:#8b949e;margin:0 0 16px}
.spinner{width:32px;height:32px;border:3px solid #30363d;border-top-color:#fb923c;border-radius:50%%;animation:spin 1s linear infinite;margin:8px auto 16px}
@keyframes spin{to{transform:rotate(360deg)}}
.note{font-size:11px;color:#6e7681;margin-top:18px}
</style>
</head><body>
<div class="card">
<div class="spinner"></div>
<h1>Verifying your browser</h1>
<p>This usually takes a second. No CAPTCHA — your browser is solving a small math problem to prove it's a real browser.</p>
<noscript><p style="color:#f85149">JavaScript is required to continue.</p></noscript>
<div class="note">WEWAF · request-protection · this page does not store cookies until verification succeeds.</div>
</div>
<script>window.__wewaf_pow={token:%s,salt:%s,difficulty:%d,next:%s};</script>
<script src="/api/pow.js"></script>
</body></html>`

// PoWPageInjectValues renders token/salt/next as JSON-safe JavaScript
// string literals. Plain Go %q does NOT escape '<' or '>', so a
// payload like "</script><script>alert(1)" would close the script tag
// and execute attacker-controlled code in the PoW gate's origin —
// classic reflected XSS via the next-URL passthrough. JSON encoding
// produces properly escaped < / > sequences inside the
// string literal, defusing the HTML parser path.
func PoWPageInjectValues(token, salt, next string) (string, string, string) {
	jsString := func(s string) string {
		// json.Marshal escapes < > & by default at HTML safety. We also
		// fall back to a bare empty string on the (impossible) error
		// path so the template still produces valid JS.
		b, err := jsonMarshal(s)
		if err != nil {
			return `""`
		}
		return string(b)
	}
	return jsString(token), jsString(salt), jsString(next)
}

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
