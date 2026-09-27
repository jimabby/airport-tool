// Outbound notifications for the background health monitor.
//
// The monitor has always known when every server stopped answering. Finding
// that out meant opening the dashboard — which is the one thing you cannot do
// from behind the firewall when nothing is reachable. This turns the check into
// a message that leaves the machine while the machine can still send it.
//
// Deliberately dependency-free: `fetch` is built into Node 18+, and a webhook
// is one POST. Kept beside the probe helpers so `gen.js` can reach it too.

'use strict';

const C = require('./configs');

const { normalizeAfterFailures } = C;

// A notification that hangs is worse than one that fails: the monitor pass is
// holding a timer slot while it waits.
const ALERT_TIMEOUT_MS = 8000;

// ── What a pass amounts to ─────────────────────────────────────────────────── //
// Disabled profiles are left out entirely. You switched them off; their being
// unreachable is the expected state, not an incident. Untestable ones (bare
// QUIC without a deep probe) are counted separately rather than as failures —
// calling a server "down" because we cannot speak its protocol would make the
// alert lie in exactly the case the deep test exists to fix.
function summarize(results) {
  const list = (Array.isArray(results) ? results : []).filter((r) => r && r.enabled !== false);
  const up = list.filter((r) => r.ok === true);
  const down = list.filter((r) => r.ok === false);
  const untestable = list.filter((r) => r.ok === null);
  let state;
  if (!list.length) state = 'empty';
  // Nothing answered either way: every profile was untestable. That is "we
  // could not ask", not "everything is down", and the two must not be confused.
  else if (!up.length && !down.length) state = 'unknown';
  else if (!down.length) state = 'ok';
  else if (!up.length) state = 'down';
  else state = 'degraded';
  return {
    state,
    total: list.length,
    up: up.length,
    down: down.length,
    untestable: untestable.length,
    upNames: up.map((r) => r.remarks),
    downNames: down.map((r) => r.remarks),
  };
}

// The sentence a human reads on their phone. The untestable count is always
// spelled out when there is one: "all 1 reachable" out of three profiles would
// otherwise read as an all-clear it has not earned.
function describe(s) {
  const aside = s.untestable ? ` (${s.untestable} untestable without a deep probe)` : '';
  if (s.state === 'empty') return 'Airport: nothing to check — every profile is disabled or removed.';
  if (s.state === 'unknown') {
    return `Airport: none of ${s.total} server(s) could be checked. Bare QUIC needs the deep test to say anything.`;
  }
  if (s.state === 'down') {
    return `Airport: ALL ${s.down} checkable server(s) are unreachable — ${s.downNames.join(', ')}${aside}.`;
  }
  if (s.state === 'degraded') {
    return `Airport: ${s.down} of ${s.total} server(s) down (${s.downNames.join(', ')}). Still up: ${s.upNames.join(', ')}${aside}.`;
  }
  return `Airport: ${s.up} of ${s.total} server(s) reachable (${s.upNames.join(', ')})${aside}.`;
}

// ── When to speak ──────────────────────────────────────────────────────────── //
// Transitions carry the information; a repeat every fifteen minutes is how
// people learn to swipe the notification away without reading it. `onEveryPass`
// is there for anyone piping this into a dashboard that wants every sample.
//
// `unknown` never triggers on its own: it means the probe could not ask, and
// waking someone for that is noise. It still ends a `down` state, because "we
// can no longer confirm it is broken" is not "it is broken".
//
// All of that is decided by evaluate() below, which is the only entry point.
// There used to be a `shouldAlert(previous, summary, cfg)` beside it answering
// the send/don't-send half on its own; once the failure threshold arrived it
// could no longer be the whole answer, and leaving it exported meant two copies
// of the same rules with nothing forcing them to agree.
//
// `afterFailures` says how many consecutive bad passes it takes before a problem
// is worth reporting, and it cannot be layered on from the outside: the caller
// also has to decide what to *remember*. If a held-back "down" were recorded as
// the current state, the transition would be consumed by the pass that stayed
// silent and the real alert would never fire at all.
//
// So the whole decision — send?, what state to remember, what the streak is now
// — is made in one place, and both the dashboard's monitor and
// `gen.js --test --alert` call it. They share the state file, so if they
// disagreed about any of the three, one would silently undo the other.
const isBad = (state) => state === 'down' || state === 'degraded';

// A pass that could not ask (`unknown`) does not reset the streak: two failed
// passes either side of one unmeasurable pass is still a server that is down.
function nextStreak(previousStreak, s) {
  const prev = Number.isFinite(previousStreak) ? previousStreak : 0;
  if (isBad(s.state)) return prev + 1;
  if (s.state === 'unknown' || s.state === 'empty') return prev;
  return 0;
}

function evaluate(previousState, previousStreak, s, cfg) {
  const streak = nextStreak(previousStreak, s);
  const threshold = normalizeAfterFailures(cfg && cfg.afterFailures);
  // Holding: something is wrong, but not for long enough to speak up yet.
  const holding = isBad(s.state) && streak < threshold;
  // Only a state we are prepared to act on is worth remembering. Everything
  // else leaves `previousState` alone so the transition survives to a later pass.
  const settled = !holding && s.state !== 'unknown' && s.state !== 'empty';
  const state = settled ? s.state : (previousState || null);

  let send = false;
  if (cfg && cfg.enabled) {
    if (cfg.onEveryPass) send = true;
    else if (holding) send = false;
    else if (s.state === 'unknown' || s.state === 'empty') send = false;
    else send = s.state !== previousState;
  }
  return { send, state, streak, holding, threshold };
}

// ── Delivery ───────────────────────────────────────────────────────────────── //
// One payload shape serves Slack (`text`), Discord (`content`) and anything
// generic (`message`), so a URL is all the configuration a webhook needs. ntfy
// and the SMS bridges want a bare string instead — that is `mode: 'text'`.
function buildRequest(cfg, text, extra = {}) {
  if (cfg.mode === 'text') {
    return { headers: { 'Content-Type': 'text/plain; charset=utf-8' }, body: text };
  }
  return {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, content: text, message: text, at: Date.now(), ...extra }),
  };
}

// Never throws: a monitor pass must not fail because a notification did.
// Returns what happened so the dashboard can show a delivery failure rather
// than leaving you to assume the silence meant everything was fine.
async function send(cfg, text, extra = {}) {
  const alert = C.normalizeAlert(cfg);
  if (!alert.enabled) return { sent: false, reason: 'alerting is off' };
  const { headers, body } = buildRequest(alert, text, extra);
  try {
    const res = await fetch(alert.url, {
      method: 'POST',
      headers,
      body,
      // Redirects are not followed. alertUrlProblem() vets the URL that was
      // typed, and a redirect is a second URL nobody vetted: a webhook host
      // answering 302 → 169.254.169.254 would walk the POST straight past the
      // metadata-endpoint block. A real webhook does not redirect a POST.
      redirect: 'manual',
      signal: AbortSignal.timeout(ALERT_TIMEOUT_MS),
    });
    if (res.status >= 300 && res.status < 400) {
      const where = res.headers.get('location');
      return {
        sent: false,
        status: res.status,
        reason: `webhook redirected (${res.status}${where ? ` to ${where}` : ''}) — redirects are not followed; use the final URL`,
      };
    }
    if (!res.ok) return { sent: false, reason: `webhook answered ${res.status}`, status: res.status };
    return { sent: true, status: res.status };
  } catch (err) {
    // AbortError has an unhelpful message; name it for what it is.
    const why = err && err.name === 'TimeoutError'
      ? `no response in ${ALERT_TIMEOUT_MS}ms` : (err && err.message) || String(err);
    return { sent: false, reason: why };
  }
}

module.exports = {
  ALERT_TIMEOUT_MS,
  summarize,
  describe,
  nextStreak,
  evaluate,
  buildRequest,
  send,
};
