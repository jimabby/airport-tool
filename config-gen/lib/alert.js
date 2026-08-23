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
function shouldAlert(previousState, s, cfg) {
  if (!cfg || !cfg.enabled) return false;
  if (cfg.onEveryPass) return true;
  if (s.state === 'unknown' || s.state === 'empty') return false;
  return s.state !== previousState;
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
      signal: AbortSignal.timeout(ALERT_TIMEOUT_MS),
    });
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
  shouldAlert,
  buildRequest,
  send,
};
