// Outbound notifications for the background health monitor.
//
// The monitor has always known when every server stopped answering. Finding
// that out meant opening the dashboard — which is the one thing you cannot do
// from behind the firewall when nothing is reachable. This turns the check into
// a message that leaves the machine while the machine can still send it.
//
// Deliberately dependency-free: a webhook is one POST, sent through
// network.js so the metadata-endpoint checks apply at the socket. Kept beside
// the probe helpers so `gen.js` can reach it too.

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

// What to remember once a delivery has been attempted. A transition is only
// "told" if the message actually left: recording it before the POST meant a
// webhook that was down at the moment everything broke swallowed the alert for
// good — every later pass saw no change and stayed quiet. Keeping the previous
// state instead makes the next pass see the same transition and try again.
// The failure streak is not affected; it describes the servers, not the webhook.
function settle(decision, previousState, outcome) {
  if (decision.send && outcome && outcome.sent === false) return previousState || null;
  return decision.state;
}

// ── Delivery ───────────────────────────────────────────────────────────────── //
// One payload shape serves Slack (`text`), Discord (`content`) and anything
// generic (`message`), so a URL is all the configuration a webhook needs. ntfy
// and the SMS bridges want a bare string instead — that is `mode: 'text'`.
//
// Two services need a shape of their own, and both are recognised from the URL
// so pasting it is still all it takes:
//   telegram  https://api.telegram.org/bot<token>/sendMessage?chat_id=<id>
//             Telegram ignores unknown fields but insists on `chat_id`, which
//             is lifted out of the query into the body.
//   bark      https://api.day.app/<device key> — the iOS push app most used in
//             China, where Slack and Discord are themselves blocked. A
//             self-hosted Bark server is picked with mode 'bark'.
//
// And the five that reach a phone from *inside* China, where Slack, Discord and
// Telegram are blocked and Bark is iOS only. Each wants its own body, and the
// generic JSON one is refused by all of them:
//   wecom       https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<key>
//   dingtalk    https://oapi.dingtalk.com/robot/send?access_token=<token>
//               (a robot with a keyword check needs "Airport" as its keyword;
//               every message starts with it)
//   feishu      https://open.feishu.cn/open-apis/bot/v2/hook/<id> (or Lark's
//               open.larksuite.com)
//   serverchan  https://sctapi.ftqq.com/<SendKey>.send (Server酱 → WeChat)
//   pushplus    https://www.pushplus.plus/send?token=<token> (→ WeChat); the
//               token is lifted into the body, as Telegram's chat_id is
const KIND_BY_HOST = [
  [/^api\.telegram\.org$/, 'telegram'],
  [/^api\.day\.app$/, 'bark'],
  [/^qyapi\.weixin\.qq\.com$/, 'wecom'],
  [/^oapi\.dingtalk\.com$/, 'dingtalk'],
  [/^open\.(?:feishu\.cn|larksuite\.com)$/, 'feishu'],
  [/^(?:sctapi\.ftqq\.com|sc\.ftqq\.com|[a-z0-9-]+\.push\.ft07\.com)$/, 'serverchan'],
  [/^(?:www\.)?pushplus\.plus$/, 'pushplus'],
];

function alertKind(cfg) {
  if (cfg.mode && cfg.mode !== 'json') return cfg.mode;
  let host = '';
  try { host = new URL(cfg.url).hostname.toLowerCase(); } catch { /* vetted elsewhere */ }
  const hit = KIND_BY_HOST.find(([re]) => re.test(host));
  return hit ? hit[1] : 'json';
}

const queryParam = (url, name) => { try { return new URL(url).searchParams.get(name) || ''; } catch { return ''; } };

function buildRequest(cfg, text, extra = {}) {
  const kind = alertKind(cfg);
  if (kind === 'text') {
    return { headers: { 'Content-Type': 'text/plain; charset=utf-8' }, body: text };
  }
  if (kind === 'telegram') {
    let chatId = '';
    try { chatId = new URL(cfg.url).searchParams.get('chat_id') || ''; } catch { /* vetted elsewhere */ }
    return {
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true }),
    };
  }
  if (kind === 'bark') {
    return {
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ title: 'Airport', body: text, group: 'airport-tool' }),
    };
  }
  const json = (obj) => ({ headers: { 'Content-Type': 'application/json; charset=utf-8' }, body: JSON.stringify(obj) });
  // WeCom and DingTalk group robots share a shape.
  if (kind === 'wecom' || kind === 'dingtalk') return json({ msgtype: 'text', text: { content: text } });
  if (kind === 'feishu') return json({ msg_type: 'text', content: { text } });
  // Server酱 shows `title` as the WeChat notification and `desp` when opened;
  // the title is capped at 32 characters by the service.
  if (kind === 'serverchan') return json({ title: text.slice(0, 32), desp: text });
  if (kind === 'pushplus') {
    return json({ token: queryParam(cfg.url, 'token'), title: 'Airport', content: text, template: 'txt' });
  }
  return {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, content: text, message: text, at: Date.now(), ...extra }),
  };
}

// The China-side services answer 200 to almost everything and put the real
// outcome in the body — a wrong key, a DingTalk keyword the message lacks, a
// rate limit. Reading only the status would record those as delivered, and the
// alert would never be retried. Returns why it was refused, or null.
function vendorRefusal(kind, text) {
  const codeField = { wecom: 'errcode', dingtalk: 'errcode', feishu: 'code', serverchan: 'code', pushplus: 'code', telegram: 'ok' }[kind];
  if (!codeField) return null;
  let body;
  try { body = JSON.parse(text); } catch { return null; }
  if (!body || typeof body !== 'object') return null;
  const okCode = kind === 'pushplus' ? 200 : 0;
  if (kind === 'telegram') return body.ok === false ? `Telegram refused it: ${String(body.description || 'no reason given').slice(0, 200)}` : null;
  // Older Feishu bots answer { StatusCode: 0 } instead of { code: 0 }.
  const code = body[codeField] !== undefined ? body[codeField] : body.StatusCode;
  if (code === undefined || Number(code) === okCode) return null;
  const why = body.errmsg || body.msg || body.message || body.StatusMessage || 'no reason given';
  return `${kind} refused it (${code}): ${String(why).slice(0, 200)}`;
}

// Never throws: a monitor pass must not fail because a notification did.
// Returns what happened so the dashboard can show a delivery failure rather
// than leaving you to assume the silence meant everything was fine.
async function send(cfg, text, extra = {}) {
  const alert = C.normalizeAlert(cfg);
  if (!alert.enabled) return { sent: false, reason: 'alerting is off' };
  const { headers, body } = buildRequest(alert, text, extra);
  try {
    const res = await require('./network').request(alert.url, {
      method: 'POST',
      headers,
      body,
      // network.request never follows a redirect. alertUrlProblem() vets the
      // URL that was typed, and a redirect is a second URL nobody vetted: a
      // webhook host answering 302 → 169.254.169.254 would otherwise walk the
      // POST straight past the metadata-endpoint block. A real webhook does
      // not redirect a POST, so a 3xx is reported below as a failure.
      timeoutMs: ALERT_TIMEOUT_MS, maxBytes: 65536,
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
    const refused = vendorRefusal(alertKind(alert), res.text);
    if (refused) return { sent: false, reason: refused, status: res.status };
    return { sent: true, status: res.status };
  } catch (err) {
    // network.request already words its timeout as "no response in Nms".
    return { sent: false, reason: (err && err.message) || String(err) };
  }
}

// ── Heads-up notices ───────────────────────────────────────────────────────── //
// Up/down transitions are the outage you are having. These are the ones you
// are about to have, each of which arrives on its own while nothing looks
// wrong: your certificate running out, or a provider plan expiring or nearly
// spent. Each is sent once per occurrence. The key changes when the thing
// itself does (a renewed certificate, a new plan), and a condition that clears
// drops out of the remembered set, so it fires again if it comes back.
const PLAN_WARN_DAYS = 7;
const QUOTA_WARN_RATIO = 0.9;
const DAY_MS = 86400000;

function formatBytes(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let v = Number(n) || 0;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

const isoDay = (ms) => new Date(ms).toISOString().slice(0, 10);

// `servers`: [{ id, remarks, enabled, cert }] where `cert` is the summary
// history.summarizeHistory() returns. `sources`: the store's sources.
// `reviews`: [{ id, name, count, hash }] for sources set to require review whose
// provider list has changed since it was last applied — `hash` names the change
// set, so a different set of changes is news again and the same one is not.
function notices({ servers = [], sources = [], reviews = [], now = Date.now() } = {}) {
  const out = [];
  for (const r of reviews) {
    if (!r || !r.id || !r.count) continue;
    out.push({
      key: `review:${r.id}:${r.hash || r.count}`,
      kind: 'review',
      text: `the "${r.name}" subscription has ${r.count} server change(s) waiting for your review in the dashboard`,
    });
  }
  for (const s of servers) {
    const c = s && s.cert;
    if (!c || s.enabled === false || c.selfSigned) continue;
    // Reality serves a borrowed site's certificate; its renewal is that site's
    // business, and an alert about it would be noise you cannot act on.
    if (c.of === 'camouflage target') continue;
    if (!c.expired && !c.expiring) continue;
    out.push({
      key: `cert:${s.id}:${c.notAfter}:${c.expired ? 'expired' : 'expiring'}`,
      kind: 'cert',
      text: c.expired
        ? `the certificate on "${s.remarks}" EXPIRED ${-c.daysLeft}d ago — clients will refuse it`
        : `the certificate on "${s.remarks}" expires in ${c.daysLeft}d (${isoDay(c.notAfter)})`,
    });
  }
  for (const src of sources) {
    const u = src && src.usage;
    if (!u) continue;
    if (u.expire && u.expire - now <= PLAN_WARN_DAYS * DAY_MS) {
      const days = Math.ceil((u.expire - now) / DAY_MS);
      out.push({
        key: `plan:${src.id}:${u.expire}:${days <= 0 ? 'expired' : 'expiring'}`,
        kind: 'plan',
        text: days <= 0
          ? `the "${src.name}" plan expired on ${isoDay(u.expire)}`
          : `the "${src.name}" plan expires in ${days}d (${isoDay(u.expire)})`,
      });
    }
    const used = (u.upload || 0) + (u.download || 0);
    if (u.total && used / u.total >= QUOTA_WARN_RATIO) {
      out.push({
        key: `quota:${src.id}:${u.total}:${used >= u.total ? 'spent' : 'low'}`,
        kind: 'quota',
        text: `"${src.name}" has used ${Math.round((used / u.total) * 100)}% of its ${formatBytes(u.total)}`,
      });
    }
  }
  return out;
}

// The notices not yet delivered, given what has been sent before.
function pendingNotices(current, sent) {
  const done = sent && typeof sent === 'object' ? sent : {};
  return current.filter((n) => !done[n.key]);
}

// What to remember after a delivery attempt: every current notice already
// sent, plus the ones that just went out. Anything no longer current is
// forgotten, which is what re-arms it.
function settleNotices(current, sent, delivered, now = Date.now()) {
  const done = sent && typeof sent === 'object' ? sent : {};
  const out = {};
  for (const n of current) {
    if (done[n.key]) out[n.key] = done[n.key];
    else if (delivered.some((d) => d.key === n.key)) out[n.key] = now;
  }
  return out;
}

function describeNotices(list) {
  return `Airport heads-up: ${list.map((n) => n.text).join('; ')}.`;
}

// Send whatever is pending in one message. Never throws. Returns the new
// remembered set and what happened, or null when there was nothing to say.
async function deliverNotices(cfg, current, sent) {
  const pending = pendingNotices(current, sent);
  if (!pending.length) return { sent: settleNotices(current, sent, []), outcome: null };
  const outcome = await send(cfg, describeNotices(pending), {
    state: 'notice',
    notices: pending.map(({ kind, text }) => ({ kind, text })),
  });
  return {
    sent: settleNotices(current, sent, outcome.sent ? pending : []),
    outcome: { ...outcome, count: pending.length },
  };
}

module.exports = {
  PLAN_WARN_DAYS,
  QUOTA_WARN_RATIO,
  formatBytes,
  notices,
  pendingNotices,
  settleNotices,
  describeNotices,
  deliverNotices,
  ALERT_TIMEOUT_MS,
  summarize,
  describe,
  nextStreak,
  evaluate,
  settle,
  alertKind,
  buildRequest,
  vendorRefusal,
  send,
};
