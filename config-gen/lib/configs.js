// Shared config model + builders for the Airport tool.
// Used by both the CLI generator (config-gen/gen.js) and the web UI
// (web-ui/server.js) so the two never drift.
//
// Supported protocols:
//   - "shadowsocks"    Shadowsocks-libev + v2ray-plugin (WebSocket, optional TLS)
//   - "vless-reality"  Xray VLESS + Reality (TLS camouflage, best DPI resistance)
//   - "hysteria2"      Hysteria2 over QUIC/UDP (best on lossy links; carries UDP)
//   - "tuic"           TUIC v5 over QUIC/UDP (quieter than Hysteria2, also carries UDP)
//   - "trojan"         Trojan over real TLS (what most commercial providers hand out)
//   - "vmess"          VMess, optionally over TLS (the older v2ray protocol)
//
// VLESS + Reality additionally supports a transport `network`: "tcp" (default),
// "grpc", or "xhttp". Only tcp may use the xtls-rprx-vision flow.
//
// Trojan and VMess exist here mainly so a link from somewhere else imports and
// generates: setup.sh does not install either (Reality does the same job with
// better camouflage), but a subscription you were handed is very likely to be
// one of the two, and being unable to read it made this tool useless for it.

'use strict';

const crypto = require('crypto');
const net = require('net');

const PROTOCOLS = ['shadowsocks', 'vless-reality', 'hysteria2', 'tuic', 'trojan', 'vmess'];

// How close to expiry a certificate has to be before it is worth mentioning.
// It lives here rather than in probe.js and history.js because it was defined
// in both, each with a comment about staying in step with the other — which is
// the arrangement that lets two numbers drift apart.
const CERT_WARN_DAYS = 14;

// Transports a VLESS + Reality profile can ride on. `xtls-rprx-vision` is a
// raw-TCP-only flow, so it has to be dropped on grpc/xhttp — Xray rejects the
// combination and the client just silently fails to connect.
const VLESS_NETWORKS = ['tcp', 'grpc', 'xhttp'];

// Trojan and VMess ride on the classic v2ray transports. `ws` is the one that
// matters in practice — it is what survives a CDN in front of the server.
const STREAM_NETWORKS = ['tcp', 'ws', 'grpc'];

// VMess payload ciphers. `auto` lets the client pick; `none` is only safe when
// the whole thing is already inside TLS.
const VMESS_CIPHERS = ['auto', 'none', 'aes-128-gcm', 'chacha20-poly1305', 'zero'];

// ── Hysteria2 port hopping ─────────────────────────────────────────────────── //
// The server redirects a whole UDP range to its real port and the client rotates
// across that range. A per-port block, or a QUIC-shaped throttle that latches
// onto one port, then stops killing the connection — which is the failure mode
// the protocol comparison in the README calls out for UDP.
//
// Accepts "20000-30000", "20000:30000", a bare port, or a comma-separated mix,
// and renders the canonical "a-b,c" form every client agrees on. Returns '' for
// anything unparseable; validateProfile() turns that into a hard error rather
// than letting a malformed range reach a client that would reject the profile.
const inPortRange = (n) => Number.isInteger(n) && n >= 1 && n <= 65535;

function normalizePortRange(v) {
  // Strip *all* whitespace, not just the ends: this arrives from a text field
  // people type into, and "20000 - 30000" is what they write.
  const parts = String(v == null ? '' : v).split(',').map((s) => s.replace(/\s+/g, '')).filter(Boolean);
  if (!parts.length) return '';
  const out = [];
  for (const part of parts) {
    const m = /^(\d+)(?:[-:](\d+))?$/.exec(part);
    if (!m) return '';
    const lo = Number(m[1]);
    const hi = m[2] === undefined ? lo : Number(m[2]);
    if (!inPortRange(lo) || !inPortRange(hi) || hi < lo) return '';
    out.push(lo === hi ? String(lo) : `${lo}-${hi}`);
  }
  return out.join(',');
}

// sing-box spells a range with a colon and wants a list.
function portRangeToSingBox(v) {
  return normalizePortRange(v).split(',').filter(Boolean)
    .map((s) => (s.includes('-') ? s.replace('-', ':') : `${s}:${s}`));
}

// How many seconds a hopping client stays on one port before moving.
const DEFAULT_HOP_INTERVAL = 30;

function normalizeHopInterval(v) {
  const n = Number(v);
  return Number.isFinite(n) && n >= 5 && n <= 600 ? Math.round(n) : DEFAULT_HOP_INTERVAL;
}

// ── Hysteria2 declared bandwidth ───────────────────────────────────────────── //
// Hysteria2's headline feature is Brutal, a congestion controller that sends at
// a rate you declare instead of one it infers from loss — which is exactly why
// it holds up on a path that makes TCP collapse. A client that declares nothing
// silently falls back to BBR, i.e. to the behaviour you picked Hysteria2 to
// avoid. 0 means "not set": leave the fields out and let the client decide.
function normalizeMbps(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.min(10000, Math.round(n)) : 0;
}

// ── Shadowsocks plugin ─────────────────────────────────────────────────────── //
// An absent `plugin` key means "unspecified", which has always meant
// v2ray-plugin here — that is what setup.sh installs. An *empty* one means a
// bare Shadowsocks server with no plugin at all. The two used to collapse
// together, so importing a plugin-less ss:// link produced a client that
// wrapped its traffic in a WebSocket the server had never heard of.
function normalizeSsPlugin(v) {
  if (v === undefined || v === null) return 'v2ray-plugin';
  const s = String(v).trim();
  return s === '' || s.toLowerCase() === 'none' ? '' : s;
}

// ── Plugin option lists ────────────────────────────────────────────────────── //
// `plugin_opts` is a `;`-delimited list of tokens, so it has to be read token by
// token. It used to be searched with `opts.includes('tls')`, which is a
// substring test: a perfectly ordinary `host=nottls.com` (or `tls.example.com`,
// or `hostels.io`) switched TLS on in the generated Clash config, the client
// then wrapped its traffic in TLS the server was not serving, and the only
// symptom was a connection that never came up.
function optsList(opts) {
  return String(opts || '').split(';').map((s) => s.trim()).filter(Boolean);
}

// True when the bare flag `name` is one of the tokens — `tls`, not `host=tls…`.
function hasOpt(opts, name) {
  return optsList(opts).includes(name);
}

// The value of a `name=value` token, or '' when it is absent. Same reasoning as
// hasOpt: /host=([^;]+)/ also matches `obfs-host=`, and picks the wrong one.
function getOpt(opts, name) {
  const prefix = `${name}=`;
  const hit = optsList(opts).find((t) => t.startsWith(prefix));
  return hit ? hit.slice(prefix.length) : '';
}

// ── Shadowsocks ciphers ────────────────────────────────────────────────────── //
// A mistyped method produces a bundle every client rejects, and the message they
// print does not name the field that is wrong. The web UI has always used a
// <select>, but `gen.js --add` and /api/import accept whatever the link said.
const SS_AEAD_METHODS = [
  'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
  'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
];

// Shadowsocks 2022. These take a base64 pre-shared key of an exact byte length
// rather than a passphrase, which is the part everybody gets wrong.
const SS_2022_METHODS = {
  '2022-blake3-aes-128-gcm': 16,
  '2022-blake3-aes-256-gcm': 32,
  '2022-blake3-chacha20-poly1305': 32,
};

// Pre-AEAD stream ciphers. Still accepted so an old link imports, but they carry
// no integrity check and current clients have dropped or deprecated them.
const SS_STREAM_METHODS = [
  'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
  'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
  'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
  'chacha20', 'chacha20-ietf', 'salsa20', 'rc4-md5', 'bf-cfb',
];

const SS_METHODS = [
  ...SS_AEAD_METHODS, ...Object.keys(SS_2022_METHODS), ...SS_STREAM_METHODS,
];

// A 2022 method's key is base64 of exactly N bytes. Checked by round-tripping
// rather than by regex: Buffer.from(…, 'base64') silently drops characters it
// does not recognise, so "looks like base64" is not the same as "is".
function ss2022KeyError(method, password) {
  const want = SS_2022_METHODS[method];
  if (!want) return null;
  const pw = String(password == null ? '' : password).replace(/\s+/g, '');
  const bytes = Buffer.from(pw, 'base64');
  const canonical = pw !== '' && bytes.toString('base64') === pw;
  if (canonical && bytes.length === want) return null;
  const got = canonical ? `${bytes.length} bytes` : 'something that is not base64';
  return `${method} needs a ${want}-byte base64 key, not a passphrase (got ${got})`
    + ` — generate one with: openssl rand -base64 ${want}`;
}

// "a;b=c" → { a: true, b: 'c' }. Used for plugins Clash knows by name but whose
// options this tool does not model field by field.
function optsToObject(opts) {
  const out = {};
  for (const part of String(opts || '').split(';').map((s) => s.trim()).filter(Boolean)) {
    const eq = part.indexOf('=');
    if (eq === -1) out[part] = true;
    else out[part.slice(0, eq)] = part.slice(eq + 1);
  }
  return out;
}

// Profile ids are injected into the web UI's DOM, so they must not be
// attacker-chosen strings. Anything that isn't a v4-shaped UUID is replaced.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isUuid(v) {
  return typeof v === 'string' && UUID_RE.test(v);
}

// Secret used to gate the subscription endpoint. base64url so it survives being
// pasted into a URL path unescaped.
function newToken() {
  return crypto.randomBytes(24).toString('base64url');
}

// ── Subscription display name ──────────────────────────────────────────────── //
// Clients render the `profile-title` response header as the name of the
// subscription; without it they fall back to showing the raw URL, token and all.
// Newlines are stripped because this string is about to become an HTTP header
// value — the base64 wrapper the header uses would hide them, but a header value
// assembled from user input has no business carrying a CR either way.
const DEFAULT_TITLE = 'Airport';

function normalizeTitle(v) {
  const s = typeof v === 'string' ? v.replace(/[\r\n\t]+/g, ' ').trim() : '';
  return s ? s.slice(0, 60) : DEFAULT_TITLE;
}

// ── Background health monitor settings ─────────────────────────────────────── //
// Probe history only ever filled in when somebody clicked a button, which made
// "which server should I be on right now?" a question you had to remember to
// ask. These settings live in the store so the CLI and the web UI agree on them
// and they survive a restart. Off by default: probing costs traffic, and a deep
// probe spawns a proxy per profile.
const ALERT_MODES = ['json', 'text'];
const ALERT_DEFAULTS = {
  enabled: false, url: '', mode: 'json', onEveryPass: false, afterFailures: 1,
};

// How many consecutive bad passes it takes to be worth waking somebody.
//
// The paths this tool exists for are lossy by nature, so a single failed probe
// is often just the link being the link — and an alert that fires at 3am for a
// server that was fine again by 3:01 is one people learn to mute, which costs
// more than the outage it was reporting. 1 keeps the original behaviour; the cap
// is 10 because past that the monitor is no longer telling you in time to act.
function normalizeAfterFailures(v) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(10, Math.max(1, Math.round(n))) : ALERT_DEFAULTS.afterFailures;
}

// ── Where a webhook may point ──────────────────────────────────────────────── //
// The monitor POSTs to whatever URL the dashboard holds, which makes it a way to
// reach things this process can see and the caller cannot. Whoever set the URL
// already holds every credential in the store, so this is not much of an
// escalation — but the cloud metadata endpoints are a special case: they hand
// out instance role credentials to anything that asks, they are reachable from
// every VPS this tool is likely to run on, and no one has ever legitimately
// pointed a notification at one.
//
// Loopback and LAN addresses are deliberately *allowed*: a self-hosted ntfy or
// Home Assistant on the same box or the same network is exactly what people
// point this at, and refusing it would break the honest case to inconvenience an
// attacker who is already inside.
const METADATA_HOSTS = new Set([
  '169.254.169.254',          // AWS / Azure / DigitalOcean / Oracle IMDS
  '169.254.170.2',            // AWS ECS task role endpoint
  'metadata.google.internal', // GCP
  'metadata.goog',
  'fd00:ec2::254',            // AWS IMDS over IPv6
  '100.100.100.200',          // Alibaba Cloud
]);

function alertUrlProblem(raw) {
  const url = String(raw || '').trim();
  if (!url) return 'no URL';
  if (!/^https?:\/\//i.test(url)) return 'only http:// and https:// URLs can be notified';
  let parsed;
  try { parsed = new URL(url); } catch { return 'that is not a URL this tool can parse'; }
  const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (METADATA_HOSTS.has(host)) {
    return `${host} is a cloud metadata endpoint, not a notification service — refusing to POST to it`;
  }
  // The rest of 169.254/16 and fe80::/10 are link-local: nothing there is a
  // webhook either, and it is where the metadata services hide behind aliases.
  if (/^169\.254\./.test(host) || /^fe80:/.test(host)) {
    return `${host} is a link-local address — nothing there is a notification service`;
  }
  return null;
}
const MONITOR_DEFAULTS = {
  enabled: false, intervalMin: 15, deep: false, autoSwitch: false, alert: { ...ALERT_DEFAULTS },
};

// ── Monitor alerting ───────────────────────────────────────────────────────── //
// The monitor already knows every server is unreachable; until now the only way
// to find that out was to open the dashboard, which is the one thing you cannot
// do when nothing is reachable. A webhook turns the check into a notification.
//
//   json  POST application/json. The body carries `text`, `content` *and*
//         `message` holding the same sentence, so one URL works for Slack,
//         Discord and a generic receiver without a mode switch per vendor.
//   text  POST text/plain — what ntfy.sh and most SMS bridges want.
//
// Only https?:// is accepted: this is a URL typed into a dashboard, and a
// file:// or a made-up scheme is a mistake, not a destination.
function normalizeAlert(a) {
  const src = a && typeof a === 'object' ? a : {};
  const raw = typeof src.url === 'string' ? src.url.trim() : '';
  // alertUrlProblem covers the scheme check this used to do inline, plus the
  // handful of addresses that are never a webhook. See its note.
  const url = alertUrlProblem(raw) ? '' : raw;
  return {
    // An alert with nowhere to go is off, whatever the checkbox says.
    enabled: (src.enabled === true || src.enabled === 'true') && !!url,
    url,
    mode: ALERT_MODES.includes(src.mode) ? src.mode : ALERT_DEFAULTS.mode,
    // Off by default: an hourly "still down" is how people learn to ignore
    // alerts. Transitions are the part that carries information.
    onEveryPass: src.onEveryPass === true || src.onEveryPass === 'true',
    afterFailures: normalizeAfterFailures(src.afterFailures),
  };
}

function normalizeMonitor(m) {
  const src = m && typeof m === 'object' ? m : {};
  const interval = Number(src.intervalMin);
  return {
    enabled: src.enabled === true || src.enabled === 'true',
    // Below a minute the probes overlap; above a day it is not a monitor.
    intervalMin: Number.isFinite(interval) ? Math.min(1440, Math.max(1, Math.round(interval))) : MONITOR_DEFAULTS.intervalMin,
    deep: src.deep === true || src.deep === 'true',
    // Moving ★ on its own is a bigger promise than measuring, so it is opt-in
    // separately: a flaky probe should not silently repoint your clients.
    autoSwitch: src.autoSwitch === true || src.autoSwitch === 'true',
    alert: normalizeAlert(src.alert),
  };
}

// ── Per-device subscription tokens ─────────────────────────────────────────── //
// The store-wide `token` is every credential you own behind one URL. Handing
// the same one to a laptop, a phone and a friend means a leak from any of them
// can only be fixed by re-pointing all three. A named client token is revocable
// on its own, and the feed it serves is identical.
function normalizeClients(list) {
  if (!Array.isArray(list)) return [];
  const out = [];
  const seen = new Set();
  for (const c of list) {
    if (!c || typeof c !== 'object') continue;
    // A short token is not a token. Drop it rather than serve a guessable feed.
    const token = typeof c.token === 'string' && c.token.length >= 16 ? c.token : null;
    if (!token || seen.has(token)) continue;
    seen.add(token);
    const created = Number(c.createdAt);
    out.push({
      id: isUuid(c.id) ? c.id : crypto.randomUUID(),
      name: String(c.name || 'Device').slice(0, 60),
      token,
      createdAt: Number.isFinite(created) ? created : Date.now(),
      // Which servers this device's feed carries. null means all of them —
      // what every token issued before subsets existed has always meant. A
      // list is profile ids; see profilesForClient for how it is applied.
      profiles: normalizeClientSubset(c.profiles),
    });
  }
  return out;
}

function normalizeClientSubset(v) {
  if (!Array.isArray(v)) return null;
  return [...new Set(v.filter(isUuid))];
}

// The profiles a device token's feed is built from. A friend handed one server
// should not also receive the other four the moment you add them, so a subset
// is an allow-list by id rather than a deny-list. Ids that no longer exist
// (the profile was deleted) are simply absent from the result.
function profilesForClient(profiles, client) {
  const list = Array.isArray(profiles) ? profiles : [];
  if (!client || !Array.isArray(client.profiles)) return list;
  const allowed = new Set(client.profiles);
  return list.filter((p) => allowed.has(p.id));
}

// ── Custom routing rules ───────────────────────────────────────────────────── //
// The generated bundles route by geography: domestic direct, everything else
// through the tunnel. That is right for almost everything and wrong for a few
// sites everyone has — a bank that refuses foreign IPs, a work VPN, a .cn
// domain that is actually hosted abroad, an ad network worth blocking. Until
// now the only fix was hand-editing a generated file, which the next generate
// run silently overwrote.
//
// Each list holds domains (matched as suffixes, so example.com also covers
// www.example.com) or IP ranges in CIDR form. They are applied before the
// geographic rules, in the order block → proxy → direct, in every bundle.
const RULE_LISTS = ['direct', 'proxy', 'block'];
const RULE_LIMIT = 500;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

// One entry → { kind, value } in its canonical spelling, or { error }. A leading
// "*." / "+." / "." is dropped: suffix matching already covers subdomains, and
// those are the three ways other tools spell "and everything under it".
function parseRuleEntry(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return { skip: true };
  const slash = s.indexOf('/');
  const addr = slash === -1 ? s : s.slice(0, slash);
  const family = net.isIP(addr);
  if (family) {
    const max = family === 4 ? 32 : 128;
    const bitsText = slash === -1 ? String(max) : s.slice(slash + 1);
    const bits = Number(bitsText);
    if (!/^\d+$/.test(bitsText) || bits > max) {
      return { error: `"${s}" has a prefix length that is not 0-${max}` };
    }
    return { kind: family === 4 ? 'ip' : 'ip6', value: `${addr.toLowerCase()}/${bits}` };
  }
  let d = s.toLowerCase().replace(/^(?:\*|\+)?\./, '').replace(/\.$/, '');
  // Someone will paste a URL. Take its hostname rather than refusing it.
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(d)) {
    try { d = new URL(d).hostname; } catch { return { error: `"${s}" is not a URL this tool can parse` }; }
  }
  // Internationalised names have to reach the clients as punycode: none of the
  // four rule formats accepts raw Unicode in a domain rule.
  if (/[^\x00-\x7f]/.test(d)) {
    try { d = new URL(`http://${d}/`).hostname; } catch { return { error: `"${s}" is not a valid domain` }; }
  }
  if (!DOMAIN_RE.test(d)) return { error: `"${s}" is not a domain, an IP address or a CIDR range` };
  return { kind: 'domain', value: d };
}

// A list arrives as an array (the API, the store) or as the text of a textarea:
// one entry per line or separated by commas, with # starting a comment. Spaces
// do not separate entries: "not a domain" is one bad entry to report, not the
// three single-label "domains" `not`, `a` and `domain` to quietly route.
function ruleTokens(v) {
  if (Array.isArray(v)) return v.map((x) => String(x));
  return String(v == null ? '' : v)
    .split(/\r?\n/).map((line) => line.replace(/#.*$/, ''))
    .join('\n').split(/[\r\n,]+/);
}

// Validate and canonicalise. Returns the cleaned lists plus every problem
// found, so the API can refuse a typo with a reason instead of silently
// dropping the rule the user was counting on. An entry that appears in two
// lists is an error too: which one should win is exactly the question the
// user has not answered.
function checkRules(raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const rules = { direct: [], proxy: [], block: [] };
  const errors = [];
  const seen = new Map();
  for (const list of RULE_LISTS) {
    for (const tok of ruleTokens(src[list])) {
      const r = parseRuleEntry(tok);
      if (r.skip) continue;
      if (r.error) { errors.push(`${list}: ${r.error}`); continue; }
      const already = seen.get(r.value);
      if (already) {
        if (already !== list) errors.push(`${r.value} is in both the ${already} and the ${list} list`);
        continue;
      }
      if (rules[list].length >= RULE_LIMIT) {
        errors.push(`${list}: more than ${RULE_LIMIT} entries`);
        break;
      }
      seen.set(r.value, list);
      rules[list].push(r.value);
    }
  }
  return { rules, errors };
}

function normalizeRules(raw) {
  return checkRules(raw).rules;
}

// Sort one stored list back into the three shapes every rule format spells
// differently.
function splitRuleKinds(list) {
  const out = { domains: [], ip: [], ip6: [] };
  for (const entry of Array.isArray(list) ? list : []) {
    const r = parseRuleEntry(entry);
    if (r.kind === 'domain') out.domains.push(r.value);
    else if (r.kind === 'ip') out.ip.push(r.value);
    else if (r.kind === 'ip6') out.ip6.push(r.value);
  }
  return out;
}

// The order the lists are emitted in. A blocked domain must never be proxied,
// and an explicit proxy entry has to beat the geographic DIRECT rules that
// follow — that is how a foreign-hosted .cn site gets reached at all.
const RULE_ORDER = ['block', 'proxy', 'direct'];

function hasRules(rules) {
  return !!rules && RULE_LISTS.some((l) => Array.isArray(rules[l]) && rules[l].length);
}

// ── Profile store ──────────────────────────────────────────────────────────── //
// The on-disk config can be any of:
//   { active, token, profiles: [ … ] }   ← canonical multi-profile store
//   [ {profile}, … ]                     ← bare array
//   { server, port, … }                  ← legacy single Shadowsocks profile
// normalizeStore() collapses all of them to the canonical shape.
function normalizeStore(raw) {
  let profiles;
  let active = 0;
  let token = null;
  let uiToken = null;
  let monitor = null;
  let clients = null;
  let title = null;
  let rules = null;
  if (Array.isArray(raw)) {
    profiles = raw;
  } else if (raw && Array.isArray(raw.profiles)) {
    profiles = raw.profiles;
    active = Number(raw.active) || 0;
    token = raw.token;
    uiToken = raw.uiToken;
    monitor = raw.monitor;
    clients = raw.clients;
    title = raw.title;
    rules = raw.rules;
  } else if (raw && (raw.server || raw.uuid)) {
    profiles = [raw]; // legacy single object
  } else {
    profiles = [];
  }
  profiles = profiles.map(normalizeProfile);
  if (!Number.isInteger(active) || active < 0 || active >= profiles.length) active = 0;
  const secret = (v) => (typeof v === 'string' && v.length >= 16 ? v : null);
  return {
    active,
    profiles,
    // `token` gates the subscription feed; `uiToken` gates the dashboard itself.
    // They are separate so you can hand a client the subscription URL without
    // also handing it write access to every profile.
    token: secret(token),
    uiToken: secret(uiToken),
    monitor: normalizeMonitor(monitor),
    // Revocable per-device subscription tokens. The store-wide `token` above
    // still works; these exist so one device can be cut off on its own.
    clients: normalizeClients(clients),
    // What a client should call this subscription. See normalizeTitle.
    title: normalizeTitle(title),
    // Your own direct / proxy / block lists. See checkRules.
    rules: normalizeRules(rules),
  };
}

// The transport half of a Trojan/VMess profile, shared by both because the
// fields and the rules are identical — only the credential differs.
function normalizeStream(p) {
  const network = STREAM_NETWORKS.includes(p.network) ? p.network : 'tcp';
  return {
    network,
    // ws: the HTTP path and the Host header the server matches on. A CDN in
    // front of the server routes on the Host, so it is not decoration.
    path: p.path || '',
    host: p.host || '',
    // grpc: has to match the server's serviceName exactly.
    serviceName: p.serviceName || '',
    fingerprint: p.fingerprint || 'chrome',
    alpn: p.alpn || '',
  };
}

function normalizeProfile(p = {}) {
  let protocol = p.protocol || (p.uuid ? 'vless-reality' : 'shadowsocks');
  if (protocol === 'hy2') protocol = 'hysteria2';
  // setup.sh's canon_protocol accepts this spelling, so a profile written by
  // hand from its output should not silently become Shadowsocks.
  if (protocol === 'vless') protocol = 'vless-reality';
  if (!PROTOCOLS.includes(protocol)) protocol = 'shadowsocks';
  const base = {
    // A non-UUID id (hand-edited file, or a client-supplied one on POST) is
    // discarded rather than trusted — see UUID_RE above.
    id: isUuid(p.id) ? p.id : crypto.randomUUID(),
    protocol,
    server: p.server,
    port: Number(p.port),
    remarks: p.remarks || 'Airport',
    // A blocked server should be able to leave the generated bundles without
    // being deleted: setup.sh cannot reproduce a password it already minted, so
    // "delete it and re-add it later" is not actually available. Absent means
    // enabled, so every store written before this field keeps working.
    enabled: p.enabled !== false && p.enabled !== 'false',
  };
  if (protocol === 'vless-reality') {
    const network = VLESS_NETWORKS.includes(p.network) ? p.network : 'tcp';
    // Vision is meaningful only over raw TCP; carrying it onto grpc/xhttp
    // produces a config that Xray and every client reject.
    const flow = network === 'tcp' ? (p.flow === undefined ? 'xtls-rprx-vision' : p.flow) : '';
    return {
      ...base,
      uuid: p.uuid,
      publicKey: p.publicKey || '',
      shortId: p.shortId || '',
      sni: p.sni || '',
      flow,
      fingerprint: p.fingerprint || 'chrome',
      network,
      // grpc calls it a serviceName, xhttp a path; keep both and use whichever
      // the chosen transport actually needs.
      serviceName: p.serviceName || '',
      path: p.path || '',
    };
  }
  if (protocol === 'trojan') {
    return {
      ...base,
      password: p.password,
      // Trojan is real TLS with a real certificate, so the SNI is the domain
      // the cert was issued for rather than a site being impersonated.
      sni: p.sni || '',
      insecure: p.insecure === true || p.insecure === 'true' || p.insecure === 1,
      ...normalizeStream(p),
    };
  }
  if (protocol === 'vmess') {
    return {
      ...base,
      uuid: p.uuid,
      // 0 is the modern value: anything else asks for the legacy non-AEAD
      // header, which current servers refuse outright.
      alterId: Number.isFinite(Number(p.alterId)) ? Math.max(0, Math.round(Number(p.alterId))) : 0,
      cipher: VMESS_CIPHERS.includes(p.cipher) ? p.cipher : 'auto',
      // Unlike Trojan, VMess encrypts on its own and TLS is optional — so it
      // has to be an explicit field rather than assumed.
      tls: p.tls === true || p.tls === 'true' || p.tls === 'tls' || p.tls === 1,
      sni: p.sni || '',
      insecure: p.insecure === true || p.insecure === 'true' || p.insecure === 1,
      ...normalizeStream(p),
    };
  }
  if (protocol === 'tuic') {
    return {
      ...base,
      uuid: p.uuid,
      password: p.password,
      sni: p.sni || '',
      insecure: p.insecure === true || p.insecure === 'true' || p.insecure === 1,
      // bbr is what the reference server ships with; native UDP relay is the
      // only mode that gives you real UDP rather than QUIC-framed emulation.
      congestion: p.congestion || 'bbr',
      udpRelayMode: p.udpRelayMode || 'native',
      alpn: p.alpn || 'h3',
    };
  }
  if (protocol === 'hysteria2') {
    // An unparseable range is kept verbatim rather than silently dropped, so
    // validateProfile() can reject it the way it already rejects a bad `port`.
    const rawPorts = p.ports == null || p.ports === '' ? '' : String(p.ports);
    return {
      ...base,
      password: p.password,
      sni: p.sni || '',
      // Self-signed certs are the norm for a domain-less Hysteria2 server, so
      // the client has to be told to skip verification.
      insecure: p.insecure === true || p.insecure === 'true' || p.insecure === 1,
      obfs: p.obfs || '',
      obfsPassword: p.obfsPassword || '',
      ports: normalizePortRange(rawPorts) || rawPorts,
      hopInterval: normalizeHopInterval(p.hopInterval),
      // Declared link speed in Mbps, 0 = let the client decide. See
      // normalizeMbps: without these the client quietly uses BBR instead of
      // Brutal, which is the reason to run Hysteria2 in the first place.
      up: normalizeMbps(p.up),
      down: normalizeMbps(p.down),
    };
  }
  const plugin = normalizeSsPlugin(p.plugin);
  return {
    ...base,
    password: p.password,
    method: p.method || 'chacha20-ietf-poly1305',
    plugin,
    // Options describe the plugin; with no plugin there is nothing for them to
    // configure, and a stray "server" would be read back as a plugin request.
    plugin_opts: plugin ? (p.plugin_opts || 'server') : '',
  };
}

// Profiles a bundled client config should actually carry. A disabled profile
// keeps its credentials in the store and stays out of every generated file —
// including the url-test group, where a dead server otherwise drags the whole
// group's latency around.
const isEnabled = (p) => !!p && p.enabled !== false;
function enabledProfiles(profiles) {
  return (Array.isArray(profiles) ? profiles : []).filter(isEnabled);
}

// Reality and TUIC both carry a UUID, and both fail the same way when it is
// mistyped: Xray maps a non-UUID id onto one of its own and keeps working,
// while sing-box and mihomo parse the field strictly — so the server is fine
// and every bundle this tool generates is rejected.
function uuidError(uuid) {
  // An absent uuid is already reported as "missing uuid"; saying it twice, once
  // as a shape complaint, would just be noise.
  if (!uuid || isUuid(uuid)) return null;
  return `uuid "${uuid}" is not a UUID — it must look like xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`;
}

// Fields that must be present for a profile to be usable, keyed by protocol.
function missingFields(p) {
  let required;
  if (p.protocol === 'vless-reality') required = ['server', 'port', 'uuid', 'publicKey', 'sni'];
  else if (p.protocol === 'hysteria2') required = ['server', 'port', 'password'];
  else if (p.protocol === 'tuic') required = ['server', 'port', 'uuid', 'password'];
  else if (p.protocol === 'trojan') required = ['server', 'port', 'password'];
  else if (p.protocol === 'vmess') required = ['server', 'port', 'uuid'];
  else required = ['server', 'port', 'password', 'method'];
  return required.filter((k) => !p[k]);
}

// Full validation: hard errors that block generation, plus soft warnings for
// configurations that are legal but usually a mistake. Shared by the CLI and
// the web UI so both reject and nag about exactly the same things.
function validateProfile(p) {
  const errors = missingFields(p).map((f) => `missing ${f}`);
  const warnings = [];

  if (p.server && /^https?:\/\//i.test(String(p.server))) {
    errors.push('server must be a bare host or IP, not a URL');
  }
  if (p.port !== undefined && p.port !== null && p.port !== '') {
    const port = Number(p.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      errors.push(`port ${p.port} is out of range (1-65535)`);
    }
  }

  if (p.protocol === 'vless-reality') {
    const badUuid = uuidError(p.uuid);
    if (badUuid) errors.push(badUuid);
    if (!p.shortId) warnings.push('no shortId — some clients require one');
    if (p.sni && /^\d+\.\d+\.\d+\.\d+$/.test(p.sni)) {
      errors.push('sni must be a real domain, not an IP — Reality borrows that site\'s handshake');
    }
    if (p.network === 'grpc' && !p.serviceName) {
      warnings.push('grpc transport with no serviceName — it has to match the server\'s exactly');
    }
    if (p.network && p.network !== 'tcp' && p.flow) {
      errors.push(`flow ${p.flow} only works over tcp — clear it for the ${p.network} transport`);
    }
    // sing-box has no XHTTP transport at all. buildSingBoxOutbound maps it onto
    // the closest thing sing-box speaks (`http`), which parses but is not the
    // same wire format — so the bundle loads and then cannot connect. Say so
    // here rather than let it be discovered from a client that just fails.
    if (p.network === 'xhttp') {
      warnings.push('xhttp works in Clash/mihomo and v2rayNG, but sing-box has no XHTTP transport — the Sing-Box bundle will carry a close-but-incompatible `http` transport for this server, so use tcp or grpc if you need sing-box');
    }
  } else if (p.protocol === 'trojan' || p.protocol === 'vmess') {
    if (p.protocol === 'vmess') {
      const badUuid = uuidError(p.uuid);
      if (badUuid) errors.push(badUuid);
      if (p.alterId) {
        warnings.push(`alterId ${p.alterId} asks for the legacy non-AEAD VMess header — current servers refuse it; use 0`);
      }
      if (!p.tls) {
        warnings.push('no TLS — VMess encrypts its payload but the handshake is recognisable on the wire, which is most of why it stopped working from China');
      }
    }
    // Trojan is nothing but TLS: without verification it is indistinguishable
    // from a man in the middle, and with an IP for an SNI no cert will match.
    const wantsTls = p.protocol === 'trojan' || p.tls;
    if (wantsTls && !p.sni && !p.insecure) {
      warnings.push('no sni and cert verification is on — set the domain the certificate was issued for, or enable insecure');
    }
    if (wantsTls && p.sni && /^\d+\.\d+\.\d+\.\d+$/.test(String(p.sni))) {
      warnings.push('sni is an IP address — no public certificate matches one, so verification will fail unless insecure is set');
    }
    if (p.network === 'ws' && !p.path) {
      warnings.push('ws transport with no path — it has to match the server\'s exactly (often /)');
    }
    if (p.network === 'grpc' && !p.serviceName) {
      warnings.push('grpc transport with no serviceName — it has to match the server\'s exactly');
    }
  } else if (p.protocol === 'tuic') {
    const badUuid = uuidError(p.uuid);
    if (badUuid) errors.push(badUuid);
    if (!p.sni && !p.insecure) {
      warnings.push('no sni and cert verification is on — set an sni or enable insecure for a self-signed cert');
    }
  } else if (p.protocol === 'hysteria2') {
    if (!p.sni && !p.insecure) {
      warnings.push('no sni and cert verification is on — set an sni or enable insecure for a self-signed cert');
    }
    if (p.obfs && !p.obfsPassword) warnings.push('obfs is set but obfsPassword is empty — obfuscation will not be applied');
    // Brutal needs both halves. One alone is not a rate, and clients differ on
    // whether they treat the missing half as zero or as "no limit".
    if ((p.up && !p.down) || (p.down && !p.up)) {
      warnings.push('only one of up/down is set — Hysteria2 needs both to use Brutal congestion control, so it will fall back to BBR');
    }
    if (!p.up && !p.down) {
      warnings.push('no up/down bandwidth — the client falls back to BBR instead of Brutal, which is most of the reason to run Hysteria2');
    }
    if (p.ports) {
      const range = normalizePortRange(p.ports);
      if (!range) {
        errors.push(`port range "${p.ports}" is not usable — write it as 20000-30000 (or a comma-separated list)`);
      } else if (!range.includes('-')) {
        warnings.push('the port range holds a single port — hopping needs a span like 20000-30000 to be worth anything');
      }
    }
  } else {
    const opts = p.plugin_opts || '';
    if (p.plugin && hasOpt(opts, 'tls') && !getOpt(opts, 'host')) {
      warnings.push('TLS mode but no host= — clients will use the server IP as SNI, which usually fails');
    }
    // A 2022 key of the wrong length cannot work, so it is a hard error rather
    // than a warning — and the client-side complaint about it names no field.
    const keyErr = ss2022KeyError(p.method, p.password);
    if (keyErr) errors.push(keyErr);
    if (p.method && !SS_METHODS.includes(p.method)) {
      warnings.push(`method "${p.method}" is not one this tool recognises — check the spelling, or every client will refuse the config`);
    } else if (SS_STREAM_METHODS.includes(p.method)) {
      warnings.push(`${p.method} is a pre-AEAD stream cipher with no integrity check — current clients have dropped it; prefer chacha20-ietf-poly1305`);
    }
    if (!p.plugin && opts) {
      warnings.push('plugin_opts are set but no plugin is — they will be ignored');
    }
    if (p.plugin && p.plugin !== 'v2ray-plugin') {
      warnings.push(`plugin "${p.plugin}" is passed through untouched — setup.sh only installs v2ray-plugin`);
    }
  }
  return { errors, warnings };
}

// ── Display-name de-duplication ────────────────────────────────────────────── //
// Clash rejects a config with two proxies of the same `name`, and Sing-Box's
// selector becomes ambiguous with duplicate tags. Profiles frequently collide —
// both the CLI and web UI default an empty label to "Airport" — so bundled
// builders must render each profile under a unique display name. Collisions get
// a " 2", " 3", … suffix in order; the first occurrence keeps the bare name.
//
// The suffix is checked against the names already handed out, not just counted
// per base. "Airport", "Airport" and "Airport 2" used to render as "Airport",
// "Airport 2" and "Airport 2" — the exact duplicate this function exists to
// prevent, and enough to make mihomo and sing-box refuse the whole bundle.
//
// The builders also add names of their own — the PROXY / Auto / Fallback
// groups, sing-box's `proxy` / `auto` / `direct` tags, and each client's
// built-in DIRECT / REJECT policies. A server labelled "Auto" collided with the
// group of the same name, which is the same duplicate by another route, so
// those are treated as already taken. Compared case-insensitively: sing-box's
// `direct` and a server called "Direct" are different strings but the same
// confusion in a selector list.
const RESERVED_NAMES = new Set([
  'proxy', 'auto', 'fallback', 'fastest', 'direct', 'reject', 'reject-drop',
  'pass', 'compatible', 'global',
]);

function uniqueNames(profiles) {
  const counter = new Map();
  const taken = new Set();
  return profiles.map((p) => {
    const base = p.remarks || 'Airport';
    let n = counter.get(base) || 0;
    let name;
    do {
      n += 1;
      name = n === 1 ? base : `${base} ${n}`;
    } while (taken.has(name) || RESERVED_NAMES.has(name.toLowerCase()));
    counter.set(base, n);
    taken.add(name);
    return name;
  });
}

// ── Shadowsocks helpers ────────────────────────────────────────────────────── //
// A profile describes the *server*, so its plugin_opts carry server-only tokens:
// `server` (server mode), and `cert=`/`key=` (the TLS cert paths). Client configs
// must drop all of these — leaving `server` makes the client's plugin listen as a
// server, and cert/key are meaningless (and leak local paths) on the client side.
const SERVER_ONLY_OPT = /^(server|cert|key|keylogfile)(=.*)?$/;
function clientPluginOpts(opts) {
  return String(opts || '')
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s && !SERVER_ONLY_OPT.test(s))
    .join(';');
}

function buildSsUri(p, name) {
  // SIP002 requires web-safe base64 (base64url, no padding) for the userinfo.
  const userinfo = Buffer.from(`${p.method}:${p.password}`).toString('base64url');
  const tag = encodeURIComponent(name || p.remarks || 'Airport');
  const authority = `ss://${userinfo}@${hostForUri(p.server)}:${p.port}`;
  // A bare Shadowsocks server has no plugin, and `?plugin=` on the link is what
  // tells the client to start one. Emitting it unconditionally handed every
  // plugin-less server a client that spoke WebSocket at it.
  if (!p.plugin) return `${authority}#${tag}`;
  const opts = clientPluginOpts(p.plugin_opts);
  const pluginField = opts ? `${p.plugin};${opts}` : p.plugin;
  return `${authority}?plugin=${encodeURIComponent(pluginField)}#${tag}`;
}

// ── VLESS + Reality helpers ────────────────────────────────────────────────── //
function buildVlessUri(p, name) {
  const network = p.network || 'tcp';
  const params = new URLSearchParams({
    encryption: 'none',
    security: 'reality',
    sni: p.sni || '',
    fp: p.fingerprint || 'chrome',
    pbk: p.publicKey || '',
    sid: p.shortId || '',
    type: network,
  });
  // An empty `flow=` is not the same as no flow at all: some clients read the
  // empty string back as a flow name and refuse the config. Only emit it on tcp.
  if (network === 'tcp' && p.flow) params.set('flow', p.flow);
  if (network === 'grpc') {
    params.set('serviceName', p.serviceName || '');
    // gun is the plain HTTP/2 gRPC mode every client agrees on; multi needs
    // matching server support that setup.sh does not configure.
    params.set('mode', 'gun');
  }
  if (network === 'xhttp') {
    params.set('path', p.path || '/');
    params.set('mode', 'auto');
  }
  const tag = encodeURIComponent(name || p.remarks || 'Airport');
  return `vless://${p.uuid}@${hostForUri(p.server)}:${p.port}?${params.toString()}#${tag}`;
}

// ── TUIC v5 helpers ────────────────────────────────────────────────────────── //
// TUIC's share link puts both halves of the credential in the userinfo:
//   tuic://<uuid>:<password>@host:port?…
function buildTuicUri(p, name) {
  const params = new URLSearchParams();
  if (p.sni) params.set('sni', p.sni);
  params.set('congestion_control', p.congestion || 'bbr');
  params.set('udp_relay_mode', p.udpRelayMode || 'native');
  if (p.alpn) params.set('alpn', p.alpn);
  if (p.insecure) params.set('allow_insecure', '1');
  const tag = encodeURIComponent(name || p.remarks || 'Airport');
  const cred = `${encodeURIComponent(p.uuid || '')}:${encodeURIComponent(p.password || '')}`;
  return `tuic://${cred}@${hostForUri(p.server)}:${p.port}?${params.toString()}#${tag}`;
}

// ── Trojan / VMess shared transport query ──────────────────────────────────── //
// Both protocols spell their transport the same way in a share link, and both
// are read back by the same clients, so the parameters are built in one place.
function streamParams(p, params) {
  const network = p.network || 'tcp';
  params.set('type', network);
  if (network === 'ws') {
    // A ws server matches on the path, and on the Host header when it sits
    // behind a CDN. Default the path to "/" rather than omitting it: an absent
    // path is read as "/" by some clients and as "" by others.
    params.set('path', p.path || '/');
    if (p.host) params.set('host', p.host);
  }
  if (network === 'grpc') {
    params.set('serviceName', p.serviceName || '');
    params.set('mode', 'gun');
  }
  if (p.fingerprint) params.set('fp', p.fingerprint);
  if (p.alpn) params.set('alpn', p.alpn);
  return params;
}

// ── Trojan helpers ─────────────────────────────────────────────────────────── //
// trojan://<password>@host:port?security=tls&sni=…#tag
function buildTrojanUri(p, name) {
  const params = new URLSearchParams();
  // Trojan is always TLS; saying so explicitly is what stops a client from
  // guessing, and every implementation in the wild emits it.
  params.set('security', 'tls');
  if (p.sni) params.set('sni', p.sni);
  if (p.insecure) params.set('allowInsecure', '1');
  streamParams(p, params);
  const tag = encodeURIComponent(name || p.remarks || 'Airport');
  const auth = encodeURIComponent(p.password || '');
  return `trojan://${auth}@${hostForUri(p.server)}:${p.port}?${params.toString()}#${tag}`;
}

function parseTrojanUri(uri) {
  const { tag } = splitFragment(uri);
  let u;
  try { u = new URL(uri); } catch { throw new Error('Malformed trojan:// URI'); }
  if (!u.username) throw new Error('Malformed trojan:// URI — no password');
  const q = u.searchParams;
  const insecure = q.get('allowInsecure') || q.get('insecure') || q.get('allow_insecure');
  return normalizeProfile({
    protocol: 'trojan',
    server: u.hostname.replace(/^\[|\]$/g, ''),
    port: Number(u.port) || 443,
    // The password sits in the userinfo, so it arrives percent-encoded. A colon
    // inside it splits into username/password, the same as hysteria2://.
    password: safeDecode(u.username) + (u.password ? `:${safeDecode(u.password)}` : ''),
    sni: q.get('sni') || q.get('peer') || '',
    insecure: insecure === '1' || insecure === 'true',
    network: q.get('type') || 'tcp',
    path: q.get('path') || '',
    host: q.get('host') || '',
    serviceName: q.get('serviceName') || '',
    fingerprint: q.get('fp') || 'chrome',
    alpn: q.get('alpn') || '',
    remarks: tag || 'Imported',
  });
}

// ── VMess helpers ──────────────────────────────────────────────────────────── //
// VMess has no agreed URI grammar. What every client actually reads is the
// v2rayN shape: vmess://base64(JSON), with abbreviated keys. A few emit a
// vless-style query string instead, so the parser accepts both and the builder
// emits the one with universal support.
function buildVmessUri(p, name) {
  const body = {
    v: '2',
    ps: name || p.remarks || 'Airport',
    add: p.server,
    port: String(p.port),
    id: p.uuid,
    aid: String(p.alterId || 0),
    scy: p.cipher || 'auto',
    net: p.network || 'tcp',
    // `type` here is the *header obfuscation* ("none" / "http"), not the
    // transport — an unfortunate name this format is stuck with.
    type: 'none',
    host: p.host || '',
    path: p.network === 'grpc' ? (p.serviceName || '') : (p.path || ''),
    tls: p.tls ? 'tls' : '',
    sni: p.tls ? (p.sni || '') : '',
    alpn: p.alpn || '',
    fp: p.fingerprint || '',
  };
  return `vmess://${Buffer.from(JSON.stringify(body), 'utf8').toString('base64')}`;
}

function parseVmessUri(uri) {
  const body = String(uri).slice('vmess://'.length).trim();
  // Query-string form first. It is recognisable by the "@" separating userinfo
  // from host, which the base64 form cannot contain before decoding.
  if (body.includes('@')) {
    let u;
    try { u = new URL(uri); } catch { throw new Error('Malformed vmess:// URI'); }
    const q = u.searchParams;
    const { tag } = splitFragment(uri);
    if (!u.username) throw new Error('Malformed vmess:// URI — no UUID');
    return normalizeProfile({
      protocol: 'vmess',
      server: u.hostname.replace(/^\[|\]$/g, ''),
      port: Number(u.port) || 443,
      uuid: safeDecode(u.username),
      cipher: q.get('encryption') || 'auto',
      network: q.get('type') || 'tcp',
      path: q.get('path') || '',
      host: q.get('host') || '',
      serviceName: q.get('serviceName') || '',
      tls: (q.get('security') || '') === 'tls',
      sni: q.get('sni') || '',
      fingerprint: q.get('fp') || 'chrome',
      alpn: q.get('alpn') || '',
      remarks: tag || 'Imported',
    });
  }
  let json;
  try {
    json = JSON.parse(b64decode(body));
  } catch {
    throw new Error('Malformed vmess:// URI — the body is not base64-encoded JSON');
  }
  if (!json || typeof json !== 'object') throw new Error('Malformed vmess:// URI — no profile object');
  const net = json.net || 'tcp';
  return normalizeProfile({
    protocol: 'vmess',
    server: String(json.add || '').replace(/^\[|\]$/g, ''),
    port: Number(json.port) || 443,
    uuid: json.id,
    alterId: json.aid !== undefined ? json.aid : json.alterId,
    cipher: json.scy || json.security || 'auto',
    network: net,
    // The single `path` field carries the grpc serviceName too, because the
    // format has nowhere else to put it.
    path: net === 'grpc' ? '' : (json.path || ''),
    serviceName: net === 'grpc' ? (json.path || '') : '',
    host: json.host || '',
    // "tls" or "". Anything else (e.g. "reality") is not something a vmess
    // profile can carry, so it reads as off rather than as a third state.
    tls: String(json.tls || '') === 'tls',
    sni: json.sni || '',
    fingerprint: json.fp || 'chrome',
    alpn: json.alpn || '',
    remarks: json.ps || 'Imported',
  });
}

// ── Hysteria2 helpers ──────────────────────────────────────────────────────── //
function buildHy2Uri(p, name) {
  const params = new URLSearchParams();
  if (p.sni) params.set('sni', p.sni);
  if (p.insecure) params.set('insecure', '1');
  if (p.obfs) {
    params.set('obfs', p.obfs);
    if (p.obfsPassword) params.set('obfs-password', p.obfsPassword);
  }
  // `mport` is what the official client and every share-link implementation
  // call the hopping range. The authority keeps the real port so a client that
  // ignores mport still connects.
  const ports = normalizePortRange(p.ports);
  if (ports) {
    params.set('mport', ports);
    // Without this the interval is lost on any round trip through a share
    // link, and the profile silently reverts to the default on re-import.
    params.set('hop-interval', String(normalizeHopInterval(p.hopInterval)));
  }
  // The share-link spec says nothing about declared bandwidth, so no client is
  // obliged to read these — but a client that ignores an unknown query
  // parameter loses nothing, while a subscription that drops the numbers turns
  // Brutal off on every device it feeds. Both spellings are emitted because
  // both are in the wild.
  if (p.up) { params.set('up', String(p.up)); params.set('upmbps', String(p.up)); }
  if (p.down) { params.set('down', String(p.down)); params.set('downmbps', String(p.down)); }
  const tag = encodeURIComponent(name || p.remarks || 'Airport');
  const query = params.toString();
  const auth = encodeURIComponent(p.password || '');
  return `hysteria2://${auth}@${hostForUri(p.server)}:${p.port}/${query ? `?${query}` : ''}#${tag}`;
}

// Bare IPv6 literals must be bracketed inside a URI authority.
function hostForUri(server) {
  const s = String(server || '');
  return s.includes(':') && !s.startsWith('[') ? `[${s}]` : s;
}

// ── URI dispatch (one profile → its import URI) ────────────────────────────── //
// `name` optionally overrides the display label (the #fragment) — bundle
// builders pass a de-duplicated name so clients don't show two identical entries.
function buildUri(p, name) {
  if (p.protocol === 'vless-reality') return buildVlessUri(p, name);
  if (p.protocol === 'hysteria2') return buildHy2Uri(p, name);
  if (p.protocol === 'tuic') return buildTuicUri(p, name);
  if (p.protocol === 'trojan') return buildTrojanUri(p, name);
  if (p.protocol === 'vmess') return buildVmessUri(p, name);
  return buildSsUri(p, name);
}

// A subscription is the base64 of all profile URIs joined by newlines — the
// de-facto format every modern client understands for auto-updating configs.
function buildSubscription(profiles) {
  // Disabled profiles are filtered here rather than at every call site: a
  // subscription that still carried a server you switched off would put it
  // straight back on the device you were trying to keep it off.
  const list = enabledProfiles(profiles);
  const names = uniqueNames(list);
  const body = list.map((p, i) => buildUri(p, names[i])).join('\n');
  return Buffer.from(body, 'utf8').toString('base64');
}

// ── URI parsing (import) ───────────────────────────────────────────────────── //
// The inverse of buildUri: turns a share link from a server, a QR scan, or
// another tool into a profile object. Throws with a readable message on bad
// input so callers can surface it directly.
function parseUri(uri) {
  const s = String(uri || '').trim();
  if (!s) throw new Error('Empty URI');
  if (/^ss:\/\//i.test(s)) return parseSsUri(s);
  if (/^vless:\/\//i.test(s)) return parseVlessUri(s);
  if (/^(hysteria2|hy2):\/\//i.test(s)) return parseHy2Uri(s);
  if (/^tuic:\/\//i.test(s)) return parseTuicUri(s);
  if (/^trojan:\/\//i.test(s)) return parseTrojanUri(s);
  if (/^vmess:\/\//i.test(s)) return parseVmessUri(s);
  const scheme = s.slice(0, Math.max(s.indexOf(':'), 0)) || s.slice(0, 12);
  throw new Error(
    `Unsupported URI scheme "${scheme}" — expected ss://, vless://, hysteria2://, tuic://, trojan:// or vmess://`,
  );
}

// Parse a subscription blob (base64 or plain text) or a multi-line paste into
// profiles. Lines that don't parse are reported rather than silently dropped.
function parseSubscription(text) {
  let body = String(text || '').trim();
  if (!body) return { profiles: [], errors: [] };
  // A subscription is base64; a raw paste is not. Detect by trying to decode
  // and checking that the result looks like URIs.
  // The character class has to cover base64url (`-` and `_`) as well as standard
  // base64: plenty of providers hand out the URL-safe alphabet, and without `_`
  // here the blob fell through to line-by-line parsing and failed as a whole.
  if (/^[A-Za-z0-9+/=_\s-]+$/.test(body) && !/:\/\//.test(body)) {
    const decoded = Buffer.from(body.replace(/\s+/g, ''), 'base64').toString('utf8');
    if (/:\/\//.test(decoded)) body = decoded;
  }
  const profiles = [];
  const errors = [];
  body.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).forEach((line, i) => {
    try { profiles.push(parseUri(line)); }
    catch (err) { errors.push(`line ${i + 1}: ${err.message}`); }
  });
  return { profiles, errors };
}

function splitFragment(uri) {
  const i = uri.indexOf('#');
  return i === -1
    ? { body: uri, tag: '' }
    : { body: uri.slice(0, i), tag: safeDecode(uri.slice(i + 1)) };
}

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

function b64decode(s) {
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

// "host:port" or "[v6::addr]:port" → { host, port }
function splitHostPort(hostport) {
  const m = /^\[(.+)\]:(\d+)$/.exec(hostport) || /^([^:]+):(\d+)$/.exec(hostport);
  if (!m) throw new Error(`Cannot parse host:port from "${hostport}"`);
  return { host: m[1], port: Number(m[2]) };
}

function parseSsUri(uri) {
  const { body: full, tag } = splitFragment(uri);
  let body = full.slice('ss://'.length);
  let query = '';
  const qIdx = body.indexOf('?');
  if (qIdx !== -1) { query = body.slice(qIdx + 1); body = body.slice(0, qIdx); }

  let cred;
  let hostport;
  if (body.includes('@')) {
    // SIP002: ss://base64url(method:password)@host:port — or, for the 2022
    // ciphers whose key is already base64, the plain percent-encoded
    // `method:password`. Neither ':' nor '%' is in the base64 alphabet, so
    // either one marks the plain form. This used to try base64 first and keep
    // the result whenever it contained a colon, which random bytes do about
    // one time in nine — silently importing a garbage method and password.
    const at = body.lastIndexOf('@');
    const userinfo = body.slice(0, at);
    hostport = body.slice(at + 1);
    if (/[:%]/.test(userinfo)) {
      cred = safeDecode(userinfo);
    } else {
      const decoded = b64decode(userinfo);
      cred = decoded.includes(':') ? decoded : safeDecode(userinfo);
    }
  } else {
    // Legacy: ss://base64(method:password@host:port)
    const decoded = b64decode(body);
    const at = decoded.lastIndexOf('@');
    if (at === -1) throw new Error('Malformed ss:// URI — no credentials found');
    cred = decoded.slice(0, at);
    hostport = decoded.slice(at + 1);
  }
  const sep = cred.indexOf(':');
  if (sep === -1) throw new Error('Malformed ss:// URI — expected method:password');
  const { host, port } = splitHostPort(hostport);

  const params = new URLSearchParams(query);
  const pluginField = params.get('plugin') || '';
  const semi = pluginField.indexOf(';');
  const plugin = semi === -1 ? pluginField : pluginField.slice(0, semi);
  const opts = semi === -1 ? '' : pluginField.slice(semi + 1);
  // A share link carries client-side opts; the profile describes the server, so
  // re-add the `server` keyword that clientPluginOpts() strips back out later.
  const pluginOpts = opts ? `server;${opts}` : 'server';

  return normalizeProfile({
    protocol: 'shadowsocks',
    server: host,
    port,
    method: cred.slice(0, sep),
    password: cred.slice(sep + 1),
    // No `plugin=` in the link means the server runs none. Substituting
    // v2ray-plugin here — which is what this used to do — produced a profile
    // that no plain Shadowsocks server could answer, and no way to say so.
    plugin,
    plugin_opts: plugin ? pluginOpts : '',
    remarks: tag || 'Imported',
  });
}

function parseVlessUri(uri) {
  const { tag } = splitFragment(uri);
  let u;
  try { u = new URL(uri); } catch { throw new Error('Malformed vless:// URI'); }
  const q = u.searchParams;
  const security = q.get('security') || '';
  if (security && security !== 'reality') {
    throw new Error(`vless:// with security=${security} is not supported (only Reality)`);
  }
  if (!u.username) throw new Error('Malformed vless:// URI — no UUID');
  const network = VLESS_NETWORKS.includes(q.get('type')) ? q.get('type') : 'tcp';
  return normalizeProfile({
    protocol: 'vless-reality',
    server: u.hostname.replace(/^\[|\]$/g, ''),
    port: Number(u.port),
    uuid: safeDecode(u.username),
    publicKey: q.get('pbk') || '',
    shortId: q.get('sid') || '',
    sni: q.get('sni') || q.get('peer') || '',
    // Pass the flow through verbatim (including absent → undefined) so
    // normalizeProfile can apply the tcp-only rule in one place.
    flow: q.has('flow') ? q.get('flow') : undefined,
    fingerprint: q.get('fp') || 'chrome',
    network,
    serviceName: q.get('serviceName') || '',
    path: q.get('path') || '',
    remarks: tag || 'Imported',
  });
}

function parseTuicUri(uri) {
  const { tag } = splitFragment(uri);
  let u;
  try { u = new URL(uri); } catch { throw new Error('Malformed tuic:// URI'); }
  if (!u.username) throw new Error('Malformed tuic:// URI — no UUID');
  const q = u.searchParams;
  const insecure = q.get('allow_insecure') || q.get('insecure');
  return normalizeProfile({
    protocol: 'tuic',
    server: u.hostname.replace(/^\[|\]$/g, ''),
    port: Number(u.port) || 443,
    uuid: safeDecode(u.username),
    password: safeDecode(u.password || ''),
    sni: q.get('sni') || '',
    insecure: insecure === '1' || insecure === 'true',
    congestion: q.get('congestion_control') || 'bbr',
    udpRelayMode: q.get('udp_relay_mode') || 'native',
    alpn: q.get('alpn') || 'h3',
    remarks: tag || 'Imported',
  });
}

function parseHy2Uri(uri) {
  const { tag } = splitFragment(uri);
  // new URL() only understands hysteria2:// once it has a recognised shape;
  // normalise the hy2:// alias first so both go down the same path.
  const normalized = uri.replace(/^hy2:\/\//i, 'hysteria2://');
  let u;
  try { u = new URL(normalized); } catch { throw new Error('Malformed hysteria2:// URI'); }
  const q = u.searchParams;
  const insecure = q.get('insecure');
  return normalizeProfile({
    protocol: 'hysteria2',
    server: u.hostname.replace(/^\[|\]$/g, ''),
    port: Number(u.port) || 443,
    password: safeDecode(u.username) + (u.password ? `:${safeDecode(u.password)}` : ''),
    sni: q.get('sni') || '',
    insecure: insecure === '1' || insecure === 'true',
    obfs: q.get('obfs') || '',
    obfsPassword: q.get('obfs-password') || '',
    ports: q.get('mport') || q.get('ports') || '',
    hopInterval: q.get('hop-interval') || q.get('hop_interval') || undefined,
    up: q.get('up') || q.get('upmbps') || 0,
    down: q.get('down') || q.get('downmbps') || 0,
    remarks: tag || 'Imported',
  });
}

// ALPN is stored as the comma-separated string a share link carries; both
// bundle formats want a list.
function alpnList(v) {
  return String(v || '').split(',').map((s) => s.trim()).filter(Boolean);
}

// The ws/grpc transport, in Clash's spelling. Shared by trojan and vmess
// because mihomo spells it identically for both.
function clashStreamOpts(p, proxy) {
  const network = p.network || 'tcp';
  if (network === 'tcp') return proxy;
  proxy.network = network;
  if (network === 'ws') {
    proxy['ws-opts'] = {
      path: p.path || '/',
      // The Host header is what a CDN in front of the server routes on, and
      // what the server matches when it hosts more than one thing.
      ...(p.host ? { headers: { Host: p.host } } : {}),
    };
  }
  if (network === 'grpc') proxy['grpc-opts'] = { 'grpc-service-name': p.serviceName || '' };
  return proxy;
}

// The same transport in sing-box's spelling.
function singBoxTransport(p) {
  const network = p.network || 'tcp';
  if (network === 'ws') {
    return {
      type: 'ws',
      path: p.path || '/',
      ...(p.host ? { headers: { Host: p.host } } : {}),
    };
  }
  if (network === 'grpc') return { type: 'grpc', service_name: p.serviceName || '' };
  return null;
}

// ── Clash / Mihomo (Clash.Meta) ────────────────────────────────────────────── //
function buildClashProxy(p, name) {
  const displayName = name || p.remarks || 'Airport';
  if (p.protocol === 'vless-reality') {
    const network = p.network || 'tcp';
    const proxy = {
      name: displayName,
      type: 'vless',
      server: p.server,
      port: Number(p.port),
      uuid: p.uuid,
      network,
      udp: true,
      tls: true,
      servername: p.sni,
      'client-fingerprint': p.fingerprint || 'chrome',
      'reality-opts': { 'public-key': p.publicKey, 'short-id': p.shortId },
    };
    // Mihomo treats an empty `flow` as a request for a flow it doesn't know.
    if (network === 'tcp' && p.flow) proxy.flow = p.flow;
    if (network === 'grpc') proxy['grpc-opts'] = { 'grpc-service-name': p.serviceName || '' };
    if (network === 'xhttp') proxy['xhttp-opts'] = { path: p.path || '/', mode: 'auto' };
    return proxy;
  }
  if (p.protocol === 'tuic') {
    return {
      name: displayName,
      type: 'tuic',
      server: p.server,
      port: Number(p.port),
      uuid: p.uuid,
      password: p.password,
      sni: p.sni || p.server,
      'congestion-controller': p.congestion || 'bbr',
      'udp-relay-mode': p.udpRelayMode || 'native',
      alpn: (p.alpn || 'h3').split(',').map((a) => a.trim()).filter(Boolean),
      'reduce-rtt': true,
      'skip-cert-verify': !!p.insecure,
    };
  }
  if (p.protocol === 'hysteria2') {
    const proxy = {
      name: displayName,
      type: 'hysteria2',
      server: p.server,
      port: Number(p.port),
      password: p.password,
      sni: p.sni || p.server,
      'skip-cert-verify': !!p.insecure,
    };
    // Mihomo prefers `ports` when both are present, and keeps `port` as the
    // fallback for the first dial — so both stay.
    const hopPorts = normalizePortRange(p.ports);
    if (hopPorts) {
      proxy.ports = hopPorts;
      proxy['hop-interval'] = normalizeHopInterval(p.hopInterval);
    }
    if (p.obfs) {
      proxy.obfs = p.obfs;
      proxy['obfs-password'] = p.obfsPassword;
    }
    // Mihomo reads a bare number as Mbps but accepts the unit, and the unit is
    // what makes a hand-edited config readable six months later.
    if (p.up) proxy.up = `${p.up} Mbps`;
    if (p.down) proxy.down = `${p.down} Mbps`;
    return proxy;
  }
  if (p.protocol === 'trojan') {
    const proxy = {
      name: displayName,
      type: 'trojan',
      server: p.server,
      port: Number(p.port),
      password: p.password,
      // Trojan is TLS by definition, so there is no `tls` flag to set — but the
      // SNI still has to fall back to something, and the server's own name is
      // the only honest default.
      sni: p.sni || p.server,
      'skip-cert-verify': !!p.insecure,
      udp: true,
      'client-fingerprint': p.fingerprint || 'chrome',
    };
    const alpn = alpnList(p.alpn);
    if (alpn.length) proxy.alpn = alpn;
    return clashStreamOpts(p, proxy);
  }
  if (p.protocol === 'vmess') {
    const proxy = {
      name: displayName,
      type: 'vmess',
      server: p.server,
      port: Number(p.port),
      uuid: p.uuid,
      alterId: Number(p.alterId || 0),
      cipher: p.cipher || 'auto',
      udp: true,
      tls: !!p.tls,
    };
    // Without TLS there is no handshake to name, and mihomo reads a stray
    // `servername` as a request to start one.
    if (p.tls) {
      proxy.servername = p.sni || p.server;
      proxy['skip-cert-verify'] = !!p.insecure;
      proxy['client-fingerprint'] = p.fingerprint || 'chrome';
      const alpn = alpnList(p.alpn);
      if (alpn.length) proxy.alpn = alpn;
    }
    return clashStreamOpts(p, proxy);
  }
  const proxy = {
    name: displayName,
    type: 'ss',
    server: p.server,
    port: Number(p.port),
    cipher: p.method,
    password: p.password,
    // A plain Shadowsocks server relays UDP; mihomo will not send any over a
    // proxy that does not say so, and every other protocol here already does.
    // v2ray-plugin's WebSocket cannot carry UDP at all, so the flag has to
    // follow the plugin rather than be set unconditionally — claiming UDP over
    // a ws-wrapped server produces a proxy that swallows DNS and QUIC.
    udp: !p.plugin,
  };
  // No plugin means no plugin keys at all: mihomo starts one the moment the
  // field is present, whatever the server is actually running.
  if (p.plugin === 'v2ray-plugin') {
    const opts = p.plugin_opts || '';
    proxy.plugin = 'v2ray-plugin';
    proxy['plugin-opts'] = {
      mode: 'websocket',
      // hasOpt, not includes(): see the note above optsList. `host=nottls.com`
      // used to turn this on and hand the client a TLS wrapper the server was
      // not serving.
      tls: hasOpt(opts, 'tls'),
      host: getOpt(opts, 'host') || p.server,
      // v2ray-plugin's default WebSocket path is "/", so match it when none is
      // given — otherwise the client mismatches a server without an explicit
      // path= and the WebSocket upgrade is rejected.
      path: getOpt(opts, 'path') || '/',
    };
  } else if (p.plugin) {
    proxy.plugin = p.plugin;
    const opts = optsToObject(clientPluginOpts(p.plugin_opts));
    if (Object.keys(opts).length) proxy['plugin-opts'] = opts;
  }
  return proxy;
}

const HEALTH_CHECK_URL = 'http://www.gstatic.com/generate_204';

// jsDelivr's testing endpoint is the mirror that stays reachable from inside the
// GFW most consistently; raw.githubusercontent.com does not.
const GEO_MIRROR = 'https://testingcf.jsdelivr.net';

// ── Names that must never get a fake IP ────────────────────────────────────── //
// fake-ip hands every lookup a 198.18.x.x placeholder and resolves the real
// address at the far end. That is what makes domain rules work without leaking
// DNS — but anything that *uses* the returned address itself, rather than just
// connecting to it, gets a number that means nothing:
//
//   captive-portal checks   the OS compares the answer against a known IP and
//                           decides the network is broken
//   NTP / STUN              the client dials the literal address it was given
//   consoles and IoT        Nintendo/Xbox/Xiaomi services do their own thing
//
// This is the list every mihomo ruleset ships for the same reason. Your own
// proxy servers are appended to it by buildClashConfig: a fake IP for the
// server you are trying to reach is a proxy that cannot dial out at all.
const FAKE_IP_FILTER = [
  '*.lan', '*.local', '*.localdomain', '*.home.arpa',
  'localhost.ptlogin2.qq.com',
  // Connectivity / captive-portal probes.
  '+.msftconnecttest.com', '+.msftncsi.com', 'dns.msftncsi.com',
  'captive.apple.com', 'network-test.debian.org',
  // Time and NAT traversal — both dial the address they are handed.
  'time.*.com', 'time.*.gov', 'time.*.apple.com', 'ntp.*.com',
  '+.stun.*.*', '+.stun.*.*.*',
  // Consoles and appliances that resolve once and cache the literal address.
  '*.n.n.srv.nintendo.net', '+.srv.nintendo.net',
  'xbox.*.microsoft.com', '*.xboxlive.com',
  '+.market.xiaomi.com',
];

// Resolvers that answer from inside China. Used for the domestic half of the
// split and, more importantly, for resolving the proxy servers' own names —
// see `proxy-server-nameserver` below.
const CN_NAMESERVERS = ['223.5.5.5', '119.29.29.29'];

// Foreign resolvers, reached *through the tunnel*. The `#PROXY` suffix is
// mihomo's way of naming the group a DNS query should ride; without it these
// queries go out in the clear to 8.8.8.8/1.1.1.1, which from inside China means
// a UDP packet to a blocked address answered by whatever the firewall feels
// like — the exact poisoning the fallback exists to route around.
const PROXIED_NAMESERVERS = [
  'https://dns.google/dns-query#PROXY',
  'https://cloudflare-dns.com/dns-query#PROXY',
];

// Hostnames a client has to resolve *before* the tunnel exists. A profile that
// names its server by IP contributes nothing here, which is the common case.
function serverDomains(list) {
  const out = [];
  for (const p of list) {
    const host = String(p.server || '').replace(/^\[|\]$/g, '');
    // Anything with a colon is an IPv6 literal; the dotted-quad test covers v4.
    if (!host || host.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(host)) continue;
    if (!out.includes(host)) out.push(host);
  }
  return out;
}

// Custom rules in Clash's spelling. IP rules carry no-resolve: a rule that
// names an address range has no business triggering a DNS lookup for a
// connection that arrived as a domain.
function clashCustomRules(rules) {
  const target = { block: 'REJECT', proxy: 'PROXY', direct: 'DIRECT' };
  const out = [];
  for (const list of RULE_ORDER) {
    const { domains, ip, ip6 } = splitRuleKinds(rules && rules[list]);
    domains.forEach((d) => out.push(`DOMAIN-SUFFIX,${d},${target[list]}`));
    ip.forEach((c) => out.push(`IP-CIDR,${c},${target[list]},no-resolve`));
    ip6.forEach((c) => out.push(`IP-CIDR6,${c},${target[list]},no-resolve`));
  }
  return out;
}

function buildClashConfig(profiles, { rules = null } = {}) {
  const list = enabledProfiles(profiles);
  const displayNames = uniqueNames(list);
  const proxies = list.map((p, i) => buildClashProxy(p, displayNames[i]));
  const names = proxies.map((p) => p.name);
  const hosts = serverDomains(list);

  // With more than one server, offer two automatic groups so a blocked or dead
  // VPS fails over without the user touching anything:
  //
  //   Auto      url-test — whichever server is *fastest* right now.
  //   Fallback  fallback — the first server in *your* order that is alive.
  //
  // Both exist because they answer different questions, and only the second one
  // makes the profile order mean anything. url-test ignores order entirely, so
  // for a while the dashboard's reordering buttons — and the README — promised
  // "the order a client walks when the one above does not answer" while nothing
  // generated here did that. Order matters when the servers are not
  // interchangeable: cheapest first, or the one whose bandwidth you have
  // already paid for, even when a pricier box happens to ping 20ms quicker.
  const groups = [];
  const multi = names.length > 1;
  const auto = multi ? ['Auto', 'Fallback'] : [];
  groups.push({ name: 'PROXY', type: 'select', proxies: [...auto, ...names, 'DIRECT'] });
  if (multi) {
    groups.push({
      name: 'Auto', type: 'url-test', proxies: names,
      url: HEALTH_CHECK_URL, interval: 300, tolerance: 50,
    });
    groups.push({
      name: 'Fallback', type: 'fallback', proxies: names,
      url: HEALTH_CHECK_URL, interval: 300,
    });
  }

  return {
    'mixed-port': 7890,
    'allow-lan': false,
    mode: 'rule',
    'log-level': 'info',
    // Without this the selector resets to the first proxy on every restart,
    // undoing whichever server you picked (or Auto settled on) last time.
    profile: { 'store-selected': true, 'store-fake-ip': true },
    'unified-delay': true,
    'tcp-concurrent': true,
    // The GEOIP/GEOSITE rules below are useless until the database exists, and
    // mihomo's default download URLs are on GitHub — unreachable from exactly
    // the network this config is written for. Point them at a CDN that isn't.
    // (Clash Verge Rev / ClashX Meta ship the files, so this only matters to
    // bare mihomo, but a first run that can't resolve anything is the worst
    // possible failure mode.)
    'geodata-mode': true,
    'geo-auto-update': true,
    'geo-update-interval': 24,
    'geox-url': {
      geoip: `${GEO_MIRROR}/gh/MetaCubeX/meta-rules-dat@release/geoip.dat`,
      geosite: `${GEO_MIRROR}/gh/MetaCubeX/meta-rules-dat@release/geosite.dat`,
      mmdb: `${GEO_MIRROR}/gh/MetaCubeX/meta-rules-dat@release/country.mmdb`,
    },
    // Sniffing recovers the domain from a connection that arrived as a bare IP
    // — anything that resolved before mihomo started, or a program that ships
    // its own resolver. Without it those connections can only be matched on
    // GEOIP, so a foreign host that happens to sit on a CN-registered address
    // goes DIRECT and stays blocked.
    sniffer: {
      enable: true,
      'force-dns-mapping': true,
      'parse-pure-ip': true,
      sniff: {
        HTTP: { ports: [80, '8080-8880'], 'override-destination': true },
        TLS: { ports: [443, 8443] },
        QUIC: { ports: [443, 8443] },
      },
      // Apple's push connection pins its own name and breaks when the
      // destination is rewritten under it.
      'skip-domain': ['+.push.apple.com'],
    },
    dns: {
      enable: true,
      ipv6: false,
      'enhanced-mode': 'fake-ip',
      'fake-ip-range': '198.18.0.1/16',
      // Your own servers are appended: a fake IP for the box the tunnel dials
      // is a tunnel that never comes up.
      'fake-ip-filter': [...FAKE_IP_FILTER, ...hosts],
      // Bootstrap + primary resolvers must be reachable from *inside* China:
      // 8.8.8.8 and 1.1.1.1 are blocked there, and rule matching can't classify
      // a domain until it resolves, so using them first stalls every lookup.
      'default-nameserver': [...CN_NAMESERVERS],
      nameserver: [...CN_NAMESERVERS],
      // The proxy server's own hostname has to be resolved *before* there is a
      // proxy to resolve it through. Left unset, mihomo runs that lookup down
      // the same fallback path as everything else — which now points through
      // the tunnel, i.e. through the server whose address is being looked up.
      'proxy-server-nameserver': [...CN_NAMESERVERS],
      // Foreign resolvers are consulted only for names the CN resolvers answer
      // with a non-CN address, which is where poisoning would otherwise bite —
      // and they are queried over DoH *through the tunnel*, so the answer is
      // one the firewall never saw.
      fallback: [...PROXIED_NAMESERVERS],
      'fallback-filter': {
        geoip: true,
        'geoip-code': 'CN',
        // Addresses the GFW hands back for a poisoned name. They are not
        // routable, so an answer containing one is a forgery by definition.
        ipcidr: ['240.0.0.0/4', '0.0.0.0/32', '127.0.0.1/32'],
      },
    },
    proxies,
    'proxy-groups': groups,
    rules: [
      // LAN and loopback must never be tunnelled — without this, router admin
      // pages and local dev servers get shipped to the VPS.
      'GEOIP,PRIVATE,DIRECT,no-resolve',
      // Your own lists come next, ahead of every geographic rule, so an entry
      // there is the last word on that site. See checkRules.
      ...clashCustomRules(rules),
      'DOMAIN-SUFFIX,cn,DIRECT',
      'DOMAIN-SUFFIX,local,DIRECT',
      // Domestic sites by name, before the GEOIP rule that needs an address.
      // Matching on the domain means no DNS lookup to classify it, and it
      // catches the Chinese services hosted on CDNs whose addresses are not
      // registered in China — which GEOIP alone sends through the tunnel. The
      // sing-box bundle has always done this with geosite-cn; this one had the
      // database configured and no rule that used it.
      'GEOSITE,CN,DIRECT',
      'GEOIP,CN,DIRECT',
      // Foreign QUIC, refused so the browser falls back to TCP. It sits after
      // the DIRECT rules, so nothing domestic is touched.
      //
      // QUIC is UDP, and half the protocols here cannot relay UDP at all —
      // Shadowsocks + v2ray-plugin carries TCP only. Chrome opens QUIC to
      // google/youtube by default, gets silence rather than a refusal, and
      // spends seconds per connection timing out before it retries over TCP.
      // The symptom is "the proxy works but YouTube is unusable", which is
      // near-impossible to attribute. A REJECT makes the fallback instant.
      'AND,((NETWORK,udp),(DST-PORT,443)),REJECT',
      'MATCH,PROXY',
    ],
  };
}

function buildClashYaml(profiles, opts) {
  return toYaml(buildClashConfig(profiles, opts));
}

// ── Sing-Box ───────────────────────────────────────────────────────────────── //
// Targets sing-box 1.12+ (rule-sets, route `action`s, `mixed` inbound, and the
// typed DNS server shape). The older schemas — the `dns` outbound type, inline
// `geoip` route rules, split socks/http inbounds, and the `address: "https://…"`
// DNS server string — are deprecated upstream and removed in newer releases.
function buildSingBoxOutbound(p, name) {
  const displayName = name || p.remarks || 'Airport';
  if (p.protocol === 'vless-reality') {
    const network = p.network || 'tcp';
    const out = {
      type: 'vless',
      tag: displayName,
      server: p.server,
      server_port: Number(p.port),
      uuid: p.uuid,
      tls: {
        enabled: true,
        server_name: p.sni,
        utls: { enabled: true, fingerprint: p.fingerprint || 'chrome' },
        reality: { enabled: true, public_key: p.publicKey, short_id: p.shortId },
      },
    };
    if (network === 'tcp' && p.flow) out.flow = p.flow;
    // XUDP is how Xray tunnels UDP inside VLESS, and it is what the server
    // setup.sh installs speaks. Recent sing-box already defaults to it for
    // VLESS, but the default is a per-version thing and has not always been
    // this one — and the failure when it is wrong is not an error, it is UDP
    // quietly going nowhere. Naming it costs a line and settles it.
    out.packet_encoding = 'xudp';
    if (network === 'grpc') out.transport = { type: 'grpc', service_name: p.serviceName || '' };
    // sing-box has no xhttp transport; http is the closest it speaks, and the
    // path lines up with what Xray serves.
    if (network === 'xhttp') out.transport = { type: 'http', path: p.path || '/' };
    return out;
  }
  if (p.protocol === 'tuic') {
    return {
      type: 'tuic',
      tag: displayName,
      server: p.server,
      server_port: Number(p.port),
      uuid: p.uuid,
      password: p.password,
      congestion_control: p.congestion || 'bbr',
      udp_relay_mode: p.udpRelayMode || 'native',
      zero_rtt_handshake: true,
      tls: {
        enabled: true,
        server_name: p.sni || p.server,
        insecure: !!p.insecure,
        alpn: (p.alpn || 'h3').split(',').map((a) => a.trim()).filter(Boolean),
      },
    };
  }
  if (p.protocol === 'hysteria2') {
    const out = {
      type: 'hysteria2',
      tag: displayName,
      server: p.server,
      server_port: Number(p.port),
      password: p.password,
      tls: {
        enabled: true,
        server_name: p.sni || p.server,
        insecure: !!p.insecure,
      },
    };
    // sing-box treats `server_port` and `server_ports` as alternatives and
    // rejects a config carrying both, so the single port gives way to the range.
    const hopPorts = portRangeToSingBox(p.ports);
    if (hopPorts.length) {
      delete out.server_port;
      out.server_ports = hopPorts;
      out.hop_interval = `${normalizeHopInterval(p.hopInterval)}s`;
    }
    if (p.obfs) out.obfs = { type: p.obfs, password: p.obfsPassword };
    if (p.up) out.up_mbps = p.up;
    if (p.down) out.down_mbps = p.down;
    return out;
  }
  if (p.protocol === 'trojan') {
    const out = {
      type: 'trojan',
      tag: displayName,
      server: p.server,
      server_port: Number(p.port),
      password: p.password,
      tls: {
        enabled: true,
        server_name: p.sni || p.server,
        insecure: !!p.insecure,
        utls: { enabled: true, fingerprint: p.fingerprint || 'chrome' },
      },
    };
    const alpn = alpnList(p.alpn);
    if (alpn.length) out.tls.alpn = alpn;
    const transport = singBoxTransport(p);
    if (transport) out.transport = transport;
    return out;
  }
  if (p.protocol === 'vmess') {
    const out = {
      type: 'vmess',
      tag: displayName,
      server: p.server,
      server_port: Number(p.port),
      uuid: p.uuid,
      security: p.cipher || 'auto',
      alter_id: Number(p.alterId || 0),
    };
    // Same rule as the Clash builder: no TLS block at all when TLS is off, or
    // sing-box negotiates a handshake the server is not expecting.
    if (p.tls) {
      out.tls = {
        enabled: true,
        server_name: p.sni || p.server,
        insecure: !!p.insecure,
        utls: { enabled: true, fingerprint: p.fingerprint || 'chrome' },
      };
      const alpn = alpnList(p.alpn);
      if (alpn.length) out.tls.alpn = alpn;
    }
    const transport = singBoxTransport(p);
    if (transport) out.transport = transport;
    return out;
  }
  const out = {
    type: 'shadowsocks',
    tag: displayName,
    server: p.server,
    server_port: Number(p.port),
    method: p.method,
    password: p.password,
  };
  // Same rule as the Clash builder: the plugin keys only exist when there is a
  // plugin. sing-box launches whatever `plugin` names, empty opts and all.
  if (p.plugin) {
    out.plugin = p.plugin;
    out.plugin_opts = clientPluginOpts(p.plugin_opts);
  }
  return out;
}

// Same reasoning as the Clash geox-url override above: raw.githubusercontent.com
// is unreachable from inside the GFW, so the rule sets come from the mirror —
// and they are fetched *directly*, the way mihomo fetches its geo files from the
// same mirror. They used to go through `proxy`, which defeated the mirror: on a
// cold start, or with the selected server blocked, the download could not
// happen, and sing-box will not start with a remote rule set it has never
// fetched. The mirror exists precisely so this does not need the tunnel.
//
// `download_detour` is deprecated in sing-box 1.14 in favour of `http_clients`,
// but that replacement does not exist before 1.14 and the old field works
// through 1.15, so it stays until the oldest supported release has the new one.
const SING_RULE_SETS = [
  {
    type: 'remote', tag: 'geosite-cn', format: 'binary',
    url: `${GEO_MIRROR}/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs`,
    download_detour: 'direct',
  },
  {
    type: 'remote', tag: 'geoip-cn', format: 'binary',
    url: `${GEO_MIRROR}/gh/SagerNet/sing-geoip@rule-set/geoip-cn.srs`,
    download_detour: 'direct',
  },
];

// Custom rules in sing-box's spelling. Within one rule, domain_suffix and
// ip_cidr are OR'd, so each list becomes a single rule. `block` is the reject
// action; the other two name an outbound.
function singBoxCustomRules(rules) {
  const out = [];
  for (const list of RULE_ORDER) {
    const { domains, ip, ip6 } = splitRuleKinds(rules && rules[list]);
    const cidrs = [...ip, ...ip6];
    if (!domains.length && !cidrs.length) continue;
    const rule = {};
    if (domains.length) rule.domain_suffix = domains;
    if (cidrs.length) rule.ip_cidr = cidrs;
    if (list === 'block') rule.action = 'reject';
    else rule.outbound = list === 'proxy' ? 'proxy' : 'direct';
    out.push(rule);
  }
  return out;
}

// Which resolver answers for a custom-listed name: a site you route direct is
// resolved domestically, one you force through the tunnel is resolved at the
// far end. Only domains — sing-box 1.14 deprecates address matching in DNS
// rules, and an IP range has nothing to resolve anyway.
function singBoxCustomDnsRules(rules) {
  const out = [];
  const direct = splitRuleKinds(rules && rules.direct).domains;
  const proxied = splitRuleKinds(rules && rules.proxy).domains;
  if (proxied.length) out.push({ domain_suffix: proxied, server: 'dns-remote' });
  if (direct.length) out.push({ domain_suffix: direct, server: 'dns-local' });
  return out;
}

// `tun: false` drops the VPN interface and leaves only the local mixed proxy.
// The tun inbound needs root/Administrator, so `sing-box run` on a desktop just
// dies without it — while the mobile apps supply the interface themselves and
// need it present. One flag, two audiences.
function buildSingBox(profiles, { tun = true, rules = null } = {}) {
  const list = enabledProfiles(profiles);
  const displayNames = uniqueNames(list);
  const outbounds = list.map((p, i) => buildSingBoxOutbound(p, displayNames[i]));
  const tags = outbounds.map((o) => o.tag);
  const hosts = serverDomains(list);

  const groups = [];
  const auto = tags.length > 1 ? ['auto'] : [];
  if (auto.length) {
    groups.push({
      type: 'urltest', tag: 'auto', outbounds: [...tags],
      url: HEALTH_CHECK_URL, interval: '5m', tolerance: 50,
    });
  }

  return {
    log: { level: 'info' },
    dns: {
      // sing-box 1.12 replaced the `address` URL string with an explicit
      // `type` + `server` pair. The old spelling still parses in 1.12 with a
      // deprecation warning and stops parsing after it, so the typed form is
      // the one that keeps working.
      servers: [
        { type: 'https', tag: 'dns-remote', server: '1.1.1.1', detour: 'proxy' },
        // No `detour` here. Without one a DNS server dials directly already,
        // and naming the empty `direct` outbound explicitly is something
        // sing-box refuses at start-up ("detour to an empty direct outbound
        // makes no sense") — which is what this used to do, so the bundle
        // never started at all.
        { type: 'udp', tag: 'dns-local', server: '223.5.5.5' },
      ],
      rules: [
        // The proxy servers' own hostnames, pinned to the domestic resolver.
        // `final` is dns-remote, which is detoured through `proxy` — so without
        // this rule, an app inside the tunnel resolving a server's name would
        // ask through that same server. (sing-box itself resolves the servers
        // through route.default_domain_resolver below, which skips DNS rules.)
        ...(hosts.length ? [{ domain: hosts, server: 'dns-local' }] : []),
        ...singBoxCustomDnsRules(rules),
        { rule_set: 'geosite-cn', server: 'dns-local' },
      ],
      final: 'dns-remote',
      strategy: 'prefer_ipv4',
      // Without this, one poisoned or stale answer is reused for every rule
      // that consults it, and the cache_file below carries it across restarts.
      independent_cache: true,
    },
    inbounds: [
      // Without a tun inbound the mobile Sing-Box apps start, report themselves
      // connected, and route nothing — the VPN interface is what actually
      // captures system traffic. The mixed inbound stays for desktop use and
      // for anything you want to point at a proxy by hand.
      ...(tun ? [{
        type: 'tun',
        tag: 'tun-in',
        address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
        auto_route: true,
        strict_route: true,
        stack: 'mixed',
        mtu: 9000,
      }] : []),
      { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 },
    ],
    // sing-box has no equivalent of Clash's `fallback` group type — `urltest`
    // is the only automatic selector it ships, and it picks by latency. So the
    // profile order shows up here as the order the selector lists its
    // outbounds (which is what you scroll through when choosing by hand) and
    // nothing more. The Clash bundle is the one that can honour it.
    outbounds: [
      {
        type: 'selector', tag: 'proxy',
        outbounds: [...auto, ...tags, 'direct'],
        default: auto.length ? 'auto' : tags[0],
      },
      ...groups,
      ...outbounds,
      { type: 'direct', tag: 'direct' },
    ],
    route: {
      rules: [
        { action: 'sniff' },
        // Only the tun inbound sees raw DNS traffic worth hijacking; without it
        // the rule matches nothing and just adds noise to the config.
        ...(tun ? [{ protocol: 'dns', action: 'hijack-dns' }] : []),
        { ip_is_private: true, outbound: 'direct' },
        // Your own lists, ahead of the geographic rule — the same place the
        // Clash bundle puts them. See checkRules.
        ...singBoxCustomRules(rules),
        { rule_set: ['geosite-cn', 'geoip-cn'], outbound: 'direct' },
        // The same foreign-QUIC refusal the Clash bundle carries, and for the
        // same reason: it sits after the direct rules so nothing domestic is
        // touched, and it turns a browser's multi-second QUIC timeout into an
        // immediate fall back to TCP. See the note on the Clash rule list.
        { action: 'reject', network: ['udp'], port: [443] },
      ],
      rule_set: SING_RULE_SETS,
      final: 'proxy',
      // How sing-box resolves the hostnames of the servers themselves (and of
      // anything the direct outbound dials). sing-box 1.12 deprecated leaving
      // this out and 1.14 refuses to start without it whenever a server is
      // named by hostname — so a bundle holding one domain-named server did not
      // run at all on a current release. The domestic resolver is the only
      // answer that works before the tunnel exists.
      default_domain_resolver: 'dns-local',
      auto_detect_interface: true,
    },
    experimental: { cache_file: { enabled: true } },
  };
}

// ── Minimal YAML emitter (avoids a yaml dependency) ────────────────────────── //
function yamlStr(value) {
  const escaped = String(value)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
  return `"${escaped}"`;
}

function yamlScalar(v) {
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  return yamlStr(v);
}

function toYaml(obj, indent = 0) {
  const pad = ' '.repeat(indent);
  let out = '';
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) {
      if (v.length === 0) { out += `${pad}${k}: []\n`; continue; }
      out += `${pad}${k}:\n`;
      for (const item of v) {
        if (item !== null && typeof item === 'object') {
          // Render "- firstKey: val" then align the rest under it.
          const lines = toYaml(item, 0).split('\n').filter((l) => l.length);
          out += `${pad}  - ${lines[0]}\n`;
          for (const line of lines.slice(1)) out += `${pad}    ${line}\n`;
        } else {
          out += `${pad}  - ${yamlScalar(item)}\n`;
        }
      }
    } else if (typeof v === 'object') {
      out += `${pad}${k}:\n${toYaml(v, indent + 2)}`;
    } else {
      out += `${pad}${k}: ${yamlScalar(v)}\n`;
    }
  }
  return out;
}

module.exports = {
  PROTOCOLS,
  VLESS_NETWORKS,
  STREAM_NETWORKS,
  VMESS_CIPHERS,
  SS_METHODS,
  SS_AEAD_METHODS,
  SS_2022_METHODS,
  SS_STREAM_METHODS,
  CERT_WARN_DAYS,
  DEFAULT_HOP_INTERVAL,
  DEFAULT_TITLE,
  MONITOR_DEFAULTS,
  ALERT_DEFAULTS,
  ALERT_MODES,
  alertUrlProblem,
  normalizeAfterFailures,
  isUuid,
  newToken,
  normalizeTitle,
  ss2022KeyError,
  optsList,
  hasOpt,
  getOpt,
  alpnList,
  normalizeMonitor,
  normalizeAlert,
  normalizeClients,
  profilesForClient,
  RULE_LISTS,
  RULE_ORDER,
  RULE_LIMIT,
  RESERVED_NAMES,
  parseRuleEntry,
  checkRules,
  normalizeRules,
  splitRuleKinds,
  hasRules,
  normalizeMbps,
  normalizeSsPlugin,
  normalizePortRange,
  normalizeHopInterval,
  portRangeToSingBox,
  normalizeStore,
  normalizeProfile,
  missingFields,
  validateProfile,
  uniqueNames,
  isEnabled,
  enabledProfiles,
  optsToObject,
  clientPluginOpts,
  serverDomains,
  buildSsUri,
  buildVlessUri,
  buildHy2Uri,
  buildTuicUri,
  buildTrojanUri,
  buildVmessUri,
  buildUri,
  buildSubscription,
  parseUri,
  parseSubscription,
  buildClashProxy,
  buildClashConfig,
  buildClashYaml,
  buildSingBoxOutbound,
  buildSingBox,
  toYaml,
};
