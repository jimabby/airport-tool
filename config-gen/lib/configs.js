// Shared config model + builders for the Airport tool.
// Used by both the CLI generator (config-gen/gen.js) and the web UI
// (web-ui/server.js) so the two never drift.
//
// Supported protocols:
//   - "shadowsocks"    Shadowsocks-libev + v2ray-plugin (WebSocket, optional TLS)
//   - "vless-reality"  Xray VLESS + Reality (TLS camouflage, best DPI resistance)
//   - "hysteria2"      Hysteria2 over QUIC/UDP (best on lossy links; carries UDP)

'use strict';

const crypto = require('crypto');

const PROTOCOLS = ['shadowsocks', 'vless-reality', 'hysteria2'];

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
  if (Array.isArray(raw)) {
    profiles = raw;
  } else if (raw && Array.isArray(raw.profiles)) {
    profiles = raw.profiles;
    active = Number(raw.active) || 0;
    token = raw.token;
  } else if (raw && (raw.server || raw.uuid)) {
    profiles = [raw]; // legacy single object
  } else {
    profiles = [];
  }
  profiles = profiles.map(normalizeProfile);
  if (!Number.isInteger(active) || active < 0 || active >= profiles.length) active = 0;
  return {
    active,
    profiles,
    token: typeof token === 'string' && token.length >= 16 ? token : null,
  };
}

function normalizeProfile(p = {}) {
  let protocol = p.protocol || (p.uuid ? 'vless-reality' : 'shadowsocks');
  if (protocol === 'hy2') protocol = 'hysteria2';
  if (!PROTOCOLS.includes(protocol)) protocol = 'shadowsocks';
  const base = {
    // A non-UUID id (hand-edited file, or a client-supplied one on POST) is
    // discarded rather than trusted — see UUID_RE above.
    id: isUuid(p.id) ? p.id : crypto.randomUUID(),
    protocol,
    server: p.server,
    port: Number(p.port),
    remarks: p.remarks || 'Airport',
  };
  if (protocol === 'vless-reality') {
    return {
      ...base,
      uuid: p.uuid,
      publicKey: p.publicKey || '',
      shortId: p.shortId || '',
      sni: p.sni || '',
      flow: p.flow || 'xtls-rprx-vision',
      fingerprint: p.fingerprint || 'chrome',
    };
  }
  if (protocol === 'hysteria2') {
    return {
      ...base,
      password: p.password,
      sni: p.sni || '',
      // Self-signed certs are the norm for a domain-less Hysteria2 server, so
      // the client has to be told to skip verification.
      insecure: p.insecure === true || p.insecure === 'true' || p.insecure === 1,
      obfs: p.obfs || '',
      obfsPassword: p.obfsPassword || '',
    };
  }
  return {
    ...base,
    password: p.password,
    method: p.method || 'chacha20-ietf-poly1305',
    plugin: p.plugin || 'v2ray-plugin',
    plugin_opts: p.plugin_opts || 'server',
  };
}

// Fields that must be present for a profile to be usable, keyed by protocol.
function missingFields(p) {
  let required;
  if (p.protocol === 'vless-reality') required = ['server', 'port', 'uuid', 'publicKey', 'sni'];
  else if (p.protocol === 'hysteria2') required = ['server', 'port', 'password'];
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
    if (!p.shortId) warnings.push('no shortId — some clients require one');
    if (p.sni && /^\d+\.\d+\.\d+\.\d+$/.test(p.sni)) {
      errors.push('sni must be a real domain, not an IP — Reality borrows that site\'s handshake');
    }
  } else if (p.protocol === 'hysteria2') {
    if (!p.sni && !p.insecure) {
      warnings.push('no sni and cert verification is on — set an sni or enable insecure for a self-signed cert');
    }
    if (p.obfs && !p.obfsPassword) warnings.push('obfs is set but obfsPassword is empty — obfuscation will not be applied');
  } else {
    const opts = p.plugin_opts || '';
    if (opts.includes('tls') && !/host=/.test(opts)) {
      warnings.push('TLS mode but no host= — clients will use the server IP as SNI, which usually fails');
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
function uniqueNames(profiles) {
  const seen = new Map();
  return profiles.map((p) => {
    const base = p.remarks || 'Airport';
    const n = (seen.get(base) || 0) + 1;
    seen.set(base, n);
    return n === 1 ? base : `${base} ${n}`;
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
  const opts = clientPluginOpts(p.plugin_opts);
  const pluginField = opts ? `${p.plugin || 'v2ray-plugin'};${opts}` : (p.plugin || 'v2ray-plugin');
  const tag = encodeURIComponent(name || p.remarks || 'Airport');
  return `ss://${userinfo}@${hostForUri(p.server)}:${p.port}?plugin=${encodeURIComponent(pluginField)}#${tag}`;
}

// ── VLESS + Reality helpers ────────────────────────────────────────────────── //
function buildVlessUri(p, name) {
  const params = new URLSearchParams({
    encryption: 'none',
    flow: p.flow || 'xtls-rprx-vision',
    security: 'reality',
    sni: p.sni || '',
    fp: p.fingerprint || 'chrome',
    pbk: p.publicKey || '',
    sid: p.shortId || '',
    type: 'tcp',
  });
  const tag = encodeURIComponent(name || p.remarks || 'Airport');
  return `vless://${p.uuid}@${hostForUri(p.server)}:${p.port}?${params.toString()}#${tag}`;
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
  return buildSsUri(p, name);
}

// A subscription is the base64 of all profile URIs joined by newlines — the
// de-facto format every modern client understands for auto-updating configs.
function buildSubscription(profiles) {
  const names = uniqueNames(profiles);
  const body = profiles.map((p, i) => buildUri(p, names[i])).join('\n');
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
  const scheme = s.slice(0, Math.max(s.indexOf(':'), 0)) || s.slice(0, 12);
  throw new Error(`Unsupported URI scheme "${scheme}" — expected ss://, vless:// or hysteria2://`);
}

// Parse a subscription blob (base64 or plain text) or a multi-line paste into
// profiles. Lines that don't parse are reported rather than silently dropped.
function parseSubscription(text) {
  let body = String(text || '').trim();
  if (!body) return { profiles: [], errors: [] };
  // A subscription is base64; a raw paste is not. Detect by trying to decode
  // and checking that the result looks like URIs.
  if (/^[A-Za-z0-9+/=\s-]+$/.test(body) && !/:\/\//.test(body)) {
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
    // SIP002: ss://base64url(method:password)@host:port
    const at = body.lastIndexOf('@');
    const userinfo = body.slice(0, at);
    hostport = body.slice(at + 1);
    const decoded = b64decode(userinfo);
    cred = decoded.includes(':') ? decoded : safeDecode(userinfo);
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
    plugin: plugin || 'v2ray-plugin',
    plugin_opts: pluginOpts,
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
  return normalizeProfile({
    protocol: 'vless-reality',
    server: u.hostname.replace(/^\[|\]$/g, ''),
    port: Number(u.port),
    uuid: safeDecode(u.username),
    publicKey: q.get('pbk') || '',
    shortId: q.get('sid') || '',
    sni: q.get('sni') || q.get('peer') || '',
    flow: q.get('flow') || 'xtls-rprx-vision',
    fingerprint: q.get('fp') || 'chrome',
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
    remarks: tag || 'Imported',
  });
}

// ── Clash / Mihomo (Clash.Meta) ────────────────────────────────────────────── //
function buildClashProxy(p, name) {
  const displayName = name || p.remarks || 'Airport';
  if (p.protocol === 'vless-reality') {
    return {
      name: displayName,
      type: 'vless',
      server: p.server,
      port: Number(p.port),
      uuid: p.uuid,
      network: 'tcp',
      udp: true,
      tls: true,
      flow: p.flow || 'xtls-rprx-vision',
      servername: p.sni,
      'client-fingerprint': p.fingerprint || 'chrome',
      'reality-opts': { 'public-key': p.publicKey, 'short-id': p.shortId },
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
    if (p.obfs) {
      proxy.obfs = p.obfs;
      proxy['obfs-password'] = p.obfsPassword;
    }
    return proxy;
  }
  const tls = (p.plugin_opts || '').includes('tls');
  const hostM = (p.plugin_opts || '').match(/host=([^;]+)/);
  const pathM = (p.plugin_opts || '').match(/path=([^;]+)/);
  return {
    name: displayName,
    type: 'ss',
    server: p.server,
    port: Number(p.port),
    cipher: p.method,
    password: p.password,
    plugin: 'v2ray-plugin',
    'plugin-opts': {
      mode: 'websocket',
      tls,
      host: hostM ? hostM[1] : p.server,
      // v2ray-plugin's default WebSocket path is "/", so match it when none is
      // given — otherwise the client mismatches a server without an explicit
      // path= and the WebSocket upgrade is rejected.
      path: pathM ? pathM[1] : '/',
    },
  };
}

const HEALTH_CHECK_URL = 'http://www.gstatic.com/generate_204';

function buildClashConfig(profiles) {
  const displayNames = uniqueNames(profiles);
  const proxies = profiles.map((p, i) => buildClashProxy(p, displayNames[i]));
  const names = proxies.map((p) => p.name);

  // With more than one server, offer an automatic lowest-latency group so a
  // blocked or dead VPS fails over without the user touching anything.
  const groups = [];
  const auto = names.length > 1 ? ['Auto'] : [];
  groups.push({ name: 'PROXY', type: 'select', proxies: [...auto, ...names, 'DIRECT'] });
  if (auto.length) {
    groups.push({
      name: 'Auto', type: 'url-test', proxies: names,
      url: HEALTH_CHECK_URL, interval: 300, tolerance: 50,
    });
  }

  return {
    'mixed-port': 7890,
    'allow-lan': false,
    mode: 'rule',
    'log-level': 'info',
    'unified-delay': true,
    'tcp-concurrent': true,
    dns: {
      enable: true,
      ipv6: false,
      'enhanced-mode': 'fake-ip',
      'fake-ip-range': '198.18.0.1/16',
      'fake-ip-filter': ['*.lan', '*.local', 'localhost.ptlogin2.qq.com'],
      // Bootstrap + primary resolvers must be reachable from *inside* China:
      // 8.8.8.8 and 1.1.1.1 are blocked there, and rule matching can't classify
      // a domain until it resolves, so using them first stalls every lookup.
      'default-nameserver': ['223.5.5.5', '119.29.29.29'],
      nameserver: ['223.5.5.5', '119.29.29.29'],
      // Foreign resolvers are consulted only for names the CN resolvers answer
      // with a non-CN address, which is where poisoning would otherwise bite.
      fallback: ['8.8.8.8', '1.1.1.1'],
      'fallback-filter': { geoip: true, 'geoip-code': 'CN' },
    },
    proxies,
    'proxy-groups': groups,
    rules: [
      // LAN and loopback must never be tunnelled — without this, router admin
      // pages and local dev servers get shipped to the VPS.
      'GEOIP,PRIVATE,DIRECT,no-resolve',
      'DOMAIN-SUFFIX,cn,DIRECT',
      'DOMAIN-SUFFIX,local,DIRECT',
      'GEOIP,CN,DIRECT',
      'MATCH,PROXY',
    ],
  };
}

function buildClashYaml(profiles) {
  return toYaml(buildClashConfig(profiles));
}

// ── Sing-Box ───────────────────────────────────────────────────────────────── //
// Targets sing-box 1.11+ (rule-sets, route `action`s, `mixed` inbound). The
// pre-1.11 schema — the `dns` outbound type, inline `geoip` route rules, split
// socks/http inbounds — is deprecated upstream and removed in newer releases.
function buildSingBoxOutbound(p, name) {
  const displayName = name || p.remarks || 'Airport';
  if (p.protocol === 'vless-reality') {
    return {
      type: 'vless',
      tag: displayName,
      server: p.server,
      server_port: Number(p.port),
      uuid: p.uuid,
      flow: p.flow || 'xtls-rprx-vision',
      tls: {
        enabled: true,
        server_name: p.sni,
        utls: { enabled: true, fingerprint: p.fingerprint || 'chrome' },
        reality: { enabled: true, public_key: p.publicKey, short_id: p.shortId },
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
    if (p.obfs) out.obfs = { type: p.obfs, password: p.obfsPassword };
    return out;
  }
  return {
    type: 'shadowsocks',
    tag: displayName,
    server: p.server,
    server_port: Number(p.port),
    method: p.method,
    password: p.password,
    plugin: p.plugin || 'v2ray-plugin',
    plugin_opts: clientPluginOpts(p.plugin_opts),
  };
}

const SING_RULE_SETS = [
  {
    type: 'remote', tag: 'geosite-cn', format: 'binary',
    url: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs',
    download_detour: 'proxy',
  },
  {
    type: 'remote', tag: 'geoip-cn', format: 'binary',
    url: 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs',
    download_detour: 'proxy',
  },
];

function buildSingBox(profiles) {
  const displayNames = uniqueNames(profiles);
  const outbounds = profiles.map((p, i) => buildSingBoxOutbound(p, displayNames[i]));
  const tags = outbounds.map((o) => o.tag);

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
      servers: [
        { tag: 'dns-remote', address: 'https://1.1.1.1/dns-query', detour: 'proxy' },
        { tag: 'dns-local', address: '223.5.5.5', detour: 'direct' },
      ],
      rules: [{ rule_set: 'geosite-cn', server: 'dns-local' }],
      final: 'dns-remote',
      strategy: 'prefer_ipv4',
    },
    inbounds: [
      { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 },
    ],
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
        { protocol: 'dns', action: 'hijack-dns' },
        { ip_is_private: true, outbound: 'direct' },
        { rule_set: ['geosite-cn', 'geoip-cn'], outbound: 'direct' },
      ],
      rule_set: SING_RULE_SETS,
      final: 'proxy',
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
  isUuid,
  newToken,
  normalizeStore,
  normalizeProfile,
  missingFields,
  validateProfile,
  uniqueNames,
  clientPluginOpts,
  buildSsUri,
  buildVlessUri,
  buildHy2Uri,
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
