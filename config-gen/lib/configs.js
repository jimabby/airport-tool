// Shared config model + builders for the Airport tool.
// Used by both the CLI generator (config-gen/gen.js) and the web UI
// (web-ui/server.js) so the two never drift.
//
// Supported protocols:
//   - "shadowsocks"    Shadowsocks-libev + v2ray-plugin (WebSocket, optional TLS)
//   - "vless-reality"  Xray VLESS + Reality (TLS camouflage, best DPI resistance)

'use strict';

const crypto = require('crypto');

// ── Profile store ──────────────────────────────────────────────────────────── //
// The on-disk config can be any of:
//   { active, profiles: [ … ] }   ← canonical multi-profile store
//   [ {profile}, … ]              ← bare array
//   { server, port, … }           ← legacy single Shadowsocks profile
// normalizeStore() collapses all of them to the canonical shape.
function normalizeStore(raw) {
  let profiles;
  let active = 0;
  if (Array.isArray(raw)) {
    profiles = raw;
  } else if (raw && Array.isArray(raw.profiles)) {
    profiles = raw.profiles;
    active = Number(raw.active) || 0;
  } else if (raw && (raw.server || raw.uuid)) {
    profiles = [raw]; // legacy single object
  } else {
    profiles = [];
  }
  profiles = profiles.map(normalizeProfile);
  if (!Number.isInteger(active) || active < 0 || active >= profiles.length) active = 0;
  return { active, profiles };
}

function normalizeProfile(p = {}) {
  const protocol = p.protocol || (p.uuid ? 'vless-reality' : 'shadowsocks');
  const base = {
    id: p.id || crypto.randomUUID(),
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
  const required = p.protocol === 'vless-reality'
    ? ['server', 'port', 'uuid', 'publicKey', 'sni']
    : ['server', 'port', 'password', 'method'];
  return required.filter((k) => !p[k]);
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

function buildSsUri(p) {
  const userinfo = Buffer.from(`${p.method}:${p.password}`).toString('base64');
  const opts = clientPluginOpts(p.plugin_opts);
  const pluginField = opts ? `${p.plugin || 'v2ray-plugin'};${opts}` : (p.plugin || 'v2ray-plugin');
  const tag = encodeURIComponent(p.remarks || 'Airport');
  return `ss://${userinfo}@${p.server}:${p.port}?plugin=${encodeURIComponent(pluginField)}#${tag}`;
}

// ── VLESS + Reality helpers ────────────────────────────────────────────────── //
function buildVlessUri(p) {
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
  const tag = encodeURIComponent(p.remarks || 'Airport');
  return `vless://${p.uuid}@${p.server}:${p.port}?${params.toString()}#${tag}`;
}

// ── URI dispatch (one profile → its import URI) ────────────────────────────── //
function buildUri(p) {
  return p.protocol === 'vless-reality' ? buildVlessUri(p) : buildSsUri(p);
}

// A subscription is the base64 of all profile URIs joined by newlines — the
// de-facto format every modern client understands for auto-updating configs.
function buildSubscription(profiles) {
  const body = profiles.map(buildUri).join('\n');
  return Buffer.from(body, 'utf8').toString('base64');
}

// ── Clash / Mihomo (Clash.Meta) ────────────────────────────────────────────── //
function buildClashProxy(p) {
  if (p.protocol === 'vless-reality') {
    return {
      name: p.remarks || 'Airport',
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
  const tls = (p.plugin_opts || '').includes('tls');
  const hostM = (p.plugin_opts || '').match(/host=([^;]+)/);
  const pathM = (p.plugin_opts || '').match(/path=([^;]+)/);
  return {
    name: p.remarks || 'Airport',
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

function buildClashConfig(profiles) {
  const proxies = profiles.map(buildClashProxy);
  const names = proxies.map((p) => p.name);
  return {
    'mixed-port': 7890,
    'allow-lan': false,
    mode: 'rule',
    'log-level': 'info',
    dns: { enable: true, nameserver: ['8.8.8.8', '1.1.1.1'] },
    proxies,
    'proxy-groups': [
      { name: 'PROXY', type: 'select', proxies: [...names, 'DIRECT'] },
    ],
    rules: ['GEOIP,CN,DIRECT', 'MATCH,PROXY'],
  };
}

function buildClashYaml(profiles) {
  return toYaml(buildClashConfig(profiles));
}

// ── Sing-Box ───────────────────────────────────────────────────────────────── //
function buildSingBoxOutbound(p) {
  if (p.protocol === 'vless-reality') {
    return {
      type: 'vless',
      tag: p.remarks || 'Airport',
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
  return {
    type: 'shadowsocks',
    tag: p.remarks || 'Airport',
    server: p.server,
    server_port: Number(p.port),
    method: p.method,
    password: p.password,
    plugin: p.plugin || 'v2ray-plugin',
    plugin_opts: clientPluginOpts(p.plugin_opts),
  };
}

function buildSingBox(profiles) {
  const outbounds = profiles.map(buildSingBoxOutbound);
  const tags = outbounds.map((o) => o.tag);
  return {
    log: { level: 'info' },
    inbounds: [
      { type: 'socks', listen: '127.0.0.1', listen_port: 2080, tag: 'socks-in' },
      { type: 'http', listen: '127.0.0.1', listen_port: 2081, tag: 'http-in' },
    ],
    outbounds: [
      { type: 'selector', tag: 'proxy', outbounds: [...tags, 'direct'], default: tags[0] },
      ...outbounds,
      { type: 'direct', tag: 'direct' },
      { type: 'dns', tag: 'dns-out' },
    ],
    route: {
      rules: [
        { protocol: 'dns', outbound: 'dns-out' },
        { geoip: ['cn', 'private'], outbound: 'direct' },
      ],
      final: 'proxy',
    },
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
    if (v === undefined) continue;
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
    } else if (v !== null && typeof v === 'object') {
      out += `${pad}${k}:\n${toYaml(v, indent + 2)}`;
    } else {
      out += `${pad}${k}: ${yamlScalar(v)}\n`;
    }
  }
  return out;
}

module.exports = {
  normalizeStore,
  normalizeProfile,
  missingFields,
  clientPluginOpts,
  buildSsUri,
  buildVlessUri,
  buildUri,
  buildSubscription,
  buildClashProxy,
  buildClashConfig,
  buildClashYaml,
  buildSingBoxOutbound,
  buildSingBox,
  toYaml,
};
