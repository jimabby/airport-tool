// Reading the two subscription bodies that are not share links: a Clash /
// mihomo config (YAML with a `proxies:` list) and a sing-box config (JSON with
// an `outbounds:` list).
//
// sources.js asks providers for the base64 link list, and most send it. But a
// provider decides what to send by User-Agent and plenty of panels ignore it,
// and some only ever serve Clash YAML — so a feed that came back as a config
// used to fail as "nothing usable in the response" and keep failing, with the
// servers it was supposed to keep current going stale behind it.
//
// Each proxy or outbound becomes the same normalized profile parseUri() would
// have produced from the equivalent link, so validation, the merge and every
// builder treat it identically. Anything this tool does not model — another
// protocol, a transport it has no field for, a plugin no client here can run —
// is reported by name instead of being approximated: a server imported as
// "nearly what the provider said" is a server that silently cannot connect.

'use strict';

const C = require('./configs');

// How an entry is named in an error message. Provider-written, so capped.
const label = (v, i) => {
  const s = typeof v === 'string' && v.trim() ? v.trim() : `#${i + 1}`;
  return s.length > 60 ? `${s.slice(0, 57)}…` : s;
};

const bool = (v) => v === true || v === 'true' || v === 1 || v === '1';
const str = (v) => (v === undefined || v === null ? '' : String(v));
const list = (v) => (Array.isArray(v) ? v.map(String) : (v ? String(v).split(',') : []))
  .map((s) => s.trim()).filter(Boolean);

const refuse = (message) => { throw new Error(message); };

// "100 Mbps", "1 Gbps", "100" → Mbps. mihomo reads a bare number as Mbps.
function mbps(v) {
  if (typeof v === 'number') return v;
  const m = /^\s*([0-9.]+)\s*([kmgt]?)(?:bps|b)?\s*$/i.exec(str(v));
  if (!m) return 0;
  const scale = { '': 1, k: 0.001, m: 1, g: 1000, t: 1000000 }[m[2].toLowerCase()];
  return Number(m[1]) * scale;
}

// "30s", "1m", 30 → seconds.
function seconds(v) {
  if (typeof v === 'number') return v;
  const m = /^\s*([0-9.]+)\s*(ms|s|m|h)?\s*$/i.exec(str(v));
  if (!m) return undefined;
  const scale = { ms: 0.001, s: 1, m: 60, h: 3600 }[(m[2] || 's').toLowerCase()];
  return Number(m[1]) * scale;
}

// A share link's plugin_opts describe the server, so every importer re-adds
// the `server` keyword that clientPluginOpts() strips back out. See parseSsUri.
const serverOpts = (tokens) => ['server', ...tokens.filter(Boolean)].join(';');

// ── Clash / mihomo ─────────────────────────────────────────────────────────── //
// The transport keys Trojan, VMess and VLESS + TLS share in mihomo's spelling.
function clashStream(px) {
  const network = str(px.network || 'tcp').toLowerCase();
  if (!C.STREAM_NETWORKS.includes(network)) refuse(`the ${network} transport is not one this tool models (tcp, ws or grpc)`);
  const ws = px['ws-opts'] || {};
  const headers = ws.headers || {};
  const grpc = px['grpc-opts'] || {};
  return {
    network,
    path: network === 'ws' ? str(ws.path || px['ws-path']) : '',
    host: network === 'ws' ? str(headers.Host || headers.host || (px['ws-headers'] || {}).Host) : '',
    serviceName: network === 'grpc' ? str(grpc['grpc-service-name']) : '',
    fingerprint: str(px['client-fingerprint']) || 'chrome',
    alpn: list(px.alpn).join(','),
  };
}

function clashSsPlugin(px) {
  const plugin = str(px.plugin).trim();
  const opts = px['plugin-opts'] || {};
  if (!plugin) return { plugin: '', plugin_opts: '' };
  if (plugin === 'obfs' || C.SIMPLE_OBFS_NAMES.includes(plugin)) {
    const mode = str(opts.mode || opts.obfs || 'http').toLowerCase();
    return {
      plugin: 'obfs-local',
      plugin_opts: serverOpts([`obfs=${mode}`, opts.host ? `obfs-host=${opts.host}` : '']),
    };
  }
  if (plugin === 'v2ray-plugin') {
    const mode = str(opts.mode || 'websocket').toLowerCase();
    if (mode !== 'websocket') refuse(`v2ray-plugin in ${mode} mode is not supported (only websocket)`);
    return {
      plugin: 'v2ray-plugin',
      plugin_opts: serverOpts([
        bool(opts.tls) ? 'tls' : '',
        opts.host ? `host=${opts.host}` : '',
        opts.path ? `path=${opts.path}` : '',
        bool(opts.mux) ? 'mux=1' : '',
      ]),
    };
  }
  return refuse(`the ${plugin} plugin is not supported — only simple-obfs and v2ray-plugin`);
}

function clashProxyToProfile(px) {
  if (!px || typeof px !== 'object' || Array.isArray(px)) refuse('not a proxy entry');
  const type = str(px.type).toLowerCase();
  const base = {
    server: str(px.server).replace(/^\[|\]$/g, ''),
    port: Number(px.port),
    remarks: str(px.name) || 'Imported',
  };
  if (type === 'ss') {
    return C.normalizeProfile({
      ...base, protocol: 'shadowsocks', method: str(px.cipher), password: str(px.password), ...clashSsPlugin(px),
    });
  }
  if (type === 'vmess') {
    if (px['reality-opts']) refuse('VMess with Reality is not something any client here can carry');
    return C.normalizeProfile({
      ...base, protocol: 'vmess', uuid: str(px.uuid),
      alterId: px.alterId !== undefined ? px.alterId : px['alter-id'],
      cipher: str(px.cipher) || 'auto',
      tls: bool(px.tls),
      sni: str(px.servername || px.sni),
      insecure: bool(px['skip-cert-verify']),
      ...clashStream(px),
    });
  }
  if (type === 'vless') {
    const reality = px['reality-opts'];
    if (reality) {
      const network = str(px.network || 'tcp').toLowerCase();
      if (!C.VLESS_NETWORKS.includes(network)) refuse(`VLESS + Reality over ${network} is not supported (tcp, grpc or xhttp)`);
      return C.normalizeProfile({
        ...base, protocol: 'vless-reality', uuid: str(px.uuid),
        publicKey: str(reality['public-key']), shortId: str(reality['short-id']),
        sni: str(px.servername || px.sni),
        flow: px.flow === undefined ? '' : str(px.flow),
        fingerprint: str(px['client-fingerprint']) || 'chrome',
        network,
        serviceName: network === 'grpc' ? str((px['grpc-opts'] || {})['grpc-service-name']) : '',
        path: network === 'xhttp' ? str((px['xhttp-opts'] || {}).path) : '',
      });
    }
    // Same policy as a vless:// link: VLESS has no encryption of its own.
    if (!bool(px.tls)) refuse('VLESS without TLS or Reality sends everything unencrypted — not supported');
    return C.normalizeProfile({
      ...base, protocol: 'vless-tls', uuid: str(px.uuid), flow: str(px.flow),
      sni: str(px.servername || px.sni), insecure: bool(px['skip-cert-verify']),
      ...clashStream(px),
    });
  }
  if (type === 'trojan') {
    if (px['reality-opts']) refuse('Trojan with Reality is not supported');
    return C.normalizeProfile({
      ...base, protocol: 'trojan', password: str(px.password),
      sni: str(px.sni || px.servername), insecure: bool(px['skip-cert-verify']),
      ...clashStream(px),
    });
  }
  if (type === 'hysteria2' || type === 'hy2') {
    return C.normalizeProfile({
      ...base, protocol: 'hysteria2', password: str(px.password || px.auth),
      sni: str(px.sni), insecure: bool(px['skip-cert-verify']),
      obfs: str(px.obfs), obfsPassword: str(px['obfs-password']),
      ports: str(px.ports), hopInterval: seconds(px['hop-interval']),
      up: mbps(px.up), down: mbps(px.down),
    });
  }
  if (type === 'tuic') {
    if (!px.uuid) refuse('TUIC v4 (token-only) is not supported — only v5 with a UUID and password');
    return C.normalizeProfile({
      ...base, protocol: 'tuic', uuid: str(px.uuid), password: str(px.password),
      sni: str(px.sni), insecure: bool(px['skip-cert-verify']),
      congestion: str(px['congestion-controller']) || 'bbr',
      udpRelayMode: str(px['udp-relay-mode']) || 'native',
      alpn: list(px.alpn).join(',') || 'h3',
    });
  }
  return refuse(`Clash proxy type "${type || '(none)'}" is not supported`);
}

// Parse a whole Clash config. js-yaml's default schema builds plain data only
// (no functions, no custom tags), and an alias is a shared reference rather
// than a copy — so a hostile body cannot run code or expand itself into memory.
function parseClashConfig(text) {
  let doc;
  try {
    doc = require('js-yaml').load(String(text || '').replace(/^﻿/, ''));
  } catch (err) {
    return { profiles: [], errors: [`the Clash config is not valid YAML: ${String(err.reason || err.message).slice(0, 200)}`] };
  }
  const proxies = doc && Array.isArray(doc.proxies) ? doc.proxies : null;
  if (!proxies) return { profiles: [], errors: ['the Clash config has no proxies list'] };
  const profiles = [];
  const errors = [];
  proxies.forEach((px, i) => {
    const name = label(px && px.name, i);
    try { profiles.push(clashProxyToProfile(px)); }
    catch (err) { errors.push(`proxy ${name}: ${err.message}`); }
  });
  return { profiles, errors };
}

// ── sing-box ───────────────────────────────────────────────────────────────── //
// Outbound types that are structure rather than servers. A provider's sing-box
// config is a whole client config, selector groups and all; these are skipped
// without comment rather than reported as forty "unsupported" errors.
const SING_STRUCTURAL = new Set(['selector', 'urltest', 'direct', 'block', 'dns']);

function singTls(o) {
  const tls = o.tls || {};
  return {
    enabled: tls.enabled === true,
    sni: str(tls.server_name),
    insecure: tls.insecure === true,
    alpn: list(tls.alpn).join(','),
    fingerprint: str(tls.utls && tls.utls.enabled !== false ? tls.utls.fingerprint : '') || 'chrome',
    reality: tls.reality && tls.reality.enabled !== false ? tls.reality : null,
  };
}

function singStream(o) {
  const t = o.transport;
  if (!t) return { network: 'tcp', path: '', host: '', serviceName: '' };
  const type = str(t.type).toLowerCase();
  if (type === 'ws') {
    const headers = t.headers || {};
    const host = Array.isArray(headers.Host) ? headers.Host[0] : (headers.Host || headers.host);
    return { network: 'ws', path: str(t.path), host: str(host), serviceName: '' };
  }
  if (type === 'grpc') return { network: 'grpc', path: '', host: '', serviceName: str(t.service_name) };
  return refuse(`the ${type || '(unnamed)'} transport is not one this tool models (tcp, ws or grpc)`);
}

// "20000:30000" (sing-box) → "20000-30000" (everyone else).
const singPorts = (v) => list(v).map((s) => s.replace(':', '-')).join(',');

function singBoxOutboundToProfile(o) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) refuse('not an outbound');
  const type = str(o.type).toLowerCase();
  const ports = singPorts(o.server_ports);
  const base = {
    server: str(o.server).replace(/^\[|\]$/g, ''),
    // A hopping Hysteria2 outbound has server_ports instead of server_port;
    // the first port of the range is the one to dial first.
    port: Number(o.server_port) || Number((ports.split(/[-,]/)[0]) || 0),
    remarks: str(o.tag) || 'Imported',
  };
  const tls = singTls(o);
  if (type === 'shadowsocks') {
    const plugin = str(o.plugin).trim();
    let pluginFields = { plugin: '', plugin_opts: '' };
    if (plugin) {
      if (C.ssPluginKind(plugin) === 'other') refuse(`the ${plugin} plugin is not supported — only obfs-local and v2ray-plugin`);
      pluginFields = { plugin: C.ssPluginKind(plugin) === 'obfs' ? 'obfs-local' : plugin, plugin_opts: serverOpts(C.optsList(o.plugin_opts)) };
    }
    return C.normalizeProfile({ ...base, protocol: 'shadowsocks', method: str(o.method), password: str(o.password), ...pluginFields });
  }
  if (type === 'vmess') {
    return C.normalizeProfile({
      ...base, protocol: 'vmess', uuid: str(o.uuid), alterId: o.alter_id, cipher: str(o.security) || 'auto',
      tls: tls.enabled, sni: tls.sni, insecure: tls.insecure, fingerprint: tls.fingerprint, alpn: tls.alpn,
      ...singStream(o),
    });
  }
  if (type === 'vless') {
    if (tls.enabled && tls.reality) {
      const stream = singStream(o);
      if (stream.network === 'ws') refuse('VLESS + Reality over ws is not supported (tcp or grpc)');
      return C.normalizeProfile({
        ...base, protocol: 'vless-reality', uuid: str(o.uuid),
        publicKey: str(tls.reality.public_key), shortId: str(tls.reality.short_id),
        sni: tls.sni, flow: str(o.flow), fingerprint: tls.fingerprint,
        network: stream.network, serviceName: stream.serviceName,
      });
    }
    if (!tls.enabled) refuse('VLESS without TLS or Reality sends everything unencrypted — not supported');
    return C.normalizeProfile({
      ...base, protocol: 'vless-tls', uuid: str(o.uuid), flow: str(o.flow),
      sni: tls.sni, insecure: tls.insecure, fingerprint: tls.fingerprint, alpn: tls.alpn,
      ...singStream(o),
    });
  }
  if (type === 'trojan') {
    return C.normalizeProfile({
      ...base, protocol: 'trojan', password: str(o.password),
      sni: tls.sni, insecure: tls.insecure, fingerprint: tls.fingerprint, alpn: tls.alpn,
      ...singStream(o),
    });
  }
  if (type === 'hysteria2') {
    const obfs = o.obfs || {};
    return C.normalizeProfile({
      ...base, protocol: 'hysteria2', password: str(o.password),
      sni: tls.sni, insecure: tls.insecure,
      obfs: str(obfs.type), obfsPassword: str(obfs.password),
      ports, hopInterval: seconds(o.hop_interval),
      up: Number(o.up_mbps) || 0, down: Number(o.down_mbps) || 0,
    });
  }
  if (type === 'tuic') {
    return C.normalizeProfile({
      ...base, protocol: 'tuic', uuid: str(o.uuid), password: str(o.password),
      sni: tls.sni, insecure: tls.insecure, alpn: tls.alpn || 'h3',
      congestion: str(o.congestion_control) || 'bbr',
      udpRelayMode: str(o.udp_relay_mode) || 'native',
    });
  }
  return refuse(`sing-box outbound type "${type || '(none)'}" is not supported`);
}

function parseSingBoxConfig(text) {
  let doc;
  try { doc = JSON.parse(String(text || '').replace(/^﻿/, '')); } catch (err) {
    return { profiles: [], errors: [`the sing-box config is not valid JSON: ${err.message}`] };
  }
  const outbounds = doc && Array.isArray(doc.outbounds) ? doc.outbounds : null;
  if (!outbounds) return { profiles: [], errors: ['the sing-box config has no outbounds list'] };
  const profiles = [];
  const errors = [];
  outbounds.forEach((o, i) => {
    if (o && SING_STRUCTURAL.has(str(o.type).toLowerCase())) return;
    const name = label(o && o.tag, i);
    try { profiles.push(singBoxOutboundToProfile(o)); }
    catch (err) { errors.push(`outbound ${name}: ${err.message}`); }
  });
  return { profiles, errors };
}

module.exports = {
  clashProxyToProfile,
  parseClashConfig,
  singBoxOutboundToProfile,
  parseSingBoxConfig,
};
