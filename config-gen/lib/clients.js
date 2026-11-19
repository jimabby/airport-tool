// Config output for the two clients that do not read Clash or Sing-Box files:
// Surge (macOS/iOS) and Quantumult X (iOS).
//
// Both use their own INI-ish plain-text format, and — the part that matters —
// neither supports every protocol this tool models. Surge has no VLESS/Reality;
// Quantumult X has no QUIC protocols at all and carries Reality only over raw
// TCP.
//
// So the rule for this file is: **never guess**. A profile that the target
// client cannot express is written out as a comment saying which one it was and
// why it was left out, and the reason is also returned to the caller so the CLI
// and the dashboard can say "3 of 5 servers" rather than quietly handing over a
// short file. A config that silently drops a server is worse than one that
// refuses it, because the missing server is only discovered when you need it.
//
// The same reasoning applies inside a protocol: Surge speaks Trojan and VMess
// over TCP and WebSocket but not over gRPC, and its Shadowsocks support covers
// simple-obfs rather than v2ray-plugin's WebSocket — so those combinations are
// skipped by name too. And it applies to options: a line that drops a setting
// the server insists on (obfuscation, say) is a line that cannot connect.
//
// Syntax references, checked against the vendors' own documentation:
//   Surge         https://manual.nssurge.com/policies/<protocol>.html
//   Quantumult X  https://github.com/crossutility/Quantumult-X/blob/master/sample.conf

'use strict';

const C = require('./configs');

// Shadowsocks ciphers Surge's `encrypt-method` accepts. Notably it has only
// two of the three 2022 ciphers, and none of the camellia / bf family.
const SURGE_SS_METHODS = new Set([
  '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
  'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
  'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
  'rc4', 'rc4-md5', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
  'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'salsa20', 'chacha20', 'chacha20-ietf',
  'none',
]);

// ── What each client can actually carry ────────────────────────────────────── //
// Returns a sentence explaining the refusal, or null when the profile is
// expressible. Written as one function per client so the two lists cannot drift
// apart from the builders that consult them.
function surgeRefusal(p) {
  const net = p.network || 'tcp';
  if (p.protocol === 'vless-reality' || p.protocol === 'vless-tls') {
    return 'Surge has no VLESS or Reality support — use the Clash or Sing-Box bundle for this one';
  }
  if (p.protocol === 'anytls') {
    return 'this tool has no Surge mapping for AnyTLS — use the Clash or Sing-Box bundle for this one';
  }
  // Surge's Shadowsocks speaks simple-obfs (obfs=http/tls) and nothing else.
  // This used to refuse every plugin, simple-obfs included, with a message
  // that called obfs-local "the WebSocket transport".
  const plugin = C.ssPluginKind(p.plugin);
  if (p.protocol === 'shadowsocks' && plugin === 'v2ray') {
    return 'Surge has no v2ray-plugin (Shadowsocks over WebSocket) — its Shadowsocks support covers simple-obfs only';
  }
  if (p.protocol === 'shadowsocks' && plugin === 'other') {
    return `Surge's Shadowsocks support covers simple-obfs only, not the ${p.plugin} plugin`;
  }
  if (p.protocol === 'shadowsocks' && !SURGE_SS_METHODS.has(p.method)) {
    return `Surge has no ${p.method} cipher`;
  }
  if ((p.protocol === 'trojan' || p.protocol === 'vmess') && net === 'grpc') {
    return 'Surge has no gRPC transport';
  }
  if ((p.protocol === 'trojan' || p.protocol === 'vmess') && net === 'httpupgrade') {
    return 'Surge has no HTTPUpgrade transport — use the Clash or Sing-Box bundle for this one';
  }
  // Salamander is the only Hysteria2 obfuscation Surge speaks. A line without
  // the obfuscation the server requires never gets past the first packet.
  if (p.protocol === 'hysteria2' && p.obfs && p.obfs !== 'salamander') {
    return `Surge has no "${p.obfs}" obfuscation for Hysteria2`;
  }
  return null;
}

function quantumultRefusal(p) {
  const net = p.network || 'tcp';
  // Quantumult X reads Reality as a parameter on an over-tls line, which means
  // raw TCP only: it has no gRPC and no XHTTP transport to put it on.
  if (p.protocol === 'vless-reality' && net !== 'tcp') {
    return `Quantumult X carries Reality over raw TCP only, not ${net} — use the Clash or Sing-Box bundle for this one`;
  }
  if (p.protocol === 'hysteria2' || p.protocol === 'tuic') {
    return `Quantumult X has no ${p.protocol} support — QUIC protocols need the Clash or Sing-Box bundle`;
  }
  if (p.protocol === 'anytls') {
    return 'Quantumult X has no AnyTLS support — use the Clash or Sing-Box bundle for this one';
  }
  if (p.protocol === 'shadowsocks' && C.ssPluginKind(p.plugin) === 'shadowtls') {
    return 'Quantumult X has no ShadowTLS support — use the Clash, Sing-Box or Surge file for this one';
  }
  if (p.protocol === 'shadowsocks' && C.ssPluginKind(p.plugin) === 'other') {
    return `Quantumult X can only carry v2ray-plugin and simple-obfs, not ${p.plugin}`;
  }
  if ((p.protocol === 'trojan' || p.protocol === 'vmess' || p.protocol === 'vless-tls') && net === 'grpc') {
    return 'Quantumult X has no gRPC transport';
  }
  if ((p.protocol === 'trojan' || p.protocol === 'vmess' || p.protocol === 'vless-tls') && net === 'httpupgrade') {
    return 'Quantumult X has no HTTPUpgrade transport — use the Clash or Sing-Box bundle for this one';
  }
  return null;
}

// Both clients' formats are comma-separated key=value lists, and a comma inside
// a value would split the line in the wrong place. Neither format defines an
// escape, so the honest move is to refuse the line rather than emit one that
// parses into something else.
//
// An equals sign inside a *value* is fine: both read `key=value` up to the first
// `=`. Refusing it used to drop every base64 secret with padding — which is
// every Shadowsocks password setup.sh generates (`openssl rand -base64 16`
// always ends in "==") and every Shadowsocks 2022 key. The *name* is different:
// Surge writes it on the left of `name = type, …`, where an `=` ends it.
const UNSAFE_VALUE = /[,\r\n]/;
const UNSAFE_NAME = /[,=\r\n]/;
// A line that *starts* with the comment character is a comment, however much
// configuration follows it: a server named "# Tokyo" disappeared from the file
// without a word. Surround-whitespace is trimmed by both parsers, so the name
// written on the line would no longer match the one the groups list.
const COMMENT_NAME = /^[#;]|^\/\/|^\s|\s$/;

function unsafeField(p, ...fields) {
  for (const [label, value] of fields) {
    if (!value) continue;
    if (label === 'name' && COMMENT_NAME.test(String(value))) {
      return 'the name starts with a comment character (# or ;) or has spaces at either end, which this format would misread';
    }
    if (label === 'name' ? UNSAFE_NAME.test(String(value)) : UNSAFE_VALUE.test(String(value))) {
      return label === 'name'
        ? 'the name contains a comma or an equals sign, which this format cannot escape'
        : `the ${label} contains a comma, which this format cannot escape`;
    }
  }
  return null;
}

// ── Which servers make it into a file ──────────────────────────────────────── //
// Shared by every line-format builder. `refuse(p)` is the client's own
// refusal; `line(p, name, relayName)` builds one entry. A relayed profile needs
// a client that can chain (`chains`), a relay that is valid at all, and a relay
// that made it into *this* file — a line naming a relay the file lacks is one
// the client refuses to load.
function planEntries(profiles, { refuse, line, chains, client }) {
  const list = C.enabledProfiles(profiles);
  const names = C.uniqueNames(list);
  const decided = list.map((p) => {
    const relay = C.relayProblem(profiles, p);
    if (relay) return { skip: `${relay}, so it is left out rather than dialled directly` };
    if (p.via && !chains) return { skip: `${client} cannot dial one server through another — use the Clash or Sing-Box bundle for this one` };
    const r = refuse(p);
    return r ? { skip: r } : null;
  });
  // Direct servers first, so a relay's own line exists (or has been refused,
  // e.g. for a comma in its password) before anything is chained through it.
  const entries = list.map((p, i) => ((decided[i] || p.via) ? decided[i] : line(p, names[i], null)));
  const indexById = new Map(list.map((p, i) => [p.id, i]));
  list.forEach((p, i) => {
    if (entries[i] || !p.via) return;
    const ri = indexById.get(p.via);
    entries[i] = ri === undefined || !entries[ri] || entries[ri].skip
      ? { skip: `its relay "${ri === undefined ? p.via : names[ri]}" is not in this file` }
      : line(p, names[i], names[ri]);
  });
  return list.map((p, i) => ({ p, name: names[i], ...entries[i] }));
}

// The parts every line-format file shares once its entries are planned.
function tally(entries) {
  const skipped = entries.filter((e) => e.skip).map((e) => ({ name: e.name, reason: e.skip }));
  const usable = entries.filter((e) => !e.skip).map((e) => e.name);
  // `names` with a null in place of every server left out, for regionGroups.
  const carriedNames = entries.map((e) => (e.skip ? null : e.name));
  return { skipped, usable, carriedNames, list: entries.map((e) => e.p) };
}

// Every free-text field either format might put on a line.
function lineFields(p, name) {
  return [
    ['server', p.server], ['method', p.method], ['plugin options', p.plugin_opts],
    ['password', p.password], ['uuid', p.uuid], ['name', name],
    ['obfs password', p.obfsPassword], ['sni', p.sni], ['ws path', p.path], ['Host header', p.host],
  ];
}

// ★ first, as in the Clash bundle: see preferredName in configs.js. Only a
// server that actually made it into the file can lead a group.
function preferredLead(list, names, usable, preferred) {
  const lead = C.preferredName(list, names, preferred);
  return lead && usable.includes(lead) ? lead : null;
}

// ── Custom rules ───────────────────────────────────────────────────────────── //
function surgeCustomRules(rules) {
  const target = { block: 'REJECT', proxy: 'PROXY', direct: 'DIRECT' };
  const out = [];
  for (const list of C.RULE_ORDER) {
    const { domains, ip, ip6 } = C.splitRuleKinds(rules && rules[list]);
    domains.forEach((d) => out.push(`DOMAIN-SUFFIX,${d},${target[list]}`));
    ip.forEach((c) => out.push(`IP-CIDR,${c},${target[list]},no-resolve`));
    ip6.forEach((c) => out.push(`IP-CIDR6,${c},${target[list]},no-resolve`));
  }
  return out;
}

function quantumultCustomRules(rules) {
  // `direct` and `reject` are Quantumult X's built-in policies; PROXY is the
  // static group this file defines.
  const target = { block: 'reject', proxy: 'PROXY', direct: 'direct' };
  const out = [];
  for (const list of C.RULE_ORDER) {
    const { domains, ip, ip6 } = C.splitRuleKinds(rules && rules[list]);
    domains.forEach((d) => out.push(`host-suffix, ${d}, ${target[list]}`));
    ip.forEach((c) => out.push(`ip-cidr, ${c}, ${target[list]}`));
    ip6.forEach((c) => out.push(`ip6-cidr, ${c}, ${target[list]}`));
  }
  return out;
}

// ── Surge ──────────────────────────────────────────────────────────────────── //
function surgeProxyLine(p, name, relayName = null) {
  const bad = unsafeField(p, ...lineFields(p, name));
  if (bad) return { skip: bad };
  const net = p.network || 'tcp';
  const parts = [];
  const notes = [];

  if (p.protocol === 'shadowsocks') {
    parts.push('ss', p.server, String(p.port),
      `encrypt-method=${p.method}`, `password=${p.password}`);
    if (C.ssPluginKind(p.plugin) === 'obfs') {
      // simple-obfs, in Surge's own spelling. The Host it fakes defaults to
      // the server's name, the same default the plugin itself applies.
      const { mode, host, uri } = C.simpleObfsOpts(p.plugin_opts);
      parts.push(`obfs=${mode}`, `obfs-host=${host || p.server}`);
      if (uri && mode === 'http') parts.push(`obfs-uri=${uri}`);
    } else if (C.ssPluginKind(p.plugin) === 'shadowtls') {
      // Surge's own ShadowTLS client. TCP only, so no udp-relay claim.
      const st = C.shadowTlsOpts(p.plugin_opts);
      parts.push(`shadow-tls-password=${st.password}`, `shadow-tls-sni=${st.host}`, `shadow-tls-version=${st.version}`);
    } else {
      // UDP relay is opt-in for Shadowsocks in Surge, and a bare server relays
      // it. simple-obfs wraps TCP only, so it is not claimed there.
      parts.push('udp-relay=true');
    }
  } else if (p.protocol === 'trojan') {
    parts.push('trojan', p.server, String(p.port), `password=${p.password}`);
    parts.push(`sni=${p.sni || p.server}`);
    if (p.insecure) parts.push('skip-cert-verify=true');
  } else if (p.protocol === 'vmess') {
    parts.push('vmess', p.server, String(p.port), `username=${p.uuid}`);
    // Surge accepts exactly two payload ciphers. VMess lets the client choose
    // (the server accepts any), so every other setting maps onto the default.
    parts.push(`encrypt-method=${p.cipher === 'chacha20-poly1305' ? 'chacha20-ietf-poly1305' : 'aes-128-gcm'}`);
    // Surge defaults to the *legacy* handshake. Current v2ray and Xray servers
    // refuse it outright, so a line without this flag connects to nothing. An
    // alterId above zero is the one case that genuinely asks for legacy.
    if (!p.alterId) parts.push('vmess-aead=true');
    if (p.tls) {
      parts.push('tls=true', `sni=${p.sni || p.server}`);
      if (p.insecure) parts.push('skip-cert-verify=true');
    }
  } else if (p.protocol === 'hysteria2') {
    parts.push('hysteria2', p.server, String(p.port), `password=${p.password}`);
    parts.push(`sni=${p.sni || p.server}`);
    if (p.insecure) parts.push('skip-cert-verify=true');
    // Surge wants the declared rate in Mbps, the same units the profile holds.
    if (p.down) parts.push(`download-bandwidth=${p.down}`);
    // Surge separates hop ranges with semicolons: a comma would end the
    // parameter, so "20000-25000,30000" used to split the line in two.
    const ports = C.normalizePortRange(p.ports);
    if (ports) {
      parts.push(`port-hopping=${ports.replace(/,/g, ';')}`,
        `port-hopping-interval=${C.normalizeHopInterval(p.hopInterval)}`);
    }
    if (p.obfs === 'salamander') {
      parts.push(`salamander-password=${p.obfsPassword}`);
      notes.push(`${name} uses Salamander obfuscation, which needs Surge Mac 6.4.3 or later`);
    }
  } else if (p.protocol === 'tuic') {
    // tuic-v5 is the UUID + password version; plain `tuic` in Surge is v4.
    parts.push('tuic-v5', p.server, String(p.port), `uuid=${p.uuid}`, `password=${p.password}`);
    parts.push(`sni=${p.sni || p.server}`, `alpn=${C.alpnList(p.alpn || 'h3')[0] || 'h3'}`);
    if (p.insecure) parts.push('skip-cert-verify=true');
  } else {
    return { skip: `no Surge mapping for ${p.protocol}` };
  }

  // Surge's certificate pin: the server's certificate is accepted when its
  // SHA-256 matches, instead of being checked against a CA. See pinOf.
  const pin = C.pinOf(p);
  if (pin) parts.push(`server-cert-fingerprint-sha256=${pin}`);

  if (net === 'ws' && (p.protocol === 'trojan' || p.protocol === 'vmess')) {
    parts.push('ws=true', `ws-path=${p.path || '/'}`);
    if (p.host) parts.push(`ws-headers=Host:${p.host}`);
  }
  // Surge's relay: this proxy's connection is made through the named one.
  if (relayName) parts.push(`underlying-proxy=${relayName}`);
  return { line: `${name} = ${parts.join(', ')}`, notes };
}

// A whole Surge profile, not just the [Proxy] block: a bare proxy list is not
// something Surge will load, and the rules are the part that keeps CN traffic
// off the tunnel — the same split the Clash and Sing-Box builders apply.
function buildSurge(profiles, { title = C.DEFAULT_TITLE, rules = null, preferred = null } = {}) {
  const entries = planEntries(profiles, { refuse: surgeRefusal, line: surgeProxyLine, chains: true, client: 'Surge' });
  const { skipped, usable, carriedNames, list } = tally(entries);
  const names = entries.map((e) => e.name);
  const proxies = [];
  for (const e of entries) {
    if (e.skip) { proxies.push(`# ${e.name}: skipped — ${e.skip}`); continue; }
    for (const note of e.notes || []) proxies.push(`# ${note}`);
    proxies.push(e.line);
  }

  // With nothing usable there is no group to build, and Surge refuses a
  // policy-group with an empty member list — so say so in the file itself.
  const groupMembers = usable.length ? [...usable, 'DIRECT'] : ['DIRECT'];
  const autoMembers = usable.length > 1 ? usable : null;
  // With a ★ to honour, Fallback leads the selector and ★ leads Fallback.
  const lead = preferredLead(list, names, usable, preferred);
  const fallbackMembers = autoMembers ? C.leadWith(autoMembers, lead) : null;
  // Per-country url-test groups, built from the servers that made it into this
  // file only. See regionGroups in configs.js.
  const regions = C.regionGroupsEnabled(rules) ? C.regionGroups(list, carriedNames) : [];
  const regionNames = regions.map((r) => r.name);

  const lines = [
    `#!name=${title}`,
    '#!desc=Generated by airport-tool. Edit servers.json, not this file.',
    '',
    '[General]',
    'loglevel = notify',
    'skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local',
    // Surge resolves names itself; these have to be reachable from inside China
    // or nothing gets classified. Same reasoning as the Clash DNS block.
    'dns-server = 223.5.5.5, 119.29.29.29',
    // Plain DNS on port 53 is the one part of the connection the firewall can
    // still rewrite. AliDNS answers the same queries over HTTPS from inside
    // China, so the domestic half of the split stops being forgeable.
    'encrypted-dns-server = https://223.5.5.5/dns-query',
    'ipv6 = false',
    '',
    '[Proxy]',
    ...proxies,
    '',
    '[Proxy Group]',
    ...(autoMembers
      ? [`Auto = url-test, ${autoMembers.join(', ')}, url = http://www.gstatic.com/generate_204, interval = 300`,
        `Fallback = fallback, ${fallbackMembers.join(', ')}, url = http://www.gstatic.com/generate_204, interval = 300`,
        ...regions.map((r) => `${r.name} = url-test, ${r.members.join(', ')}, url = http://www.gstatic.com/generate_204, interval = 300`),
        `PROXY = select, ${lead ? 'Fallback, Auto' : 'Auto, Fallback'}, ${[...regionNames, ...groupMembers].join(', ')}`]
      : [`PROXY = select, ${groupMembers.join(', ')}`]),
    '',
    '[Rule]',
    'RULE-SET,SYSTEM,DIRECT',
    'RULE-SET,LAN,DIRECT',
    // Your own lists, ahead of the geographic rule. See checkRules.
    ...surgeCustomRules(rules),
    // Surge has no geosite database to read the ad list out of, so say where
    // it went rather than leave the switch looking like it did nothing.
    ...(C.adsEnabled(rules) ? ['# Ad blocking (geosite category-ads-all) is in the Clash and Sing-Box bundles only.'] : []),
    ...(C.warpEnabled(rules) ? ['# The WARP exit for streaming and AI sites is in the Clash and Sing-Box bundles only.'] : []),
    'GEOIP,CN,DIRECT',
    // Foreign QUIC, refused so the browser falls back to TCP at once — the
    // same rule the Clash and Sing-Box bundles carry, after every DIRECT rule
    // so nothing domestic is touched. REJECT-NO-DROP answers rather than
    // silently dropping, which is what makes the fallback immediate.
    'AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP',
    'FINAL,PROXY,dns-failed',
    '',
  ];
  if (skipped.length) {
    lines.push('# Servers left out of this file, and why:');
    for (const s of skipped) lines.push(`#   ${s.name}: ${s.reason}`);
    lines.push('');
  }
  return { text: lines.join('\n'), skipped, usable: usable.length, total: list.length };
}

// ── Quantumult X ───────────────────────────────────────────────────────────── //
function quantumultLine(p, name) {
  const bad = unsafeField(p, ...lineFields(p, name), ['public key', p.publicKey], ['short id', p.shortId]);
  if (bad) return { skip: bad };
  const net = p.network || 'tcp';
  const authority = `${C.hostForUri(p.server)}:${p.port}`;
  const parts = [];

  if (p.protocol === 'shadowsocks') {
    parts.push(`shadowsocks=${authority}`, `method=${p.method}`, `password=${p.password}`);
    if (p.plugin === 'v2ray-plugin') {
      // v2ray-plugin's WebSocket, in Quantumult X's spelling: wss when the
      // plugin is wrapping it in TLS, plain ws when it is not.
      const tls = C.hasOpt(p.plugin_opts, 'tls');
      parts.push(`obfs=${tls ? 'wss' : 'ws'}`);
      const host = C.getOpt(p.plugin_opts, 'host');
      if (host) parts.push(`obfs-host=${host}`);
      parts.push(`obfs-uri=${C.getOpt(p.plugin_opts, 'path') || '/'}`);
    } else if (C.ssPluginKind(p.plugin) === 'obfs') {
      // simple-obfs: Quantumult X spells the two modes exactly as the plugin
      // does, with obfs-uri meaningful for http only.
      const { mode, host, uri } = C.simpleObfsOpts(p.plugin_opts);
      parts.push(`obfs=${mode}`, `obfs-host=${host || p.server}`);
      if (uri && mode === 'http') parts.push(`obfs-uri=${uri}`);
    }
  } else if (p.protocol === 'vless-reality') {
    // Reality is a parameter on an over-tls line: the obfs-host is the SNI of
    // the site being borrowed, and the public key and short id replace the
    // certificate check. Quantumult X picks its own TLS fingerprint for it.
    parts.push(`vless=${authority}`, 'method=none', `password=${p.uuid}`,
      'obfs=over-tls', `obfs-host=${p.sni}`, `reality-base64-pubkey=${p.publicKey}`);
    if (p.shortId) parts.push(`reality-hex-shortid=${p.shortId}`);
    if (p.flow) parts.push(`vless-flow=${p.flow}`);
  } else if (p.protocol === 'vless-tls') {
    // The Trojan spellings below, with VLESS's uuid in `password`: wss
    // *instead of* over-tls for WebSocket, over-tls for plain TLS.
    parts.push(`vless=${authority}`, 'method=none', `password=${p.uuid}`);
    if (net === 'ws') {
      parts.push('obfs=wss', `obfs-host=${p.host || p.sni || p.server}`, `obfs-uri=${p.path || '/'}`);
    } else {
      parts.push('obfs=over-tls', `obfs-host=${p.sni || p.server}`);
      if (p.flow) parts.push(`vless-flow=${p.flow}`);
    }
    parts.push(`tls-verification=${p.insecure ? 'false' : 'true'}`);
  } else if (p.protocol === 'trojan') {
    parts.push(`trojan=${authority}`, `password=${p.password}`);
    if (net === 'ws') {
      // WebSocket over TLS is spelled obfs=wss *instead of* over-tls, and the
      // sample config is explicit that the two must not be combined — which is
      // what this used to emit, producing a line Quantumult X would not load.
      // obfs-host is both the SNI and the Host header here.
      parts.push('obfs=wss', `obfs-host=${p.host || p.sni || p.server}`, `obfs-uri=${p.path || '/'}`);
    } else {
      parts.push('over-tls=true', `tls-host=${p.sni || p.server}`);
    }
    parts.push(`tls-verification=${p.insecure ? 'false' : 'true'}`);
  } else if (p.protocol === 'vmess') {
    // Quantumult X carries the VMess UUID in `password`; the payload cipher is
    // the client's choice, so method=none inside TLS and the AEAD default is
    // what every current server expects.
    parts.push(`vmess=${authority}`, `method=${p.tls ? 'none' : 'chacha20-poly1305'}`, `password=${p.uuid}`);
    if (net === 'ws') {
      parts.push(`obfs=${p.tls ? 'wss' : 'ws'}`, `obfs-uri=${p.path || '/'}`);
      if (p.host) parts.push(`obfs-host=${p.host}`);
    } else if (p.tls) {
      parts.push('obfs=over-tls', `obfs-host=${p.sni || p.server}`);
    }
    if (p.tls && p.insecure) parts.push('tls-verification=false');
    // A non-zero alterId is a request for the legacy handshake.
    if (p.alterId) parts.push('aead=false');
  } else {
    return { skip: `no Quantumult X mapping for ${p.protocol}` };
  }

  // v2ray-plugin's WebSocket carries TCP only — the same reason the Clash
  // builder sets `udp: false` for it. Claiming UDP there hands the client a
  // relay that swallows DNS and QUIC instead of falling back.
  const udp = !(p.protocol === 'shadowsocks' && p.plugin);
  parts.push(`udp-relay=${udp}`, `tag=${name}`);
  return { line: parts.join(', ') };
}

function buildQuantumultX(profiles, { title = C.DEFAULT_TITLE, rules = null, preferred = null } = {}) {
  const entries = planEntries(profiles, { refuse: quantumultRefusal, line: (p, name) => quantumultLine(p, name), chains: false, client: 'Quantumult X' });
  const { skipped, usable, carriedNames, list } = tally(entries);
  const names = entries.map((e) => e.name);
  const servers = entries.map((e) => (e.skip ? `; ${e.name}: skipped — ${e.skip}` : e.line));

  const lead = preferredLead(list, names, usable, preferred);
  // url-latency-benchmark is Quantumult X's url-test, so region groups map on
  // to it directly. See regionGroups in configs.js.
  const regions = C.regionGroupsEnabled(rules) ? C.regionGroups(list, carriedNames) : [];
  const regionNames = regions.map((r) => `${r.name}, `).join('');
  const lines = [
    `; ${title} — generated by airport-tool. Edit servers.json, not this file.`,
    '',
    '[general]',
    'server_check_url=http://www.gstatic.com/generate_204',
    'excluded_routes=192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12',
    '',
    '[dns]',
    'server=223.5.5.5',
    'server=119.29.29.29',
    'no-ipv6',
    '',
    '[server_local]',
    ...servers,
    '',
    '[policy]',
    // Quantumult X's static policy is the pick-one selector; available is its
    // fallback (first alive, in order) and round-robin is not what anyone wants
    // here. Both are offered for the same reason the Clash bundle offers both.
    ...(usable.length > 1
      ? [`static=PROXY, ${lead ? 'Fallback, Fastest' : 'Fastest, Fallback'}, ${regionNames}${usable.join(', ')}, direct`,
        `url-latency-benchmark=Fastest, ${usable.join(', ')}`,
        `available=Fallback, ${C.leadWith(usable, lead).join(', ')}`,
        ...regions.map((r) => `url-latency-benchmark=${r.name}, ${r.members.join(', ')}`)]
      : usable.length
        ? [`static=PROXY, ${usable.join(', ')}, direct`]
        : ['static=PROXY, direct']),
    '',
    '[filter_local]',
    // Your own lists, ahead of the geographic rule. See checkRules.
    ...quantumultCustomRules(rules),
    ...(C.adsEnabled(rules) ? ['; Ad blocking (geosite category-ads-all) is in the Clash and Sing-Box bundles only.'] : []),
    ...(C.warpEnabled(rules) ? ['; The WARP exit for streaming and AI sites is in the Clash and Sing-Box bundles only.'] : []),
    'geoip, cn, direct',
    'final, PROXY',
    '',
  ];
  if (skipped.length) {
    lines.push('; Servers left out of this file, and why:');
    for (const s of skipped) lines.push(`;   ${s.name}: ${s.reason}`);
    lines.push('');
  }
  return { text: lines.join('\n'), skipped, usable: usable.length, total: list.length };
}

// ── Loon ───────────────────────────────────────────────────────────────────── //
// Loon (iOS) reads its own Surge-like format: `Name = Protocol,server,port,…`
// with secrets in double quotes. Syntax from https://nsloon.app/docs/Node/.
// Its documentation describes no TUIC v5 line and only tcp/ws transports, so
// those are refused by name rather than guessed at.
function loonRefusal(p) {
  const net = p.network || 'tcp';
  if (p.protocol === 'tuic') return 'Loon\'s documentation describes no TUIC v5 line — use the Clash or Sing-Box bundle for this one';
  if (p.protocol === 'vless-reality' && net !== 'tcp') return `Loon carries Reality over raw TCP only, not ${net}`;
  if (['vmess', 'vless-tls', 'trojan'].includes(p.protocol) && !['tcp', 'ws'].includes(net)) {
    return `Loon has no ${net} transport for ${p.protocol} (tcp and ws only)`;
  }
  const plugin = C.ssPluginKind(p.plugin);
  if (p.protocol === 'shadowsocks' && plugin === 'v2ray') return 'Loon has no v2ray-plugin (Shadowsocks over WebSocket) — only simple-obfs and ShadowTLS';
  if (p.protocol === 'shadowsocks' && plugin === 'other') return `Loon cannot run the ${p.plugin} plugin`;
  if (p.protocol === 'hysteria2' && p.obfs && p.obfs !== 'salamander') return `Loon has no "${p.obfs}" obfuscation for Hysteria2`;
  return null;
}

const LOON_QUOTE_UNSAFE = /["\r\n]/;

function loonLine(p, name) {
  // Quoted values may hold commas but not a quote; the rest are written bare.
  const quoted = [['password', p.password], ['uuid', p.uuid], ['public key', p.publicKey], ['obfs password', p.obfsPassword], ['ALPN', p.alpn]];
  const badQuote = quoted.find(([, v]) => v && LOON_QUOTE_UNSAFE.test(String(v)));
  if (badQuote) return { skip: `the ${badQuote[0]} contains a double quote, which Loon cannot escape` };
  const bad = unsafeField(p, ['server', p.server], ['method', p.method], ['plugin options', p.plugin_opts],
    ['name', name], ['sni', p.sni], ['ws path', p.path], ['Host header', p.host], ['short id', p.shortId]);
  if (bad) return { skip: bad };
  const net = p.network || 'tcp';
  const tls = () => [`sni=${p.sni || p.server}`, `skip-cert-verify=${!!p.insecure}`];
  const ws = () => (net === 'ws' ? [`path=${p.path || '/'}`, ...(p.host ? [`host=${p.host}`] : [])] : []);
  const alpn = () => (p.alpn ? [`alpn="${p.alpn}"`] : []);
  let parts;
  let udp = true;
  if (p.protocol === 'shadowsocks') {
    parts = ['Shadowsocks', p.server, p.port, p.method, `"${p.password}"`];
    const kind = C.ssPluginKind(p.plugin);
    if (kind === 'obfs') {
      const { mode, host, uri } = C.simpleObfsOpts(p.plugin_opts);
      parts.push(`obfs-name=${mode}`, `obfs-host=${host || p.server}`);
      if (uri && mode === 'http') parts.push(`obfs-uri=${uri}`);
      udp = false; // simple-obfs wraps TCP only
    } else if (kind === 'shadowtls') {
      const st = C.shadowTlsOpts(p.plugin_opts);
      if (LOON_QUOTE_UNSAFE.test(st.password) || UNSAFE_VALUE.test(st.host)) return { skip: 'the ShadowTLS options hold a character Loon cannot escape' };
      parts.push(`shadow-tls-password="${st.password}"`, `shadow-tls-sni=${st.host}`, `shadow-tls-version=${st.version}`);
    }
  } else if (p.protocol === 'vmess') {
    const cipher = p.cipher === 'zero' ? 'none' : (p.cipher || 'auto');
    parts = ['VMess', p.server, p.port, cipher, `"${p.uuid}"`, `transport=${net}`, `alterId=${Number(p.alterId || 0)}`, ...ws()];
    if (p.tls) parts.push('over-tls=true', ...tls(), ...alpn());
  } else if (p.protocol === 'vless-reality') {
    parts = ['VLESS', p.server, p.port, `"${p.uuid}"`, 'transport=tcp'];
    if (p.flow) parts.push(`flow=${p.flow}`);
    parts.push(`public-key="${p.publicKey}"`);
    if (p.shortId) parts.push(`short-id=${p.shortId}`);
    parts.push('over-tls=true', `sni=${p.sni}`);
  } else if (p.protocol === 'vless-tls') {
    parts = ['VLESS', p.server, p.port, `"${p.uuid}"`, `transport=${net}`, ...ws()];
    if (net === 'tcp' && p.flow) parts.push(`flow=${p.flow}`);
    parts.push('over-tls=true', ...tls(), ...alpn());
  } else if (p.protocol === 'trojan') {
    parts = ['Trojan', p.server, p.port, `"${p.password}"`, ...(net === 'ws' ? ['transport=ws', ...ws()] : []), ...tls(), ...alpn()];
  } else if (p.protocol === 'hysteria2') {
    parts = ['Hysteria2', p.server, p.port, `"${p.password}"`, ...tls()];
    if (p.obfs === 'salamander') parts.push(`salamander-password="${p.obfsPassword}"`);
    const ports = C.normalizePortRange(p.ports);
    if (ports) parts.push(`server-ports="${ports.replace(/-/g, ':')}"`, `hop-interval=${C.normalizeHopInterval(p.hopInterval)}`);
    if (p.down) parts.push(`download-bandwidth=${p.down}`);
  } else if (p.protocol === 'anytls') {
    parts = ['AnyTLS', p.server, p.port, `"${p.password}"`, ...tls(), ...alpn()];
  } else {
    return { skip: `no Loon mapping for ${p.protocol}` };
  }
  const pin = C.pinOf(p);
  if (pin) parts.push(`tls-cert-sha256=${pin}`);
  parts.push(`udp=${udp}`);
  return { line: `${name} = ${parts.join(',')}` };
}

function buildLoon(profiles, { title = C.DEFAULT_TITLE, rules = null, preferred = null } = {}) {
  const entries = planEntries(profiles, { refuse: loonRefusal, line: (p, name) => loonLine(p, name), chains: false, client: 'Loon' });
  const { skipped, usable, carriedNames, list } = tally(entries);
  const names = entries.map((e) => e.name);
  const lead = preferredLead(list, names, usable, preferred);
  const regions = C.regionGroupsEnabled(rules) ? C.regionGroups(list, carriedNames) : [];
  const test = `url=${C.HEALTH_CHECK_URL},interval=300`;
  const groups = usable.length > 1
    ? [
      `Auto = url-test,${usable.join(',')},${test},tolerance=50`,
      `Fallback = fallback,${C.leadWith(usable, lead).join(',')},${test},max-timeout=3000`,
      ...regions.map((r) => `${r.name} = url-test,${r.members.join(',')},${test},tolerance=50`),
      `PROXY = select,${lead ? 'Fallback,Auto' : 'Auto,Fallback'},${[...regions.map((r) => r.name), ...usable, 'DIRECT'].join(',')}`,
    ]
    : [`PROXY = select,${[...usable, 'DIRECT'].join(',')}`];
  const lines = [
    `# ${title} — generated by airport-tool. Edit servers.json, not this file.`,
    '',
    '[General]',
    'ipv6 = false',
    'dns-server = 223.5.5.5, 119.29.29.29',
    'skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local',
    'bypass-tun = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255/32',
    `proxy-test-url = ${C.HEALTH_CHECK_URL}`,
    '',
    '[Proxy]',
    ...entries.map((e) => (e.skip ? `# ${e.name}: skipped — ${e.skip}` : e.line)),
    '',
    '[Proxy Group]',
    ...groups,
    '',
    '[Rule]',
    ...surgeCustomRules(rules),
    ...(C.adsEnabled(rules) ? ['# Ad blocking (geosite category-ads-all) is in the Clash and Sing-Box bundles only.'] : []),
    ...(C.warpEnabled(rules) ? ['# The WARP exit for streaming and AI sites is in the Clash and Sing-Box bundles only.'] : []),
    'GEOIP,CN,DIRECT',
    'FINAL,PROXY',
    '',
  ];
  if (skipped.length) {
    lines.push('# Servers left out of this file, and why:');
    for (const s of skipped) lines.push(`#   ${s.name}: ${s.reason}`);
    lines.push('');
  }
  return { text: lines.join('\n'), skipped, usable: usable.length, total: list.length };
}

// ── Stash ──────────────────────────────────────────────────────────────────── //
// Stash (iOS/macOS) reads Clash YAML, with a few differences from mihomo that
// stop a mihomo bundle from loading as-is (https://stash.wiki/en/proxy-protocols/
// proxy-types): Hysteria2's secret is `auth` and its rates `up-speed` /
// `down-speed`, TUIC needs `version: 5`, the certificate pin is
// `server-cert-fingerprint`, and there is no HTTPUpgrade transport, no sing-mux
// and no dialer-proxy. The mihomo-only top-level keys (geox-url, sniffer, …)
// are left out; Stash ships its own databases.
function stashRefusal(p) {
  if (['trojan', 'vmess', 'vless-tls'].includes(p.protocol) && p.network === 'httpupgrade') {
    return 'Stash has no HTTPUpgrade transport — use the Clash or Sing-Box bundle for this one';
  }
  if (p.protocol === 'shadowsocks' && C.ssPluginKind(p.plugin) === 'other') return `Stash cannot run the ${p.plugin} plugin`;
  const errors = C.validateProfile(p).errors;
  return errors.length ? errors.join('; ') : null;
}

function stashProxy(p, name) {
  // sing-mux is a client preference; a client without it still connects.
  const px = C.buildClashProxy({ ...p, mux: false }, name);
  if (px.fingerprint) {
    px['server-cert-fingerprint'] = px.fingerprint;
    delete px.fingerprint;
  }
  if (p.protocol === 'hysteria2') {
    px.auth = px.password;
    delete px.password;
    delete px.up;
    delete px.down;
    if (p.up) px['up-speed'] = p.up;
    if (p.down) px['down-speed'] = p.down;
  }
  if (p.protocol === 'tuic') {
    px.version = 5;
    delete px['udp-relay-mode'];
    delete px['reduce-rtt'];
  }
  return px;
}

const PRIVATE_CIDRS = ['10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16'];

function buildStash(profiles, { title = C.DEFAULT_TITLE, rules = null, preferred = null } = {}) {
  const entries = planEntries(profiles, { refuse: stashRefusal, line: (p, name) => ({ proxy: stashProxy(p, name) }), chains: false, client: 'Stash' });
  const { skipped, usable, carriedNames, list } = tally(entries);
  const names = entries.map((e) => e.name);
  const lead = preferredLead(list, names, usable, preferred);
  const regions = C.regionGroupsEnabled(rules) ? C.regionGroups(list, carriedNames) : [];
  const multi = usable.length > 1;
  const groups = [{
    name: 'PROXY', type: 'select',
    proxies: [...(multi ? (lead ? ['Fallback', 'Auto'] : ['Auto', 'Fallback']) : []), ...regions.map((r) => r.name), ...usable, 'DIRECT'],
  }];
  if (multi) {
    groups.push({ name: 'Auto', type: 'url-test', proxies: usable, url: C.HEALTH_CHECK_URL, interval: 300, tolerance: 50 });
    groups.push({ name: 'Fallback', type: 'fallback', proxies: C.leadWith(usable, lead), url: C.HEALTH_CHECK_URL, interval: 300 });
  }
  for (const r of regions) groups.push({ name: r.name, type: 'url-test', proxies: r.members, url: C.HEALTH_CHECK_URL, interval: 300, tolerance: 50 });
  const config = {
    mode: 'rule',
    'log-level': 'info',
    dns: {
      'default-nameserver': [...C.CN_NAMESERVERS],
      nameserver: [...C.CN_NAMESERVERS],
      'fake-ip-filter': [...C.FAKE_IP_FILTER, ...C.serverDomains(list)],
    },
    proxies: entries.filter((e) => !e.skip).map((e) => e.proxy),
    'proxy-groups': groups,
    rules: [
      ...PRIVATE_CIDRS.map((c) => `IP-CIDR,${c},DIRECT,no-resolve`),
      ...C.clashCustomRules(rules),
      ...(C.adsEnabled(rules) ? [`GEOSITE,${C.ADS_GEOSITE},REJECT`] : []),
      'DOMAIN-SUFFIX,cn,DIRECT',
      'GEOSITE,CN,DIRECT',
      'GEOIP,CN,DIRECT',
      'AND,((NETWORK,udp),(DST-PORT,443)),REJECT',
      'MATCH,PROXY',
    ],
  };
  const head = [
    `# ${String(title).replace(/[\r\n]/g, ' ')} — Stash config generated by airport-tool. Edit servers.json, not this file.`,
    ...(C.warpEnabled(rules) ? ['# The WARP exit for streaming and AI sites is in the Clash and Sing-Box bundles only.'] : []),
    ...(skipped.length ? ['# Servers left out of this file, and why:', ...skipped.map((s) => `#   ${s.name}: ${String(s.reason).replace(/[\r\n]/g, ' ')}`)] : []),
  ];
  return { text: `${head.join('\n')}\n${C.toYaml(config)}`, skipped, usable: usable.length, total: list.length };
}

// What each client would be able to carry, without building the files. The
// dashboard shows this beside the download buttons: a Surge config that quietly
// held two of your five servers is only noticed when you reach for one of the
// missing two, so the count belongs on screen before the download, not just in
// a comment inside the file.
function supportSummary(profiles) {
  const list = C.enabledProfiles(profiles);
  const names = C.uniqueNames(list);
  const summarize = (refuse) => {
    const skipped = [];
    list.forEach((p, i) => {
      const reason = C.relayProblem(profiles, p) || refuse(p);
      if (reason) skipped.push({ name: names[i], reason });
    });
    return { total: list.length, usable: list.length - skipped.length, skipped };
  };
  // The line formats are planned exactly as the builders plan them, so a relay
  // the file lacks or a name it cannot write is counted the same way.
  const planned = (opts) => {
    const { skipped } = tally(planEntries(profiles, opts));
    return { total: list.length, usable: list.length - skipped.length, skipped };
  };
  return {
    clash: summarize((p) => C.validateProfile(p).errors.join('; ') || null),
    // XHTTP, and a Shadowsocks plugin other than obfs-local / v2ray-plugin:
    // either one makes sing-box refuse the whole file. See singBoxRefusal.
    singbox: summarize((p) => C.singBoxRefusal(p) || C.validateProfile(p).errors.join('; ') || null),
    surge: planned({ refuse: surgeRefusal, line: surgeProxyLine, chains: true, client: 'Surge' }),
    quantumultx: planned({ refuse: quantumultRefusal, line: (p, n) => quantumultLine(p, n), chains: false, client: 'Quantumult X' }),
    loon: planned({ refuse: loonRefusal, line: (p, n) => loonLine(p, n), chains: false, client: 'Loon' }),
    stash: planned({ refuse: stashRefusal, line: () => ({}), chains: false, client: 'Stash' }),
  };
}

module.exports = {
  surgeRefusal,
  quantumultRefusal,
  loonRefusal,
  stashRefusal,
  supportSummary,
  buildSurge,
  buildQuantumultX,
  buildLoon,
  buildStash,
};
