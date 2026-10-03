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
  if (p.protocol === 'shadowsocks' && p.plugin) {
    return `Surge's Shadowsocks support covers simple-obfs, not the ${p.plugin} WebSocket transport`;
  }
  if (p.protocol === 'shadowsocks' && !SURGE_SS_METHODS.has(p.method)) {
    return `Surge has no ${p.method} cipher`;
  }
  if ((p.protocol === 'trojan' || p.protocol === 'vmess') && net === 'grpc') {
    return 'Surge has no gRPC transport';
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
  if (p.protocol === 'shadowsocks' && p.plugin && p.plugin !== 'v2ray-plugin') {
    return `Quantumult X can only carry v2ray-plugin, not ${p.plugin}`;
  }
  if ((p.protocol === 'trojan' || p.protocol === 'vmess' || p.protocol === 'vless-tls') && net === 'grpc') {
    return 'Quantumult X has no gRPC transport';
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

function unsafeField(p, ...fields) {
  for (const [label, value] of fields) {
    if (!value) continue;
    if (label === 'name' ? UNSAFE_NAME.test(String(value)) : UNSAFE_VALUE.test(String(value))) {
      return label === 'name'
        ? 'the name contains a comma or an equals sign, which this format cannot escape'
        : `the ${label} contains a comma, which this format cannot escape`;
    }
  }
  return null;
}

// Every free-text field either format might put on a line.
function lineFields(p, name) {
  return [
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
function surgeProxyLine(p, name) {
  const bad = unsafeField(p, ...lineFields(p, name));
  if (bad) return { skip: bad };
  const net = p.network || 'tcp';
  const parts = [];
  const notes = [];

  if (p.protocol === 'shadowsocks') {
    parts.push('ss', p.server, String(p.port),
      `encrypt-method=${p.method}`, `password=${p.password}`);
    // UDP relay is opt-in for Shadowsocks in Surge, and a bare server relays it.
    parts.push('udp-relay=true');
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

  if (net === 'ws' && (p.protocol === 'trojan' || p.protocol === 'vmess')) {
    parts.push('ws=true', `ws-path=${p.path || '/'}`);
    if (p.host) parts.push(`ws-headers=Host:${p.host}`);
  }
  return { line: `${name} = ${parts.join(', ')}`, notes };
}

// A whole Surge profile, not just the [Proxy] block: a bare proxy list is not
// something Surge will load, and the rules are the part that keeps CN traffic
// off the tunnel — the same split the Clash and Sing-Box builders apply.
function buildSurge(profiles, { title = C.DEFAULT_TITLE, rules = null, preferred = null } = {}) {
  const list = C.enabledProfiles(profiles);
  const names = C.uniqueNames(list);
  const proxies = [];
  const skipped = [];

  list.forEach((p, i) => {
    const refusal = surgeRefusal(p);
    const built = refusal ? { skip: refusal } : surgeProxyLine(p, names[i]);
    if (built.skip) {
      skipped.push({ name: names[i], reason: built.skip });
      proxies.push(`# ${names[i]}: skipped — ${built.skip}`);
      return;
    }
    for (const note of built.notes || []) proxies.push(`# ${note}`);
    proxies.push(built.line);
  });

  const usable = names.filter((n) => !skipped.some((s) => s.name === n));
  // With nothing usable there is no group to build, and Surge refuses a
  // policy-group with an empty member list — so say so in the file itself.
  const groupMembers = usable.length ? [...usable, 'DIRECT'] : ['DIRECT'];
  const autoMembers = usable.length > 1 ? usable : null;
  // With a ★ to honour, Fallback leads the selector and ★ leads Fallback.
  const lead = preferredLead(list, names, usable, preferred);
  const fallbackMembers = autoMembers ? C.leadWith(autoMembers, lead) : null;

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
        `PROXY = select, ${lead ? 'Fallback, Auto' : 'Auto, Fallback'}, ${groupMembers.join(', ')}`]
      : [`PROXY = select, ${groupMembers.join(', ')}`]),
    '',
    '[Rule]',
    'RULE-SET,SYSTEM,DIRECT',
    'RULE-SET,LAN,DIRECT',
    // Your own lists, ahead of the geographic rule. See checkRules.
    ...surgeCustomRules(rules),
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
  const authority = `${p.server}:${p.port}`;
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
  const list = C.enabledProfiles(profiles);
  const names = C.uniqueNames(list);
  const servers = [];
  const skipped = [];

  list.forEach((p, i) => {
    const refusal = quantumultRefusal(p);
    const built = refusal ? { skip: refusal } : quantumultLine(p, names[i]);
    if (built.skip) {
      skipped.push({ name: names[i], reason: built.skip });
      servers.push(`; ${names[i]}: skipped — ${built.skip}`);
      return;
    }
    servers.push(built.line);
  });

  const usable = names.filter((n) => !skipped.some((s) => s.name === n));
  const lead = preferredLead(list, names, usable, preferred);
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
      ? [`static=PROXY, ${lead ? 'Fallback, Fastest' : 'Fastest, Fallback'}, ${usable.join(', ')}, direct`,
        `url-latency-benchmark=Fastest, ${usable.join(', ')}`,
        `available=Fallback, ${C.leadWith(usable, lead).join(', ')}`]
      : usable.length
        ? [`static=PROXY, ${usable.join(', ')}, direct`]
        : ['static=PROXY, direct']),
    '',
    '[filter_local]',
    // Your own lists, ahead of the geographic rule. See checkRules.
    ...quantumultCustomRules(rules),
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
      const reason = refuse(p);
      if (reason) skipped.push({ name: names[i], reason });
    });
    return { total: list.length, usable: list.length - skipped.length, skipped };
  };
  return {
    surge: summarize(surgeRefusal),
    quantumultx: summarize(quantumultRefusal),
  };
}

module.exports = {
  surgeRefusal,
  quantumultRefusal,
  supportSummary,
  buildSurge,
  buildQuantumultX,
};
