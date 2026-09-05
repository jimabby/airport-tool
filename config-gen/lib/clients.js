// Config output for the two clients that do not read Clash or Sing-Box files:
// Surge (macOS/iOS) and Quantumult X (iOS).
//
// Both use their own INI-ish plain-text format, and — the part that matters —
// neither supports every protocol this tool models. Surge has no VLESS/Reality
// and no TUIC; Quantumult X has neither of those plus no QUIC protocols at all.
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
// skipped by name too.

'use strict';

const C = require('./configs');

// ── What each client can actually carry ────────────────────────────────────── //
// Returns a sentence explaining the refusal, or null when the profile is
// expressible. Written as one function per client so the two lists cannot drift
// apart from the builders that consult them.
function surgeRefusal(p) {
  const net = p.network || 'tcp';
  if (p.protocol === 'vless-reality') {
    return 'Surge has no VLESS or Reality support — use the Clash or Sing-Box bundle for this one';
  }
  if (p.protocol === 'tuic') {
    return 'Surge has no TUIC support — use the Clash or Sing-Box bundle for this one';
  }
  if (p.protocol === 'shadowsocks' && p.plugin) {
    return `Surge's Shadowsocks support covers simple-obfs, not the ${p.plugin} WebSocket transport`;
  }
  if ((p.protocol === 'trojan' || p.protocol === 'vmess') && net === 'grpc') {
    return 'Surge has no gRPC transport';
  }
  return null;
}

function quantumultRefusal(p) {
  const net = p.network || 'tcp';
  if (p.protocol === 'vless-reality') {
    return 'Quantumult X has no VLESS or Reality support — use the Clash or Sing-Box bundle for this one';
  }
  if (p.protocol === 'hysteria2' || p.protocol === 'tuic') {
    return `Quantumult X has no ${p.protocol} support — QUIC protocols need the Clash or Sing-Box bundle`;
  }
  if (p.protocol === 'shadowsocks' && p.plugin && p.plugin !== 'v2ray-plugin') {
    return `Quantumult X can only carry v2ray-plugin, not ${p.plugin}`;
  }
  if ((p.protocol === 'trojan' || p.protocol === 'vmess') && net === 'grpc') {
    return 'Quantumult X has no gRPC transport';
  }
  return null;
}

// Both clients' formats are comma-separated key=value lists, and a comma or an
// equals sign inside a password would split the line in the wrong place. Neither
// format defines an escape, so the honest move is to refuse the line rather than
// emit one that parses into something else.
const UNSAFE_VALUE = /[,=\r\n]/;

function unsafeField(p, ...fields) {
  for (const [name, value] of fields) {
    if (value && UNSAFE_VALUE.test(String(value))) {
      return `the ${name} contains a comma or an equals sign, which this format cannot escape`;
    }
  }
  return null;
}

// ── Surge ──────────────────────────────────────────────────────────────────── //
function surgeProxyLine(p, name) {
  const bad = unsafeField(p, ['password', p.password], ['uuid', p.uuid], ['name', name]);
  if (bad) return { skip: bad };
  const net = p.network || 'tcp';
  const parts = [];

  if (p.protocol === 'shadowsocks') {
    parts.push('ss', p.server, String(p.port),
      `encrypt-method=${p.method}`, `password=${p.password}`);
  } else if (p.protocol === 'trojan') {
    parts.push('trojan', p.server, String(p.port), `password=${p.password}`);
    parts.push(`sni=${p.sni || p.server}`);
    if (p.insecure) parts.push('skip-cert-verify=true');
  } else if (p.protocol === 'vmess') {
    parts.push('vmess', p.server, String(p.port), `username=${p.uuid}`);
    // Surge names the payload cipher this, and does not accept "auto".
    parts.push(`encrypt-method=${p.cipher === 'auto' || !p.cipher ? 'aes-128-gcm' : p.cipher}`);
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
    // Port hopping: Surge spells the range with a dash, like the profile does.
    const ports = C.normalizePortRange(p.ports);
    if (ports) parts.push(`port-hopping=${ports}`, `port-hopping-interval=${p.hopInterval || 30}`);
  } else {
    return { skip: `no Surge mapping for ${p.protocol}` };
  }

  if (net === 'ws') {
    parts.push('ws=true', `ws-path=${p.path || '/'}`);
    if (p.host) parts.push(`ws-headers=Host:${p.host}`);
  }
  parts.push('udp-relay=true');
  return { line: `${name} = ${parts.join(', ')}` };
}

// A whole Surge profile, not just the [Proxy] block: a bare proxy list is not
// something Surge will load, and the rules are the part that keeps CN traffic
// off the tunnel — the same split the Clash and Sing-Box builders apply.
function buildSurge(profiles, { title = C.DEFAULT_TITLE } = {}) {
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
    proxies.push(built.line);
  });

  const usable = names.filter((n) => !skipped.some((s) => s.name === n));
  // With nothing usable there is no group to build, and Surge refuses a
  // policy-group with an empty member list — so say so in the file itself.
  const groupMembers = usable.length ? [...usable, 'DIRECT'] : ['DIRECT'];
  const autoMembers = usable.length > 1 ? usable : null;

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
        `Fallback = fallback, ${autoMembers.join(', ')}, url = http://www.gstatic.com/generate_204, interval = 300`,
        `PROXY = select, Auto, Fallback, ${groupMembers.join(', ')}`]
      : [`PROXY = select, ${groupMembers.join(', ')}`]),
    '',
    '[Rule]',
    'RULE-SET,SYSTEM,DIRECT',
    'RULE-SET,LAN,DIRECT',
    'GEOIP,CN,DIRECT',
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
  const bad = unsafeField(p, ['password', p.password], ['uuid', p.uuid], ['name', name]);
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
  } else if (p.protocol === 'trojan') {
    parts.push(`trojan=${authority}`, `password=${p.password}`, 'over-tls=true');
    parts.push(`tls-host=${p.sni || p.server}`);
    parts.push(`tls-verification=${p.insecure ? 'false' : 'true'}`);
    if (net === 'ws') {
      parts.push('obfs=wss', `obfs-uri=${p.path || '/'}`);
      if (p.host) parts.push(`obfs-host=${p.host}`);
    }
  } else if (p.protocol === 'vmess') {
    // Quantumult X carries the VMess UUID in `password` and always sets
    // method=none; the payload cipher is not configurable there.
    parts.push(`vmess=${authority}`, 'method=none', `password=${p.uuid}`);
    if (net === 'ws') {
      parts.push(`obfs=${p.tls ? 'wss' : 'ws'}`, `obfs-uri=${p.path || '/'}`);
      if (p.host) parts.push(`obfs-host=${p.host}`);
    } else if (p.tls) {
      parts.push('obfs=over-tls', `obfs-host=${p.sni || p.server}`);
    }
    if (p.tls && p.insecure) parts.push('tls-verification=false');
  } else {
    return { skip: `no Quantumult X mapping for ${p.protocol}` };
  }

  parts.push('udp-relay=true', `tag=${name}`);
  return { line: parts.join(', ') };
}

function buildQuantumultX(profiles, { title = C.DEFAULT_TITLE } = {}) {
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
      ? [`static=PROXY, Fastest, Fallback, ${usable.join(', ')}, direct`,
        `url-latency-benchmark=Fastest, ${usable.join(', ')}`,
        `available=Fallback, ${usable.join(', ')}`]
      : usable.length
        ? [`static=PROXY, ${usable.join(', ')}, direct`]
        : ['static=PROXY, direct']),
    '',
    '[filter_local]',
    'geoip cn, direct',
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
