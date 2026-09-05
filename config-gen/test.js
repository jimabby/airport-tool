#!/usr/bin/env node
// Tests for the shared config model + builders. No test framework — just the
// built-in assert module, so `npm test` needs no extra dependencies.
// Run: node test.js  (or: npm test)

'use strict';

const assert = require('assert');
const C = require('./lib/configs');
const K = require('./lib/clients');

let passed = 0;
function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log('✓', name);
  } catch (err) {
    console.error('✗', name);
    console.error('  ', err.message);
    process.exitCode = 1;
  }
}

// ── normalizeStore accepts all supported shapes ──────────────────────────────── //
test('normalizeStore: canonical multi-profile store', () => {
  const s = C.normalizeStore({ active: 1, profiles: [{ server: 'a', port: 1 }, { server: 'b', port: 2 }] });
  assert.strictEqual(s.profiles.length, 2);
  assert.strictEqual(s.active, 1);
});

test('normalizeStore: bare array', () => {
  const s = C.normalizeStore([{ server: 'a', port: 1 }]);
  assert.strictEqual(s.profiles.length, 1);
  assert.strictEqual(s.active, 0);
});

test('normalizeStore: legacy single object', () => {
  const s = C.normalizeStore({ server: 'a', port: 1, password: 'p' });
  assert.strictEqual(s.profiles.length, 1);
  assert.strictEqual(s.profiles[0].protocol, 'shadowsocks');
});

test('normalizeStore: out-of-range active is clamped to 0', () => {
  assert.strictEqual(C.normalizeStore({ active: 9, profiles: [{ server: 'a', port: 1 }] }).active, 0);
  assert.strictEqual(C.normalizeStore({ active: -3, profiles: [{ server: 'a', port: 1 }] }).active, 0);
});

test('normalizeStore: keeps a usable token, drops a junk one', () => {
  const tok = C.newToken();
  assert.strictEqual(C.normalizeStore({ profiles: [], token: tok }).token, tok);
  assert.strictEqual(C.normalizeStore({ profiles: [], token: 'short' }).token, null);
  assert.strictEqual(C.normalizeStore({ profiles: [], token: 42 }).token, null);
});

test('normalizeProfile: infers vless-reality from uuid', () => {
  assert.strictEqual(C.normalizeProfile({ uuid: 'x' }).protocol, 'vless-reality');
});

test('normalizeProfile: unknown protocol falls back to shadowsocks', () => {
  assert.strictEqual(C.normalizeProfile({ protocol: 'wireguard' }).protocol, 'shadowsocks');
  assert.strictEqual(C.normalizeProfile({ protocol: 'hy2', password: 'p' }).protocol, 'hysteria2');
});

// A profile id is interpolated into the web UI's DOM and used as an API key, so
// anything that isn't a real UUID must be replaced rather than trusted.
test('normalizeProfile: rejects a non-UUID id', () => {
  const evil = "x'); alert(1); ('";
  const p = C.normalizeProfile({ id: evil, server: 's', port: 1, password: 'p' });
  assert.notStrictEqual(p.id, evil);
  assert.ok(C.isUuid(p.id), `expected a UUID, got ${p.id}`);
});

test('normalizeProfile: preserves a valid UUID id', () => {
  const id = '6f1e3b7c-2a44-4c9d-8f10-1b2c3d4e5f60';
  assert.strictEqual(C.normalizeProfile({ id, server: 's', port: 1, password: 'p' }).id, id);
});

// ── missingFields / validateProfile ──────────────────────────────────────────── //
test('missingFields: reports empty reality fields', () => {
  const p = C.normalizeProfile({ protocol: 'vless-reality', server: 's', port: 443 });
  assert.deepStrictEqual(C.missingFields(p).sort(), ['publicKey', 'sni', 'uuid']);
});

test('missingFields: complete SS profile is valid', () => {
  const p = C.normalizeProfile({ server: 's', port: 8388, password: 'p', method: 'aes-256-gcm' });
  assert.deepStrictEqual(C.missingFields(p), []);
});

test('missingFields: hysteria2 needs server, port and password', () => {
  const p = C.normalizeProfile({ protocol: 'hysteria2', server: 's' });
  assert.deepStrictEqual(C.missingFields(p).sort(), ['password', 'port']);
});

test('validateProfile: rejects an out-of-range port', () => {
  const p = C.normalizeProfile({ server: 's', port: 70000, password: 'p', method: 'aes-256-gcm' });
  assert.ok(C.validateProfile(p).errors.some((e) => /out of range/.test(e)));
});

test('validateProfile: rejects an IP as a Reality SNI', () => {
  const p = C.normalizeProfile({
    protocol: 'vless-reality', server: 's', port: 443,
    uuid: 'u', publicKey: 'k', sni: '1.2.3.4',
  });
  assert.ok(C.validateProfile(p).errors.some((e) => /sni must be a real domain/.test(e)));
});

test('validateProfile: warns about TLS without a host', () => {
  const p = C.normalizeProfile({
    server: 's', port: 8388, password: 'p', method: 'aes-256-gcm', plugin_opts: 'server;tls',
  });
  const { errors, warnings } = C.validateProfile(p);
  assert.deepStrictEqual(errors, []);
  assert.ok(warnings.some((w) => /no host=/.test(w)));
});

// ── clientPluginOpts strips server-only tokens ───────────────────────────────── //
test('clientPluginOpts: drops server/cert/key, keeps tls/host/path', () => {
  const out = C.clientPluginOpts('server;tls;host=ex.com;cert=/a;key=/b;path=/ws');
  assert.strictEqual(out, 'tls;host=ex.com;path=/ws');
});

// ── SS URI conforms to SIP002 (base64url userinfo, no padding) ───────────────── //
test('buildSsUri: userinfo is base64url without padding', () => {
  const p = C.normalizeProfile({ server: '1.1.1.1', port: 8388, password: 'p+w/x=y', method: 'aes-256-gcm' });
  const uri = C.buildSsUri(p);
  const userinfo = uri.slice('ss://'.length, uri.indexOf('@'));
  assert.ok(!/[+/=]/.test(userinfo), `userinfo must not contain +, / or =: ${userinfo}`);
  assert.strictEqual(Buffer.from(userinfo, 'base64url').toString(), 'aes-256-gcm:p+w/x=y');
});

test('buildUri: brackets a bare IPv6 literal', () => {
  const p = C.normalizeProfile({ server: '2001:db8::1', port: 8388, password: 'p', method: 'aes-256-gcm' });
  assert.ok(C.buildSsUri(p).includes('@[2001:db8::1]:8388'), C.buildSsUri(p));
});

// ── uniqueNames de-duplicates collisions ─────────────────────────────────────── //
test('uniqueNames: suffixes duplicate labels in order', () => {
  const profiles = [{ remarks: 'Airport' }, { remarks: 'Airport' }, { remarks: 'Tokyo' }, { remarks: 'Airport' }];
  assert.deepStrictEqual(C.uniqueNames(profiles), ['Airport', 'Airport 2', 'Tokyo', 'Airport 3']);
});

// Regression: gen.js used to write `profiles.map(C.buildUri)`, which hands map's
// index in as the display name — every line after the first was labelled "#1",
// "#2", … instead of the profile's own remarks.
test('buildUri: a numeric name argument never becomes the label', () => {
  const profiles = [
    C.normalizeProfile({ server: '1.1.1.1', port: 8388, password: 'p', method: 'aes-256-gcm', remarks: 'Tokyo' }),
    C.normalizeProfile({ server: '2.2.2.2', port: 8389, password: 'q', method: 'aes-256-gcm', remarks: 'Osaka' }),
  ];
  const names = C.uniqueNames(profiles);
  const uris = profiles.map((p, i) => C.buildUri(p, names[i]));
  assert.deepStrictEqual(uris.map((u) => decodeURIComponent(u.split('#')[1])), ['Tokyo', 'Osaka']);
});

// ── Hysteria2 ────────────────────────────────────────────────────────────────── //
const hy2 = C.normalizeProfile({
  protocol: 'hysteria2', server: '3.3.3.3', port: 443, password: 'pw/+=',
  sni: 'www.bing.com', insecure: true, obfs: 'salamander', obfsPassword: 'ob s',
  remarks: 'HK',
});

test('buildHy2Uri: percent-encodes the password and carries every option', () => {
  const uri = C.buildHy2Uri(hy2);
  const u = new URL(uri);
  assert.strictEqual(u.protocol, 'hysteria2:');
  assert.strictEqual(decodeURIComponent(u.username), 'pw/+=');
  assert.strictEqual(u.searchParams.get('sni'), 'www.bing.com');
  assert.strictEqual(u.searchParams.get('insecure'), '1');
  assert.strictEqual(u.searchParams.get('obfs'), 'salamander');
  assert.strictEqual(u.searchParams.get('obfs-password'), 'ob s');
});

test('buildHy2Uri: omits obfs-password when obfs is off', () => {
  const plain = C.normalizeProfile({ protocol: 'hysteria2', server: 's', port: 443, password: 'p' });
  const u = new URL(C.buildHy2Uri(plain));
  assert.strictEqual(u.searchParams.get('obfs'), null);
  assert.strictEqual(u.searchParams.get('insecure'), null);
});

// ── URI parsing round-trips ──────────────────────────────────────────────────── //
const roundTrip = [
  ['shadowsocks', C.normalizeProfile({
    server: '1.1.1.1', port: 8388, password: 'p@ss w/+=', method: 'aes-256-gcm',
    plugin_opts: 'server;tls;host=ex.com;path=/ws', remarks: 'Tokyo SS',
  })],
  ['vless-reality', C.normalizeProfile({
    protocol: 'vless-reality', server: '2.2.2.2', port: 443,
    uuid: '11111111-2222-3333-4444-555555555555', publicKey: 'PUBKEY', shortId: 'ab12',
    sni: 'www.microsoft.com', remarks: 'SG Reality',
  })],
  ['hysteria2', hy2],
];

for (const [label, original] of roundTrip) {
  test(`parseUri: ${label} survives build → parse`, () => {
    const back = C.parseUri(C.buildUri(original));
    assert.strictEqual(back.protocol, original.protocol);
    assert.strictEqual(back.server, original.server);
    assert.strictEqual(back.port, original.port);
    assert.strictEqual(back.remarks, original.remarks);
    if (original.protocol === 'shadowsocks') {
      assert.strictEqual(back.password, original.password);
      assert.strictEqual(back.method, original.method);
      // The parsed profile describes the server again, so `server` comes back.
      assert.strictEqual(back.plugin_opts, original.plugin_opts);
    } else if (original.protocol === 'vless-reality') {
      assert.strictEqual(back.uuid, original.uuid);
      assert.strictEqual(back.publicKey, original.publicKey);
      assert.strictEqual(back.shortId, original.shortId);
      assert.strictEqual(back.sni, original.sni);
    } else {
      assert.strictEqual(back.password, original.password);
      assert.strictEqual(back.insecure, original.insecure);
      assert.strictEqual(back.obfs, original.obfs);
      assert.strictEqual(back.obfsPassword, original.obfsPassword);
    }
  });
}

test('parseUri: accepts the legacy all-base64 ss:// form', () => {
  const legacy = 'ss://' + Buffer.from('aes-256-gcm:hunter2@9.9.9.9:8388').toString('base64') + '#Old';
  const p = C.parseUri(legacy);
  assert.strictEqual(p.server, '9.9.9.9');
  assert.strictEqual(p.port, 8388);
  assert.strictEqual(p.method, 'aes-256-gcm');
  assert.strictEqual(p.password, 'hunter2');
  assert.strictEqual(p.remarks, 'Old');
});

test('parseUri: accepts the hy2:// alias', () => {
  assert.strictEqual(C.parseUri('hy2://pw@1.2.3.4:443/#X').protocol, 'hysteria2');
});

test('parseUri: rejects an unknown scheme and a non-Reality vless', () => {
  // trojan:// used to be the example here, which stopped being true the moment
  // Trojan was supported. Anything still genuinely unhandled does the job.
  assert.throws(() => C.parseUri('wireguard://x@y:443'), /Unsupported URI scheme/);
  assert.throws(() => C.parseUri('socks5://u:p@h:1080'), /Unsupported URI scheme/);
  assert.throws(() => C.parseUri('vless://u@h:443?security=tls'), /not supported/);
});

test('parseSubscription: decodes base64 and reports bad lines', () => {
  const profiles = roundTrip.map(([, p]) => p);
  const blob = C.buildSubscription(profiles);
  const parsed = C.parseSubscription(blob);
  assert.strictEqual(parsed.profiles.length, 3);
  assert.deepStrictEqual(parsed.errors, []);

  const mixed = C.parseSubscription('ss://bogus\nnot-a-uri');
  assert.strictEqual(mixed.profiles.length, 0);
  assert.strictEqual(mixed.errors.length, 2);
});

test('parseSubscription: accepts a plain multi-line paste', () => {
  const text = roundTrip.map(([, p]) => C.buildUri(p)).join('\n');
  assert.strictEqual(C.parseSubscription(text).profiles.length, 3);
});

// ── bundled configs never emit duplicate names/tags ──────────────────────────── //
const dupProfiles = [
  C.normalizeProfile({ server: '1.1.1.1', port: 8388, password: 'p', method: 'aes-256-gcm' }),
  C.normalizeProfile({ protocol: 'vless-reality', server: '2.2.2.2', port: 443, uuid: 'u', publicKey: 'k', sni: 'www.microsoft.com' }),
  hy2,
];

test('buildClashConfig: unique proxy names and valid groups', () => {
  const cfg = C.buildClashConfig(dupProfiles);
  const names = cfg.proxies.map((p) => p.name);
  assert.strictEqual(new Set(names).size, names.length, `duplicate names: ${names}`);
  // Every proxy a group references must be a real proxy or another group.
  const groupNames = cfg['proxy-groups'].map((g) => g.name);
  const known = new Set([...names, ...groupNames, 'DIRECT']);
  for (const g of cfg['proxy-groups']) {
    for (const ref of g.proxies) assert.ok(known.has(ref), `group ${g.name} references unknown ${ref}`);
  }
});

test('buildClashConfig: emits a url-test group only when it can fail over', () => {
  const many = C.buildClashConfig(dupProfiles)['proxy-groups'];
  assert.ok(many.some((g) => g.type === 'url-test'), 'expected an Auto group for multiple servers');
  const one = C.buildClashConfig([dupProfiles[0]])['proxy-groups'];
  assert.ok(!one.some((g) => g.type === 'url-test'), 'a single server needs no Auto group');
  assert.ok(!one[0].proxies.includes('Auto'), 'PROXY must not reference a group that was not emitted');
});

// LAN traffic must never be tunnelled: without this rule, router admin pages and
// local dev servers get shipped to the VPS.
test('buildClashConfig: keeps private ranges direct, before the CN rule', () => {
  const rules = C.buildClashConfig(dupProfiles).rules;
  const priv = rules.findIndex((r) => /^GEOIP,PRIVATE,DIRECT/.test(r));
  assert.ok(priv !== -1, `no private rule in ${rules}`);
  assert.ok(priv < rules.indexOf('MATCH,PROXY'));
});

// Resolvers must be reachable from behind the firewall, or nothing resolves and
// the GEOIP rules never get a chance to classify anything.
test('buildClashConfig: primary DNS is domestic, foreign resolvers ride the tunnel', () => {
  const dns = C.buildClashConfig(dupProfiles).dns;
  assert.ok(!dns.nameserver.some((n) => /8\.8\.8\.8|1\.1\.1\.1/.test(n)),
    `blocked resolvers must not be primary: ${dns.nameserver}`);
  // The fallback is where a foreign name is really resolved, so it is the one
  // query that must not go out in the clear: a plain UDP packet to a blocked
  // resolver is answered by the firewall, not by the resolver.
  assert.ok(dns.fallback.length, 'there must be a foreign fallback');
  for (const server of dns.fallback) {
    assert.ok(server.startsWith('https://'), `fallback must be DoH: ${server}`);
    assert.ok(server.endsWith('#PROXY'), `fallback must ride the tunnel: ${server}`);
  }
  // Resolving the proxy's own hostname through the proxy is a cycle; it has to
  // be pinned to a resolver that answers without one.
  assert.deepStrictEqual(dns['proxy-server-nameserver'], dns.nameserver);
});

test('buildClashConfig: a server named by domain never gets a fake IP', () => {
  const byName = [
    C.normalizeProfile({ protocol: 'trojan', server: 'proxy.example.com', port: 443, password: 'p', sni: 'proxy.example.com' }),
    C.normalizeProfile({ protocol: 'hysteria2', server: '203.0.113.9', port: 443, password: 'p', insecure: true }),
  ];
  const dns = C.buildClashConfig(byName).dns;
  assert.ok(dns['fake-ip-filter'].includes('proxy.example.com'),
    'the proxy hostname must be exempt, or the client dials 198.18.x.x');
  // An IP literal is not a name and has nothing to exempt.
  assert.ok(!dns['fake-ip-filter'].includes('203.0.113.9'));
  // The captive-portal and NTP names that break under fake-ip are there too.
  assert.ok(dns['fake-ip-filter'].includes('captive.apple.com'));
});

test('foreign QUIC is refused, in both bundles, so the browser falls back to TCP', () => {
  const rules = C.buildClashConfig(dupProfiles).rules;
  const quic = rules.findIndex((r) => r.includes('DST-PORT,443') && r.endsWith('REJECT'));
  assert.ok(quic !== -1, 'no QUIC reject rule in the Clash bundle');
  // It has to sit after the DIRECT rules, or domestic UDP/443 dies with it.
  assert.ok(quic > rules.indexOf('GEOIP,CN,DIRECT'));
  assert.strictEqual(rules[rules.length - 1], 'MATCH,PROXY');

  const sbRules = C.buildSingBox(dupProfiles).route.rules;
  const sbQuic = sbRules.findIndex((r) => r.action === 'reject');
  assert.ok(sbQuic !== -1, 'no QUIC reject rule in the Sing-Box bundle');
  assert.deepStrictEqual(sbRules[sbQuic].port, [443]);
  const cnDirect = sbRules.findIndex((r) => Array.isArray(r.rule_set) && r.outbound === 'direct');
  assert.ok(sbQuic > cnDirect, 'the reject must come after the CN direct rules');
});

test('buildClashProxy: a plugin-less Shadowsocks server is allowed to carry UDP', () => {
  const bare = C.normalizeProfile({
    protocol: 'shadowsocks', server: '1.2.3.4', port: 8388,
    password: 'p', method: 'chacha20-ietf-poly1305', plugin: '',
  });
  assert.strictEqual(C.buildClashProxy(bare, 'Bare').udp, true);
  // v2ray-plugin's WebSocket cannot, so claiming it would swallow every UDP
  // packet handed to this proxy.
  const plugged = C.normalizeProfile({
    protocol: 'shadowsocks', server: '1.2.3.4', port: 8388,
    password: 'p', method: 'chacha20-ietf-poly1305',
  });
  assert.strictEqual(C.buildClashProxy(plugged, 'WS').udp, false);
});

test('buildSingBox: the proxy server\'s own name resolves without the proxy', () => {
  const byName = [
    C.normalizeProfile({ protocol: 'trojan', server: 'proxy.example.com', port: 443, password: 'p', sni: 'proxy.example.com' }),
  ];
  const dns = C.buildSingBox(byName).dns;
  // `final` is dns-remote, which is detoured through the proxy. Without a rule
  // pinning the server's own name to the local resolver, building the proxy
  // needs the proxy — and sing-box just never connects.
  const pin = dns.rules.find((r) => Array.isArray(r.domain) && r.domain.includes('proxy.example.com'));
  assert.ok(pin, 'the server hostname is not pinned to the domestic resolver');
  assert.strictEqual(pin.server, 'dns-local');
  assert.strictEqual(dns.rules.indexOf(pin), 0, 'the pin has to come first');
  // A store that names every server by IP has nothing to pin and gets no rule.
  assert.ok(!C.buildSingBox(dupProfiles).dns.rules.some((r) => r.domain));
});

test('buildSingBoxOutbound: VLESS names its UDP encoding rather than inheriting one', () => {
  const out = C.buildSingBoxOutbound(C.normalizeProfile({
    protocol: 'vless-reality', server: '2.2.2.2', port: 443,
    uuid: '11111111-1111-4111-8111-111111111111', publicKey: 'k', sni: 'www.microsoft.com',
  }), 'R');
  assert.strictEqual(out.packet_encoding, 'xudp');
});

test('buildClashProxy: hysteria2 carries password, sni and obfs', () => {
  const proxy = C.buildClashProxy(hy2, 'HK');
  assert.strictEqual(proxy.type, 'hysteria2');
  assert.strictEqual(proxy.password, 'pw/+=');
  assert.strictEqual(proxy['skip-cert-verify'], true);
  assert.strictEqual(proxy.obfs, 'salamander');
});

test('buildSingBox: unique tags and selector default resolves', () => {
  const sb = C.buildSingBox(dupProfiles);
  const proxyTypes = new Set(['vless', 'shadowsocks', 'hysteria2']);
  const tags = sb.outbounds.filter((o) => proxyTypes.has(o.type)).map((o) => o.tag);
  assert.strictEqual(new Set(tags).size, tags.length, `duplicate tags: ${tags}`);
  const all = new Set(sb.outbounds.map((o) => o.tag));
  const selector = sb.outbounds.find((o) => o.type === 'selector');
  assert.ok(all.has(selector.default), 'selector default must be a real outbound');
  selector.outbounds.forEach((t) => assert.ok(all.has(t), `selector references unknown ${t}`));
});

test('buildSingBox: urltest group appears only with multiple servers', () => {
  assert.ok(C.buildSingBox(dupProfiles).outbounds.some((o) => o.type === 'urltest'));
  const one = C.buildSingBox([dupProfiles[0]]);
  assert.ok(!one.outbounds.some((o) => o.type === 'urltest'));
  assert.strictEqual(one.outbounds.find((o) => o.type === 'selector').default, one.outbounds[1].tag);
});

// The pre-1.11 schema (a `dns` outbound, inline geoip route rules, split
// socks/http inbounds) is deprecated upstream and removed in newer releases.
test('buildSingBox: uses the modern 1.11+ schema', () => {
  const sb = C.buildSingBox(dupProfiles);
  assert.ok(!sb.outbounds.some((o) => o.type === 'dns'), 'the dns outbound type is removed upstream');
  assert.ok(sb.inbounds.some((i) => i.type === 'mixed'));
  assert.ok(sb.route.rules.some((r) => r.action === 'hijack-dns'));
  assert.ok(sb.route.rules.some((r) => r.ip_is_private === true));
  assert.ok(!sb.route.rules.some((r) => r.geoip), 'inline geoip rules are deprecated');
  // Every rule_set referenced by a route or DNS rule must actually be defined.
  const defined = new Set(sb.route.rule_set.map((r) => r.tag));
  const referenced = [...sb.route.rules, ...sb.dns.rules]
    .flatMap((r) => (Array.isArray(r.rule_set) ? r.rule_set : r.rule_set ? [r.rule_set] : []));
  referenced.forEach((t) => assert.ok(defined.has(t), `undefined rule_set ${t}`));
  // Rule sets are fetched through the proxy — they're unreachable directly from
  // inside the firewall, which is the only place this config gets used.
  sb.route.rule_set.forEach((rs) => assert.strictEqual(rs.download_detour, 'proxy'));
});

test('buildSubscription: decodes to unique per-line labels', () => {
  const decoded = Buffer.from(C.buildSubscription(dupProfiles), 'base64').toString('utf8');
  const labels = decoded.split('\n').map((u) => decodeURIComponent(u.split('#')[1]));
  assert.strictEqual(new Set(labels).size, labels.length, `duplicate labels: ${labels}`);
});

// ── YAML emitter ─────────────────────────────────────────────────────────────── //
test('toYaml: skips null and undefined, keeps false and 0', () => {
  const out = C.toYaml({ a: null, b: undefined, c: false, d: 0 });
  assert.ok(!/a:/.test(out) && !/b:/.test(out));
  assert.ok(/c: false/.test(out) && /d: 0/.test(out));
});

test('toYaml: nests maps inside list items', () => {
  const yaml = C.buildClashYaml([dupProfiles[0]]);
  assert.ok(/ {4}plugin-opts:\n {6}mode: "websocket"/.test(yaml), yaml);
});


// ── base64url subscriptions ──────────────────────────────────────────────────── //
// Regression: the base64 detector's character class omitted `_`, so any blob
// using the URL-safe alphabet fell through to line-by-line URI parsing and
// failed as a whole. Plenty of providers hand out exactly that alphabet.
test('parseSubscription: decodes a base64url blob containing "_"', () => {
  let urlsafe = null;
  for (let i = 0; i < 500 && !urlsafe; i += 1) {
    const p = C.normalizeProfile({ server: '9.9.9.9', port: 8388, password: `pw${i}`, method: 'aes-256-gcm', remarks: `X${i}` });
    const b = C.buildSubscription([p]).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    if (b.includes('_')) urlsafe = b;
  }
  assert.ok(urlsafe, 'could not construct a blob containing "_"');
  const parsed = C.parseSubscription(urlsafe);
  assert.deepStrictEqual(parsed.errors, []);
  assert.strictEqual(parsed.profiles.length, 1);
});

// ── TUIC v5 ──────────────────────────────────────────────────────────────────── //
const tuic = C.normalizeProfile({
  protocol: 'tuic', server: '4.4.4.4', port: 443,
  uuid: '22222222-3333-4444-5555-666666666666', password: 'pw/+= x',
  sni: 'www.bing.com', insecure: true, remarks: 'TUIC HK',
});

test('buildTuicUri: encodes both halves of the credential', () => {
  const u = new URL(C.buildTuicUri(tuic));
  assert.strictEqual(u.protocol, 'tuic:');
  assert.strictEqual(decodeURIComponent(u.username), tuic.uuid);
  assert.strictEqual(decodeURIComponent(u.password), 'pw/+= x');
  assert.strictEqual(u.searchParams.get('congestion_control'), 'bbr');
  assert.strictEqual(u.searchParams.get('udp_relay_mode'), 'native');
  assert.strictEqual(u.searchParams.get('allow_insecure'), '1');
});

test('parseUri: tuic survives build → parse', () => {
  const back = C.parseUri(C.buildUri(tuic));
  assert.strictEqual(back.protocol, 'tuic');
  assert.strictEqual(back.uuid, tuic.uuid);
  assert.strictEqual(back.password, tuic.password);
  assert.strictEqual(back.sni, tuic.sni);
  assert.strictEqual(back.insecure, true);
  assert.strictEqual(back.remarks, tuic.remarks);
});

test('missingFields: tuic needs a uuid and a password', () => {
  const p = C.normalizeProfile({ protocol: 'tuic', server: 's', port: 443 });
  assert.deepStrictEqual(C.missingFields(p).sort(), ['password', 'uuid']);
});

test('buildClashProxy / buildSingBoxOutbound: tuic carries both credentials', () => {
  const proxy = C.buildClashProxy(tuic, 'HK');
  assert.strictEqual(proxy.type, 'tuic');
  assert.strictEqual(proxy.uuid, tuic.uuid);
  assert.strictEqual(proxy.password, tuic.password);
  assert.strictEqual(proxy['skip-cert-verify'], true);
  assert.deepStrictEqual(proxy.alpn, ['h3']);

  const out = C.buildSingBoxOutbound(tuic, 'HK');
  assert.strictEqual(out.type, 'tuic');
  assert.strictEqual(out.uuid, tuic.uuid);
  assert.strictEqual(out.password, tuic.password);
  assert.strictEqual(out.tls.insecure, true);
});

// ── VLESS transports ─────────────────────────────────────────────────────────── //
// xtls-rprx-vision is a raw-TCP flow. Xray rejects it on grpc/xhttp outright, so
// a profile carrying both is one the client silently fails to connect with.
test('normalizeProfile: the Vision flow is dropped on non-tcp transports', () => {
  const base = { protocol: 'vless-reality', server: 's', port: 443, uuid: 'u', publicKey: 'k', sni: 'www.microsoft.com' };
  assert.strictEqual(C.normalizeProfile({ ...base }).flow, 'xtls-rprx-vision');
  assert.strictEqual(C.normalizeProfile({ ...base, network: 'grpc' }).flow, '');
  assert.strictEqual(C.normalizeProfile({ ...base, network: 'xhttp' }).flow, '');
  assert.strictEqual(C.normalizeProfile({ ...base, network: 'quic' }).network, 'tcp');
});

test('validateProfile: rejects a flow a non-tcp transport cannot use', () => {
  // A hand-written store can still carry the illegal pair; validation catches it.
  const p = {
    ...C.normalizeProfile({
      protocol: 'vless-reality', server: 's', port: 443, uuid: 'u', publicKey: 'k',
      sni: 'www.microsoft.com', network: 'grpc', serviceName: 'x',
    }),
    flow: 'xtls-rprx-vision',
  };
  assert.ok(C.validateProfile(p).errors.some((e) => /only works over tcp/.test(e)));
});

for (const [network, extra] of [['grpc', { serviceName: 'svc' }], ['xhttp', { path: '/abc' }]]) {
  test(`parseUri: vless over ${network} survives build → parse`, () => {
    const p = C.normalizeProfile({
      protocol: 'vless-reality', server: '2.2.2.2', port: 443, uuid: 'u',
      publicKey: 'k', shortId: 'ab12', sni: 'www.microsoft.com', network, remarks: 'T', ...extra,
    });
    const back = C.parseUri(C.buildUri(p));
    assert.strictEqual(back.network, network);
    assert.strictEqual(back.flow, '');
    if (network === 'grpc') assert.strictEqual(back.serviceName, 'svc');
    else assert.strictEqual(back.path, '/abc');
  });
}

test('buildClashProxy: a vless transport never emits an empty flow', () => {
  const p = C.normalizeProfile({
    protocol: 'vless-reality', server: 's', port: 443, uuid: 'u', publicKey: 'k',
    sni: 'www.microsoft.com', network: 'grpc', serviceName: 'svc',
  });
  const proxy = C.buildClashProxy(p, 'G');
  assert.ok(!('flow' in proxy), 'mihomo reads an empty flow as a flow it does not know');
  assert.strictEqual(proxy.network, 'grpc');
  assert.strictEqual(proxy['grpc-opts']['grpc-service-name'], 'svc');
  const out = C.buildSingBoxOutbound(p, 'G');
  assert.ok(!('flow' in out));
  assert.strictEqual(out.transport.type, 'grpc');
});

// ── Client configs must work on the devices the README points at ─────────────── //
// The mobile Sing-Box apps route system traffic through a tun inbound. With only
// a loopback mixed inbound the app connects and carries nothing.
test('buildSingBox: includes a tun inbound with auto_route', () => {
  const inbounds = C.buildSingBox(dupProfiles).inbounds;
  const tun = inbounds.find((i) => i.type === 'tun');
  assert.ok(tun, `no tun inbound in ${inbounds.map((i) => i.type)}`);
  assert.strictEqual(tun.auto_route, true);
  assert.ok(inbounds.some((i) => i.type === 'mixed'), 'the desktop mixed inbound must survive too');
});

// GEOIP/GEOSITE rules are dead weight until the database exists, and mihomo's
// default download URLs are on GitHub — unreachable from inside the firewall.
test('buildClashConfig: geo databases come from a reachable mirror', () => {
  const cfg = C.buildClashConfig(dupProfiles);
  const urls = Object.values(cfg['geox-url']);
  assert.strictEqual(urls.length, 3);
  urls.forEach((u) => assert.ok(!/github\.com|githubusercontent\.com/.test(u), `unreachable geo source: ${u}`));
});

// ── Store secrets ────────────────────────────────────────────────────────────── //
// The subscription token and the dashboard token are deliberately separate: one
// hands a client your servers, the other hands it write access to them.
test('normalizeStore: keeps subscription and dashboard tokens apart', () => {
  const sub = C.newToken();
  const ui = C.newToken();
  const s = C.normalizeStore({ profiles: [], token: sub, uiToken: ui });
  assert.strictEqual(s.token, sub);
  assert.strictEqual(s.uiToken, ui);
  assert.notStrictEqual(sub, ui);
  assert.strictEqual(C.normalizeStore({ profiles: [], uiToken: 'short' }).uiToken, null);
});

// ── Hysteria2 port hopping ───────────────────────────────────────────────────── //
const HOP = {
  protocol: 'hysteria2', server: '203.0.113.7', port: 443, password: 'pw',
  sni: 'www.bing.com', insecure: true, remarks: 'Hop',
};

test('normalizePortRange: accepts the forms clients and servers actually write', () => {
  assert.strictEqual(C.normalizePortRange('20000-30000'), '20000-30000');
  assert.strictEqual(C.normalizePortRange('20000:30000'), '20000-30000');
  assert.strictEqual(C.normalizePortRange(' 20000 - 30000 '), '20000-30000');
  assert.strictEqual(C.normalizePortRange('443,20000-30000'), '443,20000-30000');
  assert.strictEqual(C.normalizePortRange('443'), '443');
  // Anything unusable collapses to '' so validateProfile can reject it rather
  // than a client choking on a range it cannot parse.
  assert.strictEqual(C.normalizePortRange('abc'), '');
  assert.strictEqual(C.normalizePortRange('30000-20000'), '', 'backwards range');
  assert.strictEqual(C.normalizePortRange('0-100'), '', 'port 0');
  assert.strictEqual(C.normalizePortRange('1-70000'), '', 'above 65535');
  assert.strictEqual(C.normalizePortRange(''), '');
});

test('validateProfile: a malformed port range is an error, not a silent drop', () => {
  const bad = C.validateProfile(C.normalizeProfile({ ...HOP, ports: 'nope' }));
  assert.ok(bad.errors.some((e) => /port range/.test(e)), bad.errors.join(';'));
  const single = C.validateProfile(C.normalizeProfile({ ...HOP, ports: '443' }));
  assert.strictEqual(single.errors.length, 0);
  assert.ok(single.warnings.some((w) => /single port/.test(w)), single.warnings.join(';'));
  assert.strictEqual(C.validateProfile(C.normalizeProfile({ ...HOP, ports: '20000-30000' })).errors.length, 0);
});

test('hysteria2 URI: the hopping range survives a round trip', () => {
  const p = C.normalizeProfile({ ...HOP, ports: '20000:30000', hopInterval: 45 });
  const uri = C.buildUri(p);
  assert.ok(uri.includes('mport=20000-30000'), uri);
  const back = C.parseUri(uri);
  assert.strictEqual(back.ports, '20000-30000');
  assert.strictEqual(back.hopInterval, 45);
  // No range means no mport at all — an empty one makes some clients refuse
  // the whole profile.
  assert.ok(!C.buildUri(C.normalizeProfile(HOP)).includes('mport'));
});

test('hopInterval: out-of-range values fall back rather than reaching a client', () => {
  assert.strictEqual(C.normalizeProfile({ ...HOP, hopInterval: 1 }).hopInterval, C.DEFAULT_HOP_INTERVAL);
  assert.strictEqual(C.normalizeProfile({ ...HOP, hopInterval: 99999 }).hopInterval, C.DEFAULT_HOP_INTERVAL);
  assert.strictEqual(C.normalizeProfile({ ...HOP, hopInterval: 'x' }).hopInterval, C.DEFAULT_HOP_INTERVAL);
  assert.strictEqual(C.normalizeProfile({ ...HOP, hopInterval: 60 }).hopInterval, 60);
});

test('hopping reaches both client builders in the dialect each one speaks', () => {
  const p = C.normalizeProfile({ ...HOP, ports: '20000-30000', hopInterval: 45 });
  const clash = C.buildClashProxy(p, 'Hop');
  assert.strictEqual(clash.ports, '20000-30000');
  assert.strictEqual(clash['hop-interval'], 45);
  assert.strictEqual(clash.port, 443, 'mihomo keeps the single port as a fallback');

  const sb = C.buildSingBoxOutbound(p, 'Hop');
  assert.deepStrictEqual(sb.server_ports, ['20000:30000']);
  assert.strictEqual(sb.hop_interval, '45s');
  // sing-box rejects a config carrying both, so the range must replace it.
  assert.ok(!('server_port' in sb), 'server_port must give way to server_ports');

  const plain = C.buildSingBoxOutbound(C.normalizeProfile(HOP), 'Plain');
  assert.strictEqual(plain.server_port, 443);
  assert.ok(!('server_ports' in plain));
});

// ── Sing-Box desktop variant ─────────────────────────────────────────────────── //
// The tun inbound needs root, so `sing-box run` on a laptop dies on the config
// the phone apps require.
test('buildSingBox: tun:false yields a config a desktop can actually run', () => {
  const desktop = C.buildSingBox(dupProfiles, { tun: false });
  assert.ok(!desktop.inbounds.some((i) => i.type === 'tun'));
  assert.ok(desktop.inbounds.some((i) => i.type === 'mixed'), 'still needs a way in');
  assert.ok(!desktop.route.rules.some((r) => r.action === 'hijack-dns'),
    'DNS hijacking is meaningless without tun');
  // Everything else must be identical, or the two configs would behave
  // differently for reasons that have nothing to do with the interface.
  assert.deepStrictEqual(desktop.outbounds, C.buildSingBox(dupProfiles).outbounds);
});

test('buildSingBox: rule sets come from a mirror reachable behind the firewall', () => {
  const urls = C.buildSingBox(dupProfiles).route.rule_set.map((r) => r.url);
  assert.ok(urls.length >= 2);
  urls.forEach((u) => assert.ok(!/github\.com|githubusercontent\.com/.test(u), `unreachable rule set: ${u}`));
});

test('buildClashConfig: the selected proxy is remembered across restarts', () => {
  assert.strictEqual(C.buildClashConfig(dupProfiles).profile['store-selected'], true);
});

// ── Health monitor settings ──────────────────────────────────────────────────── //
test('normalizeMonitor: clamps the interval and defaults to off', () => {
  assert.deepStrictEqual(C.normalizeMonitor(undefined), C.MONITOR_DEFAULTS);
  assert.strictEqual(C.normalizeMonitor({ intervalMin: 0 }).intervalMin, 1);
  assert.strictEqual(C.normalizeMonitor({ intervalMin: 99999 }).intervalMin, 1440);
  assert.strictEqual(C.normalizeMonitor({ intervalMin: 'x' }).intervalMin, C.MONITOR_DEFAULTS.intervalMin);
  assert.strictEqual(C.normalizeMonitor({ enabled: 'true' }).enabled, true);
  // Moving the ★ on its own is a bigger promise than measuring, so it stays
  // separate from `enabled`.
  assert.strictEqual(C.normalizeMonitor({ enabled: true }).autoSwitch, false);
});

test('normalizeStore: carries the monitor settings', () => {
  const s = C.normalizeStore({ profiles: [], monitor: { enabled: true, intervalMin: 30, autoSwitch: true } });
  assert.strictEqual(s.monitor.enabled, true);
  assert.strictEqual(s.monitor.intervalMin, 30);
  assert.strictEqual(C.normalizeStore({ profiles: [] }).monitor.enabled, false);
});

// ── Plain Shadowsocks: a server with no plugin at all ────────────────────────── //
// Importing a plugin-less ss:// link used to substitute v2ray-plugin, producing
// a client that wrapped its traffic in a WebSocket the server had never heard
// of — and there was no way to express "no plugin" at all.
const plainSsUri = 'ss://' + Buffer.from('aes-256-gcm:pw123').toString('base64url') + '@1.2.3.4:8388#Plain';

test('parseSsUri: a link with no plugin= stays plugin-less', () => {
  const p = C.parseUri(plainSsUri);
  assert.strictEqual(p.plugin, '');
  assert.strictEqual(p.plugin_opts, '');
});

test('normalizeProfile: absent plugin still defaults, empty means none', () => {
  // Absent is "unspecified", which has always meant what setup.sh installs.
  assert.strictEqual(C.normalizeProfile({ protocol: 'shadowsocks', server: 'a', port: 1 }).plugin, 'v2ray-plugin');
  assert.strictEqual(C.normalizeProfile({ protocol: 'shadowsocks', plugin: '' }).plugin, '');
  assert.strictEqual(C.normalizeProfile({ protocol: 'shadowsocks', plugin: 'none' }).plugin, '');
  // Options describe a plugin; with none there is nothing for them to configure.
  assert.strictEqual(C.normalizeProfile({ protocol: 'shadowsocks', plugin: '', plugin_opts: 'server;tls' }).plugin_opts, '');
});

test('a plugin-less profile survives a build → parse round trip', () => {
  const p = C.parseUri(plainSsUri);
  assert.ok(!C.buildUri(p).includes('plugin='), 'the URI must not advertise a plugin');
  assert.strictEqual(C.parseUri(C.buildUri(p)).plugin, '');
});

test('no plugin means no plugin keys in either client config', () => {
  const p = C.parseUri(plainSsUri);
  const clash = C.buildClashProxy(p);
  assert.ok(!('plugin' in clash), 'Clash starts whatever `plugin` names');
  assert.ok(!('plugin-opts' in clash));
  const sing = C.buildSingBoxOutbound(p);
  assert.ok(!('plugin' in sing));
  assert.ok(!('plugin_opts' in sing));
});

test('a v2ray-plugin profile still carries its plugin everywhere', () => {
  const p = C.normalizeProfile({
    protocol: 'shadowsocks', server: '1.2.3.4', port: 8388, password: 'p',
    method: 'aes-256-gcm', plugin_opts: 'server;tls;host=a.example',
  });
  assert.ok(C.buildUri(p).includes('plugin=v2ray-plugin'));
  assert.strictEqual(C.buildClashProxy(p).plugin, 'v2ray-plugin');
  assert.strictEqual(C.buildClashProxy(p)['plugin-opts'].host, 'a.example');
  // Server-only keywords must never reach a client.
  assert.ok(!C.buildSingBoxOutbound(p).plugin_opts.includes('server'));
});

// ── Hysteria2 declared bandwidth ─────────────────────────────────────────────── //
// Without these the client falls back to BBR instead of Brutal, which is most of
// the reason to run Hysteria2 on a lossy path.
const hyBw = C.normalizeProfile({
  protocol: 'hysteria2', server: '1.2.3.4', port: 443, password: 'p', up: 50, down: 200,
});

test('normalizeMbps: rejects nonsense and treats 0 as unset', () => {
  assert.strictEqual(C.normalizeMbps('50'), 50);
  assert.strictEqual(C.normalizeMbps(-5), 0);
  assert.strictEqual(C.normalizeMbps('abc'), 0);
  assert.strictEqual(C.normalizeMbps(99999), 10000);
});

test('bandwidth reaches both client builders in the dialect each one speaks', () => {
  assert.strictEqual(C.buildClashProxy(hyBw).up, '50 Mbps');
  assert.strictEqual(C.buildClashProxy(hyBw).down, '200 Mbps');
  assert.strictEqual(C.buildSingBoxOutbound(hyBw).up_mbps, 50);
  assert.strictEqual(C.buildSingBoxOutbound(hyBw).down_mbps, 200);
});

test('bandwidth survives a share-link round trip', () => {
  const back = C.parseUri(C.buildUri(hyBw));
  assert.strictEqual(back.up, 50);
  assert.strictEqual(back.down, 200);
});

test('an unset bandwidth leaves the keys out rather than sending zeros', () => {
  const bare = C.normalizeProfile({ protocol: 'hysteria2', server: 'a', port: 443, password: 'p' });
  assert.ok(!('up_mbps' in C.buildSingBoxOutbound(bare)));
  assert.ok(!('up' in C.buildClashProxy(bare)));
  assert.ok(!C.buildUri(bare).includes('up='));
  // …but say so, because the silent fallback to BBR is the surprising part.
  assert.ok(C.validateProfile(bare).warnings.some((w) => /BBR/.test(w)));
});

// ── Enable / disable ─────────────────────────────────────────────────────────── //
const onProfile = C.normalizeProfile({ protocol: 'shadowsocks', server: '1.1.1.1', port: 8388, password: 'p', remarks: 'On' });
const offProfile = C.normalizeProfile({ protocol: 'shadowsocks', server: '2.2.2.2', port: 8388, password: 'p', remarks: 'Off', enabled: false });

test('enabled defaults to true so every store written before it keeps working', () => {
  assert.strictEqual(onProfile.enabled, true);
  assert.strictEqual(offProfile.enabled, false);
  assert.strictEqual(C.isEnabled({}), true);
});

test('a disabled profile reaches no bundled config', () => {
  const both = [onProfile, offProfile];
  assert.strictEqual(C.enabledProfiles(both).length, 1);
  // The subscription matters most: it would otherwise put the server straight
  // back onto the device you were trying to keep it off.
  assert.strictEqual(C.buildSubscription(both), C.buildSubscription([onProfile]));
  assert.strictEqual(C.buildClashConfig(both).proxies.length, 1);
  assert.strictEqual(C.buildSingBox(both).outbounds.filter((o) => o.tag === 'Off').length, 0);
  assert.ok(!C.buildClashYaml(both).includes('2.2.2.2'));
});

test('one enabled profile means no url-test group, as with one profile total', () => {
  const groups = C.buildClashConfig([onProfile, offProfile])['proxy-groups'];
  assert.ok(!groups.some((g) => g.name === 'Auto'), 'a group of one is not a failover group');
});

// ── Per-device subscription tokens ───────────────────────────────────────────── //
test('normalizeClients: keeps usable tokens and drops the rest', () => {
  const list = C.normalizeClients([
    { name: 'Phone', token: 'a'.repeat(32) },
    { name: 'Short', token: 'nope' },            // too short to be a secret
    { name: 'Dup', token: 'a'.repeat(32) },      // the same token twice
    'not an object',
  ]);
  assert.strictEqual(list.length, 1);
  assert.strictEqual(list[0].name, 'Phone');
  assert.ok(C.isUuid(list[0].id), 'every client needs a stable id');
});

test('normalizeStore: carries device tokens and defaults to none', () => {
  const s = C.normalizeStore({ profiles: [], clients: [{ name: 'Laptop', token: 'b'.repeat(32) }] });
  assert.strictEqual(s.clients.length, 1);
  assert.deepStrictEqual(C.normalizeStore({ profiles: [] }).clients, []);
});

// ── Monitor alerting ─────────────────────────────────────────────────────────── //
test('normalizeAlert: refuses a destination that is not http(s)', () => {
  assert.strictEqual(C.normalizeAlert({ enabled: true, url: 'file:///etc/passwd' }).url, '');
  assert.strictEqual(C.normalizeAlert({ enabled: true, url: 'file:///etc/passwd' }).enabled, false);
  // Enabled with nowhere to send is off, whatever the checkbox said.
  assert.strictEqual(C.normalizeAlert({ enabled: true, url: '' }).enabled, false);
  assert.strictEqual(C.normalizeAlert({ enabled: true, url: 'https://x/y' }).enabled, true);
  assert.strictEqual(C.normalizeAlert({ url: 'https://x/y', mode: 'bogus' }).mode, 'json');
});

test('normalizeMonitor: alert settings ride along and survive the store', () => {
  const s = C.normalizeStore({
    profiles: [],
    monitor: { enabled: true, alert: { enabled: true, url: 'https://hook/x', mode: 'text' } },
  });
  assert.strictEqual(s.monitor.alert.mode, 'text');
  assert.strictEqual(s.monitor.alert.url, 'https://hook/x');
  assert.strictEqual(C.normalizeStore({ profiles: [] }).monitor.alert.enabled, false);
});

const A = require('./lib/alert');
const probe = (remarks, ok, enabled = true) => ({ remarks, ok, enabled, protocol: 'shadowsocks' });

test('alert summary: a disabled server being down is not an incident', () => {
  const s = A.summarize([probe('A', true), probe('X', false, false)]);
  assert.strictEqual(s.state, 'ok');
  assert.strictEqual(s.total, 1);
});

test('alert summary: untestable is not the same as down', () => {
  // Bare QUIC without a deep probe answers neither way. Calling that "down"
  // would make the alert lie in exactly the case the deep test exists to fix.
  assert.strictEqual(A.summarize([probe('A', null)]).state, 'unknown');
  assert.strictEqual(A.summarize([probe('A', false), probe('B', null)]).state, 'down');
  assert.strictEqual(A.summarize([probe('A', true), probe('B', false)]).state, 'degraded');
  assert.strictEqual(A.summarize([]).state, 'empty');
});

test('alert summary: an all-clear says how much of it was actually checked', () => {
  const text = A.describe(A.summarize([probe('A', true), probe('B', null)]));
  assert.ok(/1 of 2/.test(text), text);
  assert.ok(/untestable/.test(text), text);
});

test('alerts fire on the transition, not on every pass', () => {
  // afterFailures defaults to 1, which is the behaviour this has always had.
  const on = { enabled: true, url: 'https://x/y', mode: 'json', onEveryPass: false };
  const down = A.summarize([probe('A', false)]);
  const send = (previous, summary, cfg) => A.evaluate(previous, 0, summary, cfg || on).send;
  assert.strictEqual(send('ok', down), true);
  assert.strictEqual(send('down', down), false, 'no hourly "still down"');
  assert.strictEqual(send('down', A.summarize([probe('A', true)])), true);
  // "We could not ask" is not worth waking anybody for.
  assert.strictEqual(send('ok', A.summarize([probe('A', null)])), false);
  assert.strictEqual(send('down', down, { ...on, onEveryPass: true }), true);
  assert.strictEqual(send('ok', down, { ...on, enabled: false }), false);
});

test('alert payload speaks Slack, Discord and generic at once', () => {
  const body = JSON.parse(A.buildRequest({ mode: 'json' }, 'hello').body);
  assert.strictEqual(body.text, 'hello');
  assert.strictEqual(body.content, 'hello');
  assert.strictEqual(body.message, 'hello');
  // ntfy and the SMS bridges want the bare string instead.
  assert.strictEqual(A.buildRequest({ mode: 'text' }, 'hello').body, 'hello');
});

// ── Certificate expiry from the probe history ────────────────────────────────── //
const H = require('./lib/history');
const day = 86400000;

test('summarizeHistory: reports the newest certificate it has seen', () => {
  const soon = Date.now() + 5 * day;
  const s = H.summarizeHistory([
    { at: 1, ok: true, latencyMs: 10, stage: 'tls', certNotAfter: Date.now() + 300 * day },
    { at: 2, ok: true, latencyMs: 10, stage: 'tls', certNotAfter: soon, certOf: 'server' },
    // A deep probe never observes a certificate, and must not erase the last one.
    { at: 3, ok: true, latencyMs: 10, stage: 'deep' },
  ]);
  assert.strictEqual(s.cert.notAfter, soon);
  assert.strictEqual(s.cert.expiring, true);
  assert.strictEqual(s.cert.expired, false);
});

test('summarizeHistory: an expired certificate is flagged, and no cert is null', () => {
  const gone = H.summarizeHistory([{ at: 1, ok: true, latencyMs: 1, stage: 'tls', certNotAfter: Date.now() - 3 * day }]);
  assert.strictEqual(gone.cert.expired, true);
  assert.ok(gone.cert.daysLeft < 0);
  assert.strictEqual(H.summarizeHistory([{ at: 1, ok: true, latencyMs: 1, stage: 'tcp' }]).cert, null);
});

// The two probe helpers below are async, and the harness above is not — so
// they register a promise the summary waits on rather than being counted
// before they have actually run.
const fs = require('fs');
const os = require('os');
const path = require('path');
const P = require('./lib/probe');
const pending = [];
const asyncTest = (name, fn) => pending.push(
  Promise.resolve().then(fn).then(
    () => { passed += 1; console.log('✓', name); },
    (err) => { console.error('✗', name); console.error('  ', err.message); process.exitCode = 1; },
  ),
);
// Regression: the suffix used to be a per-base counter that never checked what
// it was about to collide with, so a profile genuinely named "Airport 2" and
// the suffix minted for a second "Airport" came out identical — and mihomo and
// sing-box both refuse a bundle carrying two proxies of the same name.
test('uniqueNames: a generated suffix never collides with a real name', () => {
  const names = C.uniqueNames([{ remarks: 'Airport' }, { remarks: 'Airport' }, { remarks: 'Airport 2' }]);
  assert.strictEqual(new Set(names).size, 3, `duplicate names: ${names}`);
  assert.deepStrictEqual(names, ['Airport', 'Airport 2', 'Airport 2 2']);
});

test('uniqueNames: the collision survives into the bundles', () => {
  const mk = (remarks) => C.normalizeProfile({
    protocol: 'shadowsocks', server: '1.2.3.4', port: 8388, password: 'p', method: 'aes-256-gcm', remarks,
  });
  const profiles = [mk('Airport'), mk('Airport'), mk('Airport 2')];
  const proxyNames = C.buildClashConfig(profiles).proxies.map((p) => p.name);
  assert.strictEqual(new Set(proxyNames).size, 3, `duplicate clash names: ${proxyNames}`);
  const tags = C.buildSingBox(profiles).outbounds
    .filter((o) => o.type === 'shadowsocks').map((o) => o.tag);
  assert.strictEqual(new Set(tags).size, 3, `duplicate sing-box tags: ${tags}`);
});

// ── UUID validation ──────────────────────────────────────────────────────────── //
// Xray maps a non-UUID id onto one of its own, so a typo there produces a server
// that works and bundles that every client this tool generates for rejects.
test('validateProfile: a malformed VLESS uuid is a hard error', () => {
  const bad = C.normalizeProfile({
    protocol: 'vless-reality', server: '1.2.3.4', port: 443,
    uuid: 'not-a-uuid', publicKey: 'k', shortId: 'ab', sni: 'www.microsoft.com',
  });
  assert.ok(C.validateProfile(bad).errors.some((e) => /uuid/.test(e)));
  const good = C.normalizeProfile({ ...bad, uuid: '11111111-2222-3333-4444-555555555555' });
  assert.deepStrictEqual(C.validateProfile(good).errors, []);
});

test('validateProfile: a malformed TUIC uuid is a hard error', () => {
  const bad = C.normalizeProfile({
    protocol: 'tuic', server: '1.2.3.4', port: 443, uuid: '1234', password: 'p', insecure: true,
  });
  assert.ok(C.validateProfile(bad).errors.some((e) => /uuid/.test(e)));
  const good = C.normalizeProfile({ ...bad, uuid: '11111111-2222-3333-4444-555555555555' });
  assert.deepStrictEqual(C.validateProfile(good).errors, []);
});

// A missing uuid is already reported as "missing uuid"; saying it twice, once
// as a shape complaint, would just be noise.
test('validateProfile: an absent uuid is reported once, as missing', () => {
  const p = C.normalizeProfile({ protocol: 'tuic', server: '1.2.3.4', port: 443, password: 'p', insecure: true });
  const { errors } = C.validateProfile(p);
  assert.deepStrictEqual(errors, ['missing uuid']);
});

// ── sing-box DNS shape ───────────────────────────────────────────────────────── //
// 1.12 replaced the `address` URL string with an explicit type + server pair.
test('buildSingBox: DNS servers use the typed 1.12 shape', () => {
  const cfg = C.buildSingBox([C.normalizeProfile({
    protocol: 'shadowsocks', server: '1.2.3.4', port: 8388, password: 'p', method: 'aes-256-gcm',
  })]);
  for (const s of cfg.dns.servers) {
    assert.ok(s.type, `dns server ${s.tag} has no type`);
    assert.ok(s.server, `dns server ${s.tag} has no server`);
    assert.strictEqual(s.address, undefined, `dns server ${s.tag} still carries the removed address field`);
  }
  assert.deepStrictEqual(cfg.dns.servers.map((s) => s.type), ['https', 'udp']);
});

// ── The deep probe's fetch helper ────────────────────────────────────────────── //
// An https DEEP_TEST_URL used to be sent as an absolute-form GET, which makes
// the proxy open a plain TCP connection to port 443 and speak HTTP at a TLS
// listener — reported as "the server is broken" when it was the probe that
// could not speak. Nothing is listening on this port, so what is under test is
// which path it takes, not whether it succeeds.
asyncTest('fetchThroughProxy: a nonsense scheme is refused rather than attempted', async () => {
  const r = await P.fetchThroughProxy(1, 'ftp://example.com/x', 50);
  assert.strictEqual(r.ok, false);
  assert.ok(/http:\/\/ or https:\/\//.test(r.error), r.error);
});

asyncTest('fetchThroughProxy: an unparseable DEEP_TEST_URL says so', async () => {
  const r = await P.fetchThroughProxy(1, 'not a url', 50);
  assert.strictEqual(r.ok, false);
  assert.ok(/not a URL/.test(r.error), r.error);
});

// ── Monitor state file ───────────────────────────────────────────────────────── //
// The alert state and the per-device last-seen records used to live only in the
// dashboard's memory, so a restart re-sent an alert that had already gone out.
test('monitor state: survives a round trip, and a missing file is not an error', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-state-'));
  const p = path.join(dir, 'monitor-state.json');
  assert.deepStrictEqual(H.loadState(p), { alertState: null, downStreak: 0, clients: {} });
  H.saveState(p, { alertState: 'down', downStreak: 3, clients: { abc: { at: 1234, agent: 'clash' } } });
  const back = H.loadState(p);
  assert.strictEqual(back.alertState, 'down');
  // The failure streak has to survive a restart too, or the flap threshold
  // starts over on every deploy and delays the alert it exists to debounce.
  assert.strictEqual(back.downStreak, 3);
  assert.deepStrictEqual(back.clients.abc, { at: 1234, agent: 'clash' });
  // A corrupt file costs a duplicate alert, not a crash.
  fs.writeFileSync(p, '{ not json');
  assert.deepStrictEqual(H.loadState(p), { alertState: null, downStreak: 0, clients: {} });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('monitor state: statePathFor sits beside the store', () => {
  assert.strictEqual(
    H.statePathFor(path.join('a', 'b', 'servers.json')),
    path.join('a', 'b', 'monitor-state.json'),
  );
});

// ── The shipped example ──────────────────────────────────────────────────────── //
// servers.json.example is the file the README tells people to copy, and CI
// generates from it — so a new validation rule that the example itself trips
// over breaks the documented first step. (A UUID check did exactly that: the
// placeholders read "paste-uuid-from-setup", which is not a UUID.)
test('servers.json.example validates and builds', () => {
  const raw = JSON.parse(fs.readFileSync(path.join(__dirname, 'servers.json.example'), 'utf8'));
  const store = C.normalizeStore(raw);
  assert.ok(store.profiles.length > 1, 'the example should show more than one profile');
  for (const p of store.profiles) {
    const { errors } = C.validateProfile(p);
    assert.deepStrictEqual(errors, [], `${p.remarks}: ${errors.join('; ')}`);
  }
  // And the bundles it produces have to be well formed, not merely produced.
  const names = C.buildClashConfig(store.profiles).proxies.map((x) => x.name);
  assert.strictEqual(new Set(names).size, names.length, `duplicate names: ${names}`);
  assert.ok(C.buildSubscription(store.profiles).length > 0);
});

// ── plugin_opts is a token list, not a string to search ──────────────────────── //
// `opts.includes('tls')` is a substring test, so any host containing "tls"
// turned TLS on in the generated config. The client then wrapped its traffic in
// TLS the server was not serving, and the only symptom was a connection that
// never came up.
test('plugin_opts: tls is matched as a token, not as a substring', () => {
  assert.strictEqual(C.hasOpt('server;tls;host=a.com', 'tls'), true);
  assert.strictEqual(C.hasOpt('server;host=nottls.com', 'tls'), false);
  assert.strictEqual(C.hasOpt('server;host=tls.example.com', 'tls'), false);
  assert.strictEqual(C.hasOpt('server; tls ;host=a.com', 'tls'), true, 'whitespace around a token');
});

test('plugin_opts: getOpt picks the right key, not a suffix match', () => {
  assert.strictEqual(C.getOpt('server;host=a.com;path=/ws', 'host'), 'a.com');
  assert.strictEqual(C.getOpt('server;path=/ws', 'host'), '');
  // /host=([^;]+)/ also matches obfs-host=, and picks it.
  assert.strictEqual(C.getOpt('server;obfs-host=b.com', 'host'), '');
  assert.strictEqual(C.getOpt('server;obfs-host=b.com', 'obfs-host'), 'b.com');
});

test('buildClashProxy: a host containing "tls" does not enable TLS', () => {
  const p = C.normalizeProfile({
    protocol: 'shadowsocks', server: '1.2.3.4', port: 8388, password: 'pw',
    method: 'chacha20-ietf-poly1305', plugin: 'v2ray-plugin',
    plugin_opts: 'server;host=nottls.com',
  });
  const proxy = C.buildClashProxy(p, 'X');
  assert.strictEqual(proxy['plugin-opts'].tls, false);
  assert.strictEqual(proxy['plugin-opts'].host, 'nottls.com');
  // And the real thing still works.
  const withTls = C.normalizeProfile({ ...p, plugin_opts: 'server;tls;host=real.com' });
  assert.strictEqual(C.buildClashProxy(withTls, 'X')['plugin-opts'].tls, true);
});

// ── Shadowsocks ciphers ─────────────────────────────────────────────────────── //
test('validateProfile: an unknown cipher is a warning, not silence', () => {
  const p = C.normalizeProfile({
    protocol: 'shadowsocks', server: '1.2.3.4', port: 8388, password: 'pw',
    method: 'chacha20-ietf-poly1306', plugin: '',
  });
  const { errors, warnings } = C.validateProfile(p);
  assert.deepStrictEqual(errors, []);
  assert.ok(warnings.some((w) => /not one this tool recognises/.test(w)), warnings.join('; '));
});

test('validateProfile: a stream cipher is flagged as pre-AEAD', () => {
  const p = C.normalizeProfile({
    protocol: 'shadowsocks', server: '1.2.3.4', port: 8388, password: 'pw',
    method: 'aes-256-cfb', plugin: '',
  });
  const { errors, warnings } = C.validateProfile(p);
  assert.deepStrictEqual(errors, []);
  assert.ok(warnings.some((w) => /pre-AEAD stream cipher/.test(w)), warnings.join('; '));
});

test('ss2022KeyError: the key has to be base64 of exactly the right length', () => {
  const ok16 = Buffer.alloc(16, 7).toString('base64');
  const ok32 = Buffer.alloc(32, 7).toString('base64');
  assert.strictEqual(C.ss2022KeyError('2022-blake3-aes-128-gcm', ok16), null);
  assert.strictEqual(C.ss2022KeyError('2022-blake3-aes-256-gcm', ok32), null);
  assert.strictEqual(C.ss2022KeyError('2022-blake3-chacha20-poly1305', ok32), null);
  // Right shape, wrong length.
  assert.match(C.ss2022KeyError('2022-blake3-aes-256-gcm', ok16), /32-byte/);
  // A passphrase, which is what people actually type.
  assert.match(C.ss2022KeyError('2022-blake3-aes-128-gcm', 'hunter2'), /not a passphrase/);
  assert.match(C.ss2022KeyError('2022-blake3-aes-128-gcm', ''), /not a passphrase/);
  // Not a 2022 method: no opinion.
  assert.strictEqual(C.ss2022KeyError('aes-256-gcm', 'hunter2'), null);
});

test('validateProfile: a 2022 key of the wrong length blocks generation', () => {
  const p = C.normalizeProfile({
    protocol: 'shadowsocks', server: '1.2.3.4', port: 8388,
    password: 'hunter2', method: '2022-blake3-aes-256-gcm', plugin: '',
  });
  assert.ok(C.validateProfile(p).errors.some((e) => /32-byte base64 key/.test(e)));
  const good = C.normalizeProfile({ ...p, password: Buffer.alloc(32, 1).toString('base64') });
  assert.deepStrictEqual(C.validateProfile(good).errors, []);
});

// ── Trojan ──────────────────────────────────────────────────────────────────── //
test('trojan: URI round-trips over tcp, ws and grpc', () => {
  for (const stream of [
    { network: 'tcp' },
    { network: 'ws', path: '/tj', host: 'cdn.example.com' },
    { network: 'grpc', serviceName: 'svc' },
  ]) {
    const p = C.normalizeProfile({
      protocol: 'trojan', server: 'p.example.com', port: 443,
      password: 'p@ss:w/+=', sni: 'p.example.com', ...stream, remarks: 'TJ',
    });
    const back = C.parseUri(C.buildUri(p));
    for (const k of ['protocol', 'server', 'port', 'password', 'sni', 'network', 'path', 'host', 'serviceName']) {
      assert.strictEqual(back[k], p[k], `${stream.network}: ${k}`);
    }
  }
});

test('trojan: an IPv6 literal is bracketed and comes back bare', () => {
  const p = C.normalizeProfile({
    protocol: 'trojan', server: '2001:db8::1', port: 8443, password: 'pw', sni: 'd.example',
  });
  const uri = C.buildUri(p);
  assert.ok(uri.includes('@[2001:db8::1]:8443'), uri);
  assert.strictEqual(C.parseUri(uri).server, '2001:db8::1');
});

test('trojan: builds a Clash proxy and a sing-box outbound', () => {
  const p = C.normalizeProfile({
    protocol: 'trojan', server: 'p.example.com', port: 443, password: 'pw',
    sni: 'p.example.com', network: 'ws', path: '/tj', host: 'cdn.example.com',
  });
  const clash = C.buildClashProxy(p, 'TJ');
  assert.strictEqual(clash.type, 'trojan');
  assert.strictEqual(clash.sni, 'p.example.com');
  assert.strictEqual(clash.network, 'ws');
  assert.strictEqual(clash['ws-opts'].path, '/tj');
  assert.strictEqual(clash['ws-opts'].headers.Host, 'cdn.example.com');
  const sb = C.buildSingBoxOutbound(p, 'TJ');
  assert.strictEqual(sb.type, 'trojan');
  assert.strictEqual(sb.tls.enabled, true);
  assert.strictEqual(sb.tls.server_name, 'p.example.com');
  assert.strictEqual(sb.transport.type, 'ws');
  assert.strictEqual(sb.transport.headers.Host, 'cdn.example.com');
});

test('validateProfile: trojan wants a domain for its SNI', () => {
  const noSni = C.normalizeProfile({ protocol: 'trojan', server: '1.2.3.4', port: 443, password: 'pw' });
  assert.deepStrictEqual(C.validateProfile(noSni).errors, []);
  assert.ok(C.validateProfile(noSni).warnings.some((w) => /no sni/.test(w)));
  const ipSni = C.normalizeProfile({ ...noSni, sni: '1.2.3.4' });
  assert.ok(C.validateProfile(ipSni).warnings.some((w) => /sni is an IP/.test(w)));
});

// ── VMess ───────────────────────────────────────────────────────────────────── //
test('vmess: the base64-JSON link round-trips', () => {
  const p = C.normalizeProfile({
    protocol: 'vmess', server: 'v.example.com', port: 443,
    uuid: '11111111-2222-4333-8444-555555555555', tls: true, sni: 'v.example.com',
    network: 'ws', path: '/vm', host: 'h.example', cipher: 'auto', remarks: 'VM',
  });
  const uri = C.buildUri(p);
  assert.ok(uri.startsWith('vmess://'), uri);
  const back = C.parseUri(uri);
  for (const k of ['protocol', 'server', 'port', 'uuid', 'tls', 'sni', 'network', 'path', 'host', 'cipher']) {
    assert.strictEqual(back[k], p[k], k);
  }
  assert.strictEqual(back.remarks, 'VM');
});

test('vmess: grpc keeps its serviceName through the single path field', () => {
  const p = C.normalizeProfile({
    protocol: 'vmess', server: 'v.example.com', port: 443,
    uuid: '11111111-2222-4333-8444-555555555555', network: 'grpc', serviceName: 'gsvc',
  });
  const back = C.parseUri(C.buildUri(p));
  assert.strictEqual(back.network, 'grpc');
  assert.strictEqual(back.serviceName, 'gsvc');
  assert.strictEqual(back.path, '');
});

test('vmess: the query-string form parses too', () => {
  const p = C.parseUri('vmess://11111111-2222-4333-8444-555555555555@v.example.com:443'
    + '?encryption=auto&security=tls&sni=v.example.com&type=ws&path=%2Fvm#QS');
  assert.strictEqual(p.protocol, 'vmess');
  assert.strictEqual(p.uuid, '11111111-2222-4333-8444-555555555555');
  assert.strictEqual(p.tls, true);
  assert.strictEqual(p.network, 'ws');
  assert.strictEqual(p.path, '/vm');
  assert.strictEqual(p.remarks, 'QS');
});

test('vmess: a malformed body is reported, not swallowed', () => {
  assert.throws(() => C.parseUri('vmess://not-base64-json'), /not base64-encoded JSON/);
});

test('vmess: no TLS means no TLS keys at all in either bundle', () => {
  const p = C.normalizeProfile({
    protocol: 'vmess', server: 'v.example.com', port: 80,
    uuid: '11111111-2222-4333-8444-555555555555', tls: false, network: 'tcp',
  });
  const clash = C.buildClashProxy(p, 'VM');
  assert.strictEqual(clash.tls, false);
  assert.ok(!('servername' in clash), 'mihomo reads a stray servername as a request for TLS');
  const sb = C.buildSingBoxOutbound(p, 'VM');
  assert.ok(!('tls' in sb), 'sing-box would negotiate a handshake the server is not expecting');
  assert.strictEqual(sb.alter_id, 0);
});

test('validateProfile: a malformed vmess uuid is a hard error', () => {
  const p = C.normalizeProfile({ protocol: 'vmess', server: 'a', port: 443, uuid: 'not-a-uuid' });
  assert.ok(C.validateProfile(p).errors.some((e) => /is not a UUID/.test(e)));
});

test('validateProfile: a non-zero alterId is called out', () => {
  const p = C.normalizeProfile({
    protocol: 'vmess', server: 'a', port: 443,
    uuid: '11111111-2222-4333-8444-555555555555', alterId: 64, tls: true, sni: 'a.com',
  });
  assert.ok(C.validateProfile(p).warnings.some((w) => /legacy non-AEAD/.test(w)));
});

// ── xhttp has no sing-box equivalent ────────────────────────────────────────── //
// The Sing-Box builder maps it onto `http`, which parses and then cannot
// connect. Warning about it is the difference between a config that fails
// mysteriously and one that failed for a reason you were told.
test('validateProfile: xhttp warns that the sing-box bundle cannot carry it', () => {
  const p = C.normalizeProfile({
    protocol: 'vless-reality', server: '1.2.3.4', port: 443,
    uuid: '11111111-2222-4333-8444-555555555555', publicKey: 'pk',
    sni: 'www.microsoft.com', shortId: 'ab', network: 'xhttp', path: '/x',
  });
  const { errors, warnings } = C.validateProfile(p);
  assert.deepStrictEqual(errors, []);
  assert.ok(warnings.some((w) => /sing-box has no XHTTP transport/.test(w)), warnings.join('; '));
});

// ── Order-respecting failover ───────────────────────────────────────────────── //
// url-test picks by latency and ignores order entirely, so for a while the
// reordering buttons and the README promised "the order a client walks when the
// one above does not answer" while nothing generated here did that.
test('buildClashConfig: a fallback group makes the profile order mean something', () => {
  const mk = (n) => C.normalizeProfile({
    protocol: 'trojan', server: `s${n}.example.com`, port: 443,
    password: 'pw', sni: `s${n}.example.com`, remarks: `S${n}`,
  });
  const groups = C.buildClashConfig([mk(1), mk(2), mk(3)])['proxy-groups'];
  const fallback = groups.find((g) => g.name === 'Fallback');
  assert.ok(fallback, 'no Fallback group');
  assert.strictEqual(fallback.type, 'fallback');
  assert.deepStrictEqual(fallback.proxies, ['S1', 'S2', 'S3'], 'fallback must keep the store order');
  const select = groups.find((g) => g.name === 'PROXY');
  assert.deepStrictEqual(select.proxies, ['Auto', 'Fallback', 'S1', 'S2', 'S3', 'DIRECT']);
  // One server has nothing to fail over to, so neither group is offered.
  const single = C.buildClashConfig([mk(1)])['proxy-groups'];
  assert.strictEqual(single.length, 1);
  assert.deepStrictEqual(single[0].proxies, ['S1', 'DIRECT']);
});

// ── Subscription title ──────────────────────────────────────────────────────── //
test('normalizeTitle: defaults, trims, and cannot carry a newline', () => {
  assert.strictEqual(C.normalizeTitle(undefined), 'Airport');
  assert.strictEqual(C.normalizeTitle('   '), 'Airport');
  assert.strictEqual(C.normalizeTitle('  My Airport  '), 'My Airport');
  // It becomes an HTTP header value; a CR has no business surviving.
  assert.strictEqual(C.normalizeTitle('A\r\nX-Evil: 1'), 'A X-Evil: 1');
  assert.strictEqual(C.normalizeTitle('x'.repeat(200)).length, 60);
  assert.strictEqual(C.normalizeStore({ profiles: [], title: 'Home' }).title, 'Home');
});

// ── Where a webhook may point ───────────────────────────────────────────────── //
test('alertUrlProblem: metadata and link-local addresses are refused', () => {
  assert.strictEqual(C.alertUrlProblem('https://ntfy.sh/topic'), null);
  // Loopback and LAN stay allowed: a self-hosted ntfy is the honest case.
  assert.strictEqual(C.alertUrlProblem('http://127.0.0.1:8080/hook'), null);
  assert.strictEqual(C.alertUrlProblem('http://192.168.1.10/hook'), null);
  assert.match(C.alertUrlProblem('http://169.254.169.254/latest/meta-data/'), /metadata endpoint/);
  assert.match(C.alertUrlProblem('http://metadata.google.internal/x'), /metadata endpoint/);
  assert.match(C.alertUrlProblem('http://169.254.1.1/x'), /link-local/);
  assert.match(C.alertUrlProblem('file:///etc/passwd'), /only http/);
  assert.strictEqual(C.alertUrlProblem(''), 'no URL');
  // And normalizeAlert disarms rather than storing one it will not use.
  assert.strictEqual(C.normalizeAlert({ enabled: true, url: 'http://169.254.169.254/' }).enabled, false);
});

// ── Flap suppression ────────────────────────────────────────────────────────── //
// A single failed probe on a lossy path is often just the link. The threshold
// holds a transition back — and crucially does not *record* it — until the
// failure has repeated, or the alert it debounces would be lost entirely.
test('alert evaluate: a transition is held until the failure repeats', () => {
  const cfg = { enabled: true, url: 'http://x', mode: 'json', onEveryPass: false, afterFailures: 3 };
  const down = { state: 'down', total: 2, up: 0, down: 2, untestable: 0, upNames: [], downNames: ['a', 'b'] };
  const ok = { state: 'ok', total: 2, up: 2, down: 0, untestable: 0, upNames: ['a', 'b'], downNames: [] };

  let state = 'ok';
  let streak = 0;
  const step = (s) => {
    const r = A.evaluate(state, streak, s, cfg);
    state = r.state; streak = r.streak;
    return r;
  };

  let r = step(down);
  assert.strictEqual(r.send, false);
  assert.strictEqual(r.holding, true);
  assert.strictEqual(state, 'ok', 'a held transition must not be recorded as the current state');
  assert.strictEqual(step(down).send, false);
  r = step(down);
  assert.strictEqual(r.send, true, 'the third consecutive failure reports');
  assert.strictEqual(state, 'down');
  assert.strictEqual(step(down).send, false, 'and then it stays quiet');
  assert.strictEqual(step(ok).send, true, 'recovery is a transition too');
  assert.strictEqual(streak, 0);
});

test('alert evaluate: a blip that recovers below the threshold says nothing at all', () => {
  const cfg = { enabled: true, url: 'http://x', mode: 'json', afterFailures: 3 };
  const down = { state: 'down', total: 1, up: 0, down: 1, untestable: 0, upNames: [], downNames: ['a'] };
  const ok = { state: 'ok', total: 1, up: 1, down: 0, untestable: 0, upNames: ['a'], downNames: [] };
  const first = A.evaluate('ok', 0, down, cfg);
  assert.strictEqual(first.send, false);
  const second = A.evaluate(first.state, first.streak, ok, cfg);
  assert.strictEqual(second.send, false, 'nothing was announced, so there is nothing to retract');
  assert.strictEqual(second.state, 'ok');
});

test('alert evaluate: afterFailures 1 keeps the original behaviour', () => {
  const cfg = { enabled: true, url: 'http://x', mode: 'json', afterFailures: 1 };
  const down = { state: 'down', total: 1, up: 0, down: 1, untestable: 0, upNames: [], downNames: ['a'] };
  const r = A.evaluate('ok', 0, down, cfg);
  assert.strictEqual(r.send, true);
  assert.strictEqual(r.state, 'down');
});

test('alert evaluate: an unmeasurable pass does not reset the streak', () => {
  const cfg = { enabled: true, url: 'http://x', mode: 'json', afterFailures: 2 };
  const down = { state: 'down', total: 1, up: 0, down: 1, untestable: 0, upNames: [], downNames: ['a'] };
  const unknown = { state: 'unknown', total: 1, up: 0, down: 0, untestable: 1, upNames: [], downNames: [] };
  const a = A.evaluate('ok', 0, down, cfg);
  assert.strictEqual(a.streak, 1);
  const b = A.evaluate(a.state, a.streak, unknown, cfg);
  assert.strictEqual(b.streak, 1, 'could-not-ask is not a recovery');
  assert.strictEqual(b.send, false);
  const c = A.evaluate(b.state, b.streak, down, cfg);
  assert.strictEqual(c.send, true, 'two real failures either side of a gap still count');
});

test('normalizeAlert: afterFailures is clamped into range', () => {
  assert.strictEqual(C.normalizeAlert({}).afterFailures, 1);
  assert.strictEqual(C.normalizeAlert({ afterFailures: 3 }).afterFailures, 3);
  assert.strictEqual(C.normalizeAlert({ afterFailures: 0 }).afterFailures, 1);
  assert.strictEqual(C.normalizeAlert({ afterFailures: 99 }).afterFailures, 10);
  assert.strictEqual(C.normalizeAlert({ afterFailures: 'nope' }).afterFailures, 1);
});

// ── Surge / Quantumult X ────────────────────────────────────────────────────── //
// The rule for these builders is that they never guess. Anything the target
// client cannot express is named in a comment and reported back, because a
// config quietly missing a server is only discovered when you need that server.
test('buildSurge: expresses what it can and names what it cannot', () => {
  const profiles = [
    { protocol: 'trojan', server: 't.example.com', port: 443, password: 'pw', sni: 't.example.com', network: 'ws', path: '/tj', remarks: 'TJ' },
    { protocol: 'hysteria2', server: 'h.example.com', port: 443, password: 'hp', sni: 'h.example.com', insecure: true, up: 50, down: 200, remarks: 'HY' },
    { protocol: 'vless-reality', server: '1.2.3.4', port: 443, uuid: '11111111-2222-4333-8444-555555555555', publicKey: 'pk', sni: 'www.microsoft.com', remarks: 'RE' },
    { protocol: 'tuic', server: 'u.example.com', port: 443, uuid: '11111111-2222-4333-8444-555555555556', password: 'up', sni: 'u.example.com', remarks: 'TU' },
  ].map(C.normalizeProfile);
  const built = K.buildSurge(profiles, { title: 'Airport' });
  assert.strictEqual(built.total, 4);
  assert.strictEqual(built.usable, 2);
  assert.deepStrictEqual(built.skipped.map((s) => s.name), ['RE', 'TU']);
  assert.match(built.text, /^TJ = trojan, t\.example\.com, 443, password=pw, sni=t\.example\.com, ws=true, ws-path=\/tj/m);
  assert.match(built.text, /^HY = hysteria2, .*download-bandwidth=200/m);
  // Every omission is visible in the file itself, not only in the return value.
  assert.match(built.text, /# RE: skipped — Surge has no VLESS or Reality support/);
  assert.match(built.text, /# TU: skipped — Surge has no TUIC support/);
  // The groups only list servers that actually made it in.
  assert.match(built.text, /^Fallback = fallback, TJ, HY,/m);
  assert.ok(!/PROXY = select.*\bRE\b/m.test(built.text), 'a skipped server must not appear in a group');
});

test('buildQuantumultX: carries v2ray-plugin Shadowsocks, refuses QUIC', () => {
  const profiles = [
    { protocol: 'shadowsocks', server: 's.example.com', port: 8388, password: 'sp', method: 'chacha20-ietf-poly1305', plugin: 'v2ray-plugin', plugin_opts: 'server;tls;host=s.example.com;path=/ws', remarks: 'SS' },
    { protocol: 'hysteria2', server: 'h.example.com', port: 443, password: 'hp', sni: 'h.example.com', insecure: true, remarks: 'HY' },
  ].map(C.normalizeProfile);
  const built = K.buildQuantumultX(profiles, { title: 'Airport' });
  assert.strictEqual(built.usable, 1);
  assert.match(built.text, /^shadowsocks=s\.example\.com:8388, method=chacha20-ietf-poly1305, password=sp, obfs=wss, obfs-host=s\.example\.com, obfs-uri=\/ws/m);
  assert.deepStrictEqual(built.skipped.map((s) => s.name), ['HY']);
  assert.match(built.text, /; HY: skipped — Quantumult X has no hysteria2 support/);
});

test('the plain-text builders refuse a credential they cannot escape', () => {
  // Both formats are comma-separated key=value lists with no escape defined, so
  // a comma in a password would split the line into something else entirely.
  const p = C.normalizeProfile({
    protocol: 'trojan', server: 't.example.com', port: 443,
    password: 'has,a,comma', sni: 't.example.com', remarks: 'TJ',
  });
  for (const build of [K.buildSurge, K.buildQuantumultX]) {
    const built = build([p]);
    assert.strictEqual(built.usable, 0);
    assert.match(built.skipped[0].reason, /comma or an equals sign/);
  }
});

test('supportSummary: the same verdicts without building the files', () => {
  const profiles = [
    { protocol: 'trojan', server: 't.example.com', port: 443, password: 'pw', sni: 't.example.com', remarks: 'TJ' },
    { protocol: 'tuic', server: 'u.example.com', port: 443, uuid: '11111111-2222-4333-8444-555555555555', password: 'up', sni: 'u.example.com', remarks: 'TU' },
  ].map(C.normalizeProfile);
  const s = K.supportSummary(profiles);
  assert.strictEqual(s.surge.total, 2);
  assert.strictEqual(s.surge.usable, 1);
  assert.deepStrictEqual(s.surge.skipped.map((x) => x.name), ['TU']);
  // And it agrees with the builder, which is the whole point of it existing.
  assert.deepStrictEqual(
    s.surge.skipped.map((x) => x.reason),
    K.buildSurge(profiles).skipped.map((x) => x.reason),
  );
});

// ── Sparkline data ──────────────────────────────────────────────────────────── //
test('summarizeHistory: hands back the recent samples the dashboard charts', () => {
  const samples = [];
  for (let i = 0; i < 25; i += 1) samples.push({ at: 1000 + i, ok: true, latencyMs: 100 + i, stage: 'tcp' });
  const s = H.summarizeHistory(samples);
  assert.strictEqual(s.samples, 25);
  assert.strictEqual(s.recent.length, H.SPARK_LIMIT);
  // The newest end, not the oldest — a chart of the first twenty of thirty
  // samples would be a chart of history that has already scrolled away.
  assert.strictEqual(s.recent[s.recent.length - 1].latencyMs, 124);
  assert.deepStrictEqual(Object.keys(s.recent[0]), ['at', 'ok', 'latencyMs']);
  // A failure keeps its place in the series with no latency to plot.
  const withFail = H.summarizeHistory([{ at: 1, ok: false, stage: 'tcp' }, { at: 2, ok: null, stage: 'skipped' }]);
  assert.deepStrictEqual(withFail.recent.map((r) => r.ok), [false, null]);
  assert.strictEqual(withFail.recent[0].latencyMs, null);
});

Promise.all(pending).then(() => {
  console.log(`
${passed} passed`);
});
