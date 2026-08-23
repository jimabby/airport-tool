#!/usr/bin/env node
// Tests for the shared config model + builders. No test framework — just the
// built-in assert module, so `npm test` needs no extra dependencies.
// Run: node test.js  (or: npm test)

'use strict';

const assert = require('assert');
const C = require('./lib/configs');

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
  assert.throws(() => C.parseUri('trojan://x@y:443'), /Unsupported URI scheme/);
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
test('buildClashConfig: primary DNS is domestic, foreign resolvers are fallback', () => {
  const dns = C.buildClashConfig(dupProfiles).dns;
  assert.ok(!dns.nameserver.some((n) => /8\.8\.8\.8|1\.1\.1\.1/.test(n)),
    `blocked resolvers must not be primary: ${dns.nameserver}`);
  assert.ok(dns.fallback.includes('8.8.8.8'));
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
  const on = { enabled: true, url: 'https://x/y', mode: 'json', onEveryPass: false };
  const down = A.summarize([probe('A', false)]);
  assert.strictEqual(A.shouldAlert('ok', down, on), true);
  assert.strictEqual(A.shouldAlert('down', down, on), false, 'no hourly "still down"');
  assert.strictEqual(A.shouldAlert('down', A.summarize([probe('A', true)]), on), true);
  // "We could not ask" is not worth waking anybody for.
  assert.strictEqual(A.shouldAlert('ok', A.summarize([probe('A', null)]), on), false);
  assert.strictEqual(A.shouldAlert('down', down, { ...on, onEveryPass: true }), true);
  assert.strictEqual(A.shouldAlert('ok', down, { ...on, enabled: false }), false);
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

console.log(`\n${passed} passed`);
