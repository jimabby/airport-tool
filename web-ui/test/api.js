#!/usr/bin/env node
// API-level tests for the web UI: authentication, profile CRUD, import,
// downloads and the subscription gate.
//
// The dashboard is an admin panel for a file full of proxy credentials, and
// most of what can go wrong here is a route that forgets to be guarded — which
// is exactly what nothing used to check.
'use strict';

const http = require('http');
const https = require('https');
const net = require('net');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

// Ask the OS for a port rather than pinning one: fixed ports turn "another
// suite is running" into an opaque ECONNRESET halfway through a run.
function freePort() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

let failed = 0;
let passed = 0;

function check(name, cond, detail) {
  if (cond) { passed += 1; console.log('  ✓', name); return; }
  failed += 1;
  console.error('  ✗', name);
  if (detail !== undefined) console.error('     ', String(detail).slice(0, 220));
}

function request(port, method, pathname, { headers = {}, body, host, https: useTls } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body);
    const agent = useTls ? https : http;
    const req = agent.request({
      host: '127.0.0.1', port, method, path: pathname,
      // The certificate is self-signed by design; what is being tested is that
      // the hop is encrypted, not that a stranger vouched for it.
      ...(useTls ? { rejectUnauthorized: false } : {}),
      headers: {
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
        ...(host ? { Host: host } : {}),
        ...headers,
      },
    }, (res) => {
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(text); } catch { /* not every response is JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// A raw request, so a body express's JSON parser will reject can be sent.
function rawPost(port, pathname, raw, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, method: 'POST', path: pathname,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(raw), ...headers },
    }, (res) => {
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(text); } catch { /* html error page */ }
        resolve({ status: res.statusCode, text, json });
      });
    });
    req.on('error', reject);
    req.write(raw);
    req.end();
  });
}

async function boot(port, env, dir, scheme = 'http') {
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: {
      ...process.env,
      PORT: String(port),
      CFG_PATH: path.join(dir, 'servers.json'),
      HISTORY_PATH: path.join(dir, 'history.json'),
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let err = '';
  child.stderr.on('data', (b) => { err += b.toString(); });
  const deadline = Date.now() + 15000;
  for (;;) {
    try { await request(port, 'GET', '/', { https: scheme === 'https' }); return child; } catch {
      if (Date.now() > deadline) { child.kill(); throw new Error(`server ${port} never came up: ${err}`); }
      await new Promise((r) => setTimeout(r, 150));
    }
  }
}

const SS = {
  protocol: 'shadowsocks', server: '203.0.113.10', port: 8388,
  password: 'hunter2', method: 'aes-256-gcm', remarks: 'Tokyo',
};

async function testLoopback(dir) {
  console.log('\n── loopback: usable without a token, still guarded against rebinding');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const cfg = await request(port, 'GET', '/api/config');
    check('GET /api/config needs no token on loopback', cfg.status === 200, cfg.status);

    const rebind = await request(port, 'GET', '/api/config', { host: 'evil.example' });
    check('a rebinding Host header is still refused', rebind.status === 403, rebind.status);

    // ── CRUD ──
    const created = await request(port, 'POST', '/api/profiles', { body: SS });
    check('POST /api/profiles creates a profile', created.status === 200 && created.json.profiles.length === 1, created.text);
    const id = created.json.savedId;

    const renamed = await request(port, 'POST', '/api/profiles', { body: { ...SS, id, remarks: 'Tokyo 2' } });
    check('POST with an existing id updates in place', renamed.json.profiles.length === 1 && renamed.json.profiles[0].remarks === 'Tokyo 2', renamed.text);
    check('an update keeps the profile id', renamed.json.savedId === id, renamed.json.savedId);

    const invalid = await request(port, 'POST', '/api/profiles', { body: { protocol: 'shadowsocks', server: '1.1.1.1' } });
    check('an incomplete profile is rejected with a reason', invalid.status === 400 && /missing/.test(invalid.json.error), invalid.text);

    const second = await request(port, 'POST', '/api/profiles', {
      body: { protocol: 'hysteria2', server: '203.0.113.11', port: 443, password: 'pw', insecure: true, remarks: 'Osaka' },
    });
    check('a second profile does not steal ★', second.json.activeId === id, second.json.activeId);

    const activated = await request(port, 'POST', '/api/active', { body: { id: second.json.savedId } });
    check('POST /api/active moves ★', activated.json.activeId === second.json.savedId, activated.text);
    const missing = await request(port, 'POST', '/api/active', { body: { id: 'nope' } });
    check('POST /api/active 404s on an unknown id', missing.status === 404, missing.status);

    // ── Import ──
    const imported = await request(port, 'POST', '/api/import', {
      body: { text: 'tuic://11111111-2222-3333-4444-555555555555:pw@203.0.113.12:443?sni=www.bing.com&allow_insecure=1#Imported' },
    });
    check('POST /api/import accepts a tuic:// link', imported.status === 200 && imported.json.added[0] === 'Imported', imported.text);

    const dupe = await request(port, 'POST', '/api/import', {
      body: { text: 'tuic://11111111-2222-3333-4444-555555555555:pw@203.0.113.12:443?sni=www.bing.com#Again' },
    });
    check('re-importing the same endpoint is refused, not duplicated', dupe.status === 400 && /Already have/.test(dupe.json.error), dupe.text);

    const junk = await request(port, 'POST', '/api/import', { body: { text: 'not-a-uri' } });
    check('unparseable import input reports the bad line', junk.status === 400 && /line 1/.test(junk.json.error), junk.text);

    // ── Downloads ──
    const clash = await request(port, 'GET', '/api/download/clash');
    check('clash download is YAML with every proxy', clash.status === 200 && /proxies:/.test(clash.text) && /hunter2/.test(clash.text), clash.status);
    const singbox = await request(port, 'GET', '/api/download/singbox');
    check('singbox download parses and carries a tun inbound',
      singbox.status === 200 && JSON.parse(singbox.text).inbounds.some((i) => i.type === 'tun'), singbox.status);
    const uri = await request(port, 'GET', `/api/download/uri?id=${encodeURIComponent(id)}`);
    check('uri download is named after its protocol', /ss-uri\.txt/.test(uri.headers['content-disposition'] || ''), uri.headers['content-disposition']);
    const backup = await request(port, 'GET', '/api/download/backup');
    check('backup download returns the whole store', backup.status === 200 && JSON.parse(backup.text).profiles.length === 3, backup.status);

    // ── Deletion ──
    const deleted = await request(port, 'DELETE', `/api/profiles/${encodeURIComponent(id)}`);
    check('DELETE removes the profile', deleted.status === 200 && deleted.json.profiles.length === 2, deleted.text);
    const gone = await request(port, 'DELETE', `/api/profiles/${encodeURIComponent(id)}`);
    check('DELETE 404s on an unknown id', gone.status === 404, gone.status);

    // ── Error shape ──
    const broken = await rawPost(port, '/api/profiles', '{not json');
    check('a malformed body answers in JSON, not HTML', broken.status === 400 && broken.json && /not valid JSON/.test(broken.json.error), broken.text);

    // ── Subscription ──
    const store = JSON.parse(fs.readFileSync(path.join(dir, 'servers.json'), 'utf8'));
    const good = await request(port, 'GET', `/api/subscription/${store.token}`);
    check('the subscription token serves the feed', good.status === 200 && /:\/\//.test(Buffer.from(good.text, 'base64').toString()), good.status);
    const wrong = await request(port, 'GET', '/api/subscription/deadbeefdeadbeefdeadbeef');
    check('a wrong subscription token 404s', wrong.status === 404, wrong.status);
    const untokenized = await request(port, 'GET', '/api/subscription');
    check('the old untokenized path explains itself', untokenized.status === 401, untokenized.status);
    check('the subscription and dashboard tokens are different', store.token !== store.uiToken);
  } finally {
    child.kill();
  }
}

// Once the UI is off loopback, everything that reads or writes credentials must
// demand the dashboard token. Gating only the subscription feed left
// /api/config — which returns the same credentials *plus* that token — open to
// anyone on the network.
async function testAuthRequired(dir) {
  console.log('\n── non-loopback: every credential route demands the dashboard token');
  const port = await freePort();
  const child = await boot(port, { HOST: '0.0.0.0' }, dir);
  try {
    const store = JSON.parse(fs.readFileSync(path.join(dir, 'servers.json'), 'utf8'));
    const tok = store.uiToken;
    check('a dashboard token was minted', typeof tok === 'string' && tok.length >= 16, tok);

    const guarded = [
      ['GET', '/'],
      ['GET', '/api/config'],
      ['GET', '/api/qrcode'],
      ['GET', '/api/qrcode/subscription'],
      ['GET', '/api/download/clash'],
      ['GET', '/api/download/singbox'],
      ['GET', '/api/download/uri'],
      ['GET', '/api/download/backup'],
      ['GET', '/api/test'],
      ['GET', '/api/test-all'],
      ['GET', '/api/history'],
      ['POST', '/api/profiles'],
      ['POST', '/api/active'],
      ['POST', '/api/import'],
      ['POST', '/api/auto-active'],
      ['DELETE', '/api/profiles/abc'],
    ];
    for (const [method, pathname] of guarded) {
      const res = await request(port, method, pathname, { body: method === 'GET' ? undefined : {} });
      check(`${method} ${pathname} is refused without a token`, res.status === 401, res.status);
    }

    for (const [label, headers] of [
      ['X-UI-Token', { 'X-UI-Token': tok }],
      ['Authorization: Bearer', { Authorization: `Bearer ${tok}` }],
      ['Cookie', { Cookie: `airport_ui=${tok}` }],
    ]) {
      const res = await request(port, 'GET', '/api/config', { headers });
      check(`${label} is accepted`, res.status === 200, res.status);
    }

    const wrong = await request(port, 'GET', '/api/config', { headers: { 'X-UI-Token': 'x'.repeat(tok.length) } });
    check('a wrong token of the right length is refused', wrong.status === 401, wrong.status);

    // ?ui_token= is traded for a cookie and redirected away, so the secret stops
    // travelling in Referer headers, history and screenshots.
    const viaQuery = await request(port, 'GET', `/?ui_token=${encodeURIComponent(tok)}`);
    check('?ui_token= redirects', viaQuery.status === 302 && viaQuery.headers.location === '/', `${viaQuery.status} ${viaQuery.headers.location}`);
    const cookie = String(viaQuery.headers['set-cookie'] || '');
    check('the cookie it sets is HttpOnly and SameSite=Strict', /HttpOnly/i.test(cookie) && /SameSite=Strict/i.test(cookie), cookie);

    // Clients polling the subscription feed hold neither a cookie nor a header.
    const sub = await request(port, 'GET', `/api/subscription/${store.token}`);
    check('the subscription feed still needs only its own token', sub.status === 200, sub.status);
  } finally {
    child.kill();
  }
}

// UI_TOKEN also turns authentication on for a loopback bind, for anyone sharing
// the machine.
async function testPinnedToken(dir) {
  console.log('\n── UI_TOKEN pins the secret and forces auth on loopback');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1', UI_TOKEN: 'pinned-token-value-1234567890' }, dir);
  try {
    const denied = await request(port, 'GET', '/api/config');
    check('loopback now requires a token too', denied.status === 401, denied.status);
    const allowed = await request(port, 'GET', '/api/config', { headers: { 'X-UI-Token': 'pinned-token-value-1234567890' } });
    check('the pinned token is what works', allowed.status === 200, allowed.status);
    const storeToken = JSON.parse(fs.readFileSync(path.join(dir, 'servers.json'), 'utf8')).uiToken;
    const stale = await request(port, 'GET', '/api/config', { headers: { 'X-UI-Token': storeToken } });
    check('the stored token does not override UI_TOKEN', stale.status === 401, stale.status);
  } finally {
    child.kill();
  }
}

// Rotating a token is the only way to revoke a subscription URL that leaked,
// so "the old one stops working" is the whole feature.
async function testRotation(dir) {
  console.log('\n── token rotation revokes the old URL');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    await request(port, 'POST', '/api/profiles', { body: SS });
    const before = (await request(port, 'GET', '/api/config')).json.subscriptionPath;
    check('the old subscription URL works', (await request(port, 'GET', before)).status === 200);

    const rot = await request(port, 'POST', '/api/rotate-token', { body: { which: 'subscription' } });
    check('rotate returns a new path', rot.status === 200 && rot.json.subscriptionPath !== before, rot.text);
    check('the old subscription URL is dead', (await request(port, 'GET', before)).status === 404);
    check('the new subscription URL works', (await request(port, 'GET', rot.json.subscriptionPath)).status === 200);
    check('rotation says what it broke', /re-pointed/.test((rot.json.notes || []).join(' ')), rot.json.notes);

    const bad = await request(port, 'POST', '/api/rotate-token', { body: { which: 'nonsense' } });
    check('an unknown token name is refused', bad.status === 400, bad.status);
  } finally {
    child.kill();
  }
}

async function testRestore(dir) {
  console.log('\n── restore brings back profiles *and* both tokens');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    await request(port, 'POST', '/api/profiles', { body: SS });
    const backup = (await request(port, 'GET', '/api/download/backup')).text;
    const cfg = (await request(port, 'GET', '/api/config')).json;
    const savedSub = cfg.subscriptionPath;

    // Diverge from the backup: drop the profile and rotate the token.
    await request(port, 'DELETE', `/api/profiles/${cfg.profiles[0].id}`);
    await request(port, 'POST', '/api/rotate-token', { body: { which: 'subscription' } });
    check('the store really diverged', (await request(port, 'GET', savedSub)).status === 404);

    const res = await request(port, 'POST', '/api/restore', { body: { text: backup } });
    check('restore reports what it took back', res.status === 200 && res.json.restored === 1, res.text);
    check('the profile is back', res.json.profiles.length === 1 && res.json.profiles[0].remarks === 'Tokyo');
    check('the old subscription URL works again', (await request(port, 'GET', savedSub)).status === 200);

    const empty = await request(port, 'POST', '/api/restore', { body: { text: '{"profiles":[]}' } });
    check('an empty backup is refused, not applied', empty.status === 400, empty.status);
    check('the refused restore changed nothing',
      (await request(port, 'GET', '/api/config')).json.profiles.length === 1);

    const junk = await request(port, 'POST', '/api/restore', { body: { text: 'not json' } });
    check('a non-JSON restore is refused', junk.status === 400, junk.status);
  } finally {
    child.kill();
  }
}

// Deleting a profile used to leave its samples in the history file for good.
async function testHistoryPruning(dir) {
  console.log('\n── history follows the profiles it belongs to');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  const histFile = path.join(dir, 'history.json');
  try {
    const saved = await request(port, 'POST', '/api/profiles', { body: SS });
    await request(port, 'GET', '/api/test');
    const before = Object.keys(JSON.parse(fs.readFileSync(histFile, 'utf8')));
    check('a probe is filed under the profile', before.length === 1, before);

    await request(port, 'DELETE', `/api/profiles/${saved.json.savedId}`);
    const after = Object.keys(JSON.parse(fs.readFileSync(histFile, 'utf8')));
    check('deleting the profile takes its history with it', after.length === 0, after);
  } finally {
    child.kill();
  }
}

async function testMonitorAndDownloads(dir) {
  console.log('\n── health monitor, port hopping and the desktop config');
  const port = await freePort();
  let child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const hop = await request(port, 'POST', '/api/profiles', {
      body: {
        protocol: 'hysteria2', server: '203.0.113.20', port: 443, password: 'pw',
        sni: 'www.bing.com', insecure: true, ports: '20000-30000', hopInterval: 45, remarks: 'Hop',
      },
    });
    check('a hopping profile saves', hop.status === 200, hop.text);
    check('its URI carries mport', /mport=20000-30000/.test(hop.json.profiles[0].uri), hop.json.profiles[0].uri);

    const badHop = await request(port, 'POST', '/api/profiles', {
      body: { protocol: 'hysteria2', server: '203.0.113.21', port: 443, password: 'pw', ports: 'oops', remarks: 'Bad' },
    });
    check('an unusable range is rejected', badHop.status === 400 && /port range/.test(badHop.json.error), badHop.text);

    const mobile = await request(port, 'GET', '/api/download/singbox');
    check('the mobile config keeps its tun inbound',
      mobile.json.inbounds.some((i) => i.type === 'tun'), mobile.json.inbounds);
    const desktop = await request(port, 'GET', '/api/download/singbox?tun=0');
    check('the desktop config drops tun',
      !desktop.json.inbounds.some((i) => i.type === 'tun'), desktop.json.inbounds);
    check('the desktop config keeps a usable inbound',
      desktop.json.inbounds.some((i) => i.type === 'mixed'), desktop.json.inbounds);
    check('the two downloads are named differently',
      /singbox-desktop\.json/.test(desktop.headers['content-disposition']), desktop.headers['content-disposition']);
    check('hopping reaches the sing-box outbound',
      desktop.json.outbounds.some((o) => Array.isArray(o.server_ports) && o.server_ports[0] === '20000:30000'));

    const off = (await request(port, 'GET', '/api/monitor')).json;
    check('the monitor is off by default', off.enabled === false && off.intervalMin === 15, off);

    const on = await request(port, 'POST', '/api/monitor', { body: { enabled: true, intervalMin: 7, autoSwitch: true } });
    check('the monitor stores its settings',
      on.json.monitor.enabled && on.json.monitor.intervalMin === 7 && on.json.monitor.autoSwitch, on.text);
    check('it schedules a next run', typeof on.json.monitor.state.nextAt === 'number', on.json.monitor.state);

    // A partial body used to reset every field it left out to its default.
    const partial = await request(port, 'POST', '/api/monitor', { body: { deep: false } });
    check('a partial update keeps the other settings',
      partial.json.monitor.intervalMin === 7 && partial.json.monitor.enabled === true, partial.json.monitor);

    const clamped = await request(port, 'POST', '/api/monitor', { body: { intervalMin: 99999 } });
    check('an absurd interval is clamped', clamped.json.monitor.intervalMin === 1440, clamped.json.monitor);

    const ran = await request(port, 'POST', '/api/monitor/run', { body: {} });
    check('a pass can be run on demand', ran.status === 200 && ran.json.last.probed === 1, ran.text);

    // The settings live in the store, so they must survive a restart. Set a
    // known value first — the clamp check above left 1440 behind.
    await request(port, 'POST', '/api/monitor', { body: { intervalMin: 7 } });
    // A fresh port, because the old listener is not necessarily gone the
    // instant the kill returns and the replacement would fail to bind.
    child.kill();
    const port2 = await freePort();
    child = await boot(port2, { HOST: '127.0.0.1' }, dir);
    const after = (await request(port2, 'GET', '/api/monitor')).json;
    check('the schedule survives a restart', after.enabled === true && after.intervalMin === 7,
      JSON.stringify(after));
  } finally {
    child.kill();
  }
}

// ── Cross-site request forgery ─────────────────────────────────────────────── //
// On the loopback default there is no token and no cookie, so nothing but this
// stands between a page the user happens to have open and every write route.
// `Content-Type: text/plain` skips the CORS preflight and express.json() then
// declines to parse the body, which used to leave `POST /api/rotate-token` with
// an empty body taking its default and silently rotating the subscription token.
async function testCsrf(dir) {
  console.log('\n── cross-site writes are refused');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    await request(port, 'POST', '/api/profiles', { body: SS });
    const before = (await request(port, 'GET', '/api/config')).json.subscriptionPath;

    const simple = await rawPost(port, '/api/rotate-token', 'hello', {
      'Content-Type': 'text/plain;charset=UTF-8',
      Origin: 'https://evil.example',
      'Sec-Fetch-Site': 'cross-site',
    });
    check('a cross-site POST is refused', simple.status === 403, simple.text);
    const after = (await request(port, 'GET', '/api/config')).json.subscriptionPath;
    check('and it changed nothing', before === after, `${before} → ${after}`);

    // Older browsers send no fetch metadata, so Origin has to be enough.
    const originOnly = await rawPost(port, '/api/rotate-token', '{}', {
      Origin: 'https://evil.example',
    });
    check('an Origin from elsewhere is refused without fetch metadata', originOnly.status === 403, originOnly.text);

    // Every one of these is a state-changing route reachable as a simple request.
    for (const route of ['/api/auto-active', '/api/monitor/run', '/api/monitor']) {
      const r = await rawPost(port, route, '{}', { 'Sec-Fetch-Site': 'cross-site' });
      check(`${route} is refused cross-site`, r.status === 403, r.status);
    }

    // The dashboard's own requests must still work, as must curl, which sends
    // neither header.
    const same = await request(port, 'POST', '/api/monitor', {
      body: { enabled: false },
      headers: { Origin: `http://127.0.0.1:${port}`, 'Sec-Fetch-Site': 'same-origin' },
    });
    check('the dashboard\'s own POST still works', same.status === 200, same.text);
    const cli = await request(port, 'POST', '/api/monitor', { body: { enabled: false } });
    check('a request with no browser headers still works', cli.status === 200, cli.text);

    // Reading is safe and must stay reachable: a client polling the feed is a
    // cross-site GET by definition.
    const feed = await request(port, 'GET', before, { headers: { 'Sec-Fetch-Site': 'cross-site' } });
    check('a cross-site GET of the subscription feed still works', feed.status === 200, feed.status);

    // These responses carry passwords and both tokens.
    const cfg = await request(port, 'GET', '/api/config');
    check('credential responses are not cacheable', cfg.headers['cache-control'] === 'no-store', cfg.headers['cache-control']);
  } finally {
    child.kill();
  }
}

// ── Enable / disable ───────────────────────────────────────────────────────── //
// setup.sh cannot reproduce a password it already minted, so deleting a blocked
// server is not the reversible act it looks like. Disabling is.
async function testEnableDisable(dir) {
  console.log('\n── a disabled profile stays in the store and leaves every config');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const a = (await request(port, 'POST', '/api/profiles', { body: { ...SS, remarks: 'Alpha' } })).json.savedId;
    const b = (await request(port, 'POST', '/api/profiles', { body: { ...SS, server: '203.0.113.11', remarks: 'Beta' } })).json.savedId;

    const off = await request(port, 'POST', `/api/profiles/${b}/enabled`, { body: { enabled: false } });
    check('a profile can be disabled', off.status === 200 && off.json.enabledCount === 1, off.text);

    const clash = await request(port, 'GET', '/api/download/clash');
    check('the disabled server leaves the Clash config', !clash.text.includes('203.0.113.11'), clash.text.slice(0, 120));
    const sing = await request(port, 'GET', '/api/download/singbox');
    check('and the Sing-Box config', !sing.text.includes('203.0.113.11'));
    const sub = await request(port, 'GET', (await request(port, 'GET', '/api/config')).json.subscriptionPath);
    const decoded = Buffer.from(sub.text, 'base64').toString('utf8');
    check('and the subscription feed', !decoded.includes('203.0.113.11'), decoded);
    check('but it is still in the store', off.json.profiles.length === 2, off.json.profiles.length);

    // ★ names the profile the QR describes, so it cannot point at one that no
    // generated config carries.
    const star = await request(port, 'POST', '/api/active', { body: { id: b } });
    check('★ refuses to move to a disabled profile', star.status === 409, star.text);

    // Disabling the active one has to move ★ rather than strand it.
    const offA = await request(port, 'POST', `/api/profiles/${a}/enabled`, { body: { enabled: false } });
    check('disabling the last enabled profile is refused', offA.status === 409, offA.text);

    await request(port, 'POST', `/api/profiles/${b}/enabled`, { body: { enabled: true } });
    const moved = await request(port, 'POST', `/api/profiles/${a}/enabled`, { body: { enabled: false } });
    check('disabling the active profile moves ★ instead of stranding it',
      moved.status === 200 && moved.json.activeId === b, moved.text);

    // A save replaces the whole profile; an absent `enabled` would switch a
    // disabled server back on every time you edited anything else about it.
    const edited = await request(port, 'POST', '/api/profiles', { body: { ...SS, id: a, remarks: 'Alpha 2', enabled: false } });
    check('editing a disabled profile does not re-enable it',
      edited.json.profiles.find((p) => p.id === a).enabled === false, edited.text);

    // With everything off, a download would be a config with no servers in it.
    await request(port, 'POST', `/api/profiles/${a}/enabled`, { body: { enabled: true } });
    await request(port, 'POST', '/api/active', { body: { id: a } });
    await request(port, 'POST', `/api/profiles/${b}/enabled`, { body: { enabled: false } });
    await request(port, 'DELETE', `/api/profiles/${a}`);
    const lonely = await request(port, 'GET', '/api/download/clash');
    check('an all-disabled store refuses to emit an empty config', lonely.status === 409, lonely.status);
    const emptyFeed = await request(port, 'GET', (await request(port, 'GET', '/api/config')).json.subscriptionPath);
    check('and the subscription says so rather than serving nothing', emptyFeed.status === 409, emptyFeed.status);
  } finally {
    child.kill();
  }
}

// ── Reordering ─────────────────────────────────────────────────────────────── //
// The order decides which proxy a Clash or sing-box selector lists first and
// which server a client falls back to, so it is a real setting — and until
// there was an endpoint for it, the only way to change it was to hand-edit
// servers.json under the running dashboard.
async function testReorder(dir) {
  console.log('\n── profiles can be reordered without editing the store by hand');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const a = (await request(port, 'POST', '/api/profiles', { body: { ...SS, remarks: 'Alpha' } })).json.savedId;
    const b = (await request(port, 'POST', '/api/profiles', { body: { ...SS, server: '203.0.113.11', remarks: 'Beta' } })).json.savedId;
    const c = (await request(port, 'POST', '/api/profiles', { body: { ...SS, server: '203.0.113.12', remarks: 'Gamma' } })).json.savedId;

    await request(port, 'POST', '/api/active', { body: { id: b } });
    const moved = await request(port, 'POST', '/api/profiles/order', { body: { ids: [c, b, a] } });
    check('the new order is stored',
      moved.status === 200 && moved.json.profiles.map((p) => p.remarks).join() === 'Gamma,Beta,Alpha', moved.text);
    // ★ is an index into the array, so it has to follow the profile it named
    // rather than staying at the position that profile used to sit in.
    check('★ follows the profile it was on', moved.json.activeId === b, moved.json.activeId);

    // The Clash bundle is the reason the order matters, so it has to agree.
    const clash = await request(port, 'GET', '/api/download/clash');
    const order = ['Gamma', 'Beta', 'Alpha'].map((n) => clash.text.indexOf(`name: "${n}"`));
    check('the Clash config lists them in that order',
      order.every((i) => i !== -1) && order[0] < order[1] && order[1] < order[2], order.join());

    // A partial or repeated list would silently drop or duplicate a profile in
    // the file every client is generated from, so both are refused.
    const short = await request(port, 'POST', '/api/profiles/order', { body: { ids: [a, b] } });
    check('a list that leaves a profile out is refused', short.status === 400, short.text);
    const dupes = await request(port, 'POST', '/api/profiles/order', { body: { ids: [a, a, b] } });
    check('a list that repeats an id is refused', dupes.status === 400, dupes.text);
    const alien = await request(port, 'POST', '/api/profiles/order', {
      body: { ids: [a, b, '00000000-0000-0000-0000-000000000000'] },
    });
    check('a list naming an unknown id is refused', alien.status === 400, alien.text);
    const notList = await request(port, 'POST', '/api/profiles/order', { body: { ids: 'nope' } });
    check('a body that is not a list is refused', notList.status === 400, notList.text);

    const after = await request(port, 'GET', '/api/config');
    check('and none of those refusals changed anything',
      after.json.profiles.map((p) => p.remarks).join() === 'Gamma,Beta,Alpha', after.text);
  } finally {
    child.kill();
  }
}

// ── Per-device subscription tokens ─────────────────────────────────────────── //
async function testClientTokens(dir) {
  console.log('\n── per-device subscription URLs are revocable on their own');
  const port = await freePort();
  let child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    await request(port, 'POST', '/api/profiles', { body: SS });
    const shared = (await request(port, 'GET', '/api/config')).json.subscriptionPath;

    const unnamed = await request(port, 'POST', '/api/clients', { body: { name: '  ' } });
    check('an unnamed device is refused', unnamed.status === 400, unnamed.text);

    const phone = await request(port, 'POST', '/api/clients', { body: { name: 'Pixel' } });
    const laptop = await request(port, 'POST', '/api/clients', { body: { name: 'Laptop' } });
    check('two device URLs are issued', laptop.json.clients.length === 2, laptop.text);
    check('and they differ from each other and from the shared one',
      phone.json.created.path !== laptop.json.created.path && phone.json.created.path !== shared);

    const viaPhone = await request(port, 'GET', phone.json.created.path);
    const viaShared = await request(port, 'GET', shared);
    check('a device token serves the same feed as the shared URL',
      viaPhone.status === 200 && viaPhone.text === viaShared.text, viaPhone.status);

    const seen = (await request(port, 'GET', '/api/config')).json.clients.find((c) => c.id === phone.json.created.id);
    check('polling is recorded so you can tell which device is live', !!seen.lastSeen, JSON.stringify(seen));

    const qr = await request(port, 'GET', `/api/qrcode/client/${phone.json.created.id}`);
    check('each device URL has its own QR', qr.status === 200 && qr.json.qrcode.startsWith('data:image/png'), qr.status);

    const gone = await request(port, 'DELETE', `/api/clients/${phone.json.created.id}`);
    check('revoking one device reports what it took', gone.json.revoked === 'Pixel', gone.text);
    check('the revoked URL stops working',
      (await request(port, 'GET', phone.json.created.path)).status === 404);
    check('the other device keeps working',
      (await request(port, 'GET', laptop.json.created.path)).status === 200);
    check('and so does the shared URL', (await request(port, 'GET', shared)).status === 200);

    // Last-seen used to be memory-only, so a restart made a device that had
    // been polling for months read as "never seen" — which is exactly the
    // signal you go looking for when deciding what to revoke.
    child.kill();
    await new Promise((r) => setTimeout(r, 250));
    child = await boot(port, { HOST: '127.0.0.1' }, dir);
    const survived = (await request(port, 'GET', '/api/config')).json.clients
      .find((c) => c.id === laptop.json.created.id);
    check('last-seen survives a restart', !!survived && !!survived.lastSeen, JSON.stringify(survived));
  } finally {
    child.kill();
  }
}

// ── Per-device server subsets ────────────────────────────────────────────── //
// A friend handed one server should get that server — not the other four, and
// not every server you add after them.
async function testDeviceSubsets(dir) {
  console.log('\n── a device URL can be limited to some servers');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const a = await request(port, 'POST', '/api/profiles', { body: { ...SS, server: '203.0.113.21', remarks: 'Alpha' } });
    const b = await request(port, 'POST', '/api/profiles', { body: { ...SS, server: '203.0.113.22', remarks: 'Beta' } });
    const alpha = a.json.savedId;
    const beta = b.json.savedId;
    const decode = (text) => Buffer.from(text, 'base64').toString('utf8');

    const empty = await request(port, 'POST', '/api/clients', { body: { name: 'Friend', profiles: [] } });
    check('an empty subset is refused — that is what Revoke is for', empty.status === 400, empty.text);
    const unknown = await request(port, 'POST', '/api/clients', {
      body: { name: 'Friend', profiles: ['00000000-0000-4000-8000-000000000000'] },
    });
    check('an unknown profile id is refused rather than silently dropped', unknown.status === 400, unknown.text);

    const friend = await request(port, 'POST', '/api/clients', { body: { name: 'Friend', profiles: [beta] } });
    check('a limited device URL is issued', friend.status === 200, friend.text);
    const feed = decode((await request(port, 'GET', friend.json.created.path)).text);
    check('its feed carries only the chosen server', /Beta/.test(feed) && !/Alpha/.test(feed), feed);
    const clash = await request(port, 'GET', `${friend.json.created.path}?target=clash`);
    check('and so does every whole-config target', /Beta/.test(clash.text) && !/Alpha/.test(clash.text), clash.text.slice(0, 200));
    const listed = (await request(port, 'GET', '/api/config')).json.clients.find((c) => c.id === friend.json.created.id);
    check('the dashboard sees which servers it has', JSON.stringify(listed.profiles) === JSON.stringify([beta]), JSON.stringify(listed));

    // A server added later is not handed to a device limited to others.
    await request(port, 'POST', '/api/profiles', { body: { ...SS, server: '203.0.113.23', remarks: 'Gamma' } });
    const later = decode((await request(port, 'GET', friend.json.created.path)).text);
    check('a server added later does not leak into a limited feed', !/Gamma/.test(later), later);

    // Changing the servers keeps the URL.
    const widened = await request(port, 'POST', `/api/clients/${friend.json.created.id}`, { body: { profiles: [alpha, beta] } });
    check('the subset can be changed', widened.status === 200, widened.text);
    const wide = decode((await request(port, 'GET', friend.json.created.path)).text);
    check('without changing the URL', /Alpha/.test(wide) && /Beta/.test(wide), wide);
    const all = await request(port, 'POST', `/api/clients/${friend.json.created.id}`, { body: { profiles: null } });
    check('null goes back to every server', all.status === 200 && all.json.updated.profiles === null, all.text);

    // Deleting a device's only server empties its feed; that is reported, not
    // quietly widened to everything.
    const solo = await request(port, 'POST', '/api/clients', { body: { name: 'Solo', profiles: [alpha] } });
    await request(port, 'DELETE', `/api/profiles/${alpha}`);
    const orphaned = await request(port, 'GET', solo.json.created.path);
    check('a device whose servers are all gone gets a 409 that says why',
      orphaned.status === 409 && /None of the servers "Solo"/.test(orphaned.text), `${orphaned.status} ${orphaned.text}`);
  } finally {
    child.kill();
  }
}

// ── Custom routing rules ─────────────────────────────────────────────────── //
async function testRules(dir) {
  console.log('\n── custom routing rules reach every bundle');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    await request(port, 'POST', '/api/profiles', { body: SS });
    const bad = await request(port, 'POST', '/api/rules', { body: { direct: 'good.com\nnot a domain' } });
    check('a bad entry refuses the whole save, with the reason', bad.status === 400 && /not a domain/.test(bad.json.error), bad.text);
    check('and nothing was saved', (await request(port, 'GET', '/api/config')).json.rules.direct.length === 0);

    const saved = await request(port, 'POST', '/api/rules', {
      body: { direct: '# bank\nmybank.com\n10.8.0.0/16', proxy: ['foreign.cn'], block: 'ads.example.com' },
    });
    check('a valid set is saved in canonical form',
      saved.status === 200 && JSON.stringify(saved.json.rules.direct) === JSON.stringify(['mybank.com', '10.8.0.0/16']), saved.text);

    const clash = await request(port, 'GET', '/api/download/clash');
    check('the Clash download carries them', /DOMAIN-SUFFIX,mybank\.com,DIRECT/.test(clash.text)
      && /DOMAIN-SUFFIX,ads\.example\.com,REJECT/.test(clash.text), clash.text.slice(0, 200));
    const sb = await request(port, 'GET', '/api/download/singbox');
    check('the sing-box download carries them', /"foreign\.cn"/.test(sb.text), sb.text.slice(0, 200));
    const surge = await request(port, 'GET', '/api/download/surge');
    check('the Surge download carries them', /DOMAIN-SUFFIX,foreign\.cn,PROXY/.test(surge.text));
    const qx = await request(port, 'GET', '/api/download/quantumultx');
    check('the Quantumult X download carries them', /host-suffix, mybank\.com, direct/.test(qx.text));
    const shared = (await request(port, 'GET', '/api/config')).json.subscriptionPath;
    const sub = await request(port, 'GET', `${shared}?target=clash`);
    check('and so does a subscription target', /DOMAIN-SUFFIX,mybank\.com,DIRECT/.test(sub.text));
  } finally {
    child.kill();
  }
}

// ── Behind a reverse proxy ───────────────────────────────────────────────── //
// Requests arrive from 127.0.0.1 over plain HTTP, so URLs built from the
// request pointed a phone at localhost. PUBLIC_URL fixes what gets handed out.
async function testPublicUrl(dir) {
  console.log('\n── PUBLIC_URL is what every handed-out URL uses');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1', PUBLIC_URL: 'https://airport.example.com/' }, dir);
  try {
    await request(port, 'POST', '/api/profiles', { body: SS });
    const cfg = (await request(port, 'GET', '/api/config')).json;
    check('the dashboard is told the public origin', cfg.publicBase === 'https://airport.example.com', cfg.publicBase);
    const qr = await request(port, 'GET', '/api/qrcode/subscription');
    check('the subscription QR encodes it', qr.json.uri.startsWith('https://airport.example.com/api/subscription/'), qr.json.uri);
    const sub = await request(port, 'GET', cfg.subscriptionPath);
    check('the web-page header points at it', sub.headers['profile-web-page-url'] === 'https://airport.example.com/',
      sub.headers['profile-web-page-url']);
    const proxied = await request(port, 'GET', '/api/config', { host: 'airport.example.com' });
    check('the public host name is accepted by the Host allow-list', proxied.status === 200, proxied.status);
    // A proxy that rewrites Host still delivers the browser's real Origin.
    const write = await request(port, 'POST', '/api/title', {
      body: { title: 'Via proxy' },
      headers: { Origin: 'https://airport.example.com' },
    });
    check('a write from the public origin is not mistaken for cross-site', write.status === 200, write.text);
  } finally {
    child.kill();
  }
  // A sub-path cannot work — the page fetches /api from the root — so it is
  // refused at boot rather than half-working.
  const bad = spawnSync(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(await freePort()), CFG_PATH: path.join(dir, 'servers.json'), PUBLIC_URL: 'https://example.com/airport' },
    encoding: 'utf8', timeout: 15000,
  });
  check('a PUBLIC_URL with a path is refused at boot', bad.status === 1 && /has a path/.test(bad.stderr), bad.stderr);
}

// ── Monitor alerting ───────────────────────────────────────────────────────── //
// The monitor already knows when everything is down. This is the part that
// leaves the machine while the machine can still send it.
async function testAlerts(dir) {
  console.log('\n── the health monitor can notify a webhook');
  const received = [];
  const hook = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      received.push({ type: req.headers['content-type'], body });
      res.writeHead(204).end();
    });
  });
  await new Promise((r) => hook.listen(0, '127.0.0.1', r));
  const hookUrl = `http://127.0.0.1:${hook.address().port}/notify`;

  const port = await freePort();
  let child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const saved = await request(port, 'POST', '/api/monitor', {
      body: { enabled: true, intervalMin: 60, alert: { enabled: true, url: hookUrl, mode: 'json' } },
    });
    check('alert settings are stored', saved.json.monitor.alert.url === hookUrl, saved.text);

    // Alerting with nowhere to send is off, whatever the checkbox said.
    const nowhere = await request(port, 'POST', '/api/monitor', { body: { alert: { enabled: true, url: 'not-a-url' } } });
    check('a webhook URL that is not http(s) disarms alerting', nowhere.json.monitor.alert.enabled === false, nowhere.text);

    await request(port, 'POST', '/api/monitor', { body: { alert: { enabled: true, url: hookUrl, mode: 'json' } } });
    const test = await request(port, 'POST', '/api/monitor/test-alert', { body: {} });
    check('a test notification is delivered', test.status === 200, test.text);
    check('and the receiver got JSON carrying the message', received.length === 1
      && /application\/json/.test(received[0].type)
      && JSON.parse(received[0].body).text.includes('test notification'), JSON.stringify(received[0]));

    // One payload has to serve Slack, Discord and a generic receiver.
    const payload = JSON.parse(received[0].body);
    check('the payload names the message three ways for three vendors',
      payload.text === payload.content && payload.content === payload.message);

    const asText = await request(port, 'POST', '/api/monitor/test-alert', {
      body: { alert: { enabled: true, url: hookUrl, mode: 'text' } },
    });
    check('text mode sends a bare string for ntfy', asText.status === 200
      && /text\/plain/.test(received[1].type) && !received[1].body.startsWith('{'), JSON.stringify(received[1]));

    // An unreachable webhook must be reported, not swallowed — silence would
    // read as "everything is fine".
    const dead = await request(port, 'POST', '/api/monitor/test-alert', {
      body: { alert: { enabled: true, url: 'http://127.0.0.1:1/nope' } },
    });
    check('a webhook that cannot be reached is reported', dead.status === 502, dead.text);

    // A real pass over an unreachable server should notify.
    await request(port, 'POST', '/api/profiles', { body: { ...SS, server: '203.0.113.99' } });
    const before = received.length;
    await request(port, 'POST', '/api/monitor/run', { body: {} });
    check('a pass where nothing answers sends a notification', received.length > before,
      `${before} → ${received.length}`);
    if (received.length > before) {
      check('and it says everything is unreachable',
        /unreachable/i.test(JSON.parse(received[received.length - 1].body).text),
        received[received.length - 1].body);
    }

    // The second identical pass must stay quiet: an hourly "still down" is how
    // people learn to ignore the notification entirely.
    const quiet = received.length;
    await request(port, 'POST', '/api/monitor/run', { body: {} });
    check('a second identical pass stays quiet', received.length === quiet, `${quiet} → ${received.length}`);

    // …including across a restart. The state used to live only in this
    // process's memory, so every deploy re-sent the outage that was already
    // sent — which is the same way people learn to ignore the notification.
    const state = JSON.parse(fs.readFileSync(path.join(dir, 'monitor-state.json'), 'utf8'));
    check('the alert state is written beside the store', state.alertState === 'down', JSON.stringify(state));

    child.kill();
    await new Promise((r) => setTimeout(r, 250));
    child = await boot(port, { HOST: '127.0.0.1' }, dir);
    const beforeRestart = received.length;
    await request(port, 'POST', '/api/monitor/run', { body: {} });
    check('and a pass after a restart stays quiet too',
      received.length === beforeRestart, `${beforeRestart} → ${received.length}`);
  } finally {
    child.kill();
    hook.close();
  }
}

// ── Response hardening ─────────────────────────────────────────────────────── //
// None of these headers were set at all. The page is one self-contained file, so
// a strict policy costs nothing — and the ?ui_token= in the URL before the
// cookie redirect is exactly the kind of thing a Referer leaks.
async function testHardening(dir) {
  console.log('\n── every response carries the hardening headers');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const root = await request(port, 'GET', '/');
    const csp = root.headers['content-security-policy'] || '';
    check('a Content-Security-Policy is set', /default-src 'none'/.test(csp), csp);
    check('the policy allows the inline page and same-origin fetches',
      /script-src 'unsafe-inline'/.test(csp) && /connect-src 'self'/.test(csp), csp);
    check('and QR data: URIs, which the page needs', /img-src 'self' data:/.test(csp), csp);
    check('framing is refused two ways', /frame-ancestors 'none'/.test(csp)
      && root.headers['x-frame-options'] === 'DENY', root.headers['x-frame-options']);
    check('nosniff, because these responses are credentials as text',
      root.headers['x-content-type-options'] === 'nosniff', root.headers['x-content-type-options']);
    check('no referrer, so ?ui_token= cannot leak through one',
      root.headers['referrer-policy'] === 'no-referrer', root.headers['referrer-policy']);
    check('the framework is not advertised', !root.headers['x-powered-by'], root.headers['x-powered-by']);

    // An /api path that matches no route used to fall through to express's HTML
    // error page, so a typo in a fetch() reported only "Request failed (404)".
    const missing = await request(port, 'GET', '/api/no-such-thing');
    check('an unknown /api route answers in JSON', missing.status === 404
      && missing.json && /No such endpoint/.test(missing.json.error), missing.text.slice(0, 120));
    const staticMissing = await request(port, 'GET', '/no-such-page');
    check('a missing static file still 404s as a static file',
      staticMissing.status === 404 && !staticMissing.json, staticMissing.text.slice(0, 60));
  } finally {
    child.kill();
  }
}

// ── UI_TOKEN has to be a password ──────────────────────────────────────────── //
// A stored token is 24 random bytes and anything under 16 characters is refused
// as "not a token" — but the environment pin skipped that check entirely, so
// `UI_TOKEN=x` guarded every credential in the store. The service template
// ships `change-me` as the example, which is how that gets copied.
async function testShortUiToken(dir) {
  console.log('\n── a too-short UI_TOKEN stops the server rather than pretending');
  const port = await freePort();
  const run = (token) => new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
      env: {
        ...process.env,
        PORT: String(port),
        HOST: '127.0.0.1',
        UI_TOKEN: token,
        CFG_PATH: path.join(dir, 'servers.json'),
        HISTORY_PATH: path.join(dir, 'history.json'),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let err = '';
    child.stderr.on('data', (b) => { err += b.toString(); });
    child.stdout.on('data', () => {});
    // A server that does start has to be stopped, or it holds the port.
    const timer = setTimeout(() => { child.kill(); resolve({ code: 'ran', err }); }, 2500);
    child.on('exit', (code) => { clearTimeout(timer); resolve({ code, err }); });
  });

  const short = await run('x');
  check('one character is refused', short.code === 1, `exit ${short.code}`);
  check('and it says why, with a way to fix it',
    /UI_TOKEN is 1 character/.test(short.err) && /randomBytes/.test(short.err), short.err.slice(0, 200));

  const long = await run('a-perfectly-adequate-token');
  check('a long enough one starts normally', long.code === 'ran', `exit ${long.code} ${long.err.slice(0, 120)}`);
}

// ── ★ must never hand out a profile no bundle carries ──────────────────────── //
// reseatActive() keeps ★ on an enabled profile whenever it can, but with every
// profile disabled there is nowhere honest to move it. The bundle endpoints
// refuse in that state; the single-profile ones used to serve the credentials
// anyway, so the same store answered two different ways.
async function testDisabledActiveHandout(dir) {
  console.log('\n── a disabled ★ is refused, not quietly served');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const made = await request(port, 'POST', '/api/profiles', {
      body: { ...SS, remarks: 'Off', enabled: false },
    });
    check('the profile saves', made.status === 200, made.text);
    check('nothing is enabled', made.json.enabledCount === 0, made.text);

    const qr = await request(port, 'GET', '/api/qrcode');
    check('/api/qrcode refuses the disabled ★', qr.status === 409, `${qr.status} ${qr.text.slice(0, 80)}`);
    check('and explains what to do', /Enable it/.test(qr.json ? qr.json.error : ''), qr.text.slice(0, 160));
    const uri = await request(port, 'GET', '/api/download/uri');
    check('/api/download/uri refuses it too', uri.status === 409, `${uri.status} ${uri.text.slice(0, 80)}`);
    const clash = await request(port, 'GET', '/api/download/clash');
    check('which is the same answer the bundles already gave', clash.status === 409, String(clash.status));

    // Asking for a specific profile is a different request, and still works:
    // looking at a disabled profile is why disabling exists at all.
    const byId = await request(port, 'GET', `/api/qrcode?id=${made.json.profiles[0].id}`);
    check('an explicit ?id= is still served', byId.status === 200 && !!byId.json.qrcode, String(byId.status));

    // Enable it and ★ becomes serveable again.
    await request(port, 'POST', `/api/profiles/${made.json.profiles[0].id}/enabled`, { body: { enabled: true } });
    const again = await request(port, 'GET', '/api/qrcode');
    check('enabling it makes ★ serveable again', again.status === 200, String(again.status));
  } finally {
    child.kill();
  }
}

// ── Trojan, VMess, and the clients that need their own format ──────────────── //
async function testNewProtocolsAndFormats(dir) {
  console.log('\n── trojan and vmess import, and Surge/Quantumult X say what they dropped');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const trojan = await request(port, 'POST', '/api/import', {
      body: { text: 'trojan://pw@t.example.com:443?security=tls&sni=t.example.com&type=ws&path=%2Ftj#TJ' },
    });
    check('a trojan:// link imports', trojan.status === 200 && trojan.json.added.length === 1, trojan.text);

    const vmessBody = Buffer.from(JSON.stringify({
      v: '2', ps: 'VM', add: 'v.example.com', port: '443',
      id: '22222222-2222-4222-8222-222222222222', aid: '0', net: 'ws',
      path: '/vm', tls: 'tls', sni: 'v.example.com',
    })).toString('base64');
    const vmess = await request(port, 'POST', '/api/import', { body: { text: `vmess://${vmessBody}` } });
    check('a vmess:// link imports', vmess.status === 200 && vmess.json.added.length === 1, vmess.text);

    // A Reality profile neither plain-text client can carry: Surge has no
    // VLESS at all, and Quantumult X carries Reality over raw TCP only.
    await request(port, 'POST', '/api/profiles', {
      body: {
        protocol: 'vless-reality', server: '203.0.113.5', port: 443,
        uuid: '33333333-3333-4333-8333-333333333333', publicKey: 'pk',
        sni: 'www.microsoft.com', shortId: 'ab', remarks: 'RE',
        network: 'grpc', serviceName: 'svc',
      },
    });

    const surge = await request(port, 'GET', '/api/download/surge');
    check('the Surge config downloads', surge.status === 200, String(surge.status));
    check('it carries the trojan server', /^TJ = trojan, t\.example\.com, 443/m.test(surge.text), surge.text.slice(0, 200));
    check('and names the one it had to leave out',
      /# RE: skipped — Surge has no VLESS or Reality support/.test(surge.text), surge.text.slice(0, 400));

    const qx = await request(port, 'GET', '/api/download/quantumultx');
    check('the Quantumult X config downloads', qx.status === 200, String(qx.status));
    check('it carries the vmess server', /^vmess=v\.example\.com:443/m.test(qx.text), qx.text.slice(0, 300));
    check('and names its omission too',
      /; RE: skipped — Quantumult X carries Reality over raw TCP only, not grpc/.test(qx.text), qx.text.slice(0, 400));

    // The dashboard needs the same verdict before the download, not after.
    const cfg = await request(port, 'GET', '/api/config');
    const support = cfg.json.clientSupport;
    check('clientSupport reports the coverage up front',
      support.surge.total === 3 && support.surge.usable === 2
      && support.quantumultx.usable === 2, JSON.stringify(support));
    check('with a reason per omitted server',
      /Reality/.test(support.surge.skipped[0].reason), JSON.stringify(support.surge.skipped));

    // The sparkline data has to reach the UI, or there is nothing to draw.
    await request(port, 'GET', '/api/test-all');
    const probed = await request(port, 'GET', '/api/config');
    check('probe history includes the recent samples the chart needs',
      Array.isArray(probed.json.profiles[0].history.recent)
      && probed.json.profiles[0].history.recent.length >= 1,
      JSON.stringify(probed.json.profiles[0].history).slice(0, 200));
  } finally {
    child.kill();
  }
}

// ── The subscription's display name ────────────────────────────────────────── //
// Without profile-title a client lists this subscription by its raw URL — token
// included — in the profile list and in every screenshot of it.
// A URI list is only servers. Everything this project knows about getting out
// of China — the DNS split, the fake-ip exemptions, the CN-direct rules, the geo
// mirrors — lives in the bundled configs, and a client that subscribed to the
// URI list never sees any of it: Clash Verge converts the list using its own
// defaults instead. `?target=` serves the whole config off the same token, so
// doing the easy thing does not silently throw the routing away.
async function testSubscriptionTargets(dir) {
  console.log('\n── the subscription can serve a whole client config, not just servers');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    await request(port, 'POST', '/api/profiles', { body: SS });
    const cfg = await request(port, 'GET', '/api/config');
    const sub = cfg.json.subscriptionPath;
    check('the server names the targets it serves',
      Array.isArray(cfg.json.subscriptionTargets) && cfg.json.subscriptionTargets.includes('clash'),
      JSON.stringify(cfg.json.subscriptionTargets));

    // The default has to stay the URI list: that is what a scanned QR code is,
    // and what v2rayNG and Shadowrocket expect to find at the end of the URL.
    const plain = await request(port, 'GET', sub);
    check('with no target it is still the base64 URI list',
      plain.status === 200 && /:\/\//.test(Buffer.from(plain.text, 'base64').toString()), plain.status);

    const clash = await request(port, 'GET', `${sub}?target=clash`);
    check('target=clash serves the routing, not just the proxies',
      clash.status === 200
      && /proxy-groups:/.test(clash.text)
      && /GEOIP,CN,DIRECT/.test(clash.text)
      && /fake-ip-filter:/.test(clash.text),
      clash.text.slice(0, 200));
    check('and it says it is YAML', /yaml/.test(clash.headers['content-type'] || ''),
      clash.headers['content-type']);
    check('and still carries the title header clients name it by',
      !!clash.headers['profile-title'], JSON.stringify(clash.headers));

    const sb = await request(port, 'GET', `${sub}?target=singbox`);
    const sbJson = JSON.parse(sb.text);
    check('target=singbox serves a parseable config with the tun inbound',
      sb.status === 200 && sbJson.inbounds.some((i) => i.type === 'tun'), sb.status);
    const desk = JSON.parse((await request(port, 'GET', `${sub}?target=singbox-desktop`)).text);
    check('and the desktop target drops the tun interface that needs root',
      !desk.inbounds.some((i) => i.type === 'tun'));

    for (const t of ['surge', 'quantumultx']) {
      const r = await request(port, 'GET', `${sub}?target=${t}`);
      check(`target=${t} serves its own format`, r.status === 200 && r.text.length > 50, r.status);
    }

    // A typo must not read as "your subscription is broken".
    const bad = await request(port, 'GET', `${sub}?target=nonsense`);
    check('an unknown target names the ones that exist',
      bad.status === 400 && /clash/.test(bad.text), bad.text);

    // The token still gates every one of them.
    const nope = await request(port, 'GET', '/api/subscription/deadbeefdeadbeefdeadbeef?target=clash');
    check('a wrong token 404s whatever the target', nope.status === 404, nope.status);
  } finally {
    child.kill();
  }
}

async function testTitle(dir) {
  console.log('\n── clients are told what to call this subscription');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    await request(port, 'POST', '/api/profiles', { body: SS });
    const before = await request(port, 'GET', '/api/config');
    check('the default title is Airport', before.json.title === 'Airport', before.json.title);

    const set = await request(port, 'POST', '/api/title', { body: { title: '  Home Airport  ' } });
    check('a title is saved and trimmed', set.json.title === 'Home Airport', set.text);

    const sub = await request(port, 'GET', `/api/subscription/${before.json.subscriptionPath.split('/').pop()}`);
    check('the feed carries profile-title',
      sub.headers['profile-title'] === `base64:${Buffer.from('Home Airport').toString('base64')}`,
      sub.headers['profile-title']);
    check('and profile-web-page-url pointing back here',
      /^https?:\/\/[^/]+\/$/.test(sub.headers['profile-web-page-url'] || ''),
      sub.headers['profile-web-page-url']);
    // Traffic and expiry are not things a config generator can know, and a
    // fabricated all-zero header paints every client with an "expired" badge.
    check('and no invented Subscription-Userinfo', !sub.headers['subscription-userinfo']);

    // It becomes a header value, so a CR must not survive the trip.
    const evil = await request(port, 'POST', '/api/title', { body: { title: 'A\r\nX-Evil: 1' } });
    check('a newline cannot be smuggled into the header', evil.json.title === 'A X-Evil: 1', evil.text);
    const after = await request(port, 'GET', `/api/subscription/${before.json.subscriptionPath.split('/').pop()}`);
    check('and the response has no injected header', !after.headers['x-evil'], JSON.stringify(after.headers));

    const bad = await request(port, 'POST', '/api/title', { body: {} });
    check('a missing title is a 400, not a silent reset', bad.status === 400, bad.text);
  } finally {
    child.kill();
  }
}

// ── Flap suppression, end to end ───────────────────────────────────────────── //
// A single failed probe on a lossy path is often just the link. With a threshold
// the first failures pass in silence — and the transition must survive them, or
// the alert it debounces is lost rather than delayed.
async function testAlertThreshold(dir) {
  console.log('\n── an alert threshold debounces a flapping server');
  const received = [];
  const hook = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => { received.push(body); res.writeHead(204).end(); });
  });
  await new Promise((r) => hook.listen(0, '127.0.0.1', r));
  const hookUrl = `http://127.0.0.1:${hook.address().port}/notify`;

  const port = await freePort();
  let child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const saved = await request(port, 'POST', '/api/monitor', {
      body: {
        enabled: false,
        alert: { enabled: true, url: hookUrl, mode: 'json', afterFailures: 3 },
      },
    });
    check('the threshold is stored', saved.json.monitor.alert.afterFailures === 3, saved.text);

    // 203.0.113.0/24 is the documentation range: nothing there answers.
    await request(port, 'POST', '/api/profiles', { body: { ...SS, server: '203.0.113.99' } });

    await request(port, 'POST', '/api/monitor/run', { body: {} });
    check('the first failed pass stays quiet', received.length === 0, `${received.length} sent`);
    const held = await request(port, 'GET', '/api/monitor');
    check('but the dashboard can see the streak',
      !!held.json && held.json.state.downStreak === 1, JSON.stringify(held.json && held.json.state));

    await request(port, 'POST', '/api/monitor/run', { body: {} });
    check('the second stays quiet too', received.length === 0, `${received.length} sent`);

    await request(port, 'POST', '/api/monitor/run', { body: {} });
    check('the third reports it', received.length === 1, `${received.length} sent`);
    if (received.length) {
      check('and says everything is unreachable',
        /unreachable/i.test(JSON.parse(received[0]).text), received[0].slice(0, 160));
    }

    await request(port, 'POST', '/api/monitor/run', { body: {} });
    check('and then goes quiet again', received.length === 1, `${received.length} sent`);

    // The streak is state too: a restart used to hand every deploy a fresh
    // grace period, delaying exactly the alert the threshold was debouncing.
    const state = JSON.parse(fs.readFileSync(path.join(dir, 'monitor-state.json'), 'utf8'));
    check('the streak is written beside the store', state.downStreak >= 3, JSON.stringify(state));

    child.kill();
    await new Promise((r) => setTimeout(r, 250));
    child = await boot(port, { HOST: '127.0.0.1' }, dir);
    const afterRestart = received.length;
    await request(port, 'POST', '/api/monitor/run', { body: {} });
    check('a pass after a restart does not re-send', received.length === afterRestart,
      `${afterRestart} → ${received.length}`);
  } finally {
    child.kill();
    hook.close();
  }
}

// ── HTTPS ──────────────────────────────────────────────────────────────────── //
// Off loopback the dashboard token, every proxy password and the whole
// subscription feed cross the LAN. Unverified TLS still beats none for that.
async function testTls(dir) {
  console.log('\n── TLS_SELFSIGNED encrypts the LAN hop');
  const haveOpenssl = (() => {
    try { return spawnSync('openssl', ['version']).status === 0; } catch { return false; }
  })();
  if (!haveOpenssl) {
    console.log('  · skipped — openssl is not on PATH, so no certificate can be minted');
    return;
  }
  const port = await freePort();
  const token = 'z'.repeat(32);
  const child = await boot(port, { HOST: '127.0.0.1', TLS_SELFSIGNED: '1', UI_TOKEN: token }, dir, 'https');
  try {
    const cfg = await request(port, 'GET', '/api/config', { headers: { 'X-UI-Token': token }, https: true });
    check('the dashboard answers over TLS', cfg.status === 200, cfg.status);
    check('and it says so, so the UI can build https:// URLs', cfg.json.tls === true, cfg.text);
    check('a certificate was written beside the store', fs.existsSync(path.join(dir, 'ui-cert.pem')));
    check('HSTS keeps the browser on https', /max-age=\d+/.test(String(cfg.headers['strict-transport-security'])), cfg.headers['strict-transport-security']);

    // Marking the cookie Secure on a plain-HTTP origin makes the browser drop
    // it — which locks you out of your own dashboard — so it is TLS-only.
    const redirect = await request(port, 'GET', `/?ui_token=${token}`, { https: true });
    check('the cookie is marked Secure under TLS',
      /Secure/.test(String(redirect.headers['set-cookie'])), redirect.headers['set-cookie']);

    // Plain HTTP to a TLS listener must fail rather than downgrade.
    const plain = await request(port, 'GET', '/api/config', { headers: { 'X-UI-Token': token } })
      .then((r) => r.status).catch(() => 'refused');
    check('plain HTTP does not get through', plain !== 200, plain);
  } finally {
    child.kill();
  }
}

// ── Same-site is not same-origin ───────────────────────────────────────────── //
// A sibling subdomain (or another localhost port) is "same-site", and
// SameSite=Strict cookies are still sent to it — so it could write here.
async function testSameSiteAndGuardedGets(dir) {
  console.log('\n── a same-site page cannot write, and side-effecting GETs are guarded');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const created = await request(port, 'POST', '/api/profiles', { body: SS });
    const tokenBefore = created.json.subscriptionPath;
    const sameSite = await request(port, 'POST', '/api/rotate-token', {
      body: {}, headers: { 'Sec-Fetch-Site': 'same-site' },
    });
    check('a same-site POST is refused', sameSite.status === 403, sameSite.status);
    const after = await request(port, 'GET', '/api/config');
    check('and the token did not rotate', after.json.subscriptionPath === tokenBefore);

    const ownPage = await request(port, 'POST', '/api/title', {
      body: { title: 'Mine' }, headers: { 'Sec-Fetch-Site': 'same-origin' },
    });
    check('the dashboard itself can still write', ownPage.status === 200, ownPage.text);

    const probe = await request(port, 'GET', '/api/test-all', { headers: { 'Sec-Fetch-Site': 'cross-site' } });
    check('a cross-site GET of /api/test-all is refused (no <img> can start probes)', probe.status === 403, probe.status);
    const feed = await request(port, 'GET', tokenBefore, { headers: { 'Sec-Fetch-Site': 'cross-site' } });
    check('the subscription feed is still reachable from a link anywhere', feed.status === 200, feed.status);
    const page = await request(port, 'GET', '/', { headers: { 'Sec-Fetch-Site': 'cross-site' } });
    check('and so is the dashboard page itself', page.status === 200, page.status);
    check('no HSTS over plain HTTP', !page.headers['strict-transport-security'], page.headers['strict-transport-security']);
  } finally {
    child.kill();
  }
}

// ── ★ reaches what clients download and subscribe to ───────────────────────── //
async function testStarInBundles(dir) {
  console.log('\n── ★ leads the failover group in every bundle a client receives');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    await request(port, 'POST', '/api/profiles', { body: { ...SS, remarks: 'First' } });
    const second = await request(port, 'POST', '/api/profiles', { body: { ...SS, server: '203.0.113.11', remarks: 'Second' } });
    await request(port, 'POST', '/api/active', { body: { id: second.json.savedId } });
    const clash = await request(port, 'GET', '/api/download/clash');
    check('the downloaded Clash config tries ★ first', /- name: "Fallback"\n\s+type: "fallback"\n\s+proxies:\n\s+- "Second"\n\s+- "First"/.test(clash.text), clash.text.slice(clash.text.indexOf('proxy-groups'), clash.text.indexOf('proxy-groups') + 400));
    check('and defaults to that group', /- name: "PROXY"\n\s+type: "select"\n\s+proxies:\n\s+- "Fallback"/.test(clash.text));
    const cfg = await request(port, 'GET', '/api/config');
    // Quantumult X rather than Surge: Surge cannot carry v2ray-plugin at all.
    const feed = await request(port, 'GET', `${cfg.json.subscriptionPath}?target=quantumultx`);
    check('a subscribed Quantumult X config does too', /^available=Fallback, Second, First$/m.test(feed.text), feed.text);
  } finally {
    child.kill();
  }
}

// ── A failed delivery is retried, not forgotten ─────────────────────────────── //
async function testAlertRetry(dir) {
  console.log('\n── an alert the webhook failed to take is sent again on the next pass');
  let answers = [500];
  const received = [];
  const hook = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const status = answers.length ? answers.shift() : 204;
      received.push(status);
      res.writeHead(status).end();
    });
  });
  await new Promise((r) => hook.listen(0, '127.0.0.1', r));
  const hookUrl = `http://127.0.0.1:${hook.address().port}/notify`;
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    await request(port, 'POST', '/api/monitor', { body: { alert: { enabled: true, url: hookUrl } } });
    await request(port, 'POST', '/api/profiles', { body: { ...SS, server: '203.0.113.99' } });
    const first = await request(port, 'POST', '/api/monitor/run', { body: {} });
    check('the first attempt reached a failing webhook', received.length === 1 && first.json.last.alert.sent === false, JSON.stringify(first.json.last));
    const state = JSON.parse(fs.readFileSync(path.join(dir, 'monitor-state.json'), 'utf8'));
    check('and the transition was not recorded as told', state.alertState !== 'down', JSON.stringify(state));
    answers = [];
    await request(port, 'POST', '/api/monitor/run', { body: {} });
    check('the next pass sends it again, and it lands', received.length === 2 && received[1] === 204, JSON.stringify(received));
    await request(port, 'POST', '/api/monitor/run', { body: {} });
    check('after which it goes quiet', received.length === 2, JSON.stringify(received));
  } finally {
    child.kill();
    hook.close();
  }
}

// ── VLESS + TLS through the API ───────────────────────────────────────────── //
async function testVlessTls(dir) {
  console.log('\n── a VLESS + TLS link imports and lands in the bundles');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const link = 'vless://11111111-2222-4333-8444-555555555555@v.example.com:443?encryption=none&security=tls&sni=v.example.com&type=ws&path=%2Fray#VL';
    const imp = await request(port, 'POST', '/api/import', { body: { text: link } });
    check('it imports', imp.status === 200 && imp.json.profiles[0].protocol === 'vless-tls', imp.text);
    const uri = await request(port, 'GET', `/api/download/uri?id=${imp.json.profiles[0].id}`);
    check('its URI download is named for what it is', /vless-uri\.txt/.test(uri.headers['content-disposition']), uri.headers['content-disposition']);
    const clash = await request(port, 'GET', '/api/download/clash');
    check('Clash carries it as TLS VLESS', /type: "vless"/.test(clash.text) && /tls: true/.test(clash.text) && !/reality-opts/.test(clash.text));
  } finally {
    child.kill();
  }
}

// ── Remote subscription sources ─────────────────────────────────────────────── //
async function testSources(dir) {
  console.log('\n── a provider subscription is followed, refreshed and let go');
  const uri = (host, name) => `trojan://pw@${host}:443?security=tls&sni=${host}#${encodeURIComponent(name)}`;
  let body = Buffer.from([uri('a.example.com', 'A'), uri('b.example.com', 'B')].join('\n')).toString('base64');
  let status = 200;
  let agent = '';
  const provider = http.createServer((req, res) => {
    agent = req.headers['user-agent'];
    if (req.url === '/hop') { res.writeHead(302, { Location: '/sub' }).end(); return; }
    res.writeHead(status, { 'Content-Type': 'text/plain' }).end(body);
  });
  await new Promise((r) => provider.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${provider.address().port}`;
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const mine = await request(port, 'POST', '/api/profiles', { body: SS });
    const bad = await request(port, 'POST', '/api/sources', { body: { url: 'http://169.254.169.254/latest' } });
    check('a metadata endpoint is refused as a source', bad.status === 400, bad.text);

    const added = await request(port, 'POST', '/api/sources', { body: { name: 'Provider', url: `${base}/hop`, intervalHours: 6 } });
    check('adding a source fetches it at once (through a redirect)', added.status === 200 && added.json.profiles.length === 3, added.text);
    check('as a v2rayN-style client, so the provider sends a link list', /v2rayN/.test(agent), agent);
    const src = added.json.sources[0];
    check('the source records what it found', src && src.count === 2 && src.lastCount === 2 && !src.lastError && src.intervalHours === 6, JSON.stringify(src));
    const fromSource = added.json.profiles.filter((p) => p.source === src.id);
    check('its servers are tagged with it, yours are not', fromSource.length === 2 && !added.json.profiles[0].source);
    const dup = await request(port, 'POST', '/api/sources', { body: { url: `${base}/hop` } });
    check('the same URL twice is refused', dup.status === 409, dup.status);

    const a = fromSource.find((p) => p.remarks === 'A');
    const b = fromSource.find((p) => p.remarks === 'B');
    await request(port, 'POST', `/api/profiles/${b.id}/enabled`, { body: { enabled: false } });
    // The provider drops A, renames B and adds C — and lists a server you
    // already have by hand.
    body = Buffer.from([uri('b.example.com', 'B renamed'), uri('c.example.com', 'C'),
      `ss://${Buffer.from('aes-256-gcm:hunter2').toString('base64url')}@203.0.113.10:8388#dup`].join('\n')).toString('base64');
    const refreshed = await request(port, 'POST', `/api/sources/${src.id}/refresh`, { body: {} });
    check('a refresh reports what changed', refreshed.status === 200 && /1 new, 1 updated, 1 gone, 1 skipped/.test(refreshed.json.summary), refreshed.text);
    const after = refreshed.json.profiles;
    const b2 = after.find((p) => p.id === b.id);
    check('a server still listed keeps its id and takes the new name', b2 && b2.remarks === 'B renamed', JSON.stringify(after.map((p) => p.remarks)));
    check('and stays switched off', b2 && b2.enabled === false);
    check('a server the provider dropped is gone', !after.some((p) => p.id === a.id));
    check('your own server was not duplicated', after.filter((p) => p.server === '203.0.113.10').length === 1);

    status = 500;
    const failing = await request(port, 'POST', `/api/sources/${src.id}/refresh`, { body: {} });
    check('a provider error is reported', failing.status === 502 && /500/.test(failing.json.error), failing.text);
    const kept = await request(port, 'GET', '/api/config');
    check('and the last good servers are kept', kept.json.profiles.length === after.length && /500/.test(kept.json.sources[0].lastError), JSON.stringify(kept.json.sources[0]));
    status = 200;
    body = '';
    const empty = await request(port, 'POST', `/api/sources/${src.id}/refresh`, { body: {} });
    check('an empty feed is an error, not an instruction to delete everything', empty.status === 502
      && (await request(port, 'GET', '/api/config')).json.profiles.length === after.length, empty.text);

    const edited = await request(port, 'POST', `/api/sources/${src.id}`, { body: { name: 'Renamed', intervalHours: 9999 } });
    check('a source can be renamed and rescheduled (clamped to a week)', edited.json.sources[0].name === 'Renamed' && edited.json.sources[0].intervalHours === 168, edited.text);

    // A hand edit keeps the tag, so the next refresh updates rather than duplicates.
    const c = after.find((p) => p.remarks === 'C');
    const saved = await request(port, 'POST', '/api/profiles', { body: { ...c, remarks: 'C edited' } });
    check('editing a source server keeps its source tag', saved.json.profiles.find((p) => p.id === c.id).source === src.id);

    const kept2 = await request(port, 'DELETE', `/api/sources/${src.id}?keep=1`);
    check('removing a source with keep=1 leaves its servers as your own',
      kept2.status === 200 && kept2.json.sources.length === 0 && kept2.json.profiles.length === after.length
      && kept2.json.profiles.every((p) => !p.source), kept2.text);
    void mine;
  } finally {
    child.kill();
    provider.close();
  }
}

(async () => {
  const dirs = [];
  const mk = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-api-')); dirs.push(d); return d; };
  try {
    await testLoopback(mk());
    await testAuthRequired(mk());
    await testPinnedToken(mk());
    await testRotation(mk());
    await testRestore(mk());
    await testHistoryPruning(mk());
    await testMonitorAndDownloads(mk());
    await testCsrf(mk());
    await testEnableDisable(mk());
    await testReorder(mk());
    await testClientTokens(mk());
    await testDeviceSubsets(mk());
    await testRules(mk());
    await testPublicUrl(mk());
    await testAlerts(mk());
    await testHardening(mk());
    await testShortUiToken(mk());
    await testDisabledActiveHandout(mk());
    await testNewProtocolsAndFormats(mk());
    await testTitle(mk());
    await testSubscriptionTargets(mk());
    await testAlertThreshold(mk());
    await testTls(mk());
    await testSameSiteAndGuardedGets(mk());
    await testStarInBundles(mk());
    await testAlertRetry(mk());
    await testVlessTls(mk());
    await testSources(mk());
  } catch (err) {
    console.error('✗ harness error:', err.message);
    failed += 1;
  } finally {
    for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* temp dir */ } }
  }
  console.log(failed ? `\n${passed} passed, ${failed} FAILED` : `\n${passed} passed`);
  process.exit(failed ? 1 : 0);
})();
