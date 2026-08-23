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

// ── Per-device subscription tokens ─────────────────────────────────────────── //
async function testClientTokens(dir) {
  console.log('\n── per-device subscription URLs are revocable on their own');
  const port = await freePort();
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
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
  } finally {
    child.kill();
  }
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
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
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
    await testClientTokens(mk());
    await testAlerts(mk());
    await testTls(mk());
  } catch (err) {
    console.error('✗ harness error:', err.message);
    failed += 1;
  } finally {
    for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* temp dir */ } }
  }
  console.log(failed ? `\n${passed} passed, ${failed} FAILED` : `\n${passed} passed`);
  process.exit(failed ? 1 : 0);
})();
