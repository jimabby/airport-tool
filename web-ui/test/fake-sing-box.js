#!/usr/bin/env node
// A stand-in for the sing-box binary, used to exercise the deep connection test
// without a real proxy or a real server. It understands just enough of the CLI
// the deep probe uses: `version`, and `run -c <config>`.
//
// In `run` mode it reads the generated config, opens a plain HTTP proxy on the
// inbound's listen_port, and forwards requests to a loopback origin named by
// FAKE_ORIGIN. That covers everything the probe actually depends on: that the
// config is well-formed, that the listener comes up, that an absolute-form
// request through it succeeds, and that the child is cleaned up afterwards.
//
// An outbound pointed at FAIL_SERVER makes it exit the way the real binary does
// on a config it rejects, so the failure branch is testable from the same run.
'use strict';

const fs = require('fs');
const http = require('http');

const [, , cmd, ...rest] = process.argv;

if (cmd === 'version') {
  console.log('sing-box version 0.0.0-fake');
  process.exit(0);
}
if (cmd !== 'run') {
  console.error(`fake-sing-box: unsupported command ${cmd}`);
  process.exit(2);
}
const FAIL_SERVER = '198.51.100.254';

const cfgPath = rest[rest.indexOf('-c') + 1];
const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
const inbound = cfg.inbounds[0];
if (cfg.outbounds && cfg.outbounds[0] && cfg.outbounds[0].server === FAIL_SERVER) {
  console.error('FATAL decode config: simulated bad outbound');
  process.exit(1);
}
// Fail loudly on a config the real binary would reject, so a malformed outbound
// shows up as a test failure rather than a silent pass.
if (!cfg.outbounds || !cfg.outbounds.length || !cfg.outbounds[0].type) {
  console.error('FATAL decode config: no usable outbound');
  process.exit(1);
}

const origin = process.env.FAKE_ORIGIN;

http.createServer((req, res) => {
  if (!origin) { res.writeHead(502); res.end(); return; }
  const target = new URL(req.url);
  const proxied = http.request(
    { host: '127.0.0.1', port: Number(origin), path: target.pathname, method: req.method },
    (up) => { res.writeHead(up.statusCode, up.headers); up.pipe(res); },
  );
  proxied.on('error', () => { res.writeHead(502); res.end(); });
  req.pipe(proxied);
}).listen(inbound.listen_port, '127.0.0.1');
