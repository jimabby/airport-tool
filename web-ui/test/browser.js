'use strict';

const { chromium, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const assert = require('assert/strict');
const { spawn } = require('child_process');
const C = require('../../config-gen/lib/configs');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-browser-'));
const root = path.resolve(__dirname, '../..');
const fixture = C.normalizeStore({ token: 'browser-subscription-token', uiToken: 'browser-dashboard-token', active: 1,
  profiles: ['Alpha', 'Bravo', 'Charlie'].map((remarks, i) => ({ protocol: 'shadowsocks', server: '127.0.0.1', port: 31000 + i, method: 'aes-256-gcm', plugin: '', password: 'test-only', remarks })) });
fs.writeFileSync(path.join(dir, 'servers.json'), JSON.stringify(fixture));
let feed = 'trojan://first@example.com:443?sni=example.com#Provider';
let app, browser, provider, origin;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  provider = http.createServer((_req, res) => res.end(feed));
  await new Promise((r) => provider.listen(0, '127.0.0.1', r));
  origin = http.createServer((_req, res) => { const timer = setTimeout(() => res.writeHead(204).end(), 3000); res.on('close', () => clearTimeout(timer)); });
  await new Promise((r) => origin.listen(0, '127.0.0.1', r));
  const reservation = http.createServer(); await new Promise((r) => reservation.listen(0, '127.0.0.1', r));
  const port = reservation.address().port; await new Promise((r) => reservation.close(r));
  const base = `http://127.0.0.1:${port}`;
  app = spawn(process.execPath, [path.join(root, 'web-ui/server.js')], { env: { ...process.env,
    CFG_PATH: path.join(dir, 'servers.json'), HOST: '127.0.0.1', PORT: String(port), PUBLIC_URL: '', UI_TOKEN: '', TLS_SELFSIGNED: '', TLS_CERT: '', TLS_KEY: '',
    SINGBOX_BIN: process.execPath, SINGBOX_ARGS: JSON.stringify([path.join(__dirname, 'fake-sing-box.js')]),
    DEEP_TEST_URL: 'http://test.invalid/', FAKE_ORIGIN: String(origin.address().port),
  }, stdio: 'ignore' });
  for (let i = 0; ; i++) { try { await fetch(base); break; } catch (e) { if (i > 100) throw e; await sleep(100); } }
  browser = await chromium.launch({ headless: true, ...(process.env.BROWSER_EXECUTABLE ? { executablePath: process.env.BROWSER_EXECUTABLE } : {}) });
  const page = await browser.newPage();
  const errors = []; page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(base);
  await expect(page.locator('#profile-count')).toContainText('3 of 3');
  await page.locator('#profile-search').fill('Bravo');
  await expect(page.locator('#profile-tabs .profile-tab')).toHaveCount(1);
  await page.locator('#bulk-select').click();
  await expect(page.locator('#profile-count')).toContainText('1 checked');
  await page.locator('#bulk-disable').click();
  await expect(page.locator('#profile-count')).toContainText('0 checked');
  await page.locator('#profile-enabled').selectOption('disabled');
  await expect(page.locator('#profile-tabs .profile-tab')).toHaveCount(1);
  await page.locator('#bulk-select').click(); await page.locator('#bulk-enable').click();
  await expect(page.locator('#profile-tabs .profile-tab')).toHaveCount(0);
  await page.locator('#profile-search').fill(''); await page.locator('#profile-enabled').selectOption('');
  console.log('✓ profile search, filters, selection and bulk enable/disable');

  await page.locator('#source-name').fill('Demo');
  await page.locator('#source-url').fill(`http://127.0.0.1:${provider.address().port}/feed`);
  await page.locator('#btn-source-add').click();
  await expect(page.locator('#source-preview-changes')).toContainText('added: Provider');
  await expect(page.locator('#profile-count')).toContainText('3 of 3');
  await page.locator('#source-preview-apply').click();
  await expect(page.locator('#profile-count')).toContainText('4 of 4');
  feed = 'trojan://changed@example.com:443?sni=example.com#Provider';
  await page.getByRole('button', { name: 'Preview changes', exact: true }).click();
  await expect(page.locator('#source-preview-changes')).toContainText('password');
  await page.request.post(`${base}/api/title`, { data: { title: 'Concurrent change' } });
  await page.locator('#source-preview-apply').click();
  await expect(page.locator('#source-preview-message')).toContainText('Settings changed');
  await page.getByRole('button', { name: 'Preview changes', exact: true }).click();
  await expect(page.locator('#source-preview-apply')).toBeEnabled();
  await page.locator('#source-preview-apply').click();
  await expect(page.locator('#source-preview')).toBeHidden();
  console.log('✓ subscription preview, explicit apply and stale-preview recovery');

  await page.locator('#backup-create').click();
  await expect(page.locator('#toast')).toContainText('Encrypted snapshot saved');
  const backupId = await page.locator('#backup-select').inputValue();
  await page.locator('#profile-search').fill('Alpha'); await page.locator('#bulk-select').click();
  await page.locator('#bulk-disable').click();
  await expect(page.locator('#profile-count')).toContainText('0 checked');
  await page.locator('#backup-select').selectOption(backupId);
  page.once('dialog', (d) => d.accept());
  await page.locator('#backup-rollback').click();
  await expect(page.locator('#toast')).toContainText('Recovery snapshot restored');
  await page.locator('#profile-enabled').selectOption('disabled');
  await expect(page.locator('#profile-tabs .profile-tab')).toHaveCount(0);
  await page.locator('#profile-search').fill(''); await page.locator('#profile-enabled').selectOption('');
  console.log('✓ encrypted snapshot creation and rollback through the dashboard');

  await page.locator('#deep-test').check(); await page.locator('#btn-test-all').click();
  await expect(page.locator('#test-cancel')).toBeVisible();
  await page.locator('#test-cancel').click();
  await expect(page.locator('#test-progress')).toContainText('cancelled', { timeout: 15000 });
  await expect(page.locator('#btn-test-all')).toBeEnabled();
  await page.locator('#btn-test-all').click();
  await expect(page.locator('#test-progress')).toContainText('4/4 completed — complete', { timeout: 15000 });
  await expect(page.locator('#test-all-results .result-row')).toHaveCount(4);
  console.log('✓ cancellable deep tests, progress and completed results');

  const response = await page.request.post(`${base}/api/profiles`, { data: { protocol: 'vless-reality', server: 'example.com', port: 443,
    uuid: '11111111-2222-4333-8444-555555555555', publicKey: 'test-key', sni: 'example.com', shortId: 'ab', network: 'xhttp', remarks: 'XHTTP' } });
  assert.equal(response.status(), 200);
  await page.reload();
  await expect(page.locator('#client-support-hint')).toContainText('Sing-Box has no XHTTP');
  await page.locator('[data-dl="singbox"]').click();
  await expect(page.locator('#toast')).toContainText('Sing-Box export refused');
  assert.deepEqual(errors, []);
  console.log('✓ incompatible export explained; no browser script errors');
}
main().then(() => console.log('Browser workflows passed')).catch((err) => { console.error(err); process.exitCode = 1; }).finally(async () => {
  if (browser) await browser.close();
  if (app && app.exitCode === null) { app.kill(); await new Promise((r) => app.once('exit', r)); }
  for (const server of [provider, origin]) if (server) { server.closeAllConnections(); await new Promise((r) => server.close(r)); }
  const resolved = path.resolve(dir);
  assert.ok(resolved.startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(resolved).startsWith('airport-browser-'));
  fs.rmSync(resolved, { recursive: true, force: true });
});
