/* Seal Chat 1.9.0 self-test: which updates the ANDROID app takes (update.json "android").
 *   node test/android-update-test.js                                       */
const http = require('http');
const assert = require('assert');
const { Updater } = require('../src/main/updater');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
let info = {};
const srv = http.createServer((q, r) => { r.writeHead(200, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(info)); });

(async () => {
  console.log('android updates:');
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${srv.address().port}/update.json`;
  const up = () => new Updater({ currentVersion: '1.9.0', updatesDir: '/tmp/x', settings: () => ({ updateViaTor: false }), socksPort: () => null, primaryUrl: url, allowHttp: true });
  const base = { version: '1.9.1', url: 'https://example.com/SealChat-1.9.1.sealchat', notes: ['x'] };

  process.env.SEALCHAT_ANDROID_SHELL = '1';
  info = base;
  let s = await up().check();
  ok(s.available && s.available.version === '1.9.1' && !s.available.needsApk, 'phone, no "android" entry: the update is offered (same file as the desktop)');
  info = { ...base, android: { minShell: 1 } };
  s = await up().check();
  ok(s.available && !s.available.needsApk, 'phone, minShell 1: offered');
  info = { ...base, android: { minShell: 2 } };
  const u = up(); s = await u.check();
  ok(s.available && s.available.needsApk, 'phone, minShell 2: shown, marked "needs the new APK"');
  let e = null; try { await u.downloadAndInstall(); } catch (x) { e = x; }
  ok(e && /needs a newer Android app/.test(e.message), '…and it is not installed: "' + (e && e.message) + '"');
  info = { ...base, android: false };
  s = await up().check();
  ok(!s.available, 'phone, "android": false: not offered');

  delete process.env.SEALCHAT_ANDROID_SHELL;
  s = await up().check();
  ok(s.available && !s.available.needsApk, 'desktop: "android": false makes no difference');

  srv.close();
  console.log(`\n${passed} passed`);
})().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
