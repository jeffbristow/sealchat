/* Seal Chat 1.3.0 self-test: update signatures + download checks (local web server). node test/update-test.js */
const fs = require('fs'); const os = require('os'); const path = require('path'); const http = require('http'); const crypto = require('crypto');
const assert = require('assert');
const { Updater, verifySignature, signedText, UPDATE_PUBLIC_KEY } = require('../src/main/updater');
let passed = 0; const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealchat-upd-'));

// a throw-away signing key for the test (the real one stays private)
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const pub = publicKey.export({ type: 'spki', format: 'pem' });
const sign = (v, sha) => crypto.sign(null, Buffer.from(signedText(v, sha)), privateKey).toString('base64');

// a fake update file (asar with package.json) — reuse the asar format via @electron/asar
const asar = require('@electron/asar');
async function makeUpdate(version) {
  const dir = path.join(root, 'app-' + version); fs.mkdirSync(path.join(dir, 'src/main'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'sealchat', version, main: 'src/main/bootstrap.js' }));
  fs.writeFileSync(path.join(dir, 'src/main/main.js'), '// test'); fs.writeFileSync(path.join(dir, 'src/main/bootstrap.js'), '// test');
  const out = path.join(root, `SealChat-${version}.sealchat`); await asar.createPackage(dir, out); return out;
}

(async () => {
  ok(!verifySignature('1.0', 'a'.repeat(64), 'AAAA'), 'garbage signature refused');
  ok(UPDATE_PUBLIC_KEY.includes('BEGIN PUBLIC KEY'), 'Seal Chat\'s signing key is built in');

  const file = await makeUpdate('9.9.9');
  const sha = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  const files = { '/update.php': null, '/u/SealChat-9.9.9.sealchat': fs.readFileSync(file), '/u/SealChat-9.9.9.sealchat.sig': JSON.stringify({ version: '9.9.9', sha256: sha, sig: sign('9.9.9', sha) }) };
  let info = { version: '9.9.9', url: '/u/SealChat-9.9.9.sealchat', notes: ['Better things'], size: '1 KB' };
  const srv = http.createServer((q, r) => {
    const body = q.url.startsWith('/update.php') ? JSON.stringify(info) : files[q.url];
    if (body == null) { r.statusCode = 404; return r.end(); }
    r.setHeader('Content-Length', Buffer.byteLength(body)); r.end(body);
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const settings = { updateUrl: base + '/update.php', updateViaTor: false };
  const mk = (cur, key = pub) => new Updater({ currentVersion: cur, updatesDir: path.join(root, 'updates-' + cur), settings: () => settings, socksPort: () => null, allowHttp: true, publicKey: key });

  // newer version found
  let u = mk('1.3.0');
  await u.check();
  ok(u.state.available && u.state.available.version === '9.9.9' && u.state.available.notes[0] === 'Better things', '1.3.0 sees that 9.9.9 is available, with its notes');
  ok(u.state.available.url === base + '/u/SealChat-9.9.9.sealchat', 'a path on the site becomes a full address');
  const r = await u.downloadAndInstall();
  ok(r.version === '9.9.9' && fs.existsSync(path.join(root, 'updates-1.3.0', 'sealchat-9.9.9.asar')), 'downloaded, verified and placed for the next start');

  // same / older version: nothing offered
  u = mk('9.9.9'); await u.check(); ok(!u.state.available, 'nothing offered when you already have that version');
  u = mk('10.0.0'); await u.check(); ok(!u.state.available, 'never offers an OLDER version');

  // tampered file
  files['/u/SealChat-9.9.9.sealchat'] = Buffer.concat([fs.readFileSync(file), Buffer.from('x')]);
  u = mk('1.3.0'); await u.check();
  await assert.rejects(u.downloadAndInstall(), /does not match/); ok(!fs.existsSync(path.join(root, 'updates-1.3.0b')), 'changed file refused');
  files['/u/SealChat-9.9.9.sealchat'] = fs.readFileSync(file);

  // signed with someone else's key (website taken over)
  const other = crypto.generateKeyPairSync('ed25519');
  files['/u/SealChat-9.9.9.sealchat.sig'] = JSON.stringify({ version: '9.9.9', sha256: sha, sig: crypto.sign(null, Buffer.from(signedText('9.9.9', sha)), other.privateKey).toString('base64') });
  u = mk('1.3.0'); await u.check();
  await assert.rejects(u.downloadAndInstall(), /NOT valid/); ok(true, 'update signed with a different key is refused');

  // no signature at all
  delete files['/u/SealChat-9.9.9.sealchat.sig'];
  u = mk('1.3.0'); await u.check();
  await assert.rejects(u.downloadAndInstall(), /no valid signature/); ok(true, 'unsigned update is refused');

  // signature valid but the file inside claims another version
  const f2 = await makeUpdate('9.9.8'); const sha2 = crypto.createHash('sha256').update(fs.readFileSync(f2)).digest('hex');
  files['/u/SealChat-9.9.9.sealchat'] = fs.readFileSync(f2);
  files['/u/SealChat-9.9.9.sealchat.sig'] = JSON.stringify({ version: '9.9.9', sha256: sha2, sig: sign('9.9.9', sha2) });
  u = mk('1.3.0'); await u.check();
  await assert.rejects(u.downloadAndInstall(), /contains version/); ok(true, 'a file whose version differs from what was announced is refused');

  // https only (outside tests)
  const strict = new Updater({ currentVersion: '1.0.0', updatesDir: root, settings: () => ({ updateUrl: base + '/update.php', updateViaTor: false }), socksPort: () => null, publicKey: pub });
  await assert.rejects(strict.check(), /https/); ok(true, 'plain http:// update addresses are refused');

  // a server with a certificate that isn't trusted is refused
  const S = path.join(root, 'tls'); fs.mkdirSync(S);
  require('child_process').execSync(`openssl req -x509 -newkey rsa:2048 -nodes -keyout "${S}/k" -out "${S}/c" -days 1 -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null`);
  const hs = require('https').createServer({ key: fs.readFileSync(S + '/k'), cert: fs.readFileSync(S + '/c') }, (q, r) => r.end(JSON.stringify(info)));
  await new Promise(r => hs.listen(0, '127.0.0.1', r));
  const tlsU = new Updater({ currentVersion: '1.0.0', updatesDir: root, settings: () => ({ updateUrl: `https://127.0.0.1:${hs.address().port}/update.php`, updateViaTor: false }), socksPort: () => null, publicKey: pub });
  await assert.rejects(tlsU.check(), /certificate/); ok(true, 'an update server with an untrusted certificate is refused');
  hs.close();

  // ---- 1.7.0: the GitHub mirror (update.php's host blocks Tor) ----
  files['/u/SealChat-9.9.9.sealchat'] = fs.readFileSync(file);
  files['/u/SealChat-9.9.9.sealchat.sig'] = JSON.stringify({ version: '9.9.9', sha256: sha, sig: sign('9.9.9', sha) });
  const mir = http.createServer((q, r) => {
    if (q.url === '/update.json') return r.end(JSON.stringify({ version: '9.9.9', url: base + '/u/SealChat-9.9.9.sealchat' }));
    r.statusCode = 404; r.end();
  });
  await new Promise(r => mir.listen(0, '127.0.0.1', r));
  const mbase = `http://127.0.0.1:${mir.address().port}`;
  const blocked = http.createServer((q, r) => { r.writeHead(403, { 'Content-Type': 'text/html' }); r.end('<h1>Access denied</h1>'); });   // a host that blocks Tor visitors
  await new Promise(r => blocked.listen(0, '127.0.0.1', r));
  const bbase = `http://127.0.0.1:${blocked.address().port}`;
  const mkM = (cur, primary, set = {}) => new Updater({ currentVersion: cur, updatesDir: path.join(root, 'm-' + cur + Math.random()), settings: () => ({ updateViaTor: false, ...set }), socksPort: () => null, allowHttp: true, publicKey: pub, primaryUrl: primary, mirrors: [mbase + '/update.json'] });
  u = mkM('1.3.0', bbase + '/update.php'); await u.check();
  ok(u.state.available && u.state.available.version === '9.9.9' && u.state.source === 'fallback', 'first source blocked → the fallback answers (source: ' + u.state.source + ')');
  ok((await u.downloadAndInstall()).version === '9.9.9', 'installed from the fallback\'s address, signature checked as always');
  u = mkM('1.3.0', base + '/update.php'); await u.check();
  ok(u.state.source === 'primary', 'first source reachable → it is used first');
  const keep = files['/u/SealChat-9.9.9.sealchat']; info.url = '/missing/SealChat-9.9.9.sealchat';
  u = mkM('1.3.0', base + '/update.php'); await u.check();
  ok((await u.downloadAndInstall()).version === '9.9.9', 'download from the first source fails → same version fetched via the fallback');
  info.url = '/u/SealChat-9.9.9.sealchat'; void keep;
  u = mkM('1.3.0', bbase + '/update.php', { updateUrl: bbase + '/own.php' });
  await assert.rejects(u.check(), /answered 403/); ok(u.sources().length === 1, 'your own update address: the fallback is not used');
  { const { Updater: U2, DEFAULT_CHECK_URL: GH, WEBSITE_URL: WS } = require('../src/main/updater');
    const d = new U2({ currentVersion: '1.0.0', updatesDir: root, settings: () => ({}), socksPort: () => null });
    ok(d.sources().length === 1 && d.sources()[0] === GH && /^https:\/\/raw\.githubusercontent\.com\/jeffbristow\/sealchat-updates\//.test(GH), 'default: GitHub only (jeffbristow.com is not asked)');
    const old = new U2({ currentVersion: '1.0.0', updatesDir: root, settings: () => ({ updateUrl: WS }), socksPort: () => null });
    ok(old.sources().length === 1 && old.sources()[0] === GH && old.checkUrl() === GH, 'an old saved copy of the jeffbristow.com address → GitHub'); void WS; }
  mir.close(); blocked.close();

  srv.close();
  console.log(`\nUpdate tests: ${passed} passed`);
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
