/* =====================================================================
 * Seal Chat — web-test.js   (1.4.0 web access, end to end)
 * Runs the real Seal Chat Web files (Apache + mod_php when installed, else
 * php -S), the real WebAccess engine and the real browser client
 * (client.js + crypto.js, in Node):
 *   connection link → idle wake checks (no relay.php!) → pairing with
 *   matching codes → PIN → contacts/history/send → live pushes → back to
 *   idle → woken again → replay/forgery refused → remove device → disconnect
 * Needs: php (or Apache with mod_php). Seal Chat Web folder: ../sealchat-web
 * (or SITE_DIR). WEB_SERVER=php forces php -S.
 * ===================================================================== */
const fs = require('fs');
const os = require('os');
const path = require('path');
const server = require('./webserver');
const { WebAccess, parseLink } = require('../src/main/webaccess');

const SITE = process.env.SITE_DIR || path.join(__dirname, '..', '..', 'sealchat-web');
const Client = require(path.join(SITE, 'client.js'));
const K = require(path.join(SITE, 'crypto.js'));

// The phone's fetch(): one connection per request (php -S, the fallback test server,
// can otherwise make a request wait behind a long poll on the same worker).
const http = require('http');
globalThis.fetch = (url, o = {}) => new Promise((resolve, reject) => {
  const req = http.request(url, { method: o.method || 'GET', headers: o.headers, agent: false }, res => {
    const c = []; res.on('data', d => c.push(d));
    res.on('end', () => { const body = Buffer.concat(c).toString(); resolve({ status: res.statusCode, json: async () => JSON.parse(body) }); });
  });
  req.on('error', reject);
  if (o.signal) o.signal.addEventListener('abort', () => { req.destroy(); const e = new Error('aborted'); e.name = 'AbortError'; reject(e); });
  if (o.body) req.write(o.body);
  req.end();
});

let pass = 0, fail = 0;
const ok = (c, name) => { if (c) { pass++; console.log('  ✓ ' + name); } else { fail++; console.log('  ✗ ' + name); } };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, ms = 20000, step = 100) { const end = Date.now() + ms; while (Date.now() < end) { const v = await fn(); if (v) return v; await sleep(step); } return null; }

(async () => {
  /* ---------- website copy with its own data folder ---------- */
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scweb-'));
  const site = path.join(tmp, 'site'), data = path.join(tmp, 'data');
  fs.cpSync(SITE, site, { recursive: true });
  fs.mkdirSync(data);
  let cfg = fs.readFileSync(path.join(site, 'config.php'), 'utf8').replace(/'data_dir'\s*=>\s*''/, `'data_dir' => '${data}'`);
  fs.writeFileSync(path.join(site, 'config.php'), cfg);
  fs.writeFileSync(path.join(data, 'relay.json'), JSON.stringify({ enabled: true, code: 'TEST-CODE-WXYZ-2345' }));
  const srv = await server.start(site, tmp);
  const base = srv.base;
  console.log('Web server: ' + srv.kind);

  try {
    console.log('Link');
    ok(parseLink(base + '#relay=TEST-CODE-WXYZ-2345', true).code === 'TEST-CODE-WXYZ-2345', 'connection link parsed');
    let threw = null; try { parseLink('https://example.com/web/'); } catch (e) { threw = e.message; }
    ok(/relay code/.test(threw || ''), 'link without code refused: ' + threw);

    /* ---------- the computer ---------- */
    const vault = { web: {} };
    let settings = { webViaTor: false };
    const sent = [];
    const chats = { alice: [{ id: 'm1', dir: 'in', text: 'Hi from Alice', at: Date.now() - 60000, read: false }] };
    const handler = {
      me: () => ({ name: 'Jeff', avatar: null }),
      contacts: () => [{ id: 'alice', name: 'Alice', unread: 1, lastText: 'Hi from Alice', lastAt: Date.now(), status: 'accepted', online: true }],
      history: (cid, before) => ({ msgs: (chats[cid] || []).slice(-50), more: false }),
      send: (cid, text) => { if (!chats[cid]) throw new Error('Unknown contact'); const m = { id: 'o' + sent.length, dir: 'out', text, at: Date.now(), state: 'queued' }; chats[cid].push(m); sent.push(m); return m; },
      read: cid => { for (const m of chats[cid] || []) m.read = true; },
      // 1.6.0 contacts from the phone (the real ones are in main.js; these record what was asked)
      myId: async () => ({ id: 'sealchat:me', qr: 'data:image/png;base64,AAAA' }),
      checkId: text => { if (!/^sealchat:/.test(text)) throw new Error('That is not a Seal Chat ID'); return { id: text, prettyFp: 'ABCD', mine: false, existing: null }; },
      addContact: (id, nick) => { contactLog.push(['add', id, nick]); return { id: 'new1', name: nick || 'x', status: 'pending-out' }; },
      contactDetails: async cid => ({ contact: { id: cid, name: 'Alice', status: 'accepted' }, safety: '11111 22222' }),
      contactAct: (cid, act, value) => { contactLog.push([act, cid, value]); return act === 'remove' ? null : { id: cid, name: act === 'rename' ? value : 'Alice', status: 'accepted' }; }
    };
    const contactLog = [];
    const wa = new WebAccess({
      state: () => vault.web, save: () => {}, settings: () => settings, setSettings: p => { settings = { ...settings, ...p }; for (const k in settings) if (settings[k] === undefined) delete settings[k]; },
      socksPort: () => null, handler, allowHttp: true, idleMs: 1500, activeMs: 15000, quietMs: 1500, waitS: 3
    });
    const pairReqs = [];
    if (process.env.DEBUG_PUSH) {
      const t0 = Date.now(), T = () => ((Date.now() - t0) / 1000).toFixed(1);
      let lm = ''; wa.on('status', st => { if (st.mode !== lm) { lm = st.mode; console.log('    [' + T() + '] mode', st.mode, st.error || ''); } });
      const fd = wa._fromDevice.bind(wa); wa._fromDevice = async (id, d) => { const dv = vault.web.devices[id]; let t = '?'; try { t = require('../src/main/webaccess').open(require('../src/main/webaccess').unb64u(dv.k), 'sealchat-web-v1|d2c|' + id, d).t; } catch {} console.log('    [' + T() + '] got', t); return fd(id, d); };
      const sd = wa._send.bind(wa); wa._send = (id, o) => { console.log('    [' + T() + '] reply', o.t); return sd(id, o); };
    }
    wa.on('pairRequest', r => pairReqs.push(r));

    console.log('Connect');
    threw = null; try { await wa.connect(base + '#relay=WRONG-CODE-0000-0000'); } catch (e) { threw = e; }
    ok(threw && threw.code === 'code', 'wrong relay code refused: ' + (threw && threw.message));
    ok(!vault.web.box, 'nothing saved after a refused link');
    await wa.connect(base + '#relay=test-code-wxyz-2345');
    ok(!!vault.web.box && /^wake\/[a-f0-9]{32}\.txt$/.test(vault.web.wake), 'mailbox registered, wake file ' + vault.web.wake);
    ok(fs.existsSync(path.join(site, vault.web.wake)), 'wake file exists on the website');
    threw = null; try { wa.startPairing && await wa.startPairing(); } catch (e) { threw = e.message; }
    ok(/Turn web access on/.test(threw || ''), 'pairing needs web access on');
    ok(settings.webEnabled === undefined, 'web access is OFF by default');

    /* ---------- off = no traffic at all ---------- */
    wa.start();
    const before0 = srv.requests().length;
    await sleep(2500);
    ok(srv.requests().length === before0, 'while off: no requests to the website at all');

    /* ---------- idle: only the wake file ---------- */
    wa.setEnabled(true);
    await until(() => wa.mode === 'active');            // first look: wake file "new" → listens briefly
    await until(() => wa.mode === 'idle', 15000);
    ok(wa.mode === 'idle', 'idle after the first look');
    const l1 = srv.requests().length, c1 = wa.stats.checks;
    await sleep(5000);
    const idleLines = srv.requests().slice(l1);
    ok(wa.stats.checks - c1 >= 2, `idle checks happen (${wa.stats.checks - c1} in 5 s at 1.5 s interval)`);
    ok(idleLines.every(l => !/relay\.php/.test(l)), 'while idle: relay.php is NOT called (only the wake file): ' + idleLines.filter(l => /\/wake\//.test(l)).length + ' wake requests' + (srv.kind === 'apache' ? ', answered 304: ' + idleLines.filter(l => / 304 /.test(l)).length : ''));

    /* ---------- pairing ---------- */
    console.log('Pairing');
    const pr = await wa.startPairing();
    ok(/#pair=[a-f0-9]{32}\.[a-f0-9]{16}\./.test(pr.link), 'pairing link: ' + pr.link.replace(/\.[A-Za-z0-9_-]{30,}$/, '.<secret>'));
    let rec = null;
    const store = { load: async () => rec, save: async r => { rec = r; }, clear: async () => { rec = null; } };
    const phone = new Client({ base, storage: store });
    if (process.env.DEBUG_PUSH) {
      const t0 = Date.now(); const oc = phone.call.bind(phone);
      phone.call = async (a, b, ...r) => { const st = Date.now(); try { const j = await oc(a, b, ...r); if (a !== 'recv' || j.items.length) console.log('    phone', a, b && b.wait !== undefined ? 'wait' + b.wait : '', 'ok', Date.now() - st + 'ms', a === 'recv' ? j.items.length + ' items' : '', a === 'wake' ? 'woke=' + j.woke : ''); return j; } catch (e) { console.log('    phone', a, 'ERR', e.code || e.message); throw e; } };
    }
    const hash = pr.link.slice(pr.link.indexOf('#'));
    const p = Client.parsePair(hash);
    ok(p && p.box === vault.web.box, 'device reads the pairing link');
    let devCode = null;
    const pairing = phone.pair(p, 'iPhone', '2468', c => { devCode = c; });
    const req = await until(() => pairReqs[0], 20000);
    ok(!!req && req.name === 'iPhone', 'computer gets the pairing request');
    await until(() => devCode, 10000);
    ok(devCode && req && devCode === req.code, `same code on both screens: ${devCode} / ${req && req.code}`);
    await wa.approvePairing(req.tid);
    await pairing;
    ok(rec && rec.dev && rec.key, 'device saved its key');
    ok(Object.keys(vault.web.devices).length === 1 && !JSON.stringify(vault.web.devices).includes('2468'), 'computer stores the device (PIN only as a hash)');

    /* ---------- PIN + requests ---------- */
    console.log('Using it');
    threw = null; try { await phone.unlock('1111'); } catch (e) { threw = e; }
    ok(threw && threw.code === 'badpin' && /9 tries left/.test(threw.message), 'wrong PIN: ' + (threw && threw.message));
    const w = await phone.unlock('2468');
    ok(w.t === 'welcome' && w.contacts[0].name === 'Alice' && w.me.name === 'Jeff', 'right PIN → contacts');
    const h = await phone.ask('history', { cid: 'alice' });
    ok(h.msgs[0].text === 'Hi from Alice', 'chat history');
    await phone.ask('read', { cid: 'alice' });
    ok(chats.alice[0].read === true, 'opening the chat marks it read on the computer');
    const t0 = Date.now();
    const s = await phone.ask('send', { cid: 'alice', text: 'Hello from my phone 👋', tmp: 'x1' });
    ok(s.msg && sent[0] && sent[0].text === 'Hello from my phone 👋', `sent through the computer (${Date.now() - t0} ms round trip)`);
    threw = null; try { await phone.ask('send', { cid: 'bob', text: 'x' }); } catch (e) { threw = e.message; }
    ok(threw === 'Unknown contact', 'errors come back: ' + threw);
    const pushes = [];
    phone.on('push', o => pushes.push(o));
    wa.push({ t: 'msg', cid: 'alice', msg: { id: 'm2', dir: 'in', text: 'New one', at: Date.now() } });
    const gotPush = await until(() => pushes.find(x => x.t === 'msg'));
    if (!gotPush && process.env.DEBUG_PUSH) {
      const bd = path.join(data, 'relay', vault.web.box);
      for (const f of fs.readdirSync(bd)) console.log('   ', f, fs.readFileSync(path.join(bd, f), 'utf8').slice(0, 200));
      console.log('    phone ack', phone.ack, 'running', phone.running, 'pushes', pushes.map(x => x.t), 'mode', wa.mode, 'sessions', [...wa.sessions.keys()]);
    }
    ok(gotPush, 'live push reaches the phone');

    /* ---------- 1.6.0: contacts from the phone ---------- */
    console.log('Contacts from the phone (1.6.0)');
    let r16 = await phone.ask('checkId', { text: 'sealchat:abc' });
    ok(r16.id === 'sealchat:abc', 'checkId goes to the computer');
    threw = null; try { await phone.ask('checkId', { text: 'nonsense' }); } catch (e) { threw = e.message; }
    ok(threw === 'That is not a Seal Chat ID', 'bad ID → the computer\'s error comes back');
    r16 = await phone.ask('addContact', { id: 'sealchat:abc', nick: 'Bob' });
    ok(r16.contact && r16.contact.status === 'pending-out' && contactLog.some(l => l[0] === 'add' && l[2] === 'Bob'), 'addContact: the computer adds it (request pending)');
    r16 = await phone.ask('contactAct', { cid: 'alice', act: 'rename', value: 'Ali' });
    ok(r16.contact.name === 'Ali', 'contactAct rename');
    r16 = await phone.ask('contactAct', { cid: 'alice', act: 'remove' });
    ok(r16.contact === null, 'contactAct remove → no contact');
    r16 = await phone.ask('myId', {});
    ok(r16.id === 'sealchat:me' && /^data:image\/png/.test(r16.qr), 'myId: ID + QR picture from the computer');
    r16 = await phone.ask('contactDetails', { cid: 'alice' });
    ok(r16.safety === '11111 22222', 'contactDetails incl. safety number');

    /* ---------- 1.6.0: notifications ---------- */
    console.log('Notifications (1.6.0)');
    const http = require('http'), webpush = require('../src/main/webpush'), ncrypto = require('crypto');   // ("crypto" here is the web interface's crypto.js)
    const posts = []; let pushAnswer = 201;
    const ps = http.createServer((q, rr) => { const ch = []; q.on('data', d => ch.push(d)); q.on('end', () => { posts.push({ h: q.headers, body: Buffer.concat(ch) }); rr.writeHead(pushAnswer); rr.end(); }); });
    await new Promise(r => ps.listen(0, '127.0.0.1', r));
    const ua = ncrypto.createECDH('prime256v1'); ua.generateKeys(); const auth = ncrypto.randomBytes(16);
    // the browser's side of RFC 8291 (decrypting what the computer sent)
    const uaDecrypt = buf => {
      const salt = buf.subarray(0, 16), idlen = buf[20], keyid = buf.subarray(21, 21 + idlen), ct = buf.subarray(21 + idlen);
      const shared = ua.computeSecret(keyid);
      const ikm = Buffer.from(ncrypto.hkdfSync('sha256', shared, auth, Buffer.concat([Buffer.from('WebPush: info\0'), ua.getPublicKey(), keyid]), 32));
      const cek = Buffer.from(ncrypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16));
      const nonce = Buffer.from(ncrypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12));
      const d = ncrypto.createDecipheriv('aes-128-gcm', cek, nonce); d.setAuthTag(ct.subarray(ct.length - 16));
      const plain = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
      return JSON.parse(plain.subarray(0, plain.lastIndexOf(2)).toString());
    };
    const key = (await phone.ask('pushKey', {})).key;
    ok(Buffer.from(key, 'base64url').length === 65 && vault.web.vapid && vault.web.vapid.pub === key, 'the computer has a push key (made once, in the vault)');
    const sub = { endpoint: `http://127.0.0.1:${ps.address().port}/push/abc`, keys: { p256dh: ua.getPublicKey().toString('base64url'), auth: auth.toString('base64url') } };
    r16 = await phone.ask('pushOn', { sub, names: false });
    const devId0 = Object.keys(vault.web.devices)[0];
    ok(r16.push.on && vault.web.devices[devId0].push.endpoint === sub.endpoint, 'pushOn saves the subscription');
    wa.notify({ kind: 'msg', name: 'Alice' }); await sleep(800);
    ok(posts.length === 0, 'no notification while the phone is active');
    vault.web.devices[devId0].lastUsed = Date.now() - 120e3;
    wa.notify({ kind: 'msg', name: 'Alice' });
    ok(await until(() => posts.length === 1, 10000), 'notification sent once the phone is idle');
    ok(uaDecrypt(posts[0].body).body === 'New message', 'decrypts to the plain "New message" (no name by default)');
    ok(posts[0].h['content-encoding'] === 'aes128gcm' && /^vapid t=/.test(posts[0].h.authorization), 'Web Push headers');
    await phone.ask('pushNames', { names: true }); vault.web.devices[devId0].push.lastTry = 0; vault.web.devices[devId0].lastUsed = Date.now() - 120e3;
    wa.notify({ kind: 'msg', name: 'Alice' }); await until(() => posts.length === 2, 10000);
    ok(uaDecrypt(posts[1].body).body === 'New message from Alice', 'with names allowed: "New message from Alice"');
    wa.setDevicePush(devId0, { on: false }); vault.web.devices[devId0].push.lastTry = 0;
    wa.notify({ kind: 'msg', name: 'Alice' }); await sleep(800);
    ok(posts.length === 2, 'switched off on the computer: nothing sent');
    wa.setDevicePush(devId0, { on: true }); pushAnswer = 410; vault.web.devices[devId0].push.lastTry = 0;
    wa.notify({ kind: 'msg', name: 'Alice' }); await until(() => !vault.web.devices[devId0].push, 10000);
    ok(!vault.web.devices[devId0].push, '410 from the push service → subscription forgotten');
    threw = null; try { webpush.checkEndpoint('https://evil.example/x'); } catch (e) { threw = e.message; }
    ok(/unknown push service/.test(threw || ''), 'only the browser makers\' push services are allowed: ' + threw);
    ps.close();

    /* ---------- replay + forgery ---------- */
    console.log('Security');
    const q = JSON.parse(fs.readFileSync(path.join(data, 'relay', vault.web.box, 'state.json'), 'utf8'));
    ok(!JSON.stringify(q).includes(rec.token), 'relay keeps only token hashes');
    // the relay (or anyone) replays an old sealed request → ignored
    const old = await K.seal(rec.key, K.AAD.msg('d2c', rec.dev), { t: 'send', cid: 'alice', text: 'REPLAY', s: 1, sid: phone.sid, q: 999 });
    await phone.call('send', { to: 'c', items: [old] });
    // a message sealed with a wrong key → ignored
    const bad = await K.seal(await crypto.subtle.importKey('raw', K.random(32), 'AES-GCM', false, ['encrypt']), K.AAD.msg('d2c', rec.dev), { t: 'send', cid: 'alice', text: 'FORGED', s: Date.now() * 2000, sid: phone.sid, q: 998 });
    await phone.call('send', { to: 'c', items: [bad] });
    await sleep(2500);
    ok(!sent.some(m => /REPLAY|FORGED/.test(m.text)), 'replayed and forged messages are ignored');
    const relayFiles = fs.readdirSync(path.join(data, 'relay', vault.web.box)).map(f => fs.readFileSync(path.join(data, 'relay', vault.web.box, f), 'utf8')).join('');
    ok(!/Hello from my phone|Alice|2468/.test(relayFiles), 'nothing readable is stored on the website');

    /* ---------- back to idle, then woken by the page ---------- */
    console.log('Idle ↔ active');
    phone.lock();
    await until(() => wa.mode === 'idle', 20000);
    ok(wa.mode === 'idle', 'computer goes back to idle after the page locks/closes');
    const phone2 = new Client({ base, storage: store });
    await phone2.load();
    const t1 = Date.now();
    const w2 = await phone2.unlock('2468');
    ok(w2.t === 'welcome', `opening the page again wakes the computer (${Date.now() - t1} ms with a 1.5 s idle interval)`);

    /* ---------- auto-off timer ---------- */
    settings.webUntil = Date.now() - 1;
    ok(wa.enabled() === false && !settings.webEnabled, '"turn off after…" switches web access off');
    wa.setEnabled(true);

    /* ---------- remove device ---------- */
    console.log('Remove');
    let revoked = null;
    phone2.on('revoked', r => { revoked = r; });
    await wa.removeDevice(rec.dev);
    phone2.ask('ping', {}).catch(() => {});
    ok(await until(() => revoked, 10000), 'removed device is locked out: ' + revoked);
    phone2.stop();

    /* ---------- disconnect ---------- */
    const box = vault.web.box;
    await wa.disconnect();
    ok(!fs.existsSync(path.join(data, 'relay', box)) && !vault.web.box && !settings.webEnabled, 'disconnect removes the mailbox and turns web access off');
    wa.stop();
  } catch (e) {
    fail++; console.log('  ✗ crashed: ' + (e.stack || e));
  } finally {
    srv.stop();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  console.log(`\nweb-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
