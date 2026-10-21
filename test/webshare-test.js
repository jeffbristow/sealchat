/* =====================================================================
 * Seal Chat — webshare-test.js   (1.9.3: web access shared by linked devices)
 * Two "computers" (two WebAccess engines, as on two linked devices) and one
 * phone (the real client.js) against the real Seal Chat Web files:
 *   A connects → B gets the connection by sync → pair on A → B knows the
 *   phone → only ONE of them answers (the lease) → A stops → B takes over
 *   (no double answers, messages keep arriving) → wrong PINs counted
 *   together → removing the phone on B removes it on A → new token after a
 *   device is removed → two different connections: one is kept → an older
 *   website (no lease): only the device that connected it answers.
 * Needs: php. Seal Chat Web folder: ../sealchat-web (or SITE_DIR).
 * ===================================================================== */
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const server = require('./webserver');
const { WebAccess } = require('../src/main/webaccess');

const SITE = process.env.SITE_DIR || path.join(__dirname, '..', '..', 'sealchat-web');
const Client = require(path.join(SITE, 'client.js'));

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

/** One "computer": its own vault + settings; sync goes straight to the others' applyShared. */
function computer(name, node, peers) {
  const c = { name, node, vault: { web: {} }, settings: { webViaTor: false }, sent: [], linked: true };
  const handler = {
    me: () => ({ name: 'Jeff', avatar: null }),
    contacts: () => [{ id: 'alice', name: 'Alice', unread: 0, status: 'accepted', online: true }],
    history: () => ({ msgs: [], more: false }),
    send: (cid, text) => { const m = { id: name + c.sent.length, dir: 'out', text, at: Date.now(), state: 'queued' }; c.sent.push(m); return m; },
    read: () => {}
  };
  c.wa = new WebAccess({
    state: () => c.vault.web, save: () => {}, settings: () => c.settings,
    setSettings: p => { c.settings = { ...c.settings, ...p }; for (const k in c.settings) if (c.settings[k] === undefined) delete c.settings[k]; },
    socksPort: () => null, handler, allowHttp: true, idleMs: 1200, activeMs: 15000, quietMs: 1500, waitS: 3, shareDelayMs: 50,
    node: () => node,
    siblings: () => c.linked ? peers.filter(p => p !== c && p.linked).length : 0,
    nodeName: id => (peers.find(p => p.node === id) || {}).name,
    syncOut: w => { const copy = JSON.parse(JSON.stringify(w)); for (const p of peers) if (p !== c && p.linked && c.linked) setTimeout(() => p.wa.applyShared(copy).catch(e => console.log('    apply', e.message)), 20); }
  });
  c.wa.on('log', l => { if (process.env.DEBUG) console.log('    [' + name + '] ' + l); });
  return c;
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scshare-'));
  const site = path.join(tmp, 'site'), data = path.join(tmp, 'data');
  fs.cpSync(SITE, site, { recursive: true });
  fs.mkdirSync(data);
  fs.writeFileSync(path.join(site, 'config.php'), fs.readFileSync(path.join(site, 'config.php'), 'utf8').replace(/'data_dir'\s*=>\s*''/, `'data_dir' => '${data}'`));
  fs.writeFileSync(path.join(data, 'relay.json'), JSON.stringify({ enabled: true, code: 'TEST-CODE-WXYZ-2345' }));
  const srv = await server.start(site, tmp);
  const base = srv.base;
  console.log('Web server: ' + srv.kind);
  const peers = [];
  const A = computer('A', 'aaaaaaaaaaaaaaaa', peers), B = computer('B', 'bbbbbbbbbbbbbbbb', peers);
  peers.push(A, B);
  const pairReqs = [];
  A.wa.on('pairRequest', r => pairReqs.push(r));

  try {
    console.log('Sharing the connection');
    await A.wa.connect(base + '#relay=TEST-CODE-WXYZ-2345');
    ok((A.vault.web.feat || []).includes('lease'), 'Seal Chat Web 1.3.2 says it can hand out a lease');
    A.wa.setEnabled(true);
    await until(() => B.vault.web.box === A.vault.web.box && B.settings.webEnabled, 5000);
    ok(B.vault.web.box === A.vault.web.box && B.vault.web.token === A.vault.web.token, 'B got the same connection by sync');
    ok(B.settings.webEnabled === true, 'web access on → on for B too');
    ok(B.vault.web.vapid && B.vault.web.vapid.pub === A.vault.web.vapid.pub, 'same notification key on both');
    A.wa.start(); B.wa.start();
    await until(() => A.wa.mode === 'idle' && B.wa.mode === 'idle', 30000);
    ok(A.wa.mode === 'idle' && B.wa.mode === 'idle', 'both waiting (idle)');

    console.log('Pairing on A');
    const pr = await A.wa.startPairing();
    let rec = null;
    const store = { load: async () => rec, save: async r => { rec = r; }, clear: async () => { rec = null; } };
    const phone = new Client({ base, storage: store });
    const p = Client.parsePair(pr.link.slice(pr.link.indexOf('#')));
    let code = null;
    const pairing = phone.pair(p, 'Pixel', '2468', c => { code = c; });
    const req = await until(() => pairReqs[0], 25000);
    ok(!!req, 'A gets the pairing request (pairing takes the lease)');
    await until(() => code, 10000);
    await A.wa.approvePairing(req.tid);
    await pairing;
    const devId = rec && rec.dev;
    ok(!!devId, 'phone paired');
    await until(() => B.vault.web.devices && B.vault.web.devices[devId], 5000);
    ok(!!(B.vault.web.devices || {})[devId], 'B knows the phone too (key, PIN check)');

    console.log('Only one answers');
    const w = await phone.unlock('2468');
    ok(w.t === 'welcome', 'unlocked');
    const r1 = await phone.ask('send', { cid: 'alice', text: 'one' });
    ok(r1.t === 'sent', 'message sent from the phone');
    await sleep(2500);
    ok(A.sent.length + B.sent.length === 1, `sent once in all (A ${A.sent.length}, B ${B.sent.length})`);
    const holder = A.wa.holding ? A : B, other = holder === A ? B : A;
    await until(() => other.wa.mode === 'standby', 25000);
    ok(holder.wa.holding && other.wa.mode === 'standby', `${holder.name} answers, ${other.name} stands by`);
    ok(other.wa.status().shared && other.wa.status().shared.standbyBy === holder.name, 'standby shows who answers: ' + (other.wa.status().shared || {}).standbyBy);
    await phone.ask('ping', {});
    ok(await until(() => other.wa._viewing(devId), 25000), 'the standby device knows the phone is looking (no notification from it)');

    console.log('The answering device stops');
    // "switched off": nothing it still has in flight gets answered, and it can't reach the website
    const orig = { call: holder.wa._call, from: holder.wa._fromDevice };
    holder.wa._fromDevice = async () => {};
    holder.wa._call = () => Promise.reject(Object.assign(new Error('offline'), { code: 'net' }));
    holder.wa.stop();
    const t0 = Date.now();
    const r2 = await phone.ask('send', { cid: 'alice', text: 'two' }, 120000);
    ok(r2.t === 'sent', `${other.name} took over and answered (${Math.round((Date.now() - t0) / 1000)} s)`);
    ok(other.wa.holding, other.name + ' holds the lease now');
    const r3 = await phone.ask('send', { cid: 'alice', text: 'three' }, 30000);
    ok(r3.t === 'sent', 'next message straight away');
    await sleep(1500);
    const texts = [...A.sent, ...B.sent].map(m => m.text).sort();
    ok(JSON.stringify(texts) === JSON.stringify(['one', 'three', 'two']), 'each message sent exactly once: ' + texts.join(','));

    console.log('Back');
    holder.wa._call = orig.call; holder.wa._fromDevice = orig.from; holder.wa.holding = false;
    holder.wa.start();
    await until(() => holder.wa.mode === 'standby' || holder.wa.mode === 'idle', 20000);
    ok(['standby', 'idle'].includes(holder.wa.mode), holder.name + ' back: does not answer twice (' + holder.wa.mode + ')');
    const r4 = await phone.ask('send', { cid: 'alice', text: 'four' }, 30000);
    await sleep(2000);
    ok(r4.t === 'sent' && [...A.sent, ...B.sent].filter(m => m.text === 'four').length === 1, 'still once');

    console.log('Wrong PINs counted together');
    phone.lock();
    let e1 = null; try { await phone.unlock('0000'); } catch (e) { e1 = e; }
    ok(e1 && e1.code === 'badpin', 'wrong PIN: ' + (e1 && e1.message));
    await sleep(600);
    ok(A.vault.web.devices[devId].fails === 1 && B.vault.web.devices[devId].fails === 1, 'both have 1 wrong try');
    phone.lock();
    await phone.unlock('2468');
    await sleep(600);
    ok(A.vault.web.devices[devId].fails === 0 && B.vault.web.devices[devId].fails === 0, 'reset on both after the right PIN');

    console.log('Removing the phone on one device');
    const rm = other;
    await rm.wa.removeDevice(devId);
    await sleep(800);
    ok(!A.vault.web.devices[devId] && !B.vault.web.devices[devId], 'gone on both');
    const state = JSON.parse(fs.readFileSync(path.join(data, 'relay', A.vault.web.box, 'state.json'), 'utf8'));
    ok(!state.devices[devId], 'and on the website');
    phone.stop();

    console.log('New token after removing a device');
    const oldTok = A.vault.web.token;
    ok(await A.wa.rekey(), 'A gives the website a new token');
    await until(() => B.vault.web.token !== oldTok, 3000);
    ok(B.vault.web.token === A.vault.web.token && A.vault.web.token !== oldTok, 'B got the new token by sync');
    const r = await new Promise(res => { const q = http.request(base + 'relay.php?a=recv', { method: 'POST', headers: { 'X-SC-Box': A.vault.web.box, Authorization: 'Bearer ' + oldTok } }, s => { let b = ''; s.on('data', d => b += d); s.on('end', () => res({ status: s.statusCode, body: b })); }); q.end('{}'); });
    ok(r.status === 401, 'the old token (the removed device) is refused: ' + r.status);

    console.log('Two different connections');
    A.wa.stop(); B.wa.stop();
    const C = computer('C', 'cccccccccccccccc', peers);
    C.linked = false;                                  // not linked yet: connects on its own
    await C.wa.connect(base + '#relay=TEST-CODE-WXYZ-2345');
    ok(C.vault.web.box && C.vault.web.box !== A.vault.web.box, 'C has its own connection');
    peers.push(C); C.linked = true;                    // now linked: C's is the newest choice → kept for all
    C.wa.shareNow();
    await until(() => A.vault.web.box === C.vault.web.box && B.vault.web.box === C.vault.web.box, 5000);
    ok(A.vault.web.box === C.vault.web.box && B.vault.web.box === C.vault.web.box, 'one connection for all three (the one chosen most recently)');

    console.log('Older Seal Chat Web (no lease)');
    for (const x of [A, B, C]) x.vault.web.feat = [];
    ok(C.wa._serves() && !A.wa._serves() && !B.wa._serves(), 'only the device that connected it answers');

    console.log('Turned off / removed');
    C.wa.setEnabled(false);
    await sleep(300);
    ok(!A.settings.webEnabled && !B.settings.webEnabled, 'off on one → off on all');
    B.wa.forgetLocal('removed');
    ok(!B.vault.web.box && !B.settings.webEnabled, 'a removed device stops using it');
  } catch (e) {
    fail++; console.log('  ✗ ' + (e.stack || e));
  } finally {
    for (const x of peers) x.wa.stop();
    await srv.stop();
  }
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
