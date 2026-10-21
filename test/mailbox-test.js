/* Seal Chat 1.8.0 self-test: the MAILBOX, end to end — two contacts (fake
 * Tor), the real Seal Chat Web relay.php (Apache/php) as the mailbox.
 *   node test/mailbox-test.js                                              */
const os = require('os');
const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert');
const { EventEmitter } = require('events');
const { Store } = require('../src/main/store');
const { Identity } = require('../src/main/identity');
const { Peer } = require('../src/main/peer');
const { FileVault } = require('../src/main/files');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, ms, what) { const end = Date.now() + ms; while (Date.now() < end) { if (await fn()) return; await sleep(40); } throw new Error('timed out: ' + what); }
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealchat-files-'));
const plain = { strong: false, encrypt: b => b, decrypt: b => b };
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const streamToBuf = s => new Promise((res, rej) => { const a = []; s.on('data', d => a.push(d)); s.on('end', () => res(Buffer.concat(a))); s.on('error', rej); });

/* ---- fake Tor (as in core-test) with an optional speed limit ---- */
const routes = new Map(); const offline = new Set();
const torBlocked = new Set();   // 1.8.2: ports of websites that refuse Tor visitors
let throttle = 0; // bytes per 50 ms per connection (0 = unlimited)
const socks = net.createServer(c => {
  c.once('data', () => { c.write(Buffer.from([5, 0])); c.once('data', d => {
    const rawHost = d.subarray(5, 5 + d[4]).toString();
    const host = rawHost.replace(/\.onion$/, '');
    if (!rawHost.endsWith('.onion')) {                     // an ordinary website (the mailbox): straight through, like Tor would
      const wport = d.readUInt16BE(5 + d[4]);
      if (torBlocked.has(wport)) { c.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); return; }   // the host refuses Tor
      const up = net.connect(wport, rawHost, () => { c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])); c.pipe(up); up.pipe(c); });
      up.on('error', () => c.destroy()); c.on('error', () => up.destroy());
      return;
    }
    const port = routes.get(host);
    if (!port || offline.has(host)) { c.end(Buffer.from([5, 0xf0, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
    const up = net.connect(port, '127.0.0.1', () => {
      c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
      // both directions, optionally slowed down (to test interruptions)
      const pipe = (from, to) => from.on('data', chunk => {
        if (!throttle) { to.write(chunk); return; }
        from.pause();
        const step = throttle;
        (async () => { for (let o = 0; o < chunk.length; o += step) { if (to.destroyed) return; to.write(chunk.subarray(o, o + step)); await sleep(50); } from.resume(); })();
      });
      pipe(c, up); pipe(up, c);
    });
    up.on('error', () => c.destroy()); c.on('error', () => up.destroy()); c.on('close', () => up.destroy()); up.on('close', () => c.destroy());
  }); });
});
class FakeTor extends EventEmitter {
  constructor() { super(); this.ready = true; }
  async publish(key, port) { const k = key || 'k' + crypto.randomBytes(8).toString('hex'); const onion = crypto.createHash('sha256').update(k).digest('hex').replace(/[^a-z2-7]/g, 'a').padEnd(55, 'b').slice(0, 55) + 'd'; routes.set(onion, port); this.onion = onion; return { onion, key: k }; }
  async unpublish() { if (this.onion) routes.delete(this.onion); }
}
async function node(name, armored, pass) {
  const dir = path.join(root, name);
  const store = new Store(dir, plain);
  const identity = await new Identity().load(armored, pass);
  const tor = new FakeTor(); tor.socksPort = socks.address().port;
  const files = new FileVault(path.join(dir, 'files'));
  const peer = new Peer({ store, identity, tor, files, allowHttpMailbox: true, mbAfter: 0, log: l => process.env.DEBUG && console.log('[' + name + '] ' + l) });
  await peer.start();
  return { store, identity, peer, files };
}

const server = require('./webserver');
// 1.8.4: a host that answers every visitor with a "security check" page (HTTP 200, HTML)
const http0 = require('http');
let pagePort = 0;
const pageSrv = http0.createServer((q, res) => { q.resume(); q.on('end', () => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<html><head><title>Checking your browser before accessing</title></head><body>wait</body></html>'); }); });
const { WebAccess } = require('../src/main/webaccess');
const SITE = process.env.SITE_DIR || path.join(__dirname, '..', '..', 'sealchat-web');

(async () => {
  await new Promise(r => socks.listen(0, '127.0.0.1', r));
  await new Promise(r => pageSrv.listen(0, '127.0.0.1', r)); pagePort = pageSrv.address().port;
  // ---- Jeff's website (real relay.php) ----
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scmb-'));
  const site = path.join(tmp, 'site'), data = path.join(tmp, 'data');
  fs.cpSync(SITE, site, { recursive: true }); fs.mkdirSync(data);
  fs.writeFileSync(path.join(site, 'config.php'), fs.readFileSync(path.join(site, 'config.php'), 'utf8').replace(/'data_dir'\s*=>\s*''/, `'data_dir' => '${data}'`));
  fs.writeFileSync(path.join(data, 'relay.json'), JSON.stringify({ enabled: true, code: 'TEST-CODE-WXYZ-2345' }));
  try { require('child_process').execFileSync('chown', ['-R', 'www-data:www-data', tmp]); } catch { /* not root */ }
  const srv = await server.start(site, tmp);

  const jk = await Identity.generate({ name: 'Jeff', passphrase: 'jeff-pass-123' });
  const ak = await Identity.generate({ name: 'Ann', passphrase: 'ann-pass-1234' });
  const jeff = await node('jeff', jk, 'jeff-pass-123');
  const ann = await node('ann', ak, 'ann-pass-1234');
  ann.peer.addContact(jeff.peer.myId());
  await until(() => jeff.store.contact(ann.identity.fp), 5000, 'request');
  jeff.peer.accept(ann.identity.fp);
  await until(() => ann.store.contact(jeff.identity.fp).status === 'accepted', 5000, 'accept');
  const J = jeff.identity.fp, A = ann.identity.fp;

  // ---- Jeff turns his mailbox on ----
  const vault = { web: {} }; let settings = { webViaTor: false };
  const web = new WebAccess({ state: () => vault.web, save: () => {}, settings: () => settings, setSettings: p => { settings = { ...settings, ...p }; }, socksPort: () => null, handler: { me: () => ({}), contacts: () => [] }, allowHttp: true });
  await web.connect(srv.base + '#relay=TEST-CODE-WXYZ-2345');
  const drop = crypto.randomBytes(24).toString('base64url');
  const set = await web.mboxSet(drop);
  ok(set.ok && set.mailbox === true, 'the computer turns its mailbox on (the website keeps only a hash of the drop token)');
  const place = web.mailboxPlace();
  jeff.peer.setMailbox({ url: place.url, box: place.box, drop });
  jeff.peer.send(A, 'mailbox is on');
  await until(() => ann.store.contact(J).mailbox, 10000, 'mailbox info');
  ok(ann.store.contact(J).mailbox.box === place.box && ann.store.contact(J).mailbox.drop === drop, 'Ann learns where Jeff\'s mailbox is (sent signed + encrypted, only to contacts)');

  // ---- Jeff goes offline; Ann writes ----
  const keep = await ann.peer.send(J, 'hello before'); await until(() => jeff.store.chat(A).messages.some(m => m.id === keep.id), 8000, 'direct');
  offline.add(jeff.peer.onion);
  for (const l of [...jeff.peer.links.values(), ...ann.peer.links.values()]) l.destroy();
  const m1 = ann.peer.send(J, 'Are you there? Left this while you were away.');
  const m2 = ann.peer.send(J, 'Second one', { re: m1.id });
  const old = jeff.store.chat(A).messages.find(m => m.id === keep.id);
  ann.peer.react(J, keep.id, '👍');
  const fm = await ann.peer.sendFile(J, { buffer: Buffer.from('photo bytes') }, { name: 'pic.jpg', mime: 'image/jpeg' });
  await until(() => ['mailbox'].includes(ann.store.chat(J).messages.find(m => m.id === m1.id).state) && ann.store.chat(J).messages.find(m => m.id === fm.id).state === 'mailbox', 45000, 'left in mailbox');
  ok(true, 'Jeff is offline → Ann\'s messages and file offer are left in his mailbox (📬)');
  await until(() => !(ann.store.vault.ctl || []).some(x => x.k === 'react'), 10000, 'react mailed');
  ok(true, 'her reaction goes to the mailbox too');
  const stored = fs.readFileSync(path.join(data, 'relay', place.box, 'q-m.json'), 'utf8');
  ok(!stored.includes('Are you there') && !stored.includes(A) && !stored.includes('Ann'), 'the website holds only encrypted blobs — no text, no sender');

  // ---- Jeff starts again and picks up ----
  const got = [];
  const r = await web.mboxGet(0);
  for (const it of r.items) got.push(await jeff.peer.fromMailbox(it.d));
  ok(got.length >= 4 && got.every(g => g.ok && g.from === A), `Jeff picks up ${got.length} items — each checked as signed by Ann`);
  const jc = jeff.store.chat(A).messages;
  const j1 = jc.find(m => m.id === m1.id), j2 = jc.find(m => m.id === m2.id);
  ok(j1 && j1.text.startsWith('Are you there') && j2 && j2.re && j2.re.id === m1.id, 'the messages (and the reply) appear in his chat');
  ok(old.reactions && old.reactions.them === '👍', 'the reaction appears');
  ok(jc.find(m => m.id === fm.id && m.kind === 'file'), 'the file offer appears (the file itself downloads once Ann is reachable)');
  await web.mboxGet(Math.max(...r.items.map(i => i.id)));
  ok((await web.mboxGet(0)).items.length === 0, 'picked-up messages are deleted from the website');
  ok((await jeff.peer.fromMailbox(r.items[0].d)).ok && jeff.store.chat(A).messages.filter(m => m.id === m1.id).length === 1, 'a message seen twice (mailbox replayed) still appears once');

  // ---- back online: Ann's 📬 become ✓ ----
  offline.delete(jeff.peer.onion);
  ann.peer.retryNow(J);
  await until(() => ann.store.chat(J).messages.find(m => m.id === m1.id).state === 'sent' || ann.store.chat(J).messages.find(m => m.id === m1.id).state === 'read', 20000, 'confirmed');
  ok(jeff.store.chat(A).messages.filter(m => m.id === m1.id).length === 1, 'once both are online, 📬 turns into ✓ — without a duplicate on Jeff\'s side');

  // ---- refusals ----
  const http = require('http');
  const post = (hdrs, body) => new Promise(res => { const q = http.request(srv.base + 'relay.php?a=mbox_drop', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-SC-Box': place.box, ...hdrs } }, s => { const c = []; s.on('data', d => c.push(d)); s.on('end', () => res({ status: s.statusCode, j: JSON.parse(Buffer.concat(c).toString() || '{}') })); }); q.end(JSON.stringify(body)); });
  ok((await post({ 'X-SC-Drop': 'x'.repeat(32) }, { d: 'AAAA' })).status === 404, 'a wrong drop token can\'t leave anything');
  ok((await post({ 'X-SC-Drop': drop }, { d: 'A'.repeat(800 * 1024) })).status === 413, 'an oversized message is refused');
  const stranger = await Identity.generate({ name: 'Mallory', passphrase: 'mallory-pass-1' });
  const sId = new Identity(); await sId.load(stranger, 'mallory-pass-1');
  const fake = await sId.sealFor(jeff.identity.pubArmored, { k: 'text', id: 'evil1', text: 'hi', to: J, from: { fp: A, onion: ann.peer.onion } });
  await post({ 'X-SC-Drop': drop }, { d: fake });
  const fr = await web.mboxGet(0);
  const res = await jeff.peer.fromMailbox(fr.items[fr.items.length - 1].d);
  ok(!res.ok && res.why === 'bad signature' && !jeff.store.chat(A).messages.some(m => m.id === 'evil1'), 'a message claiming to be from Ann but not signed by her is refused');
  await web.mboxGet(fr.items[fr.items.length - 1].id);
  const notContact = await sId.sealFor(jeff.identity.pubArmored, { k: 'text', id: 'evil2', text: 'hi', to: J, from: { fp: sId.fp, onion: 'x' } });
  ok((await jeff.peer.fromMailbox(notContact)).why === 'not from a contact', 'a message from someone who isn\'t a contact is refused');

  // ---- Jeff turns it off ----
  await web.mboxSet(null);
  jeff.peer.setMailbox(null);
  ok((await post({ 'X-SC-Drop': drop }, { d: 'AAAA' })).status === 404, 'after turning the mailbox off, nothing can be left');
  jeff.peer.send(A, 'mailbox off now');
  await until(() => !ann.store.contact(J).mailbox, 10000, 'mailbox removed');
  ok(true, 'contacts are told the mailbox is gone');

  // ---- 1.8.4: Jeff's website blocks Tor → the message waits, and Ann's chat says so ----
  await web.mboxSet(drop);
  jeff.peer.setMailbox({ url: place.url, box: place.box, drop });
  jeff.peer.send(A, 'mailbox back on');
  await until(() => ann.store.contact(J).mailbox, 10000, 'mailbox info again');
  const sitePort = Number(new URL(srv.base).port);
  torBlocked.add(sitePort);
  offline.add(jeff.peer.onion);
  for (const l of [...jeff.peer.links.values(), ...ann.peer.links.values()]) l.destroy();
  await until(() => ![...ann.peer.out.values()].some(v => v.busy), 100000, 'ann idle');
  await jeff.peer.stop();                                              // Jeff really offline (no links either way)
  { const cj = ann.store.contact(J); cj.lastError = null; ann.store.putContact(cj); }
  const fm2 = ann.peer.send(J, 'host blocks Tor'); ann.peer.retryNow(J);
  await until(() => ann.store.contact(J).lastError && /blocks visitors that come through Tor/.test(ann.store.contact(J).lastError), 45000, 'blocked message: ' + ann.store.contact(J).lastError + ' / ' + ann.store.contact(J).mailboxError);
  ok(ann.store.chat(J).messages.find(m => m.id === fm2.id).state === 'queued', 'host blocks Tor: it waits, and Ann\'s chat says so — "' + ann.store.contact(J).lastError + '"');
  torBlocked.delete(sitePort); offline.delete(jeff.peer.onion);
  // a security-check page (HTTP 200, HTML) instead of relay.php's answer
  { const cj = ann.store.contact(J); cj.lastError = null; cj.mailbox = { ...cj.mailbox, url: `http://127.0.0.1:${pagePort}/` }; ann.store.putContact(cj); }
  ann.peer.retryNow(J);
  await until(() => ann.store.contact(J).lastError && /web page/.test(ann.store.contact(J).lastError), 45000, 'page message');
  ok(/Checking your browser/.test(ann.store.contact(J).lastError), 'a security-check page is named in the message — "' + ann.store.contact(J).lastError + '"');
  { const cj = ann.store.contact(J); cj.mailbox = { ...cj.mailbox, url: place.url }; ann.store.putContact(cj); }
  await jeff.peer.start();

  // ---- 1.8.1: a contact who was on an older Seal Chat when the mailbox was shared ----
  const ck = await Identity.generate({ name: 'Cat', passphrase: 'cat-pass-12345' });
  const cat = await node('cat', ck, 'cat-pass-12345');
  cat.peer.o.oldKinds = ['mbox', 'devices', 'react'];                  // acts like Seal Chat 1.7
  const C = cat.identity.fp;
  cat.peer.addContact(jeff.peer.myId());
  await until(() => jeff.store.contact(C), 8000, 'cat request');
  jeff.peer.accept(C);
  await until(() => cat.store.contact(J).status === 'accepted', 8000, 'cat accepted');
  await web.mboxSet(drop);
  jeff.peer.setMailbox({ url: place.url, box: place.box, drop });       // mailbox on again
  const cm1 = jeff.peer.send(C, 'hi Cat');
  await until(() => cat.store.chat(J).messages.some(m => m.id === cm1.id) && !(jeff.store.vault.ctl || []).some(x => x.to === C && x.k === 'mbox'), 10000, 'cat got message');
  ok(!cat.store.contact(J).mailbox && jeff.store.contact(C).olderVersion && !jeff.store.contact(C).mboxSent, 'an older Seal Chat can\'t take the mailbox address — it is NOT marked as sent');
  cat.peer.o.oldKinds = null;                                          // Cat updates to 1.8
  cat.peer.send(J, 'updated now');
  await until(() => cat.store.contact(J).mailbox, 15000, 'mailbox after update');
  ok(cat.store.contact(J).mailbox.box === place.box && !jeff.store.contact(C).olderVersion, 'once Cat is on 1.8, Jeff\'s Seal Chat sends the mailbox address again by itself');

  srv.stop(); web.stop && web.stop();
  console.log(`\nMailbox tests: ${passed} passed`);
  process.exit(0);
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
