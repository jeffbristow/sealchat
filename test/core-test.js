/* Seal Chat core self-test (no Tor needed: a tiny fake SOCKS proxy maps
 * .onion names to local ports).   node test/core-test.js                  */
const os = require('os');
const fs = require('fs');
const net = require('net');
const path = require('path');
const assert = require('assert');
const { EventEmitter } = require('events');
const { Store } = require('../src/main/store');
const { Identity, safetyNumber } = require('../src/main/identity');
const { Peer, parseId, formatId } = require('../src/main/peer');
const { socksConnect, FrameSocket } = require('../src/main/wire');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, ms, what) { const end = Date.now() + ms; while (Date.now() < end) { if (await fn()) return; await sleep(50); } throw new Error('timed out: ' + what); }
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealchat-core-'));
const plainProtect = { strong: false, encrypt: b => b, decrypt: b => b };
const xorProtect = { strong: true, encrypt: b => Buffer.from(b.map(x => x ^ 0x5a)), decrypt: b => Buffer.from(b.map(x => x ^ 0x5a)) };

/* ---- fake Tor: SOCKS5 server that maps <onion>.onion -> 127.0.0.1:port ---- */
const routes = new Map();
const offline = new Set();
const socks = net.createServer(c => {
  c.once('data', () => {
    c.write(Buffer.from([5, 0]));
    c.once('data', d => {
      const host = d.subarray(5, 5 + d[4]).toString().replace(/\.onion$/, '');
      const port = routes.get(host);
      if (!port || offline.has(host)) { c.end(Buffer.from([5, 0xf0, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
      const up = net.connect(port, '127.0.0.1', () => { c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])); c.pipe(up); up.pipe(c); });
      up.on('error', () => c.destroy()); c.on('error', () => up.destroy());
    });
  });
});
class FakeTor extends EventEmitter {
  constructor() { super(); this.ready = true; this.socksPort = 0; }
  async publish(key, port) {
    const k = key || 'ED25519-V3:' + require('crypto').randomBytes(32).toString('base64');
    const onion = require('crypto').createHash('sha256').update(k).digest('hex').replace(/[^a-z2-7]/g, 'a').padEnd(55, 'b').slice(0, 55) + 'd';
    routes.set(onion, port); this.onion = onion; return { onion, key: k };
  }
  async unpublish() { if (this.onion) routes.delete(this.onion); }
}

async function makeNode(name, armored, pass) {
  const store = new Store(path.join(root, name), plainProtect);
  store.vault.identity = { armored, passphrase: pass };
  const identity = await new Identity().load(armored, pass);
  const tor = new FakeTor(); tor.socksPort = socks.address().port;
  const peer = new Peer({ store, identity, tor });
  await peer.start();
  return { store, identity, tor, peer };
}

(async () => {
  await new Promise(r => socks.listen(0, '127.0.0.1', r));

  // ---- 1. IDs ----
  const onion = 'a'.repeat(55) + 'd', fp = 'ABCDEF0123456789ABCDEF0123456789ABCDEF01';
  ok(parseId(formatId(onion, fp)).fp === fp, 'ID round-trips');
  ok(parseId(`  sealchat:${onion.slice(0, 20)}\n${onion.slice(20)}:${fp.toLowerCase()} `).onion === onion, 'ID pasted with line breaks / lower case still works');
  ok(parseId(`${onion}.onion ${fp}`).fp === fp, '"address.onion fingerprint" form accepted');
  assert.throws(() => parseId('sealchat:xyz:123')); ok(true, 'garbage ID rejected');

  // ---- 2. store encryption + data key protection ----
  const s1 = new Store(path.join(root, 'st'), xorProtect);
  s1.vault.identity = { armored: 'SECRET-KEY-TEXT', passphrase: 'pw' }; s1.saveVault();
  s1.chat('X').messages.push({ id: '1', text: 'very private words' }); s1.saveChat('X'); s1.flush();
  const allBytes = fs.readdirSync(path.join(root, 'st')).concat(fs.readdirSync(path.join(root, 'st', 'chats')).map(f => 'chats/' + f))
    .filter(f => !f.endsWith('chats')).map(f => fs.readFileSync(path.join(root, 'st', f))).reduce((a, b) => Buffer.concat([a, b]), Buffer.alloc(0));
  ok(!allBytes.includes(Buffer.from('SECRET-KEY-TEXT')) && !allBytes.includes(Buffer.from('very private')), 'nothing readable on disk');
  const s2 = new Store(path.join(root, 'st'), xorProtect);
  ok(s2.vault.identity.passphrase === 'pw' && s2.chat('X').messages[0].text === 'very private words', 'reopens with the protected data key');
  const vf = path.join(root, 'st', 'vault.dat'); const b = fs.readFileSync(vf); b[b.length - 1] ^= 1; fs.writeFileSync(vf, b);
  assert.throws(() => new Store(path.join(root, 'st'), xorProtect)); ok(true, 'tampered file is refused (authenticated encryption)');

  // ---- 3. safety number ----
  ok(safetyNumber('AA', 'BB') === safetyNumber('BB', 'AA') && /^(\d{5} ){11}\d{5}$/.test(safetyNumber('AA', 'BB')), 'safety number: same on both sides, 60 digits');

  // ---- 4. key import checks ----
  const jk = await Identity.generate({ name: 'Jeff', passphrase: 'jeff-pass-123' });
  const ak = await Identity.generate({ name: 'Ann', passphrase: 'ann-pass-1234' });
  const mk = await Identity.generate({ name: 'Mallory', passphrase: 'mal-pass-1234' });
  await assert.rejects(Identity.inspectPrivate(jk, 'wrong')); ok(true, 'import: wrong passphrase refused');
  const pubOnly = (await new Identity().load(jk, 'jeff-pass-123')).pubArmored;
  await assert.rejects(Identity.inspectPrivate(pubOnly, 'x')); ok(true, 'import: a public key is refused (private key needed)');
  ok((await Identity.inspectPrivate(jk, 'jeff-pass-123')).name === 'Jeff', 'import: good key accepted');

  // ---- 5. peers over the fake network ----
  const jeff = await makeNode('jeff', jk, 'jeff-pass-123');
  const ann = await makeNode('ann', ak, 'ann-pass-1234');
  const mal = await makeNode('mal', mk, 'mal-pass-1234');
  ann.peer.addContact(jeff.peer.myId(), { note: 'hi' });
  await until(() => jeff.store.contact(ann.identity.fp), 5000, 'request');
  jeff.peer.accept(ann.identity.fp);
  await until(() => ann.store.contact(jeff.identity.fp).status === 'accepted', 5000, 'accept');
  ok(true, 'request + accept');
  const m = ann.peer.send(jeff.identity.fp, 'ping');
  await until(() => jeff.store.chat(ann.identity.fp).messages.some(x => x.id === m.id), 5000, 'deliver');
  ok(jeff.peer.links.has(ann.identity.fp), 'Ann proved who she is: Jeff can reply over the same connection');
  const r = jeff.peer.send(ann.identity.fp, 'pong');
  await until(() => ann.store.chat(jeff.identity.fp).messages.some(x => x.id === r.id), 5000, 'reply');
  ok(true, 'reply travels back over the proven connection');

  // ---- 6. impostors ----
  // Mallory connects to Jeff claiming to be Ann and tries to authenticate with her own key
  const sock = await socksConnect(socks.address().port, jeff.peer.onion + '.onion', 80);
  const w = await sock.request({ t: 'hello', onion: ann.peer.onion, fp: ann.identity.fp }, f => f.t === 'welcome');
  const forged = await mal.identity.signText(`sealchat-auth-v1|${w.nonce}|${jeff.peer.onion}|${ann.peer.onion}|${ann.identity.fp}`);
  const a = await sock.request({ t: 'auth', sig: forged }, f => f.t === 'authok' || f.t === 'authno');
  ok(a.t === 'authno', 'impostor claiming to be Ann cannot authenticate');
  // ...and a message signed by Mallory but claiming to be from Ann is refused
  const box = await mal.identity.sealFor(jeff.identity.pubArmored, { k: 'text', id: 'evil1', to: jeff.identity.fp, from: { onion: ann.peer.onion, fp: ann.identity.fp }, text: 'send money' });
  const n = await sock.request({ t: 'msg', id: 'evil1', box }, f => f.id === 'evil1');
  ok(n.t === 'nack' && !jeff.store.chat(ann.identity.fp).messages.some(x => x.text === 'send money'), 'forged message (wrong signature) refused');
  // replaying Ann's old message does not create a duplicate
  const before = jeff.store.chat(ann.identity.fp).messages.length;
  const realBox = await ann.identity.sealFor(jeff.identity.pubArmored, { k: 'text', id: m.id, to: jeff.identity.fp, from: { onion: ann.peer.onion, fp: ann.identity.fp }, text: 'ping' });
  await sock.request({ t: 'msg', id: m.id, box: realBox }, f => f.id === m.id);
  ok(jeff.store.chat(ann.identity.fp).messages.length === before, 'replayed message is not shown twice');
  sock.destroy();
  // a message from Jeff to Ann is encrypted to Ann only
  await assert.rejects(mal.identity.open(await jeff.identity.sealFor(ann.identity.pubArmored, { k: 'text' }))); ok(true, 'Mallory cannot decrypt a message meant for Ann');

  // oversized frame -> connection dropped
  const raw = net.connect(routes.get(jeff.peer.onion), '127.0.0.1');
  await new Promise(r => raw.once('connect', r));
  const head = Buffer.alloc(4); head.writeUInt32BE(10 * 1024 * 1024); raw.write(head);
  await new Promise(r => raw.once('close', r)); ok(true, 'oversized frame: connection dropped');

  // ---- 7. offline -> outbox -> delivered when back ----
  offline.add(jeff.peer.onion);
  for (const l of jeff.peer.links.values()) l.destroy();
  for (const l of ann.peer.links.values()) l.destroy();
  await sleep(100);
  const q = ann.peer.send(jeff.identity.fp, 'are you there?');
  await until(() => ann.store.contact(jeff.identity.fp).lastError, 5000, 'offline noticed');
  ok(ann.store.chat(jeff.identity.fp).messages.find(x => x.id === q.id).state === 'queued', 'offline: waits in Outbox');
  ok(ann.peer.counts().queued === 1, 'Outbox count = 1');
  offline.delete(jeff.peer.onion);
  ann.peer.retryNow(jeff.identity.fp);
  await until(() => jeff.store.chat(ann.identity.fp).messages.some(x => x.id === q.id), 5000, 'after back');
  ok(true, 'delivered once reachable');

  // ---- 8. remove + requests switched off ----
  jeff.store.setSettings({ allowRequests: false });
  mal.peer.addContact(jeff.peer.myId());
  await until(() => /not accepting/.test(mal.store.contact(jeff.identity.fp).lastError || ''), 5000, 'refused');
  ok(!jeff.store.contact(mal.identity.fp), '"Allow contact requests" off: stranger\'s request refused');

  // ---- 9. profile pictures (1.2.0) ----
  const pic = 'data:image/jpeg;base64,' + Buffer.from('fake-jpeg-bytes-for-test').toString('base64');
  ann.store.vault.me = { avatar: pic, shareAvatar: true, avatarAt: Date.now() };
  ann.store.setSettings({ displayName: 'Ann B.' });
  ann.peer.shareProfileAll(); ann.peer.retryNow(jeff.identity.fp);
  await until(() => jeff.store.contact(ann.identity.fp).sharedAvatar === pic, 8000, 'avatar shared');
  ok(jeff.store.contact(ann.identity.fp).name === 'Ann B.', 'shared picture and new name reach the contact');
  ann.store.vault.me.shareAvatar = false;
  ann.peer.shareProfileAll(); ann.peer.retryNow(jeff.identity.fp);
  await until(() => jeff.store.contact(ann.identity.fp).sharedAvatar === null, 8000, 'avatar unshared');
  ok(true, 'turning sharing off removes the picture on the contact\'s side');
  ok(!mal.store.contact(ann.identity.fp), 'non-contacts get no profile');

  await jeff.peer.stop(); await ann.peer.stop(); await mal.peer.stop();
  socks.close();
  console.log(`\nCore tests: ${passed} passed`);
  process.exit(0);
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
