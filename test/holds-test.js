/* Seal Chat 1.8.5 self-test: the CONTACT MAILBOX, end to end over a fake Tor.
 * Ann, Bob, Cat all know each other; Dan knows only Bob.
 *   Ann offline → Bob's message is left with Cat (Dan is asked and says no:
 *   he doesn't know Ann) → Bob goes offline → Ann comes back → Cat passes it
 *   on → Ann has it, signed by Bob → Bob back online: confirmed ✓ directly,
 *   no duplicate. Plus: turned off, older Seal Chat, limits, expiry.
 *   node test/holds-test.js                                                */
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

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, ms, what) { const end = Date.now() + ms; while (Date.now() < end) { if (await fn()) return; await sleep(40); } throw new Error('timed out: ' + what); }
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealchat-hold-'));
const plain = { strong: false, encrypt: b => b, decrypt: b => b };

/* ---- fake Tor: .onion → local port ---- */
const routes = new Map();
const socks = net.createServer(c => {
  c.once('data', () => { c.write(Buffer.from([5, 0])); c.once('data', d => {
    const host = d.subarray(5, 5 + d[4]).toString().replace(/\.onion$/, '');
    const port = routes.get(host);
    if (!port) { c.end(Buffer.from([5, 0xf0, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
    const up = net.connect(port, '127.0.0.1', () => { c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])); c.pipe(up); up.pipe(c); });
    up.on('error', () => c.destroy()); c.on('error', () => up.destroy()); c.on('close', () => up.destroy()); up.on('close', () => c.destroy());
  }); });
});
class FakeTor extends EventEmitter {
  constructor() { super(); this.ready = true; }
  async publish(key, port) { const k = key || 'k' + crypto.randomBytes(8).toString('hex'); const onion = crypto.createHash('sha256').update(k).digest('hex').replace(/[^a-z2-7]/g, 'a').padEnd(55, 'b').slice(0, 55) + 'd'; routes.set(onion, port); this.onion = onion; return { onion, key: k }; }
  async unpublish() { if (this.onion) routes.delete(this.onion); }
  async publishExtra(key, port, vport, expect) { routes.set(expect, port); return { onion: expect }; }
  async unpublishExtra(onion) { routes.delete(onion); }
}
async function node(name, armored, pass, extra = {}) {
  const store = new Store(path.join(root, name), plain);
  store.setSettings({ displayName: name });
  const identity = await new Identity().load(armored, pass);
  const tor = new FakeTor(); tor.socksPort = socks.address().port;
  const peer = new Peer({ store, identity, tor, mbAfter: 0, log: l => process.env.DEBUG && console.log('[' + name + '] ' + l), ...extra });
  await peer.start();
  return { name, store, identity, peer };
}
/** a and b become contacts (single-use invite) */
async function pair(a, b) {
  const inv = await a.peer.invites.create({ lifetime: '1h' });
  const r = await b.peer.invites.join(inv.code); b.peer.addContact(r.id);
  await until(() => a.store.contact(b.identity.fp) && a.store.contact(b.identity.fp).status === 'accepted' && b.store.contact(a.identity.fp) && b.store.contact(a.identity.fp).status === 'accepted', 15000, a.name + '+' + b.name);
}
const msgOf = (n, other, id) => n.store.chat(other.identity.fp).messages.find(m => m.id === id);

(async () => {
  console.log('contact mailbox:');
  await new Promise(r => socks.listen(0, '127.0.0.1', r));
  const keys = await Promise.all(['Ann', 'Bob', 'Cat', 'Dan'].map(n => Identity.generate({ name: n, passphrase: n + '-pass-1234' })));
  const ann = await node('Ann', keys[0], 'Ann-pass-1234'), bob = await node('Bob', keys[1], 'Bob-pass-1234');
  const cat = await node('Cat', keys[2], 'Cat-pass-1234'), dan = await node('Dan', keys[3], 'Dan-pass-1234');
  const A = ann.identity.fp, B = bob.identity.fp, C = cat.identity.fp, D = dan.identity.fp;
  await pair(ann, bob); await pair(ann, cat); await pair(bob, cat); await pair(bob, dan);
  ok(true, 'Ann, Bob and Cat know each other; Dan knows only Bob');
  await sleep(1500);

  /* 1. Ann goes offline; Bob writes to her */
  await ann.peer.stop(); await sleep(1500);      // (let connections that were opening finish closing)
  const m1 = await bob.peer.send(A, 'left with a friend');
  await until(() => (cat.store.vault.held || []).length === 1, 20000, 'Cat holds it');
  ok(cat.store.vault.held[0].to === A && cat.store.vault.held[0].from === B, 'Ann is offline: Bob\'s message is left with Cat (a contact they both have)');
  ok(!/left with a friend/.test(JSON.stringify(cat.store.vault.held)), 'Cat can\'t read it (sealed for Ann)');
  await until(() => msgOf(bob, ann, m1.id).state === 'mailbox', 5000, 'bob 📬');
  ok(JSON.stringify(msgOf(bob, ann, m1.id).heldBy) === '["Cat"]', 'Bob sees 📬 "left with Cat"');
  await until(() => bob.store.contact(A).holdNo && bob.store.contact(A).holdNo[D], 8000, 'dan says no');
  ok(!(dan.store.vault.held || []).length, 'Dan was asked too, but doesn\'t know Ann: he keeps nothing (and learns nothing — he only saw a hash)');
  ok(!(bob.store.vault.ctl || []).some(x => x.k === 'hold'), 'nothing left waiting on Bob\'s PC to ask again');

  /* 2. Bob goes offline, Ann comes back: Cat passes it on */
  await bob.peer.stop();
  await ann.peer.start();
  await until(() => msgOf(ann, bob, m1.id), 20000, 'ann got it');
  const got = msgOf(ann, bob, m1.id);
  ok(got.text === 'left with a friend' && got.dir === 'in', 'Ann comes back while Bob is offline: Cat passes it on and Ann has Bob\'s message');
  await until(() => !(cat.store.vault.held || []).length, 5000, 'cat empty');
  ok(true, 'Cat no longer keeps it');

  /* 3. Bob back: confirmed directly, no duplicate */
  await bob.peer.start();
  await until(() => msgOf(bob, ann, m1.id).state === 'sent', 20000, 'confirmed');
  ok(ann.store.chat(B).messages.filter(m => m.id === m1.id).length === 1, 'Bob back online: the message is confirmed ✓ directly — Ann has it once');

  /* 4. Cat has it turned off */
  cat.store.setSettings({ contactMailbox: false });
  await ann.peer.stop(); await sleep(1500);
  const m2 = await bob.peer.send(A, 'second');
  await until(() => bob.store.contact(A).holdNo && bob.store.contact(A).holdNo[C], 15000, 'cat says no');
  ok(!(cat.store.vault.held || []).length && msgOf(bob, ann, m2.id).state === 'queued', 'Cat turned the contact mailbox off: she keeps nothing; the message waits on Bob\'s PC as before');
  cat.store.setSettings({ contactMailbox: true });

  /* 5. Cat's side: limits and checks (direct calls) */
  const bobAtCat = cat.store.contact(B);
  const { createHash } = crypto;
  const tagOf = fp => createHash('sha256').update('sealchat-hold-v1|' + fp).digest('hex').slice(0, 32);
  ok(cat.peer._hold(bobAtCat, { for: tagOf(D), d: 'QUJD' }, 'direct') === 'nohold', 'a tag Cat doesn\'t know (Dan): refused');
  ok(cat.peer._hold(bobAtCat, { for: tagOf(B), d: 'QUJD' }, 'direct') === 'nohold', 'holding for the sender himself: refused');
  ok(cat.peer._hold(bobAtCat, { for: tagOf(A), d: 'QUJD' }, 'mailbox') === 'bad', 'only straight from a contact (not via a mailbox)');
  ok(cat.peer._hold(bobAtCat, { for: tagOf(A), d: 'A'.repeat(301 * 1024) }, 'direct') === 'nohold', 'too large: refused');
  ok(cat.peer._hold(bobAtCat, { for: tagOf(A), d: 'QUJDRA==' }, 'direct') === null && cat.peer._hold(bobAtCat, { for: tagOf(A), d: 'QUJDRA==' }, 'direct') === null && cat.store.vault.held.length === 1, 'the same message twice is kept once');
  cat.store.vault.held[0].ts = Date.now() - 15 * 86400e3; cat.peer._purgeHolds();
  ok(!cat.store.vault.held.length, 'held messages are deleted after 14 days');

  /* 6. a contact on an older Seal Chat */
  for (const n of [ann, bob, cat, dan]) await n.peer.stop();
  const cat2 = await node('Cat', keys[2], 'Cat-pass-1234', { oldKinds: ['hold', 'held'] });
  await bob.peer.start();
  bob.store.contact(A).holdNo = {}; bob.store.putContact(bob.store.contact(A));
  const m3 = await bob.peer.send(A, 'third');
  await until(() => bob.store.contact(C).noHold, 15000, 'old cat');
  ok(!(cat2.store.vault.held || []).length && msgOf(bob, ann, m3.id).state !== 'sent', 'Cat on an older Seal Chat: not asked again; nothing lost (it waits on Bob\'s PC)');

  for (const n of [bob, cat2]) await n.peer.stop();
  socks.close();
  console.log(`\n${passed} passed`);
  process.exit(0);
})().catch(e => { console.error('FAILED:', e.stack || e.message); process.exit(1); });
