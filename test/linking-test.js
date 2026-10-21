/* Seal Chat 1.9.0 self-test: LINKED DEVICES, end to end over a fake Tor.
 * Ann has Seal Chat on her desktop (ann1) and links her laptop (ann2) with
 * a link code. Bob is her contact.
 *   wrong code / wrong passphrase → linked → contacts + chats copied →
 *   Bob learns both addresses → desktop off: Bob's message reaches the laptop →
 *   laptop replies → desktop back: gets both, doesn't send the laptop's again →
 *   read, contacts, name passed on → device removed.
 *   node test/linking-test.js                                              */
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
const linking = require('../src/main/linking');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, ms, what) { const end = Date.now() + ms; while (Date.now() < end) { if (await fn()) return; await sleep(50); } throw new Error('timed out: ' + what); }
async function fails(p, re, m) { let e = null; try { await p; } catch (x) { e = x; } ok(e && re.test(e.message), m + ' — "' + (e && e.message) + '"'); }
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealchat-link-'));
const plain = { strong: false, encrypt: b => b, decrypt: b => b };

/* ---- fake Tor: .onion → local port ---- */
const routes = new Map();
const fixed = new Map();             // onion key → the address it really has (as Tor would work it out)
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
  async publish(key, port) { const k = key || 'k' + crypto.randomBytes(8).toString('hex'); const onion = fixed.get(k) || crypto.createHash('sha256').update(k).digest('hex').replace(/[^a-z2-7]/g, 'a').padEnd(55, 'b').slice(0, 55) + 'd'; routes.set(onion, port); this.onion = onion; return { onion, key: k }; }
  async unpublish() { if (this.onion) routes.delete(this.onion); }
  async publishExtra(key, port, vport, expect) { routes.set(expect, port); return { onion: expect }; }
  async unpublishExtra(onion) { routes.delete(onion); }
}
const sockPort = () => socks.address().port;
async function node(name, armored, pass, store) {
  store = store || new Store(path.join(root, name), plain);
  if (!store.settings.displayName) store.setSettings({ displayName: name });
  const identity = await new Identity().load(armored, pass);
  const tor = new FakeTor(); tor.socksPort = sockPort();
  const peer = new Peer({ store, identity, tor, mbAfter: 0, log: l => process.env.DEBUG && console.log('[' + name + '] ' + l) });
  await peer.start();
  return { name, store, identity, peer, armored, pass };
}
async function pair(a, b) {
  const inv = await a.peer.invites.create({ lifetime: '1h' });
  const r = await b.peer.invites.join(inv.code); b.peer.addContact(r.id);
  await until(() => a.store.contact(b.identity.fp) && a.store.contact(b.identity.fp).status === 'accepted' && b.store.contact(a.identity.fp) && b.store.contact(a.identity.fp).status === 'accepted', 15000, a.name + '+' + b.name);
}
const msgs = (n, other) => n.store.chat(other.identity.fp).messages;
const find = (n, other, id) => msgs(n, other).find(m => m.id === id);

(async () => {
  console.log('linked devices:');
  await new Promise(r => socks.listen(0, '127.0.0.1', r));
  const PASS = 'Ann-pass-1234';
  const [ka, kb, kc] = await Promise.all(['Ann', 'Bob', 'Cat'].map(n => Identity.generate({ name: n, passphrase: n + '-pass-1234' })));
  const ann1 = await node('Ann1', ka, PASS), bob = await node('Bob', kb, 'Bob-pass-1234');
  ann1.store.setSettings({ displayName: 'Ann' });
  ann1.store.vault.identity = { armored: ka, passphrase: PASS, remember: true, fp: ann1.identity.fp };   // (main.js keeps it here)
  await pair(ann1, bob);
  const A = ann1.identity.fp, B = bob.identity.fp;
  const h1 = await bob.peer.send(A, 'hello Ann'); await until(() => find(ann1, bob, h1.id), 10000, 'h1');
  const h2 = await ann1.peer.send(B, 'hi Bob'); await until(() => find(bob, ann1, h2.id), 10000, 'h2');
  ok(true, 'Ann (desktop) and Bob are contacts with a short chat');

  /* 1. link codes */
  const st = await ann1.peer.linker.start();
  ok(/^link-\d{3}(-[a-z]+){4}$/.test(st.code), 'a link code: ' + st.code);
  const p = linking.parseCode(st.code.toUpperCase().replace(/-/g, ' '));
  ok(p && p.code === st.code && !linking.parseCode(st.code.replace('link-', '')) && linking.looksLikeLink(' Link 1'), 'typed in any case; an invite code is not a link code');
  const unlock = pass => async b => { await new Identity().load(b.armored, pass); };
  const parts = st.code.split('-');
  const wrong = [...parts.slice(0, 5), parts[5] === 'zoo' ? 'zone' : 'zoo'].join('-');
  await fails(linking.join({ code: wrong, socksPort: sockPort(), name: 'Laptop', unlock: unlock(PASS) }), /isn't right/, 'a wrong word: refused');
  await fails(linking.join({ code: st.code, socksPort: sockPort(), name: 'Laptop', unlock: unlock('not-the-pass') }), /Wrong key passphrase/, 'the wrong passphrase: refused, nothing linked');
  ok(ann1.peer.myDevices().length === 1, 'still one device');

  /* 2. link the laptop */
  const r = await linking.join({ code: st.code, socksPort: sockPort(), name: 'Ann laptop', unlock: unlock(PASS) });
  ok(r.bundle.armored === ka && r.onion && r.device.id, 'linked: the laptop got Ann\'s key (still locked with her passphrase) and made its own address and device key');
  fixed.set(r.onionKey, r.onion);
  const store2 = new Store(path.join(root, 'Ann2'), plain);
  linking.adoptLink(store2, r);
  const ann2 = await node('Ann2', r.bundle.armored, PASS, store2);
  ok(ann2.identity.fp === A && ann2.peer.onion === r.onion && ann2.peer.onion !== ann1.peer.onion, 'same ID (fingerprint), its own .onion address');
  await until(() => ann1.peer.myDevices().length === 2, 5000, 'added');
  ok(ann1.peer.myDevices()[1].name === 'Ann laptop', 'the desktop lists "Ann laptop" under your devices');
  await until(() => ann2.store.contact(B) && msgs(ann2, bob).length === 2, 20000, 'full copy');
  ok(ann2.store.contact(B).status === 'accepted' && ann2.store.contact(B).publicKey, 'the laptop got Bob as a contact…');
  ok(msgs(ann2, bob).map(m => m.text).join('|') === 'hello Ann|hi Bob', '…and the chat history');
  ok(ann2.store.settings.displayName === 'Ann', 'and Ann\'s name');

  /* 3. Bob learns both addresses */
  await until(() => { const d = bob.store.contact(A).devices; return d && d.devices.length === 2 && d.devices.every(x => x.onion); }, 20000, 'bob has the list');
  ok(bob.store.contact(A).devices.devices.some(x => x.onion === ann2.peer.onion), 'Bob\'s Seal Chat knows both of Ann\'s addresses (signed by her key)');

  /* 4. desktop off: Bob reaches the laptop */
  await ann1.peer.stop(); await sleep(1500);
  const m3 = await bob.peer.send(A, 'are you on your laptop?');
  await until(() => find(ann2, bob, m3.id), 30000, 'laptop got it');
  ok(find(bob, ann1, m3.id).state === 'sent', 'Ann\'s desktop is off: Bob\'s message is delivered to her laptop ✓');
  const m4 = await ann2.peer.send(B, 'yes, from the laptop');
  await until(() => find(bob, ann1, m4.id), 20000, 'bob got reply');
  ok(true, 'Ann answers from the laptop; Bob gets it');

  /* 5. desktop back: catches up */
  await ann1.peer.start();
  await until(() => find(ann1, bob, m3.id) && find(ann1, bob, m4.id) && find(ann1, bob, m4.id).state === 'sent', 30000, 'desktop caught up');
  ok(find(ann1, bob, m3.id).dir === 'in' && find(ann1, bob, m4.id).dir === 'out', 'the desktop comes back: it has Bob\'s message and the laptop\'s answer (marked ✓)');
  await sleep(2500);
  ok(msgs(bob, ann1).filter(m => m.id === m4.id).length === 1 && !ann1.peer._hasWork(ann1.store.contact(B)), 'the desktop does not send the laptop\'s message again');

  /* 6. reading, contacts, name */
  ann1.peer.markRead(B);
  await until(() => find(ann2, bob, m3.id).read === true, 15000, 'read');
  ok(true, 'read on the desktop → read on the laptop');
  const cat = await node('Cat', kc, 'Cat-pass-1234');
  const ci = await cat.peer.invites.create({ lifetime: '1h' });
  const cr = await ann2.peer.invites.join(ci.code); ann2.peer.addContact(cr.id);
  await until(() => ann1.store.contact(cat.identity.fp), 15000, 'cat on desktop');
  ok(true, 'a contact added on the laptop appears on the desktop');
  ann1.store.setSettings({ displayName: 'Ann B.' }); ann1.peer.shareProfileAll();
  await until(() => ann2.store.settings.displayName === 'Ann B.', 15000, 'name');
  ok(true, 'a new name on the desktop → the laptop');
  const rx = await ann2.peer.react(B, h1.id, '👍');
  await until(() => find(ann1, bob, h1.id).reactions && find(ann1, bob, h1.id).reactions.me === '👍', 15000, 'react');
  ok(rx && true, 'a reaction on the laptop → the desktop');

  /* 7. remove the laptop */
  await ann1.peer.removeDevice(ann2.peer.device.id);
  ok(ann1.peer.myDevices().length === 1 && !ann1.peer.siblings().length, 'the desktop removes the laptop from Ann\'s ID');
  await until(() => { const d = bob.store.contact(A).devices; return d && d.devices.length === 1; }, 20000, 'bob list');
  ok(true, 'Bob\'s Seal Chat gets the new list (only the desktop now)');
  await fails(ann2.peer._sendSync(ann2.peer.selfLinks.get(ann1.peer.device.id) || await ann2.peer._selfConnection({ id: ann1.peer.device.id, onion: ann1.peer.onion }), { id: ann1.peer.device.id }, [{ e: 'hi' }]), /refused: unknown/, 'even over a connection it already had, the removed laptop can no longer sync with the desktop');
  for (const l of ann2.peer.selfLinks.values()) l.destroy();
  await fails(ann2.peer._selfConnection({ id: ann1.peer.device.id, onion: ann1.peer.onion, name: 'desktop' }), /did not accept/, '…nor connect to it again');

  for (const n of [ann1, ann2, bob, cat]) await n.peer.stop();
  socks.close();
  console.log(`\n${passed} passed`);
  process.exit(0);
})().catch(e => { console.error('FAILED:', e.stack || e.message); process.exit(1); });
