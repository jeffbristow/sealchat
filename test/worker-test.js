/* Seal Chat 1.8.5 self-test: the CLOUDFLARE WORKER MAILBOX — the real Worker
 * script (as Seal Chat makes it) running in Cloudflare's own runtime
 * (Miniflare/workerd) with a D1 database; Ann's Seal Chat sets it up and
 * picks up, Bob (a contact) leaves sealed messages through a fake Tor,
 * exactly as he would on Seal Chat Web's relay.php.
 *   npm i --no-save miniflare@4   (once)
 *   node test/worker-test.js                                               */
const os = require('os');
const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert');
const { EventEmitter } = require('events');
let Miniflare;
try { ({ Miniflare } = require(process.env.MINIFLARE || 'miniflare')); }
catch { console.log('worker mailbox: skipped (npm i --no-save miniflare@4 to run it)'); process.exit(0); }
const { Store } = require('../src/main/store');
const { Identity } = require('../src/main/identity');
const { Peer } = require('../src/main/peer');
const wb = require('../src/main/workerbox');
const { request } = require('../src/main/webhttp');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, ms, what) { const end = Date.now() + ms; while (Date.now() < end) { if (await fn()) return; await sleep(40); } throw new Error('timed out: ' + what); }
async function fails(p, re, m) { let e = null; try { await p; } catch (x) { e = x; } ok(e && re.test(e.message), m + ' — "' + (e && e.message) + '"'); }
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealchat-wb-'));
const plain = { strong: false, encrypt: b => b, decrypt: b => b };

/* ---- fake Tor: .onion → local port; ordinary websites straight through ---- */
const routes = new Map();
const socks = net.createServer(c => {
  c.once('data', () => { c.write(Buffer.from([5, 0])); c.once('data', d => {
    const rawHost = d.subarray(5, 5 + d[4]).toString();
    const port = rawHost.endsWith('.onion') ? routes.get(rawHost.replace(/\.onion$/, '')) : d.readUInt16BE(5 + d[4]);
    if (!port) { c.end(Buffer.from([5, 0xf0, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
    const up = net.connect(port, rawHost.endsWith('.onion') ? '127.0.0.1' : rawHost, () => { c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])); c.pipe(up); up.pipe(c); });
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
async function node(name, armored, pass) {
  const store = new Store(path.join(root, name), plain);
  store.setSettings({ displayName: name, contactMailbox: false });
  const identity = await new Identity().load(armored, pass);
  const tor = new FakeTor(); tor.socksPort = socks.address().port;
  const peer = new Peer({ store, identity, tor, mbAfter: 0, allowHttpMailbox: true, log: l => process.env.DEBUG && console.log('[' + name + '] ' + l) });
  await peer.start();
  return { name, store, identity, peer, tor };
}

(async () => {
  console.log('worker mailbox:');
  await new Promise(r => socks.listen(0, '127.0.0.1', r));
  const SP = socks.address().port;

  /* 1. the script Seal Chat makes */
  const setup = wb.newSetup();
  const script = wb.makeScript(setup);
  ok(script.includes(wb.sha256hex(setup.owner)) && script.includes(setup.box) && !script.includes(setup.owner), 'the Worker script has the HASH of this PC\'s mailbox key (never the key itself)');
  ok(wb.cleanUrl('sealchat-mailbox.ann.workers.dev/x?y') === 'https://sealchat-mailbox.ann.workers.dev/', 'a pasted address is tidied up');

  /* 2. the Worker running in Cloudflare's runtime, with a D1 database */
  const mf = new Miniflare({ modules: true, script, d1Databases: ['DB'], port: 0, host: '127.0.0.1' });
  const base = (await mf.ready).toString();
  const mfNoDb = new Miniflare({ modules: true, script, port: 0, host: '127.0.0.1' });
  const baseNoDb = (await mfNoDb.ready).toString();
  const visit = await request(base, { allowHttp: true });
  ok(visit.status === 200 && /mailbox is working/.test(visit.body.toString()), 'opening the Worker\'s address in a browser: "Seal Chat mailbox is working"');
  const visit2 = await request(baseNoDb, { allowHttp: true });
  ok(visit2.status === 500 && /binding named DB/.test(visit2.body.toString()), 'without the database: says to add the D1 binding named DB');

  /* 3. Ann sets it up (through Tor) */
  const o = { socksPort: SP, allowHttp: true };
  const W = { url: base, owner: setup.owner, box: setup.box };
  await fails(wb.setDrop({ ...W, owner: 'x'.repeat(43) }, 'd'.repeat(32), o), /different Seal Chat/, 'someone else\'s key is refused');
  await fails(wb.setDrop({ ...W, url: baseNoDb }, 'd'.repeat(32), o), /binding named DB/, 'no database: a clear message');
  const keys = await Promise.all(['Ann', 'Bob'].map(n => Identity.generate({ name: n, passphrase: n + '-pass-1234' })));
  const ann = await node('Ann', keys[0], 'Ann-pass-1234'), bob = await node('Bob', keys[1], 'Bob-pass-1234');
  const drop = crypto.randomBytes(24).toString('base64url');
  const set = await wb.setDrop(W, drop, o);
  ok(set.ok && set.mailbox === true, 'Ann\'s Seal Chat turns the mailbox on (through Tor)');

  /* 4. Bob and Ann are contacts; Ann gives Bob her Worker as her mailbox */
  const inv = await ann.peer.invites.create({ lifetime: '1h' });
  const r = await bob.peer.invites.join(inv.code); bob.peer.addContact(r.id);
  const A = ann.identity.fp, B = bob.identity.fp;
  await until(() => ann.store.contact(B) && ann.store.contact(B).status === 'accepted' && bob.store.contact(A).status === 'accepted', 15000, 'contacts');
  ann.peer.setMailbox({ url: base, box: setup.box, drop });
  await until(() => bob.store.contact(A).mailbox && bob.store.contact(A).mailbox.url === base, 15000, 'bob knows the mailbox');
  ok(true, 'Bob learns Ann\'s mailbox address (the Worker) like any mailbox');

  /* 5. Ann offline: Bob's message goes into the Worker */
  await ann.peer.stop(); await sleep(1500);
  const m = await bob.peer.send(A, 'kept by Cloudflare');
  await until(() => bob.store.chat(A).messages.find(x => x.id === m.id).state === 'mailbox', 20000, 'dropped');
  ok(true, 'Ann is offline: Bob\'s message is left in her Cloudflare mailbox (📬)');
  await fails(request(base + 'relay.php?a=mbox_drop', { method: 'POST', allowHttp: true, headers: { 'X-SC-Drop': 'wrong-token-wrong-token-wrong-token' }, body: JSON.stringify({ d: 'QUJD' }) }).then(x => { const j = JSON.parse(x.body); if (!j.ok) throw new Error(j.code); }), /nombox/, 'a wrong drop token: "no mailbox here"');
  await fails(request(base + '?a=mbox_get', { method: 'POST', allowHttp: true, body: '{"ack":0}' }).then(x => { const j = JSON.parse(x.body); if (!j.ok) throw new Error(j.code); }), /owner/, 'nobody else can pick up');

  /* 6. Ann back: picks up (what main.js does) */
  await ann.peer.start();
  let ack = 0, n = 0;
  const g = await wb.get(W, 0, o);
  for (const it of g.items) { const res = await ann.peer.fromMailbox(it.d); if (res.ok) n++; ack = Math.max(ack, it.id); }
  ok(n === 1 && ann.store.chat(B).messages.some(x => x.id === m.id && x.text === 'kept by Cloudflare'), 'Ann\'s Seal Chat picks it up from the Worker: signed by Bob, readable only by her');
  const g2 = await wb.get(W, ack, o);
  ok(g2.items.length === 0 && g2.mailbox === true, '"ack" deletes what was picked up');

  /* 7. limits and turning off */
  const bigOk = await request(base + 'relay.php?a=mbox_drop', { method: 'POST', allowHttp: true, headers: { 'X-SC-Drop': drop }, body: JSON.stringify({ d: 'A'.repeat(800 * 1024) }) });
  ok(bigOk.status === 413, 'a message over 768 KB is refused');
  await wb.setDrop(W, null, o);
  const after = await request(base + 'relay.php?a=mbox_drop', { method: 'POST', allowHttp: true, headers: { 'X-SC-Drop': drop }, body: JSON.stringify({ d: 'QUJD' }) });
  ok(JSON.parse(after.body).code === 'nombox', 'turned off: contacts are told there\'s no mailbox (and they stop using it)');

  for (const x of [ann, bob]) await x.peer.stop();
  await mf.dispose(); await mfNoDb.dispose();
  socks.close();
  console.log(`\n${passed} passed`);
  process.exit(0);
})().catch(e => { console.error('FAILED:', e.stack || e.message); process.exit(1); });
