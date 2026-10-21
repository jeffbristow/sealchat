/* Seal Chat 1.8.0 self-test: device keys + signed device lists (groundwork
 * for one ID on several devices).   node test/devices-test.js            */
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
let throttle = 0; // bytes per 50 ms per connection (0 = unlimited)
const socks = net.createServer(c => {
  c.once('data', () => { c.write(Buffer.from([5, 0])); c.once('data', d => {
    const host = d.subarray(5, 5 + d[4]).toString().replace(/\.onion$/, '');
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
  const peer = new Peer({ store, identity, tor, files, log: l => process.env.DEBUG && console.log('[' + name + '] ' + l) });
  await peer.start();
  return { store, identity, peer, files };
}

const devices = require('../src/main/devices');

(async () => {
  await new Promise(r => socks.listen(0, '127.0.0.1', r));
  // ---- the pieces ----
  const d1 = devices.makeDevice('Test PC');
  ok(/^[0-9a-f]{16}$/.test(d1.id) && Buffer.from(d1.pub, 'base64').length === 32 && d1.id === devices.deviceIdOf(d1.pub), 'a device key has a 32-byte public key and a short id derived from it');
  const sg = devices.deviceSign(d1, 'hello');
  ok(devices.deviceVerify(d1.pub, 'hello', sg) && !devices.deviceVerify(d1.pub, 'hellO', sg) && !devices.deviceVerify(devices.makeDevice().pub, 'hello', sg), 'device signatures check out, and only for that text + that device');

  const jk = await Identity.generate({ name: 'Jeff', passphrase: 'jeff-pass-123' });
  const ak = await Identity.generate({ name: 'Ann', passphrase: 'ann-pass-1234' });
  const jeff = await node('jeff', jk, 'jeff-pass-123');
  const ann = await node('ann', ak, 'ann-pass-1234');
  ok(jeff.store.vault.device && jeff.store.vault.device.id && jeff.store.vault.device.id !== ann.store.vault.device.id, 'every installation makes its own device key on start');
  ann.peer.addContact(jeff.peer.myId());
  await until(() => jeff.store.contact(ann.identity.fp), 5000, 'request');
  jeff.peer.accept(ann.identity.fp);
  await until(() => ann.store.contact(jeff.identity.fp).status === 'accepted', 5000, 'accept');
  const J = jeff.identity.fp, A = ann.identity.fp;
  ann.peer.send(J, 'hi'); jeff.peer.send(A, 'hello');
  await until(() => ann.store.contact(J).devices && jeff.store.contact(A).devices, 10000, 'lists exchanged');
  const annSeesJeff = ann.store.contact(J).devices.devices;
  ok(annSeesJeff.length === 1 && annSeesJeff[0].id === jeff.store.vault.device.id && annSeesJeff[0].pub === jeff.store.vault.device.pub, 'contacts receive each other\'s signed device list');
  await until(() => ann.store.contact(J).lastDevice === jeff.store.vault.device.id, 8000, 'from.dev');
  ok(true, 'each message says which device sent it');

  // rename → a newer list goes out
  const ts0 = ann.store.contact(J).devices.ts;
  jeff.peer.renameDevice('Jeff’s laptop');
  jeff.peer.send(A, 'renamed');
  await until(() => ann.store.contact(J).devices.devices[0].name === 'Jeff’s laptop', 10000, 'renamed list');
  ok(ann.store.contact(J).devices.ts > ts0, 'renaming the device sends the new list (newer one wins)');

  // forged + old lists are refused
  const c = { ...ann.store.contact(J) };
  const forged = { v: 1, fp: J, ts: Date.now() + 1000, devices: [{ id: d1.id, pub: d1.pub, name: 'evil', added: 1 }] };
  const annSig = await ann.identity.signText('sealchat-devices-v1|' + JSON.stringify(forged));
  ok((await devices.checkList(ann.identity, c, forged, annSig)).why === 'bad signature', 'a list signed by anyone but the contact is refused');
  const { doc, sig } = await devices.signedList(jeff.identity, [jeff.store.vault.device]);
  ok((await devices.checkList(ann.identity, { ...c, devices: { ts: doc.ts + 1 } }, doc, sig)).why === 'not newer', 'an older (replayed) list is ignored');
  ok((await devices.checkList(ann.identity, { ...c, fp: A }, doc, sig)).why === 'for someone else', 'a list for a different ID is refused');
  const bad = { ...doc, devices: [{ ...doc.devices[0], id: '0000000000000000' }] };
  ok((await devices.checkList(ann.identity, { ...c, devices: null }, bad, sig)).why === 'bad device', 'a device whose id doesn\'t match its key is refused');
  ok((await devices.checkList(ann.identity, { ...c, devices: null }, doc, sig)).keep, 'the genuine list is accepted');

  console.log(`\nDevice tests: ${passed} passed`);
  process.exit(0);
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
