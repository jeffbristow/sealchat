/* Seal Chat 1.7.0 self-test: files to / from Seal Chat Web (webfiles.js), over the
 * real file transfer between two contacts (fake SOCKS proxy, no Tor needed).
 *   node test/webfiles-test.js                                                */
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
const { WebFiles, PART, WEB_FILE_MAX } = require('../src/main/webfiles');

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

const rejects = async (p, re, m) => { try { await p; } catch (e) { ok(re.test(e.message), m + ' (' + e.message + ')'); return; } throw new Error('did not fail: ' + m); };

(async () => {
  await new Promise(r => socks.listen(0, '127.0.0.1', r));
  const jk = await Identity.generate({ name: 'Jeff', passphrase: 'jeff-pass-123' });
  const ak = await Identity.generate({ name: 'Ann', passphrase: 'ann-pass-1234' });
  const jeff = await node('jeff', jk, 'jeff-pass-123');
  const ann = await node('ann', ak, 'ann-pass-1234');
  ann.peer.addContact(jeff.peer.myId());
  await until(() => jeff.store.contact(ann.identity.fp), 5000, 'request');
  jeff.peer.accept(ann.identity.fp);
  await until(() => ann.store.contact(jeff.identity.fp).status === 'accepted', 5000, 'accept');
  const J = jeff.identity.fp, A = ann.identity.fp;
  const sent = [];
  const mk = n => new WebFiles({ peer: n.peer, files: n.files, dir: path.join(root, 'webup-' + crypto.randomBytes(3).toString('hex')), mimeOf: () => 'application/octet-stream',
    thumbFor: () => null, webMsg: (m, cid) => ({ id: m.id, kind: m.kind, file: { name: m.file.name, size: m.file.size }, cid }), onSent: (cid, m) => sent.push([cid, m.id]) });
  const wfA = mk(ann), wfJ = mk(jeff);

  // ---- 1. phone → Ann's computer → Jeff ----
  const data = crypto.randomBytes(PART * 4 + 4321);         // 5 pieces
  const st = await wfA.upStart('dev1', { cid: J, name: '../holiday clip.mp4', size: data.length, mime: 'video/mp4' });
  ok(st.n === 5 && st.part === PART, 'an upload is split into 512 KB pieces');
  for (const i of [0, 2, 1, 4, 3]) await wfA.upPart('dev1', { up: st.up, i, d: data.subarray(i * PART, (i + 1) * PART).toString('base64') });
  const msg = await wfA.upEnd('dev1', { up: st.up });
  ok(msg.file.name === 'holiday clip.mp4' && msg.file.size === data.length && msg.cid === J, 'the file becomes a normal file message (name made safe)');
  ok(sent.length === 1 && sent[0][0] === J, 'the computer window / other phones are told');
  await until(() => { const m = jeff.store.chat(A).messages.find(x => x.id === msg.id); return m && m.transfer.state === 'done'; }, 20000, 'Jeff gets it');
  const ref = jeff.peer.fileRef(A, msg.id);
  ok(sha(await streamToBuf(jeff.files.plainStream(ref.where, msg.id, ref.meta))) === sha(data), 'Jeff receives it byte-for-byte (pieces may arrive out of order)');
  await until(() => fs.readdirSync(wfA.o.dir).length === 0, 5000, 'temp gone');
  ok(true, 'the temporary pieces are deleted once the file is in encrypted storage');

  // ---- 2. Jeff's phone opens that file from Jeff's computer ----
  const parts = [];
  let first = await wfJ.get({ cid: A, id: msg.id, i: 0 });
  ok(first.n === 5 && first.size === data.length && first.name === 'holiday clip.mp4', 'the phone learns the size and piece count');
  for (let i = 0; i < first.n; i++) parts.push(Buffer.from((await wfJ.get({ cid: A, id: msg.id, i })).d, 'base64'));
  ok(sha(Buffer.concat(parts)) === sha(data), 'the phone gets the file back exactly, piece by piece');
  await rejects(wfJ.get({ cid: A, id: msg.id, i: 5 }), /piece/, 'a piece past the end is refused');
  await rejects(wfJ.get({ cid: 'nobody', id: msg.id, i: 0 }), /Unknown contact/, 'an unknown chat is refused');
  ok(wfJ.thumb({ cid: A, id: msg.id }).thumb === null, 'no preview for a video (fileThumb answers null)');

  // a file still offered (not downloaded) → "download it" first
  jeff.store.setSettings({ autoDownloadMB: 1 });
  const m2 = await ann.peer.sendFile(J, { buffer: crypto.randomBytes(2 * 1024 * 1024) }, { name: 'big.bin', mime: 'application/octet-stream' });
  await until(() => jeff.store.chat(A).messages.find(x => x.id === m2.id), 5000, 'offer');
  await rejects(wfJ.get({ cid: A, id: m2.id, i: 0 }), /not finished downloading/, 'a file not on the computer yet can\'t be opened');
  wfJ.fetch({ cid: A, id: m2.id });
  await until(() => jeff.store.chat(A).messages.find(x => x.id === m2.id).transfer.state === 'done', 15000, 'fetched');
  ok((await wfJ.get({ cid: A, id: m2.id, i: 0 })).d.length > 0, '"Download it" from the phone fetches it to the computer, then it opens');

  // ---- 3. refusals ----
  await rejects(wfA.upStart('dev1', { cid: J, name: 'x', size: WEB_FILE_MAX + 1 }), /up to 100 MB/, 'over 100 MB is refused');
  await rejects(wfA.upStart('dev1', { cid: J, name: 'x', size: 0 }), /empty/, 'an empty file is refused');
  await rejects(wfA.upStart('dev1', { cid: 'nobody', name: 'x', size: 10 }), /Unknown contact/, 'an unknown contact is refused');
  const s2 = await wfA.upStart('dev1', { cid: J, name: 'a.txt', size: PART + 10 });
  await rejects(wfA.upPart('dev1', { up: s2.up, i: 1, d: Buffer.alloc(11).toString('base64') }), /size/, 'a piece of the wrong size is refused');
  await rejects(wfA.upPart('dev2', { up: s2.up, i: 0, d: Buffer.alloc(PART).toString('base64') }), /expired/, 'another device can\'t add to this upload');
  await wfA.upPart('dev1', { up: s2.up, i: 0, d: Buffer.alloc(PART).toString('base64') });
  await rejects(wfA.upEnd('dev1', { up: s2.up }), /Only 1 of 2/, 'a file with a missing piece is not sent');
  const s3 = await wfA.upStart('dev1', { cid: J, name: 'b.txt', size: 10 });
  wfA.upStop('dev1', { up: s3.up });
  await rejects(wfA.upPart('dev1', { up: s3.up, i: 0, d: Buffer.alloc(10).toString('base64') }), /expired/, 'a cancelled upload is gone');
  await wfA.upStart('dev1', { cid: J, name: 'c', size: 5 }); await wfA.upStart('dev1', { cid: J, name: 'd', size: 5 });
  await rejects(wfA.upStart('dev1', { cid: J, name: 'e', size: 5 }), /Wait/, 'at most 3 uploads at once per device');
  wfA.dropDevice('dev1');
  ok(wfA.ups.size === 0, 'removing a device forgets its uploads');
  jeff.store.setSettings({ maxFileMB: 1 });
  ann.store.setSettings({ maxFileMB: 1 });
  await rejects(wfA.upStart('dev1', { cid: J, name: 'x', size: 2 * 1048576 }), /largest file/, 'the computer\'s own "largest file" setting applies');

  wfA.stop(); wfJ.stop();
  console.log(`\nWeb file tests: ${passed} passed`);
  process.exit(0);
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
