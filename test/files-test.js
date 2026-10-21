/* Seal Chat 1.1.0 self-test: file transfers (no Tor needed — fake SOCKS proxy).
 *   node test/files-test.js                                                   */
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
const { FileVault, openPiece, safeName, isRisky, PIECE } = require('../src/main/files');

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

(async () => {
  await new Promise(r => socks.listen(0, '127.0.0.1', r));

  // ---- 1. storage basics ----
  const v = new FileVault(path.join(root, 'v'));
  const data = crypto.randomBytes(PIECE * 2 + 12345);
  const meta = await v.importFile('X|abc', 'abc', { buffer: data });
  ok(meta.pieces === 3, 'a 524 KB file is stored as 3 encrypted pieces');
  ok(!fs.readFileSync(v.pathFor('X|abc')).includes(data.subarray(0, 64)), 'stored pieces are not readable');
  ok(sha(await streamToBuf(v.plainStream('X|abc', 'abc', meta))) === sha(data), 'reads back exactly');
  const s = PIECE - 100, e = PIECE + 5000;
  ok((await streamToBuf(v.plainStream('X|abc', 'abc', meta, s, e))).equals(data.subarray(s, e + 1)), 'part of a file (for video seeking) reads back exactly, across pieces');
  const p0 = await v.readSealed('X|abc', meta, 1);
  const bad = Buffer.from(p0); bad[100] ^= 1;
  assert.throws(() => openPiece(meta, 'abc', 1, bad)); ok(true, 'a changed piece is detected');
  assert.throws(() => openPiece(meta, 'abc', 0, p0)); ok(true, 'a piece in the wrong place is detected');
  assert.throws(() => openPiece(meta, 'zzz', 1, p0)); ok(true, 'a piece from another file is detected');
  ok(safeName('..\\..\\evil:name?.txt') === 'evil_name_.txt' && safeName('CON.txt') === '_CON.txt', 'received names are made safe');
  ok(isRisky('photo.jpg.exe') && isRisky('x.PS1') && !isRisky('report.pdf'), 'program files are recognised');

  // ---- 2. two contacts ----
  const jk = await Identity.generate({ name: 'Jeff', passphrase: 'jeff-pass-123' });
  const ak = await Identity.generate({ name: 'Ann', passphrase: 'ann-pass-1234' });
  const jeff = await node('jeff', jk, 'jeff-pass-123');
  const ann = await node('ann', ak, 'ann-pass-1234');
  ann.peer.addContact(jeff.peer.myId());
  await until(() => jeff.store.contact(ann.identity.fp), 5000, 'request');
  jeff.peer.accept(ann.identity.fp);
  await until(() => ann.store.contact(jeff.identity.fp).status === 'accepted', 5000, 'accept');
  const J = jeff.identity.fp, A = ann.identity.fp;
  const inJeff = id => jeff.store.chat(A).messages.find(m => m.id === id);
  const outAnn = id => ann.store.chat(J).messages.find(m => m.id === id);

  // small file: downloads by itself
  const photo = crypto.randomBytes(3 * 1024 * 1024 + 7);
  const src = path.join(root, 'holiday photo.jpg'); fs.writeFileSync(src, photo);
  const m1 = await ann.peer.sendFile(J, { path: src }, { name: 'holiday photo.jpg', mime: 'image/jpeg', thumb: 'data:image/jpeg;base64,AAAA' });
  await until(() => inJeff(m1.id) && inJeff(m1.id).transfer.state === 'done', 15000, 'auto download');
  const ref = jeff.peer.fileRef(A, m1.id);
  ok(sha(await streamToBuf(jeff.files.plainStream(ref.where, m1.id, ref.meta))) === sha(photo), '3 MB photo arrives by itself, byte-for-byte identical');
  ok(inJeff(m1.id).file.name === 'holiday photo.jpg' && inJeff(m1.id).file.thumb === 'data:image/jpeg;base64,AAAA', 'name and preview arrive with it');
  await until(() => outAnn(m1.id).transfer.state === 'done', 5000, 'sender sees done');
  ok(true, 'Ann sees "Downloaded" once Jeff has it');

  // big file: asks first
  jeff.store.setSettings({ autoDownloadMB: 1 });
  const big = crypto.randomBytes(5 * 1024 * 1024);
  const m2 = await ann.peer.sendFile(J, { buffer: big }, { name: 'video.mp4', mime: 'video/mp4' });
  await until(() => inJeff(m2.id), 5000, 'offer');
  await sleep(1500);
  ok(inJeff(m2.id).transfer.state === 'offered' && !jeff.files.has(A + '|' + m2.id), 'a file over the automatic limit waits for "Download"');

  // download with a slow line, interrupted half-way, then resumed
  throttle = 64 * 1024;
  jeff.peer.download(A, m2.id);
  await until(() => (inJeff(m2.id).transfer.got || 0) >= 6, 20000, 'some pieces');
  offline.add(ann.peer.onion);
  for (const l of [...jeff.peer.links.values(), ...ann.peer.links.values()]) l.destroy();
  await until(() => inJeff(m2.id).transfer.state === 'queued' && !jeff.peer.dl.get(A + '|' + m2.id).running, 10000, 'interrupted').catch(e => { console.log('STATE', JSON.stringify(inJeff(m2.id).transfer), jeff.peer.dl.get(A + '|' + m2.id)); throw e; });
  const gotBefore = jeff.files.completePieces(A + '|' + m2.id, inJeff(m2.id).file);
  ok(gotBefore >= 6 && gotBefore < 20, `connection lost after ${gotBefore} of 20 pieces: waits to resume`);
  throttle = 0; offline.delete(ann.peer.onion);
  jeff.peer.download(A, m2.id);
  await until(() => inJeff(m2.id).transfer.state === 'done', 15000, 'resumed');
  const r2 = jeff.peer.fileRef(A, m2.id);
  ok(sha(await streamToBuf(jeff.files.plainStream(r2.where, m2.id, r2.meta))) === sha(big), 'resumed from where it stopped and the file is identical');

  // pause / resume
  throttle = 32 * 1024;
  const m3 = await ann.peer.sendFile(J, { buffer: crypto.randomBytes(3 * 1024 * 1024) }, { name: 'song.mp3', mime: 'audio/mpeg' });
  await until(() => inJeff(m3.id), 5000, 'offer3');
  jeff.peer.download(A, m3.id);
  await until(() => (inJeff(m3.id).transfer.got || 0) >= 2, 20000, 'started');
  jeff.peer.pauseDownload(A, m3.id);
  await sleep(1500);
  const pausedAt = jeff.files.completePieces(A + '|' + m3.id, inJeff(m3.id).file);
  await sleep(1500);
  ok(inJeff(m3.id).transfer.state === 'paused' && jeff.files.completePieces(A + '|' + m3.id, inJeff(m3.id).file) === pausedAt, 'Pause stops the download');
  throttle = 0;
  jeff.peer.download(A, m3.id);
  await until(() => inJeff(m3.id).transfer.state === 'done', 15000, 'resume after pause').catch(e => { console.log('STATE3', JSON.stringify(inJeff(m3.id).transfer), JSON.stringify(jeff.peer.dl.get(A + '|' + m3.id)), jeff.files.completePieces(A + '|' + m3.id, inJeff(m3.id).file)); throw e; });
  ok(true, 'Resume finishes it');

  // decline
  const m4 = await ann.peer.sendFile(J, { buffer: crypto.randomBytes(2 * 1024 * 1024) }, { name: 'big.zip' });
  await until(() => inJeff(m4.id), 5000, 'offer4');
  jeff.peer.declineFile(A, m4.id);
  await until(() => outAnn(m4.id).transfer.state === 'declined', 5000, 'declined');
  ok(true, 'Decline: Ann sees "Declined"');

  // sender removed it
  const m5 = await ann.peer.sendFile(J, { buffer: crypto.randomBytes(2 * 1024 * 1024) }, { name: 'gone.pdf' });
  await until(() => outAnn(m5.id).state === 'sent', 5000, 'offer5');
  ann.peer.deleteMessage(J, m5.id);
  jeff.peer.download(A, m5.id);
  await until(() => inJeff(m5.id).transfer.state === 'failed', 10000, 'gone');
  ok(/no longer has/.test(inJeff(m5.id).transfer.err), 'deleted by the sender: "The sender no longer has this file"');

  // empty file
  const m6 = await ann.peer.sendFile(J, { buffer: Buffer.alloc(0) }, { name: 'empty.txt', mime: 'text/plain' });
  await until(() => inJeff(m6.id) && inJeff(m6.id).transfer.state === 'done', 8000, 'empty');
  ok(true, 'an empty file works too');

  // size limit
  ann.store.setSettings({ maxFileMB: 1 });
  await assert.rejects(ann.peer.sendFile(J, { buffer: crypto.randomBytes(2 * 1024 * 1024) }, { name: 'toolarge.bin' }), /largest file/);
  ok(true, 'files over your size limit are refused before sending');
  ann.store.setSettings({ maxFileMB: 2048 });

  // offline receiver: offer waits in the outbox, then arrives + downloads
  offline.add(jeff.peer.onion);
  for (const l of [...jeff.peer.links.values(), ...ann.peer.links.values()]) l.destroy();
  const m7 = await ann.peer.sendFile(J, { buffer: crypto.randomBytes(1024 * 1024) }, { name: 'later.png', mime: 'image/png' });
  await sleep(1500);
  ok(outAnn(m7.id).state === 'queued', 'Jeff offline: the file waits in Ann\'s Outbox');
  offline.delete(jeff.peer.onion);
  ann.peer.retryNow(J);
  await until(() => inJeff(m7.id) && inJeff(m7.id).transfer.state === 'done', 15000, 'later');
  ok(true, 'it goes through when Jeff is back');

  // removing a chat removes the files on disk
  const before = jeff.files.usage().files;
  jeff.peer.clearChat(A);
  ok(jeff.files.usage().files < before && jeff.files.usage().files === 0, 'clearing a conversation deletes its files from disk');

  // a stranger can't fetch files
  const raw = await require('../src/main/wire').socksConnect(socks.address().port, ann.peer.onion + '.onion', 80);
  await raw.request({ t: 'hello', onion: 'a'.repeat(55) + 'd', fp: 'F'.repeat(40) }, f => f.t === 'welcome');
  const g = await raw.request({ t: 'get', id: m7.id, i: 0, n: 1 }, f => f.id === m7.id);
  ok(g.t === 'gone', 'nobody but the receiver can download a file (unproven connection gets nothing)');
  raw.destroy();

  await jeff.peer.stop(); await ann.peer.stop(); socks.close();
  console.log(`\nFile tests: ${passed} passed`);
  process.exit(0);
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
