/* Seal Chat end-to-end test over Tor.
 * Needs a Tor network: set SEALCHAT_TOR_TESTNET to a private test network
 * config (developers), or run with real Tor (takes longer).
 *   node test/tor-test.js                                                     */
const os = require('os');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { TorService } = require('../src/main/tor');
const { Store } = require('../src/main/store');
const { Identity } = require('../src/main/identity');
const { Peer, formatId } = require('../src/main/peer');
const { FileVault } = require('../src/main/files');
const crypto = require('crypto');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, ms, what) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return true; await sleep(250); }
  throw new Error('timed out waiting for: ' + what);
}
const plainProtect = { strong: false, encrypt: b => b, decrypt: b => b };
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealchat-tor-'));

async function node(name, armored, pass) {
  const dir = path.join(root, name);
  const store = new Store(dir, plainProtect);
  if (!store.vault.identity) { store.vault.identity = { armored, passphrase: pass }; store.saveVault(); }
  const identity = await new Identity().load(store.vault.identity.armored, store.vault.identity.passphrase);
  const tor = new TorService({ dataDir: path.join(dir, 'tor') });
  await tor.start();
  await tor.whenReady(180000);
  const files = new FileVault(path.join(dir, 'files'));
  const peer = new Peer({ store, identity, tor, files, log: l => process.env.DEBUG && console.log(`[${name}] ${l}`) });
  await peer.start();
  return { name, dir, store, identity, tor, peer, files, async stop() { await peer.stop(); await tor.stop(); store.flush(); } };
}

(async () => {
  console.log('Making keys…');
  const jk = await Identity.generate({ name: 'Jeff', passphrase: 'jeff-pass-123' });
  const ak = await Identity.generate({ name: 'Ann', passphrase: 'ann-pass-1234' });
  const mk = await Identity.generate({ name: 'Mallory', passphrase: 'mal-pass-1234' });

  console.log('Starting Tor for Jeff and Ann…');
  let jeff = await node('jeff', jk, 'jeff-pass-123');
  const ann = await node('ann', ak, 'ann-pass-1234');
  const jeffId = jeff.peer.myId();
  ok(/^sealchat:[a-z2-7]{56}:[0-9A-F]{40}$/.test(jeffId), 'Jeff has a Seal Chat ID: ' + jeffId.slice(0, 30) + '…');
  const jeffOnion = jeff.peer.onion;

  // ---- 1. contact request + accept ----
  const reqSeen = new Promise(r => jeff.peer.once('request', r));
  ann.peer.addContact(jeffId, { note: 'Hi Jeff, it is Ann' });
  const req = await Promise.race([reqSeen, sleep(120000).then(() => null)]);
  ok(req && req.fp === ann.identity.fp && req.note === 'Hi Jeff, it is Ann', 'Jeff receives Ann\'s signed contact request with her note');
  ok(jeff.store.contact(ann.identity.fp).status === 'pending-in', 'request waits for Jeff to accept');

  ann.peer.send(jeff.identity.fp, 'sent before you accepted');
  await sleep(4000);
  ok(!jeff.store.chat(ann.identity.fp).messages.length, 'messages are NOT accepted before the request is');

  jeff.peer.accept(ann.identity.fp);
  await until(() => ann.store.contact(jeff.identity.fp).status === 'accepted', 120000, 'Ann sees accept');
  ok(true, 'Ann sees that Jeff accepted');
  await until(() => jeff.store.chat(ann.identity.fp).messages.length === 1, 200000, 'queued message delivered');
  ok(jeff.store.chat(ann.identity.fp).messages[0].text === 'sent before you accepted', 'Ann\'s waiting message is delivered after the accept');

  // ---- 2. chatting both ways + receipts ----
  const m1 = jeff.peer.send(ann.identity.fp, 'Hello Ann! Ünïcödé ✓ 🎉');
  await until(() => ann.store.chat(jeff.identity.fp).messages.some(m => m.id === m1.id), 60000, 'Jeff→Ann');
  ok(ann.store.chat(jeff.identity.fp).messages.find(m => m.id === m1.id).text === 'Hello Ann! Ünïcödé ✓ 🎉', 'Jeff → Ann delivered, text intact');
  await until(() => jeff.store.chat(ann.identity.fp).messages.find(m => m.id === m1.id).state === 'sent', 30000, 'delivered tick');
  ok(true, 'Jeff sees "Delivered"');
  ann.peer.markRead(jeff.identity.fp);
  await until(() => jeff.store.chat(ann.identity.fp).messages.find(m => m.id === m1.id).state === 'read', 60000, 'read receipt');
  ok(true, 'Jeff sees "Read" after Ann opens the chat');

  // ---- 2b. a 20 MB file over Tor (1.1.0) ----
  jeff.store.setSettings({ autoDownloadMB: 100 });
  const big = crypto.randomBytes(20 * 1024 * 1024);
  const tf0 = Date.now();
  const fm = await ann.peer.sendFile(jeff.identity.fp, { buffer: big }, { name: 'video.mp4', mime: 'video/mp4' });
  const inJ = () => jeff.store.chat(ann.identity.fp).messages.find(m => m.id === fm.id);
  await until(() => inJ() && inJ().transfer.state === 'done', 300000, 'file over Tor');
  const secs = (Date.now() - tf0) / 1000;
  const ref = jeff.peer.fileRef(ann.identity.fp, fm.id);
  const back = await new Promise((res, rej) => { const a = []; const st = jeff.files.plainStream(ref.where, fm.id, ref.meta); st.on('data', d => a.push(d)); st.on('end', () => res(Buffer.concat(a))); st.on('error', rej); });
  ok(back.equals(big), `20 MB file sent over Tor in ${secs.toFixed(1)} s (${(20 / secs).toFixed(1)} MB/s on this test network), identical`);

  // ---- 3. Jeff offline: message waits, delivered when he comes back ----
  await jeff.stop();
  const m2 = ann.peer.send(jeff.identity.fp, 'while you were away');
  await sleep(8000);
  ok(ann.store.chat(jeff.identity.fp).messages.find(m => m.id === m2.id).state === 'queued', 'Jeff offline: message waits in Ann\'s Outbox');
  await until(() => ann.store.contact(jeff.identity.fp).lastError, 150000, 'offline noticed');
  ok(/Offline/i.test(ann.store.contact(jeff.identity.fp).lastError || ''), 'Ann sees Jeff is offline: ' + ann.store.contact(jeff.identity.fp).lastError);
  jeff = await node('jeff', null, null);                 // same data folder → same address and key
  ok(jeff.peer.onion === jeffOnion, 'Jeff restarts with the SAME .onion address');
  const t0 = Date.now();
  await until(() => jeff.store.chat(ann.identity.fp).messages.some(m => m.id === m2.id), 120000, 'delivery after restart');
  ok(true, `waiting message delivered ${Math.round((Date.now() - t0) / 1000)}s after Jeff came back (his hello triggers it)`);

  // ---- 4. strangers ----
  const mal = await node('mal', mk, 'mal-pass-1234');
  const fake = formatId(jeffOnion, ann.identity.fp);     // Jeff's address but someone else's fingerprint
  mal.peer.addContact(fake);
  await until(() => mal.store.contact(ann.identity.fp).status === 'failed', 120000, 'fake ID rejected');
  ok(/does not match/.test(mal.store.contact(ann.identity.fp).failReason), 'an ID whose fingerprint doesn\'t match the address is rejected');

  // Mallory adds Jeff properly but Jeff blocks her
  mal.peer.addContact(jeff.peer.myId());
  await until(() => jeff.store.contact(mal.identity.fp), 120000, 'mallory request');
  jeff.peer.block(mal.identity.fp);
  mal.peer.send(jeff.identity.fp, 'spam');
  await sleep(6000);
  ok(!jeff.store.chat(mal.identity.fp).messages.length, 'blocked contact\'s messages are refused');

  // ---- 5. stored data is encrypted ----
  jeff.store.flush();
  const raw = fs.readFileSync(path.join(jeff.dir, 'vault.dat'));
  ok(!raw.includes(Buffer.from('BEGIN PGP')) && !raw.includes(Buffer.from('ED25519')), 'vault on disk is encrypted');
  const chats = fs.readdirSync(path.join(jeff.dir, 'chats'));
  ok(chats.every(f => !fs.readFileSync(path.join(jeff.dir, 'chats', f)).includes(Buffer.from('Hello Ann'))), 'chat files on disk are encrypted');

  await mal.stop(); await ann.stop(); await jeff.stop();
  console.log(`\nTor tests: ${passed} passed`);
  process.exit(0);
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
