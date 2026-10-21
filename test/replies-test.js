/* Seal Chat 1.8.0 self-test: replies + reactions between two contacts
 * (fake SOCKS proxy, no Tor needed).   node test/replies-test.js          */
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
  const inJeff = id => jeff.store.chat(A).messages.find(m => m.id === id);
  const inAnn = id => ann.store.chat(J).messages.find(m => m.id === id);
  const ups = []; ann.peer.on('msgupdate', d => ups.push(d)); const reacted = []; ann.peer.on('reacted', d => reacted.push(d));

  // ---- replies ----
  const m1 = ann.peer.send(J, 'Lunch on Friday?');
  await until(() => inJeff(m1.id), 8000, 'first message');
  const r1 = jeff.peer.send(A, 'Yes — the place on 5th', { re: m1.id });
  ok(r1.re && r1.re.id === m1.id && r1.re.dir === 'in' && r1.re.snip === 'Lunch on Friday?', 'a reply keeps a reference + excerpt of the message it answers');
  await until(() => inAnn(r1.id), 8000, 'reply arrives');
  const got = inAnn(r1.id);
  ok(got.re && got.re.id === m1.id && got.re.dir === 'out', 'the reply arrives knowing it answers Ann\'s OWN message (dir "out" on her side)');
  ok(got.text === 'Yes — the place on 5th', 'the reply text itself is unchanged (older versions just show this)');
  await rejects(Promise.resolve().then(() => jeff.peer.send(A, 'x', { re: 'nope' })), /no longer here/, 'replying to a message that isn\'t there is refused');
  const big = 'word '.repeat(200);
  const m2 = ann.peer.send(J, big); await until(() => inJeff(m2.id), 8000, 'long');
  const r2 = jeff.peer.send(A, 'ok', { re: m2.id });
  ok(r2.re.snip.length <= 140, 'the excerpt is short (' + r2.re.snip.length + ' characters)');

  // ---- reactions ----
  jeff.peer.react(A, m1.id, '👍🏽');
  ok(inJeff(m1.id).reactions.me === '👍🏽', 'my reaction is shown on my side straight away');
  await until(() => inAnn(m1.id).reactions && inAnn(m1.id).reactions.them === '👍🏽', 8000, 'reaction arrives');
  ok(true, 'Ann sees Jeff\'s 👍🏽 on her message');
  ok(ups.some(u => u.msg.id === m1.id) && reacted.some(r => r.e === '👍🏽'), 'her window is told to redraw it, and a notification can say who reacted');
  jeff.peer.react(A, m1.id, '❤️');
  await until(() => inAnn(m1.id).reactions.them === '❤️', 8000, 'changed');
  ok(true, 'changing the reaction replaces it (one per person per message)');
  ann.peer.react(J, m1.id, '😂');
  await until(() => inJeff(m1.id).reactions.them === '😂', 8000, 'both');
  ok(inJeff(m1.id).reactions.me === '❤️', 'both people can react to the same message');
  jeff.peer.react(A, m1.id, '');
  await until(() => !inAnn(m1.id).reactions.them, 8000, 'removed');
  ok(true, 'removing a reaction removes it on the other side too');
  await rejects(Promise.resolve().then(() => jeff.peer.react(A, m1.id, 'lol')), /one emoji/, 'a reaction must be an emoji, not text');
  await rejects(Promise.resolve().then(() => jeff.peer.react(A, 'missing', '👍')), /no longer here/, 'reacting to a message that isn\'t there is refused');

  // ---- an older contact that doesn't know reactions ----
  const realOnMsg = ann.peer._onMsg.bind(ann.peer);
  ann.peer._onMsg = async (fsk, st, f) => {
    const c = ann.store.contact(st.hello && st.hello.fp);
    if (c && c.publicKey) { const r = await ann.identity.open(f.box, c.publicKey); if (r.obj && r.obj.k === 'react') return fsk.send({ t: 'nack', id: f.id, why: 'unsupported' }); }
    return realOnMsg(fsk, st, f);
  };
  jeff.peer.react(A, m1.id, '🙏');
  await until(() => !(jeff.store.vault.ctl || []).some(x => x.k === 'react'), 8000, 'dropped');
  const after = jeff.peer.send(A, 'still works?');
  await until(() => inAnn(after.id), 8000, 'next message');
  ok(!ann.store.chat(J).messages.find(m => m.id === m1.id).reactions?.them, 'an older Seal Chat that can\'t show reactions: the reaction is dropped quietly, and later messages still go through');
  ann.peer._onMsg = realOnMsg;

  // ---- replies with files ----
  const fm = await jeff.peer.sendFile(A, { buffer: Buffer.from('hello file') }, { name: 'notes.txt', mime: 'text/plain', re: m1.id });
  await until(() => inAnn(fm.id), 8000, 'file reply');
  ok(inAnn(fm.id).re && inAnn(fm.id).re.id === m1.id, 'a file can be sent as a reply too');

  console.log(`\nReply/reaction tests: ${passed} passed`);
  process.exit(0);
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
