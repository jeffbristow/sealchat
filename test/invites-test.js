/* Seal Chat 1.8.0 self-test: INVITE CODES — codes, the temporary .onion
 * address, SPAKE2, and three people end to end over a fake Tor:
 * single use (both added at once), wrong codes (3 tries), several uses
 * (requests marked with the invite), cancel, expiry.
 *   node test/invites-test.js                                              */
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
const inv = require('../src/main/invites');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, ms, what) { const end = Date.now() + ms; while (Date.now() < end) { if (await fn()) return; await sleep(40); } throw new Error('timed out: ' + what); }
async function fails(p, re, m) { let e = null; try { await p; } catch (x) { e = x; } ok(e && re.test(e.message), m + ' — "' + (e && e.message) + '"'); }
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealchat-inv-'));
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
  async publishExtra(key, port, vport, expect) { if (routes.has(expect)) throw new Error('collision'); routes.set(expect, port); return { onion: expect }; }
  async unpublishExtra(onion) { routes.delete(onion); }
}
async function node(name, armored, pass) {
  const store = new Store(path.join(root, name), plain);
  store.setSettings({ displayName: name });
  const identity = await new Identity().load(armored, pass);
  const tor = new FakeTor(); tor.socksPort = socks.address().port;
  const peer = new Peer({ store, identity, tor, inviteTimeout: 5000, log: l => process.env.DEBUG && console.log('[' + name + '] ' + l) });
  await peer.start();
  return { store, identity, peer };
}
/* what main.js does with a code: use it, then add the person */
async function useCode(n, code) { const r = await n.peer.invites.join(code); n.peer.addContact(r.id); return r; }

(async () => {
  console.log('invite codes:');
  /* 1. codes */
  const c1 = inv.makeCode(inv.LIFETIMES['24h']), c30 = inv.makeCode(inv.LIFETIMES['30d']);
  ok(/^\d{3}(-[a-z]+){3}$/.test(c1) && /^\d{3}(-[a-z]+){4}$/.test(c30), 'codes: number + 3 words (30 days: 4 words) — ' + c1 + ' / ' + c30);
  const p = inv.parseCode('  482 Crys.ORAN river ');
  ok(p && p.code === '482-crystal-orange-river', 'typing: any case, any separator, words shortened to 4 letters');
  ok(!inv.parseCode('482-crystal-orange') && !inv.parseCode('48-crystal-orange-river') && !inv.parseCode('482-crystal-orange-zzzz') && !inv.looksLikeCode('ann@example.com'), 'too short, bad number, unknown word, a name: not codes');
  const o = inv.onionFor(p);
  ok(o.onion === inv.onionFor(inv.parseCode('482-crystal-pizza-lemon')).onion && o.onion !== inv.onionFor(inv.parseCode('483-crystal-orange-river')).onion && /^[a-z2-7]{55}d$/.test(o.onion), 'the address comes only from the number + first word (a valid v3 .onion)');
  ok(o.onion === 'ebiloywe3dbcnalnf46dtpqjt3u6scngqrgmhgt5joxfu4pi2zjmixqd' || o.onion.length === 56, 'address: ' + o.onion);

  /* 2. SPAKE2 */
  const A = inv.spake('A', o.onion, p), B = inv.spake('B', o.onion, p);
  const ka = A.finish(B.msg), kb = B.finish(A.msg);
  ok(ka.macA === kb.macA && ka.macB === kb.macB && ka.keyA.equals(kb.keyA), 'SPAKE2: the same password gives both sides the same keys');
  const W = inv.spake('A', o.onion, inv.parseCode('482-crystal-orange-lemon')), B2 = inv.spake('B', o.onion, p);
  ok(W.finish(B2.msg).macA !== B2.finish(W.msg).macA, 'SPAKE2: a different password gives different keys');
  ok(A.msg !== inv.spake('A', o.onion, p).msg, 'SPAKE2: a fresh random value every time (nothing to replay)');
  let bad = false; try { inv.spake('A', o.onion, p).finish(Buffer.alloc(32).toString('base64')); } catch { bad = true; }
  ok(bad, 'SPAKE2: the zero point is refused');

  /* 3. end to end */
  await new Promise(r => socks.listen(0, '127.0.0.1', r));
  const keys = await Promise.all(['Ann', 'Bob', 'Cat', 'Dan'].map(n => Identity.generate({ name: n, passphrase: n + '-pass-1234' })));
  const ann = await node('Ann', keys[0], 'Ann-pass-1234'), bob = await node('Bob', keys[1], 'Bob-pass-1234');
  const cat = await node('Cat', keys[2], 'Cat-pass-1234'), dan = await node('Dan', keys[3], 'Dan-pass-1234');
  const AF = ann.identity.fp, BF = bob.identity.fp;

  // single use
  const one = await ann.peer.invites.create({ lifetime: '1h', label: 'For Bob' });
  ok(one.open && one.triesLeft === 3 && ann.peer.invites.list().length === 1, 'Ann makes a single-use invite: ' + one.code);
  await fails(ann.peer.invites.join(one.code), /your own invite/, 'Ann can\'t use her own code');
  const used = [];
  ann.peer.on('invite', e => used.push(e));
  const r = await useCode(bob, one.code.toUpperCase().replace(/-/g, ' '));
  ok(r.fp === AF && r.name === 'Ann' && !r.multi, 'Bob uses it (typed in capitals with spaces) and gets Ann\'s ID');
  await until(() => ann.store.contact(BF) && ann.store.contact(BF).status === 'accepted' && bob.store.contact(AF).status === 'accepted', 10000, 'both accepted');
  ok(true, 'single use: Ann and Bob are both contacts at once — no request to accept');
  ok(used.length === 1 && used[0].kind === 'used' && used[0].name === 'Bob', 'Ann is told "Bob used your invite"');
  ok(ann.peer.invites.list().length === 0, 'a single-use invite is gone once used');
  await sleep(3500);
  await fails(useCode(cat, one.code), /Couldn't reach that invite/, 'the used code no longer works');
  const m = await bob.peer.send(AF, 'hi from the invite');
  await until(() => ann.store.chat(BF).messages.some(x => x.id === m.id), 8000, 'message');
  ok(true, 'and they can chat');

  // wrong codes
  const two = await ann.peer.invites.create({ lifetime: '24h' });
  const pc = inv.parseCode(two.code);
  const wrong = n => `${pc.num}-${pc.words[0]}-${pc.words[1]}-${pc.words[2] === 'zoo' ? 'zone' : 'zoo'}${n ? '' : ''}`;
  await fails(useCode(cat, wrong()), /isn't right/, 'a wrong last word: "That code isn\'t right"');
  ok(ann.peer.invites.list()[0].triesLeft === 2, 'one try used (2 left)');
  await fails(useCode(cat, wrong()), /isn't right/, 'second wrong try');
  await fails(useCode(cat, wrong()), /isn't right/, 'third wrong try');
  ok(ann.peer.invites.list().length === 0 && used.some(e => e.kind === 'closed'), 'after 3 wrong tries the invite closes (and Ann is told)');
  await sleep(3500);
  await fails(useCode(cat, two.code), /Couldn't reach/, 'even the right code no longer works then');
  ok(!ann.store.contact(cat.identity.fp), 'Cat was never added');

  // several uses
  const club = await ann.peer.invites.create({ lifetime: '30d', multi: true, label: 'Book club' });
  ok(/^\d{3}(-[a-z]+){4}$/.test(club.code) && club.multi, '30 days, several people: a 4-word code ' + club.code);
  const rc = await useCode(cat, club.code);
  ok(rc.multi, 'Cat is told it is a group invite (Ann accepts each person)');
  await until(() => ann.store.contact(cat.identity.fp), 8000, 'cat request');
  const cc = ann.store.contact(cat.identity.fp);
  ok(cc.status === 'pending-in' && cc.invite && cc.invite.label === 'Book club', 'Cat\'s request waits for Ann, marked "Book club"');
  await useCode(dan, club.code);
  await until(() => ann.store.contact(dan.identity.fp), 8000, 'dan request');
  ok(ann.store.contact(dan.identity.fp).status === 'pending-in' && ann.peer.invites.list()[0].uses === 2, 'Dan too — the invite stays open (used 2 times)');
  ann.peer.accept(cat.identity.fp);
  await until(() => cat.store.contact(AF).status === 'accepted', 8000, 'cat accepted');
  ok(true, 'Ann accepts Cat as usual');

  // cancel, restart, expiry
  await ann.peer.invites.cancel(club.id);
  await fails(useCode(bob, club.code), /Couldn't reach/, 'a cancelled invite can\'t be used');
  const three = await ann.peer.invites.create({ lifetime: '7d' });
  await ann.peer.stop();
  ok(!routes.has(inv.onionFor(inv.parseCode(three.code)).onion), 'Seal Chat closed: the invite is offline (but kept)');
  await ann.peer.start();
  await until(() => routes.has(inv.onionFor(inv.parseCode(three.code)).onion), 3000, 'republished');
  ok(ann.peer.invites.list()[0].open, 'Seal Chat opened again: the invite is back');
  ann.store.vault.invites[0].expires = Date.now() - 1;
  ann.peer.invites._expire();
  ok(ann.peer.invites.list().length === 0 && !routes.has(inv.onionFor(inv.parseCode(three.code)).onion), 'an invite that ran out is removed and taken offline');
  for (let i = 0; i < inv.MAX_OPEN; i++) await ann.peer.invites.create({ lifetime: '1h' });
  await fails(ann.peer.invites.create({ lifetime: '1h' }), /5 invite codes open/, 'at most 5 open at once');
  await fails(ann.peer.invites.create({ lifetime: '90d' }), /how long/, 'only the offered lifetimes');
  ok(JSON.stringify(ann.store.vault.invites).includes(ann.peer.invites.list()[0].code), 'codes are kept in the encrypted vault (not in settings)');

  for (const n of [ann, bob, cat, dan]) await n.peer.stop();
  socks.close();
  console.log(`\n${passed} passed`);
  process.exit(0);
})().catch(e => { console.error('FAILED:', e.stack || e.message); process.exit(1); });
