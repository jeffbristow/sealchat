/* Seal Chat 1.10.0 self-test: SEAL ID — verifying Seal ID chains, whether a
 * Seal ID belongs to a Seal Chat ID (same key, or signed by the Seal Chat key),
 * domain aliases (website file and DNS-over-HTTPS), and pinning.
 * A local test server plays the Seal ID websites.
 *   node test/sealid-test.js                                                */
const http = require('http');
const crypto = require('crypto');
const assert = require('assert');
const openpgp = require('openpgp');
const sid = require('../src/main/sealid');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const rejects = async (p, re, m) => { try { await p; } catch (e) { ok(re.test(e.message), m + ' (' + e.message + ')'); return; } assert.fail(m + ': no error'); };

const routes = {};
const srv = http.createServer((req, res) => {
  const path = req.url.split('?')[0];
  const r = routes[path];
  if (!r) { res.writeHead(404); return res.end('no'); }
  const body = typeof r === 'function' ? r(req) : r;
  if (body && typeof body === 'object' && body.status) { res.writeHead(body.status, { 'Content-Type': 'text/html' }); return res.end(body.body || ''); }   // e.g. a host that blocks Tor
  res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(body);
});

async function key(name) {
  const { privateKey, publicKey } = await openpgp.generateKey({ userIDs: [{ name }], format: 'armored' });
  const priv = await openpgp.readPrivateKey({ armoredKey: privateKey });
  return { priv, pub: publicKey, fp: priv.getFingerprint().toUpperCase() };
}
const signWith = async (k, text) => openpgp.sign({ message: await openpgp.createMessage({ binary: Buffer.from(text, 'utf8') }), signingKeys: k.priv, detached: true });

/** A Seal ID chain, as Seal ID itself writes it. */
async function chain(url, k, statements) {
  const links = [];
  let prev = null, ts = Math.floor(Date.now() / 1000) - 500;
  for (const [type, body] of statements) {
    const payload = JSON.stringify({ v: 1, seq: links.length + 1, prev, ts: ts++, url, fp: k.fp, type, body });
    links.push({ payload, sig: await signWith(k, payload) });
    prev = crypto.createHash('sha256').update(payload).digest('hex');
  }
  return { seal_id: 1, url, fp: k.fp, keys: { [k.fp]: k.pub }, chain: links, attestations: {}, checks: {}, aliases: [] };
}
const onion = c => c.repeat(55) + 'd';

(async () => {
  console.log('Seal ID:');
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const host = `127.0.0.1:${srv.address().port}`;
  const base = p => `http://${host}/${p}`;
  const net = { allowHttp: true, doh: `http://${host}/doh` };

  /* 1. addresses */
  ok(sid.normUrl('ID.Example.com/') === 'https://id.example.com' && sid.normUrl('https://example.com/seal/admin.php') === 'https://example.com/seal', 'addresses are normalised like Seal ID does');
  ok(sid.normUrl('http://example.com') === null && sid.normUrl('https://x.com/?q=1') === null && sid.normUrl('javascript:alert(1)') === null, 'http, queries and other schemes are refused');
  ok(sid.looksLikeAddress('jeffbristow.com') && sid.looksLikeAddress('https://id.bristow.ch') && !sid.looksLikeAddress('ann@example.com') && !sid.looksLikeAddress('sealchat:abc:DEF'), 'addresses are told apart from names and IDs');
  ok(/^sid1:[A-Za-z0-9_-]{22}$/.test(sid.token('{"v":1}')), 'proof tokens look like Seal ID\'s');

  /* 2. Seal ID's own test chain (made by OpenPGP.js, also verified by Seal ID's PHP) */
  const fx = require('./sealid-chain.json');
  const st = await sid.verifyChain({ chain: fx.links, keys: fx.keys }, fx.url);
  ok(st.seq === 8 && st.fps.length === 2 && st.fp === fx.fp2 && st.name === 'Chain Tester', 'Seal ID\'s test chain verifies here too (8 links, key rotated to a v6 key)');
  ok(!st.proofs[2] && st.proofs[3], 'a revoked proof is gone, the other stays');
  const tampered = JSON.parse(JSON.stringify(fx.links));
  tampered[1].payload = tampered[1].payload.replace('"handle":"example.test"', '"handle":"evil.test"');
  await rejects(sid.verifyChain({ chain: tampered, keys: fx.keys }, fx.url), /bad signature/, 'an edited statement is refused');
  await rejects(sid.verifyChain({ chain: fx.links, keys: fx.keys }, 'https://id.evil.test'), /different identity/, 'a chain for another address is refused');
  await rejects(sid.verifyChain({ chain: fx.links.slice(1), keys: fx.keys }, fx.url), /out of order|eldest/, 'a chain with its first link removed is refused');

  /* 3. does a Seal ID belong to a Seal Chat ID? */
  const ann = await key('Ann');                 // Seal ID key = Seal Chat key
  const bob = await key('Bob Seal ID'), bobChat = await key('Bob Seal Chat');   // two keys
  const eve = await key('Eve');
  const annUrl = base('ann'), bobUrl = base('bob');
  const annB = await chain(annUrl, ann, [['eldest', { name: 'Ann', bio: '' }], ['proof', { service: 'sealchat', handle: `sealchat:${onion('a')}:${ann.fp}` }]]);
  const bobB = await chain(bobUrl, bob, [['eldest', { name: 'Bob', bio: '' }], ['proof', { service: 'sealchat', handle: `sealchat:${onion('b')}:${bobChat.fp}` }], ['proof', { service: 'github', handle: 'bob' }]]);
  bobB.checks = { 3: { status: 'verified', at: 1 } };
  routes['/ann/api.php'] = JSON.stringify(annB);
  routes['/bob/api.php'] = () => JSON.stringify(bobB);

  let r = await sid.resolve(annUrl, net);
  let l = await sid.sealChatLink(r.state, r.bundle, ann.fp);
  ok(l.ok && l.how === 'same-key', 'same key: the Seal ID proves the Seal Chat ID by itself');
  l = await sid.sealChatLink(r.state, r.bundle, eve.fp);
  ok(!l.ok && /does not name/.test(l.why), 'someone else\'s Seal Chat ID is not proven');

  r = await sid.resolve(bobUrl, net);
  l = await sid.sealChatLink(r.state, r.bundle, bobChat.fp);
  ok(!l.ok && /not signed/.test(l.why), 'two keys: the claim alone is not enough');
  const tok = r.state.proofs[2].token;
  bobB.attestations = { 2: { key: eve.pub, sig: await signWith(eve, sid.proofText(bobUrl, tok)) } };
  r = await sid.resolve(bobUrl, net);
  ok(!(await sid.sealChatLink(r.state, r.bundle, bobChat.fp)).ok, 'a signature by another key does not count');
  bobB.attestations = { 2: { key: bobChat.pub, sig: await signWith(bobChat, sid.proofText(bobUrl, tok) + 'x') } };
  r = await sid.resolve(bobUrl, net);
  ok(!(await sid.sealChatLink(r.state, r.bundle, bobChat.fp)).ok, 'a signature over other text does not count');
  bobB.attestations = { 2: { key: bobChat.pub, sig: await signWith(bobChat, sid.proofText(bobUrl, tok)) } };
  r = await sid.resolve(bobUrl, net);
  l = await sid.sealChatLink(r.state, r.bundle, bobChat.fp);
  ok(l.ok && l.how === 'signed', 'two keys: proven once the Seal Chat key signed the claim');
  const ids = await sid.provenSealChatIds(r.state, r.bundle);
  ok(ids.length === 1 && ids[0].fp === bobChat.fp && ids[0].onion === onion('b'), 'add by Seal ID: the proven Seal Chat ID is found');
  const s = sid.summary(r, l);
  ok(s.name === 'Bob' && s.proofs.length === 1 && s.proofs[0].status === 'verified' && s.ok, 'summary: name, other proofs with their reported status');

  /* 4. aliases */
  const dom = host;                                 // the test server plays the domain too
  const cat = await key('Cat');
  const catUrl = base('cat');
  const catB = await chain(catUrl, cat, [['eldest', { name: 'Cat', bio: '' }], ['proof', { service: 'web', handle: dom }]]);
  routes['/cat/api.php'] = JSON.stringify(catB);
  const catTok = (await sid.verifyChain(catB, catUrl)).proofs[2].token;
  routes['/.well-known/seal-id.txt'] = `Verifying my Seal ID ${catUrl} ${catTok}\n`;
  r = await sid.resolve(dom, net);
  ok(r.url === catUrl && r.alias === dom, 'a domain with a website proof leads to its Seal ID');
  routes['/.well-known/seal-id.txt'] = `Verifying my Seal ID ${catUrl} sid1:AAAAAAAAAAAAAAAAAAAAAA\n`;
  await rejects(sid.resolve(dom, net), /doesn't point to one/, 'a domain whose token is not in the signed chain is refused');
  delete routes['/.well-known/seal-id.txt'];
  const dnsB = await chain(catUrl, cat, [['eldest', { name: 'Cat', bio: '' }], ['proof', { service: 'dns', handle: dom }]]);
  routes['/cat/api.php'] = JSON.stringify(dnsB);
  const dnsTok = (await sid.verifyChain(dnsB, catUrl)).proofs[2].token;
  routes['/doh'] = () => JSON.stringify({ Answer: [{ type: 16, data: `"${dnsTok} id=${catUrl}"` }] });
  r = await sid.resolve(dom, net);
  ok(r.url === catUrl && r.alias === dom, 'a domain with a DNS proof (found through DNS-over-HTTPS) leads to its Seal ID');
  routes['/doh'] = () => JSON.stringify({ Answer: [{ type: 16, data: `"${dnsTok} id=${annUrl}"` }] });
  await rejects(sid.resolve(dom, net), /doesn't point to one/, 'a DNS record pointing to a Seal ID that never claimed the domain is refused');
  delete routes['/doh'];
  await rejects(sid.resolve(base('nobody'), net), /No Seal ID/, 'an address with no Seal ID says so');

  /* 4b. hosts that block Tor: mirrors from the DNS key record, and the key record itself */
  const dan = await key('Dan');
  const danUrl = base('dan');
  const danB = await chain(danUrl, dan, [['eldest', { name: 'Dan', bio: '' }], ['mirrors', { urls: ['https://mirror.example.net/dan.json'] }]]);
  const blocked = { status: 403, body: '<html>Access denied by bot protection</html>' };
  routes['/dan/api.php'] = () => blocked;
  routes['/dan/.well-known/seal-id.json'] = () => blocked;
  await rejects(sid.resolve(danUrl, net), /blocks visitors that come through Tor.*Settings → Privacy/, 'a host that blocks Tor is named as such, with what to do');
  routes['/mirror/dan.json'] = JSON.stringify(danB);
  const txt = (rec) => () => JSON.stringify({ Answer: [{ type: 16, data: `"${rec}"` }] });
  routes['/doh'] = txt(`v=sealid1; id=${danUrl}; fp=${dan.fp}; mirror=${base('mirror/dan.json')}`);
  r = await sid.resolve(danUrl, net);
  ok(r.via === 'mirror' && r.state.name === 'Dan' && r.dnsConfirmed, 'blocked host: read from the mirror in its DNS key record, key confirmed by DNS');
  ok(sid.pinOf(r.state).mirrors[0] === 'https://mirror.example.net/dan.json', 'the signed mirror list is remembered with the pin');
  routes['/doh'] = txt(`v=sealid1; id=${danUrl}; fp=${eve.fp}; mirror=${base('mirror/dan.json')}`);
  await rejects(sid.resolve(danUrl, net), /different key.*impersonating/, 'a DNS key record naming another key is refused');
  routes['/doh'] = txt(`v=sealid1; id=${base('someone-else')}; fp=${eve.fp}; mirror=${base('mirror/dan.json')}`);
  await rejects(sid.resolve(danUrl, net), /blocks visitors/, 'a DNS record for another identity on the same host is not used');
  routes['/elsewhere/dan.json'] = JSON.stringify(danB);
  delete routes['/doh'];
  r = await sid.resolve(danUrl, net, { mirrors: [base('elsewhere/dan.json')] });
  ok(r.via === 'mirror', 'a mirror remembered from earlier still works without DNS');
  const fake = JSON.parse(JSON.stringify(danB)); fake.chain[0].payload = fake.chain[0].payload.replace('"Dan"', '"Mallory"');
  routes['/elsewhere/dan.json'] = JSON.stringify(fake);
  await rejects(sid.resolve(danUrl, net, { mirrors: [base('elsewhere/dan.json')] }), /bad signature/, 'a changed copy on a mirror is refused');

  /* 5. pinning */
  const st1 = await sid.verifyChain(annB, annUrl);
  const pin = sid.pinOf(st1);
  ok(sid.pinCheck(null, st1) === 'new' && sid.pinCheck(pin, st1) === 'match', 'pin: new, then the same');
  const grown = await chain(annUrl, ann, [['eldest', { name: 'Ann', bio: '' }], ['proof', { service: 'sealchat', handle: `sealchat:${onion('a')}:${ann.fp}` }], ['profile', { name: 'Ann B', bio: '' }]]);
  grown.chain[0] = annB.chain[0]; grown.chain[1] = annB.chain[1];        // same first links, one more
  // rebuild link 3 so it follows the original link 2
  const p3 = JSON.parse(grown.chain[2].payload);
  p3.prev = crypto.createHash('sha256').update(annB.chain[1].payload).digest('hex');
  p3.ts = JSON.parse(annB.chain[1].payload).ts + 1;
  const pay3 = JSON.stringify(p3);
  grown.chain[2] = { payload: pay3, sig: await signWith(ann, pay3) };
  ok(sid.pinCheck(pin, await sid.verifyChain(grown, annUrl)) === 'match', 'pin: a Seal ID that grew is still the same');
  const newer = sid.pinOf(await sid.verifyChain(grown, annUrl));
  ok(sid.pinCheck(newer, st1) === 'behind', 'pin: an older copy of the same Seal ID (a mirror not updated yet) is "behind", not a warning');
  ok(sid.pinCheck({ ...newer, hashes: { ...newer.hashes, 2: 'f'.repeat(64) } }, st1) === 'changed', 'pin: an older copy that does not match what was seen is a warning');
  const other = await chain(annUrl, eve, [['eldest', { name: 'Ann', bio: '' }]]);
  ok(sid.pinCheck(pin, await sid.verifyChain(other, annUrl)) === 'changed', 'pin: a replaced Seal ID (other key) is a warning');

  srv.close();
  console.log(`\nSeal ID: ${passed} checks passed`);
})().catch(e => { console.error('FAILED:', e.message); srv.close(); process.exit(1); });
