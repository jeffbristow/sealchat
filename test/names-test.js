/* Seal Chat 1.8.0 self-test: NAMES (name@domain) — reading a name, looking
 * it up from a website's /.well-known/sealchat.json (a local test server),
 * errors people will actually see, and the file Seal Chat Web writes.
 *   node test/names-test.js                                                */
const http = require('http');
const assert = require('assert');
const { parseHandle, looksLikeHandle, lookup, buildFile } = require('../src/main/names');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const ID = 'sealchat:' + 'a'.repeat(55) + 'd:' + 'AB'.repeat(20);
const ID2 = 'sealchat:' + 'b'.repeat(55) + 'd:' + 'CD'.repeat(20);

/* ---- a tiny website: /good/, /none/ (404), /bad/ (not JSON), /moved/ (redirect) ---- */
const files = {
  '/good/.well-known/sealchat.json': JSON.stringify({ v: 1, names: { ann: ID, sam: { id: ID2, name: 'Sam\u0007 Smith' }, broken: 'sealchat:nope' } }),
  '/bad/.well-known/sealchat.json': '<html>Just a moment…</html>'
};
const srv = http.createServer((req, res) => {
  if (req.url === '/moved/.well-known/sealchat.json') { res.writeHead(301, { Location: 'https://evil.example.net/.well-known/sealchat.json' }); return res.end(); }
  const f = files[req.url];
  if (!f) { res.writeHead(404); return res.end('no'); }
  res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(f);
});

(async () => {
  console.log('names (name@domain):');
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const base = p => `http://127.0.0.1:${srv.address().port}/${p}/`;

  /* 1. reading a name */
  ok(parseHandle('Ann@Example.COM').handle === 'ann@example.com', 'a name is read case-insensitively');
  ok(parseHandle(' @ann@example.com ').name === 'ann', 'a leading @ and spaces are allowed');
  ok(!looksLikeHandle(ID) && !looksLikeHandle('ann') && !looksLikeHandle('ann@localhost') && !looksLikeHandle('ann@abc.onion'), 'IDs, bare words, localhost and .onion are not names');

  /* 2. looking it up */
  const a = await lookup('ann@example.com', { base: base('good') });
  ok(a.id === ID && a.fp === 'AB'.repeat(20) && a.handle === 'ann@example.com', 'a plain entry gives the ID and fingerprint');
  const s = await lookup('SAM@example.com', { base: base('good') });
  ok(s.id === ID2 && s.display === 'Sam Smith', 'an entry with a display name (control characters removed)');
  const err = async (t, b, re, m) => { let e = null; try { await lookup(t, { base: base(b) }); } catch (x) { e = x; } ok(e && re.test(e.message), m + ' — "' + (e && e.message) + '"'); };
  await err('zoe@example.com', 'good', /no Seal Chat name "zoe"/, 'an unknown name says so');
  await err('broken@example.com', 'good', /not a valid Seal Chat ID/, 'a bad ID in the file is refused');
  await err('ann@example.com', 'none', /has no Seal Chat names/, 'a website without the file says so');
  await err('ann@example.com', 'bad', /not readable/, 'a challenge page (not JSON) is refused');
  await err('ann@example.com', 'moved', /answered 301/, 'a redirect to another website is not followed');
  await err('not a name', 'good', /not a name like/, 'text that is not a name is refused before any lookup');

  /* 3. through Tor that the website blocks */
  const blocked = Object.assign(new Error('blocked'), { code: 'TOR_BLOCKED' });
  let directCalls = 0;
  const fake = async (url, o) => { if (o.socksPort) throw blocked; directCalls++; return { status: 200, headers: {}, body: Buffer.from(files['/good/.well-known/sealchat.json']) }; };
  let e3 = null; try { await lookup('ann@example.com', { socksPort: 9050, http: fake }); } catch (x) { e3 = x; }
  ok(e3 && /blocks visitors that come through Tor/.test(e3.message) && directCalls === 0, 'Tor blocked: never goes direct unless allowed');
  const d = await lookup('ann@example.com', { socksPort: 9050, direct: true, http: fake });
  ok(d.id === ID && directCalls === 1, 'Tor blocked + "contact directly" allowed: looked up directly');
  let seenUrl = '';
  await lookup('ann@example.com', { socksPort: 9050, http: async u => { seenUrl = u; return { status: 200, headers: {}, body: Buffer.from(files['/good/.well-known/sealchat.json']) }; } });
  ok(seenUrl === 'https://example.com/.well-known/sealchat.json', 'the real address is https://<domain>/.well-known/sealchat.json');
  const hops = [];
  const www = await lookup('ann@example.com', { socksPort: 9050, http: async u => { hops.push(u); return hops.length === 1 ? { status: 301, headers: { location: 'https://www.example.com/.well-known/sealchat.json' }, body: Buffer.alloc(0) } : { status: 200, headers: {}, body: Buffer.from(files['/good/.well-known/sealchat.json']) }; } });
  ok(www.id === ID && hops[1] === 'https://www.example.com/.well-known/sealchat.json', 'example.com → www.example.com redirect is followed');

  /* 3b. 1.8.4: a web page instead of Seal Chat's answer is described */
  const { pageHint } = require('../src/main/webhttp');
  ok(pageHint({ body: Buffer.from('<html><head><title>Just a moment...</title></head><body>x</body></html>') }) === '"Just a moment..."', 'a page is described by its title');
  ok(pageHint({ body: Buffer.from('<html><body><script>var a=1</script><h1>Access denied</h1> by Imunify360</body></html>') }) === '"Access denied by Imunify360"', 'or by its first words');

  /* 4. the file format */
  const f = buildFile({ Ann: ID, sam: { id: ID2, name: 'Sam' }, 'bad name': ID, x: 'nope' });
  ok(f.v === 1 && f.names.ann === ID && f.names.sam.id === ID2 && f.names.sam.name === 'Sam' && Object.keys(f.names).length === 2, 'buildFile keeps good names and skips bad ones');

  srv.close();
  console.log(`\n${passed} passed`);
})().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
