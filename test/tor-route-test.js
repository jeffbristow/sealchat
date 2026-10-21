/* =====================================================================
 * Seal Chat — tor-route-test.js   (1.4.1)
 * "Through Tor" requests (update checks, web access) must really use the
 * Tor SOCKS socket — never connect directly. A fake SOCKS proxy forwards
 * to a local web server; the requested host name does not exist, so a
 * direct connection would fail. Also checks the "host blocks Tor" errors.
 * ===================================================================== */
const net = require('net'), http = require('http');
const { request } = require('../src/main/webhttp');
const { httpsGet } = require('../src/main/updater');
let pass = 0, fail = 0;
const ok = (c, n) => { if (c) { pass++; console.log('  ✓ ' + n); } else { fail++; console.log('  ✗ ' + n); } };
let mode = 'forward', fwd = 0, used = 0;
const socks = net.createServer(c => {
  let st = 0;
  const onData = () => {
    if (st === 0) { c.write(Buffer.from([5, 0])); st = 1; return; }
    if (st === 2) return; st = 2; used++;
    if (mode === 'refuse') { c.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
    c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
    c.off('data', onData); const up = net.connect(fwd, '127.0.0.1'); c.pipe(up).pipe(c);
  };
  c.on('data', onData);
});
let status = 200;
const site = http.createServer((q, r) => { r.writeHead(status); r.end(status === 200 ? 'hello via tor' : 'blocked'); });
(async () => {
  await new Promise(r => socks.listen(0, '127.0.0.1', r)); await new Promise(r => site.listen(0, '127.0.0.1', r));
  fwd = site.address().port; const sp = socks.address().port;
  const url = 'http://no-such-host.invalid/x';
  const r1 = await request(url, { socksPort: sp, allowHttp: true });
  ok(r1.status === 200 && r1.body.toString() === 'hello via tor' && used === 1, 'web access request goes through the Tor socket');
  const r2 = await httpsGet(url, { socksPort: sp, allowHttp: true });
  ok(r2.toString() === 'hello via tor' && used === 2, 'update check goes through the Tor socket');
  mode = 'refuse';
  let e = null; try { await request('https://example.com/', { socksPort: sp }); } catch (x) { e = x; }
  ok(e && e.code === 'TOR_BLOCKED', 'Tor exit refused → TOR_BLOCKED: ' + (e && e.message));
  console.log(`Tor route tests: ${pass} passed${fail ? `, ${fail} FAILED` : ''}`);
  process.exit(fail ? 1 : 0);
})();
