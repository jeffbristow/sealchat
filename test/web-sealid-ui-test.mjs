// Seal Chat Web 1.4.0 UI test (with Seal Chat 1.11.0): the Seal ID mark (chat list), pill (chat
// header) and the contact page's Seal ID section. Runs the real index.php + app.js from a throwaway
// copy of ../sealchat-web (or SITE_DIR) under php -S, in headless Microsoft Edge, with a stand-in
// for the client (no computer, no relay) that answers with example contacts in each Seal ID state.
//   npm run test:web-sealid            (screenshots: node test/web-sealid-ui-test.mjs <folder>)
import { spawn } from 'node:child_process';
import { writeFileSync, mkdirSync, cpSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
const SITE = process.env.SITE_DIR || resolve(here, '..', '..', 'sealchat-web');
const out = process.argv[2] || null;
const tmp = join(tmpdir(), 'scweb-sid-' + Date.now());
const site = join(tmp, 'site'), dataDir = join(tmp, 'data');
mkdirSync(dataDir, { recursive: true });
cpSync(SITE, site, { recursive: true });
const fwd = p => p.split(String.fromCharCode(92)).join('/');   // Windows paths → forward slashes for PHP
writeFileSync(join(site, 'config.php'), readFileSync(join(site, 'config.php'), 'utf8').replace(/'data_dir'\s*=>\s*'[^']*'/, `'data_dir' => '${fwd(dataDir)}'`));
writeFileSync(join(dataDir, 'relay.json'), JSON.stringify({ enabled: true, code: 'test-relay-code-123456' }));
const port = 18000 + Math.floor(Math.random() * 1000);
const php = spawn('php', ['-S', '127.0.0.1:' + port], { cwd: site, stdio: 'ignore' });
const base = `http://127.0.0.1:${port}/`;
let fails = 0;
const ok = (n, c, x = '') => { if (!c) { fails++; console.log('FAIL', n, x); } else console.log('  ok', n); };
const edge = 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
const proc = spawn(edge, ['--headless=new', '--disable-gpu', '--hide-scrollbars', '--remote-debugging-port=19342', '--user-data-dir=' + process.env.TEMP + '/scweb-sid-' + Date.now(), 'about:blank'], { stdio: 'ignore' });
const done = code => { try { proc.kill(); } catch {} try { php.kill(); } catch {} setTimeout(() => { try { rmSync(tmp, { recursive: true, force: true }); } catch {} process.exit(code); }, 500); };
setTimeout(() => { console.log('TIMEOUT'); done(2); }, 120000);
const wait = ms => new Promise(r => setTimeout(r, ms));
let ws;
for (let i = 0; i < 40 && !ws; i++) { try { const t = await (await fetch('http://127.0.0.1:19342/json')).json(); const p = t.find(x => x.type === 'page'); if (p) ws = new WebSocket(p.webSocketDebuggerUrl); } catch {} await wait(250); }
if (ws.readyState !== 1) await new Promise(r => ws.addEventListener('open', r));
let id = 0; const pend = new Map(); const errs = [];
ws.addEventListener('message', e => { const m = JSON.parse(e.data); if (m.id && pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); }
  if (m.method === 'Runtime.exceptionThrown') errs.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text); });
const send = (method, params = {}) => new Promise(r => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const js = async e => { const r = await send('Runtime.evaluate', { expression: e, awaitPromise: true, returnByValue: true }); return r.result?.result?.value; };
const shot = async name => { if (!out) return; const s = await send('Page.captureScreenshot', { format: 'png' }); writeFileSync(out + '/' + name + '.png', Buffer.from(s.result.data, 'base64')); };
const until = async (e, ms = 8000) => { for (let t = 0; t < ms; t += 200) { if (await js(e)) return true; await wait(200); } return false; };
await send('Page.enable'); await send('Runtime.enable');

const now = Date.now();
const base0 = { status: 'accepted', lastText: 'See you tomorrow', lastDir: 'in', unread: 0, online: false, lastSeen: now - 3600e3 };
const fake = [
  { ...base0, id: 'c-ok', name: 'Alex Rivera', verified: true, lastAt: now - 1000,
    sealid: { url: 'https://id.example.com', ok: true, how: 'same-key', name: 'Alex Rivera', checked: now - 3 * 3600e3, aliases: ['example.com'],
      proofs: [{ service: 'github', handle: 'alexrivera', status: 'verified' }, { service: 'x', handle: 'alex_rivera', status: 'verified' }, { service: 'dns', handle: 'example.com', status: 'verified' }] } },
  { ...base0, id: 'c-warn', name: 'Sam Chen', lastAt: now - 2000,
    sealid: { url: 'https://id.samchen.dev', ok: true, warning: 'Its key or history no longer matches what your computer saw before.', checked: now - 600e3, proofs: [], aliases: [] } },
  { ...base0, id: 'c-bad', name: 'Jordan Lee', lastAt: now - 3000,
    sealid: { url: 'https://jordan.example.org/id', ok: false, why: 'This Seal ID has no Seal Chat proof for this contact.', checked: now - 7200e3, proofs: [], aliases: [] } },
  { ...base0, id: 'c-none', name: 'Morgan Diaz', lastAt: now - 5000 },            // an older Seal Chat: no sealid field at all
];
// the stand-in client, installed before the page's scripts run
await send('Page.addScriptToEvaluateOnNewDocument', { source: `(() => {
  const FAKE = ${JSON.stringify(fake)};
  let Real = null;
  function Fake(opts) { this.h = {}; this.rec = null; this.sid = 'test'; }
  Fake.prototype.on = function (e, f) { this.h[e] = f; };
  Fake.prototype.unlock = async function () { return { me: { name: 'Test' }, contacts: FAKE, can: [], push: { on: false } }; };
  Fake.prototype.ask = async function (what, o) {
    if (what === 'history') return { msgs: [], more: false };
    if (what === 'contactDetails') return { contact: FAKE.find(c => c.id === o.cid), safety: '12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890', sealId: 'sealchat:' + 'a'.repeat(55) + 'd:' + 'AB'.repeat(20), theirName: '', nick: '' };
    return {};
  };
  Fake.prototype.lock = Fake.prototype.stop = function () {};
  Object.defineProperty(window, 'SCClient', { configurable: true,
    set(v) { Real = v; Fake.parsePair = v.parsePair; }, get() { return Real ? Fake : undefined; } });
})();` });

// a saved pairing, so the page goes straight to the PIN screen
await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
await send('Page.navigate', { url: base });
await wait(1500);
await js(`new Promise((res, rej) => { const r = indexedDB.open('sealchat-web', 1); r.onupgradeneeded = () => r.result.createObjectStore('kv');
  r.onsuccess = () => { const t = r.result.transaction('kv', 'readwrite'); t.objectStore('kv').put({ name: 'Test phone', key: null, keyRaw: Array(32).fill(1) }, 'device'); t.oncomplete = () => res(true); t.onerror = () => rej(t.error); }; })`);
await send('Page.reload'); await wait(1500);
ok('PIN screen', await until(`!document.getElementById('scrLock').classList.contains('hidden')`),
  JSON.stringify(await js(`[...document.querySelectorAll('[id^=scr]')].filter(e => !e.classList.contains('hidden')).map(e => e.id).join() + ' / SCClient=' + typeof SCClient + ' / ' + document.body.innerText.slice(0, 160)`)) + ' errs: ' + errs.join(' | '));
await js(`document.getElementById('lkPin').value = '123456'; document.getElementById('lkForm').requestSubmit(); true`);
ok('chat list', await until(`!document.getElementById('scrMain').classList.contains('hidden') && document.querySelectorAll('.contact').length === 4`));
ok('mark for a proven Seal ID', await js(`!!document.querySelector('.contact[data-id="c-ok"] img.sid-mark[src="img/sealid.svg"]')`));
ok('mark title names the Seal ID + proofs', await js(`/id\\.example\\.com.*GitHub alexrivera/.test(document.querySelector('.contact[data-id="c-ok"] .sid-mark').title)`));
ok('warning mark for a replaced Seal ID', await js(`!!document.querySelector('.contact[data-id="c-warn"] .sid-mark.warn')`));
ok('no mark when not proven / none', await js(`!document.querySelector('.contact[data-id="c-bad"] .sid-mark') && !document.querySelector('.contact[data-id="c-none"] .sid-mark')`));
ok('Seal ID logo loads', await js(`(() => { const i = document.querySelector('.contact img.sid-mark'); return i && i.complete && i.naturalWidth > 0; })()`));
await shot('scweb-list');

const openC = async cid => { await js(`document.querySelector('.contact[data-id="${cid}"]').click(); true`); await wait(600);
  return js(`(() => { const p = document.getElementById('chSealId'); return { hidden: p.classList.contains('hidden'), visible: p.offsetWidth > 0, w: p.offsetWidth, cls: p.className, text: p.textContent, title: p.title, nameCut: document.getElementById('chName').scrollWidth > document.getElementById('chName').clientWidth }; })()`); };
let h = await openC('c-ok');
ok('header pill: proven (logo only on a phone, name not cut)', !h.hidden && h.visible && h.w < 40 && /\bok\b/.test(h.cls) && h.text === 'id.example.com' && !h.nameCut, JSON.stringify(h));
await shot('scweb-chat-ok');
await js(`document.getElementById('btnInfo').click(); true`);
ok('contact page Seal ID section', await until(`!document.getElementById('ctSealId').classList.contains('hidden') && /Proven/.test(document.getElementById('ctSidBody').textContent)`));
ok('section lists the proofs and domains', await js(`/GitHub: alexrivera/.test(document.getElementById('ctSidBody').textContent) && /Their domains: example\\.com/.test(document.getElementById('ctSidBody').textContent)`));
ok('Seal ID link opens outside', await js(`(() => { const a = document.querySelector('#ctSidBody a'); return a && a.target === '_blank' && /noopener/.test(a.rel) && a.href === 'https://id.example.com/'; })()`));
await js(`document.getElementById('ctSealId').scrollIntoView({ block: 'center' }); true`); await wait(300);
await shot('scweb-contact-ok');
await js(`document.querySelector('#pgContact [data-close]').click(); true`); await wait(500);
h = await openC('c-warn');
ok('header pill: changed', /\bwarn\b/.test(h.cls) && /Seal ID changed/.test(h.text), JSON.stringify(h));
await js(`document.getElementById('btnInfo').click(); true`);
ok('contact page warns about the change', await until(`/Changed/.test(document.getElementById('ctSidBody').textContent) && /on your computer/.test(document.getElementById('ctSidBody').textContent)`));
await js(`document.querySelector('#pgContact [data-close]').click(); true`); await wait(500);
h = await openC('c-bad');
ok('header pill: not proven', /\bbad\b/.test(h.cls) && h.text === 'Seal ID not proven' && !h.visible, JSON.stringify(h));
h = await openC('c-none');
ok('no pill (older Seal Chat sends no Seal ID)', h.hidden);
await js(`document.getElementById('btnInfo').click(); true`); await wait(600);
ok('no Seal ID section without one', await js(`document.getElementById('ctSealId').classList.contains('hidden')`));
const sw = await js(`document.documentElement.scrollWidth`);
ok('no sideways scrolling on a phone', sw <= 390, String(sw));
ok('no script errors', errs.length === 0, errs.join(' | '));
console.log(fails ? fails + ' FAILED' : 'all Seal Chat Web Seal ID checks passed');
ws.close(); done(fails ? 1 : 0);
