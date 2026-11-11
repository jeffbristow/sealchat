// Seal Chat 1.11.0 UI test: the Seal ID mark (contact list), pill (chat header) and banner,
// drawn for example contacts in each state. Throwaway profile (SEALCHAT_DATA_DIR); no Tor needed.
//   npm run test:sealid-ui            (screenshots: node test/sealid-ui-test.mjs <folder>)
import { spawn } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = process.argv[2] || null;
const data = tmpdir() + '/sealchat-sidui-' + Date.now();
mkdirSync(data, { recursive: true });
const electron = require('electron');
const proc = spawn(electron, [root, '--remote-debugging-port=19341'], { env: { ...process.env, SEALCHAT_DATA_DIR: data }, stdio: 'ignore' });
const wait = ms => new Promise(r => setTimeout(r, ms));
const kill = () => { try { proc.kill(); } catch {} };
setTimeout(() => { console.log('TIMEOUT'); kill(); process.exit(2); }, 180000);
let fails = 0;
const ok = (n, c, x = '') => { if (!c) { fails++; console.log('FAIL', n, x); } else console.log('  ok', n); };

let ws;
for (let i = 0; i < 80 && !ws; i++) { try { const t = await (await fetch('http://127.0.0.1:19341/json')).json(); const p = t.find(x => x.type === 'page' && /index\.html/.test(x.url)); if (p) ws = new WebSocket(p.webSocketDebuggerUrl); } catch {} await wait(500); }
if (!ws) { console.log('no window'); kill(); process.exit(1); }
if (ws.readyState !== 1) await new Promise(r => ws.addEventListener('open', r));
let id = 0; const pending = new Map(); const errors = [];
ws.addEventListener('message', e => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  if (m.method === 'Runtime.exceptionThrown') errors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text); });
const send = (method, params = {}) => new Promise(r => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const js = async expr => { const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true }); return r.result.result ? r.result.result.value : undefined; };
const shot = async name => { const s = await send('Page.captureScreenshot', { format: 'png' }); out && writeFileSync(out + '/' + name + '.png', Buffer.from(s.result.data, 'base64')); };
const until = async (expr, ms) => { const end = Date.now() + ms; while (Date.now() < end) { if (await js(expr)) return true; await wait(500); } return false; };
await send('Runtime.enable'); await send('Page.enable');
await send('Emulation.setDeviceMetricsOverride', { width: 1100, height: 720, deviceScaleFactor: 1, mobile: false });
await wait(3000);

// a throwaway key, to reach the main screen
await js(`document.querySelector('[data-step=stCreate]').click()`);
await wait(500);
await js(`(() => { const s = (id, v) => { const e = document.getElementById(id); e.value = v; e.dispatchEvent(new Event('input')); }; s('newName', 'UI Test'); s('newPass', 'uitest-pass-123'); s('newPass2', 'uitest-pass-123'); document.getElementById('newGo').click(); })()`);
ok('main screen', await until(`!document.getElementById('mainScreen').classList.contains('hidden')`, 60000));
await wait(1500);

// example contacts, one per Seal ID state
const now = Date.now();
const base = { status: 'accepted', fp: 'AB'.repeat(20), lastAt: now - 60000, lastText: 'See you tomorrow', lastDir: 'in', unread: 0 };
const fake = [
  { ...base, id: 'c-ok', name: 'Alex Rivera', verified: true, lastAt: now - 1000,
    sealid: { url: 'https://id.example.com', ok: true, how: 'same-key', name: 'Alex Rivera', checked: now - 3 * 3600e3,
      proofs: [{ service: 'github', handle: 'alexrivera', status: 'verified' }, { service: 'x', handle: 'alex_rivera', status: 'verified' }, { service: 'dns', handle: 'example.com', status: 'verified' }] } },
  { ...base, id: 'c-warn', name: 'Sam Chen', lastAt: now - 2000,
    sealid: { url: 'https://id.samchen.dev', ok: true, warning: 'Its key or history no longer matches what this PC saw before.', checked: now - 600e3, proofs: [] } },
  { ...base, id: 'c-bad', name: 'Jordan Lee', lastAt: now - 3000,
    sealid: { url: 'https://jordan.example.org/id', ok: false, why: 'This Seal ID has no Seal Chat proof for this contact.', checked: now - 7200e3, proofs: [] } },
  { ...base, id: 'c-wait', name: 'Taylor Kim', lastAt: now - 4000, sealid: { url: 'https://id.taylor.example', ok: false, checked: 0, proofs: [] } },
  { ...base, id: 'c-none', name: 'Morgan Diaz', lastAt: now - 5000, sealid: null },
];
await js(`contacts = ${JSON.stringify(fake)}; renderContacts(); true`);
ok('mark for a proven Seal ID', await js(`!!document.querySelector('.contact[data-id="c-ok"] img.sid-mark[src="sealid.svg"]')`));
ok('mark title names the Seal ID and proofs', await js(`/id\\.example\\.com.*GitHub alexrivera/.test(document.querySelector('.contact[data-id="c-ok"] .sid-mark').title)`));
ok('warning mark for a replaced Seal ID', await js(`!!document.querySelector('.contact[data-id="c-warn"] .sid-mark.warn')`));
ok('no mark when not proven / checking / none', await js(`['c-bad','c-wait','c-none'].every(i => !document.querySelector('.contact[data-id="' + i + '"] .sid-mark'))`));

const head = async (cid) => js(`(() => { currentId = ${JSON.stringify(cid)}; document.getElementById('emptyPane').classList.add('hidden'); document.getElementById('chatPane').classList.remove('hidden'); renderContacts(); renderChatHead(contacts.find(c => c.id === currentId)); const p = document.getElementById('chSealId'); return { hidden: p.classList.contains('hidden'), cls: p.className, text: p.textContent, title: p.title, banner: document.getElementById('chBanner').className + '|' + document.getElementById('chBanner').textContent }; })()`);
let h = await head('c-ok');
ok('header pill: proven', !h.hidden && /\bok\b/.test(h.cls) && h.text === 'id.example.com', JSON.stringify(h));
ok('no banner for a proven Seal ID', /hidden/.test(h.banner));
await wait(300); await shot('sc-sid-ok');
h = await head('c-warn');
ok('header pill: changed', /\bwarn\b/.test(h.cls) && /Seal ID changed/.test(h.text), JSON.stringify(h));
ok('banner warns about the change', /bad/.test(h.banner) && /changed/.test(h.banner) && /Details/.test(h.banner), h.banner);
await wait(300); await shot('sc-sid-warn');
h = await head('c-bad');
ok('header pill: not proven', /\bbad\b/.test(h.cls) && h.text === 'Seal ID not proven' && /no Seal Chat proof/.test(h.title), JSON.stringify(h));
h = await head('c-wait');
ok('header pill: checking', /\bchecking\b/.test(h.cls) && /checking/.test(h.text), JSON.stringify(h));
h = await head('c-none');
ok('no pill without a Seal ID', h.hidden);
// clicking the pill opens the details (the example contact isn't in the store, so the app answers with an error toast)
await head('c-ok');
await js(`document.getElementById('chSealId').click(); true`);
ok('pill click asks for the contact details', await until(`!!document.querySelector('.toast') || !!document.getElementById('cdSealId')`, 5000));
ok('no script errors', errors.length === 0, errors.join(' | '));
console.log(fails ? fails + ' FAILED' : 'all Seal ID UI checks passed');
ws.close(); kill(); process.exit(fails ? 1 : 0);
