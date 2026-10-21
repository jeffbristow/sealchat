/* Seal Chat 1.9.1 self-test: NO \p{…} REGEX LITERALS in code the Android app runs.
 * The Android app's Node.js (nodejs-mobile) can't compile Unicode property
 * escapes; one regex literal with \p{…} makes its whole file fail to load and
 * Seal Chat never starts on the phone. Desktop Node (and test:node18) can't
 * show that, so this checks it directly:
 *   1. every Node-side file (src/main + production node_modules) is parsed;
 *      a regex literal with \p{…} or \P{…} fails the test
 *   2. noicu.js's explicit ranges match the \p{…} originals
 *   3. openpgp and Seal Chat's emoji check work when \p{…} is NOT supported
 *   node test/noicu-test.js [nodejs-project folder]   (the Android app's, to check it too)
 * Runs in npm test and before every update file is built (make-update.js). */
'use strict';
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { execFileSync } = require('child_process');
const acorn = require('acorn');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const root = path.join(__dirname, '..');
const target = process.argv[2] ? path.resolve(process.argv[2]) : null;

/* ---------- 1. scan ---------- */
function files(dir, skip, out = []) {
  let list = []; try { list = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of list) {
    const p = path.join(dir, e.name);
    if (skip(p, e)) continue;
    if (e.isDirectory()) files(p, skip, out);
    else if (/\.(c?js)$/.test(e.name)) out.push(p);
  }
  return out;
}
function badLiterals(file) {
  const src = fs.readFileSync(file, 'utf8');
  if (!/\\[pP]\{/.test(src)) return [];
  const found = [];
  const opts = { ecmaVersion: 'latest', allowHashBang: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, onToken: t => { if (t.type.label === 'regexp' && /\\[pP]\{/.test(t.value.pattern)) found.push(t.value.pattern.slice(0, 60)); } };
  try { acorn.parse(src, { ...opts, sourceType: 'script' }); }
  catch { try { found.length = 0; acorn.parse(src, { ...opts, sourceType: 'module' }); } catch (e) { return ['(could not parse: ' + e.message + ')']; } }
  return found;
}
// browser-only builds and ES-module copies are never loaded by Node's require()
const notNode = p => /node_modules[\\/]openpgp[\\/]dist[\\/](?!node(?:[\\/]|$))/.test(p) || /\.mjs$/.test(p) || /[\\/](esm|test|tests|example|examples|bin)[\\/]/.test(p) || /[\\/]\.bin$/.test(p);
const prodModules = () => {
  try { return execFileSync('npm', ['ls', '--omit=dev', '--all', '--parseable'], { cwd: root, encoding: 'utf8' }).split(/\r?\n/).filter(l => l && l !== root && /node_modules/.test(l)); }
  catch (e) { return String(e.stdout || '').split(/\r?\n/).filter(l => l && l !== root && /node_modules/.test(l)); }
};
console.log('no \\p{…} regex literals (Android):');
const scanList = [];
if (target) {
  // the Android app's nodejs-project: everything Node loads (not the screens, which run in the WebView)
  scanList.push(...files(target, p => notNode(p) || /[\\/]app[\\/]src[\\/]renderer$/.test(p) || /^[\\/]?ui$/.test(path.relative(target, p))));
} else {
  scanList.push(...files(path.join(root, 'src', 'main'), () => false));
  for (const m of prodModules()) scanList.push(...files(m, (p, e) => notNode(p) || (e.isDirectory() && e.name === 'node_modules')));
}
const bad = [];
for (const f of scanList) for (const lit of badLiterals(f)) bad.push(path.relative(target || root, f) + ': /' + lit + '…/');
if (bad.length) console.log(bad.map(b => '    ✗ ' + b).join('\n'));
ok(!bad.length, `${scanList.length} Node-side files parsed: no \\p{…} regex literal (they crash the Android app)`);

/* ---------- 2. the fallbacks match the originals ---------- */
const N = require('../src/main/noicu');
const pairs = [
  ['email', new RegExp(N.EMAIL_PROPS, 'u'), new RegExp(N.EMAIL_PLAIN, 'u')],
  ['emoji', new RegExp('^[\\p{Extended_Pictographic}\\p{Emoji_Component}\\u200d\\ufe0f\\u20e3]+$', 'u'), new RegExp(`^[${require('../src/main/noicu-ranges').EMOJI}]+$`, 'u')],
  ['pictograph', new RegExp('\\p{Extended_Pictographic}', 'u'), new RegExp(`[${require('../src/main/noicu-ranges').PICT}]`, 'u')]
];
const samples = ['user@example.com', 'a@b.c', 'a@b.', 'a b@c.d', '<a@b.c>', 'ü@ö.de', 'x@y.com!', 'a@@b.c', '用户@例子.广告', 'a​@b.c', '👍', '👍🏽', '👨‍👩‍👧', '❤️', '1️⃣', '🇺🇸', 'a', '#', 'hi👍', '', '©'];
let seed = 7; const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
for (let i = 0; i < 60000; i++) {
  let s = ''; const n = 1 + (rnd() * 6 | 0);
  for (let j = 0; j < n; j++) { const r = rnd(); s += r < .3 ? '@' : r < .5 ? String.fromCodePoint(0x1F300 + (rnd() * 0x700 | 0)) : String.fromCodePoint(rnd() < .5 ? 32 + (rnd() * 300 | 0) : (rnd() * 0x2FFFF | 0) % 0xD800); }
  samples.push(s);
}
let diff = 0;
const ru = require('../src/main/noicu-ranges').unicode;
if (ru === process.versions.unicode) {
  for (const [, a, b] of pairs) for (const s of samples) if (a.test(s) !== b.test(s)) diff++;
  ok(diff === 0, `the explicit ranges match the \\p{…} originals (${samples.length * pairs.length} comparisons, Unicode ${ru})`);
} else console.log(`  · the ranges are from Unicode ${ru}, this runtime has ${process.versions.unicode}: comparison skipped here (npm run test:electron compares them)`);

/* ---------- 3. as on Android: \p{…} not supported ---------- */
const nm = target ? path.join(target, 'node_modules') : path.join(root, 'node_modules');
const appMain = target ? path.join(target, 'app', 'src', 'main') : path.join(root, 'src', 'main');
const child = `
  const Orig = RegExp;
  const NoProps = function (p, f) { if (/\\\\[pP]\\{/.test(String(p && p.source !== undefined ? p.source : p))) throw new SyntaxError('Invalid property name'); return new Orig(p, f); };
  NoProps.prototype = Orig.prototype; Object.setPrototypeOf(NoProps, Orig);
  global.RegExp = NoProps;
  module.paths.unshift(${JSON.stringify(nm)});
  const N = require(${JSON.stringify(path.join(appMain, 'noicu.js'))});
  if (N.supported) throw new Error('simulation failed');
  const { cleanEmoji } = require(${JSON.stringify(path.join(appMain, 'peer.js'))});
  const emo = ['👍', '👍🏽', 'a', 'hi👍'].map(cleanEmoji).join(',');
  const openpgp = require('openpgp');
  openpgp.generateKey({ type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'Ann', email: 'ann@example.com' }], format: 'armored' })
    .then(() => openpgp.generateKey({ type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'Bad', email: 'not an email' }], format: 'armored' }).then(() => 'accepted', () => 'refused'))
    .then(bad => { console.log(JSON.stringify({ emo, bad })); });
`;
const r = JSON.parse(execFileSync(process.execPath, ['-e', child], { encoding: 'utf8' }).trim().split('\n').pop());
ok(r.emo === '👍,👍🏽,,', 'without \\p{…} support: the emoji check still works (' + r.emo + ')');
ok(r.bad === 'refused', 'without \\p{…} support: openpgp loads, makes a key with an email, and still refuses a bad email');

console.log(`\n${passed} passed`);
