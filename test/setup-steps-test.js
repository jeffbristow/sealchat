/* =====================================================================
 * Seal Chat — setup-steps-test.js   (1.9.4)
 * The first-start screen (index.html #setupScreen) has one <div id="st…">
 * per step. 1.9.0–1.9.3: setupStep() in app.js switched steps from a
 * hard-coded list that missed "stLink", so "Link to my Seal Chat on another
 * device" showed an empty screen. This checks, for EVERY welcome button,
 * that its step exists and is the only one shown after setupStep() — with
 * the real setupStep() from app.js run against the real step list.
 * ===================================================================== */
const fs = require('fs');
const path = require('path');

const R = path.join(__dirname, '..', 'src', 'renderer');
const html = fs.readFileSync(path.join(R, 'index.html'), 'utf8');
const app = fs.readFileSync(path.join(R, 'app.js'), 'utf8');
let pass = 0, fail = 0;
const ok = (c, name) => { if (c) { pass++; console.log('  ✓ ' + name); } else { fail++; console.log('  ✗ ' + name); } };

// the setup card and its step divs (direct children with id="st…")
const card = html.slice(html.indexOf('id="setupScreen"'), html.indexOf('</section>', html.indexOf('id="setupScreen"')));
const steps = [...card.matchAll(/<div id="(st[A-Za-z]+)"( class="hidden")?/g)].map(m => ({ id: m[1], hidden: !!m[2] }));
const buttons = [...card.matchAll(/data-step="(st[A-Za-z]+)"/g)].map(m => m[1]);
console.log('setup steps:');
ok(steps.length >= 5 && steps.some(s => s.id === 'stLink'), 'steps on the page: ' + steps.map(s => s.id).join(', '));
ok(buttons.length >= 4, 'welcome buttons: ' + buttons.join(', '));

// the real setupStep() from app.js, against a small stand-in for the page
const src = /function setupStep\(id\) \{[\s\S]*?\n\}/.exec(app);
ok(!!src, 'setupStep() found in app.js');
const els = new Map(steps.map(s => {
  const cls = new Set(s.hidden ? ['hidden'] : []);
  return [s.id, { id: s.id, cls, classList: { toggle: (c, on) => (on ? cls.add(c) : cls.delete(c)), contains: c => cls.has(c) }, querySelector: () => null }];
}));
const document = { querySelectorAll: sel => (/#setupScreen/.test(sel) ? [...els.values()] : []) };
const $ = id => els.get(id) || { classList: { toggle() {} }, querySelector: () => null };
const setupStep = new Function('document', '$', 'setTimeout', src[0] + '\nreturn setupStep;')(document, $, () => {});

for (const target of [...buttons, 'stWelcome']) {
  setupStep(target);
  const shown = [...els.values()].filter(e => !e.cls.has('hidden')).map(e => e.id);
  ok(shown.length === 1 && shown[0] === target, `"${target}": only that step is shown (${shown.join(', ') || 'nothing'})`);
}

console.log(`\nSetup step tests: ${pass} passed${fail ? ', ' + fail + ' FAILED' : ''}`);
process.exit(fail ? 1 : 0);
