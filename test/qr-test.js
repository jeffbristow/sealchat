/* Seal Chat 1.2.0 self-test: QR codes (generator ↔ decoder round trip).   node test/qr-test.js */
const assert = require('assert');
const QRCode = require('qrcode');
const jsQR = require('jsqr');
const { parseId, formatId } = require('../src/main/peer');
let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };

/** Draws a QR code into an RGBA buffer (scale px per module, 4-module white border). */
function render(text, scale = 6, noise = 0) {
  const q = QRCode.create(text, { errorCorrectionLevel: 'M' });
  const n = q.modules.size, size = (n + 8) * scale;
  const px = new Uint8ClampedArray(size * size * 4).fill(255);
  const finder = (x, y) => (x < 9 && y < 9) || (x > n - 10 && y < 9) || (x < 9 && y > n - 10);
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (!!q.modules.get(y, x) !== (!finder(x, y) && Math.random() < noise)) {
    for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) { const i = (((y + 4) * scale + dy) * size + (x + 4) * scale + dx) * 4; px[i] = px[i + 1] = px[i + 2] = 0; }
  }
  return { px, size, version: q.version };
}

const id = formatId('abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwd', 'F3BA4AF914A2BFB4C47DC9BCB7B0E950EA7A7BE2');
const r = render(id);
ok(r.version <= 8, `a Seal Chat ID fits in a small QR code (version ${r.version})`);
const d = jsQR(r.px, r.size, r.size);
ok(d && d.data === id, 'the scanner reads the ID back exactly');
ok(parseId(d.data).fp === 'F3BA4AF914A2BFB4C47DC9BCB7B0E950EA7A7BE2', 'and it is a valid Seal Chat ID');
const dull = render(id, 6);
for (let i = 0; i < dull.px.length; i += 4) { const v = dull.px[i] ? 190 : 70; dull.px[i] = v; dull.px[i + 1] = v - 10; dull.px[i + 2] = v + 15; }
ok((jsQR(dull.px, dull.size, dull.size) || {}).data === id, 'reads a dull, low-contrast picture (like a phone photo of a screen)');
const small = render(id, 3);
ok((jsQR(small.px, small.size, small.size) || {}).data === id, 'reads from a small picture (3 px per square)');
console.log(`\nQR tests: ${passed} passed`);
