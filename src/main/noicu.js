/* =====================================================================
 * Seal Chat — noicu.js   (regular expressions that also work on Android, 1.9.1)
 * ---------------------------------------------------------------------
 * The Android app's Node.js (nodejs-mobile 18) can't compile Unicode
 * property escapes (\p{…}) — a regex LITERAL with one makes the whole file
 * fail to load ("Invalid property name"), and Seal Chat never starts.
 * So Node-side code never writes them as literals; it asks here instead:
 * the \p{…} pattern where the runtime supports it (desktop), otherwise the
 * same character class written out as explicit ranges (noicu-ranges.js,
 * made by build/gen-noicu.js from the desktop's Unicode data).
 *
 * Also patches openpgp (it has one such literal, in util.isEmailAddress):
 * build/patch-openpgp.js on the desktop, and the Android app on each update.
 * test/noicu-test.js fails the build if a \p{…} literal appears again.
 * (Thanks to the developer who found the crash and wrote the first fix.)
 *
 * Sections:
 *   1. pick(): the \p{…} pattern, or its explicit fallback
 *   2. The regexes Seal Chat uses
 *   3. Patching openpgp's source
 * ===================================================================== */
'use strict';
const R = require('./noicu-ranges');

/* ---------- 1. pick ---------- */
function pick(withProps, plain, flags = 'u') {
  try { return new RegExp(withProps, flags); }
  catch { return new RegExp(plain, flags); }
}
const supported = (() => { try { new RegExp('\\p{L}', 'u'); return true; } catch { return false; } })();

/* ---------- 2. THE REGEXES ---------- */
// peer.js cleanEmoji(): one emoji (with skin tone / joiners) and at least one pictograph
const EMOJI_ONLY = pick('^[\\p{Extended_Pictographic}\\p{Emoji_Component}\\u200d\\ufe0f\\u20e3]+$', `^[${R.EMOJI}]+$`);
const EMOJI_PICT = pick('\\p{Extended_Pictographic}', `[${R.PICT}]`);
// openpgp util.isEmailAddress (source strings — used in the patch below)
const EMAIL_PROPS = '^[^\\p{C}\\p{Z}@<>\\\\]+@[^\\p{C}\\p{Z}@<>\\\\]+[^\\p{C}\\p{Z}\\p{P}]$';
const EMAIL_PLAIN = `^[${R.EMAIL_LOCAL}]+@[${R.EMAIL_LOCAL}]+[${R.EMAIL_LAST}]$`;

/* ---------- 3. PATCHING OPENPGP ---------- */
const MARK = '__scEmailRe';
const EMAIL_LITERAL = '/' + EMAIL_PROPS + '/u';
/** The code put at the top of openpgp: the email regex built the safe way. */
const emailInit = () => `var ${MARK}=(function(){try{return new RegExp(${JSON.stringify(EMAIL_PROPS)},"u")}catch(_){return new RegExp(${JSON.stringify(EMAIL_PLAIN)},"u")}})();`;

/**
 * openpgp's Node build (dist/node/openpgp.cjs or .min.cjs) as text → patched text.
 * Returns null when it's already patched, throws when it doesn't look as expected.
 */
function patchOpenpgpSource(src) {
  if (src.includes(MARK)) return null;
  const n = src.split(EMAIL_LITERAL).length - 1;
  if (n !== 1) throw new Error(`openpgp: expected the email regex once, found ${n} (a different openpgp version?)`);
  const strict = /^(\s*(?:\/\*[\s\S]*?\*\/\s*)?)(['"])use strict\2;/.exec(src);
  if (!strict) throw new Error('openpgp: "use strict" header not found');
  const at = strict[0].length;
  return src.slice(0, at) + emailInit() + src.slice(at).replace(EMAIL_LITERAL, () => ' ' + MARK);   // (the minified build has "return/…/u.test(e)": keep a space)
}
/** Patches the openpgp in a node_modules folder (both Node builds). Returns the files changed. */
function patchOpenpgp(nodeModules) {
  const fs = require('fs'), path = require('path');
  const changed = [];
  for (const f of ['openpgp.cjs', 'openpgp.min.cjs']) {
    const file = path.join(nodeModules, 'openpgp', 'dist', 'node', f);
    if (!fs.existsSync(file)) continue;
    const out = patchOpenpgpSource(fs.readFileSync(file, 'utf8'));
    if (out === null) continue;
    fs.writeFileSync(file, out);
    changed.push(file);
  }
  return changed;
}

module.exports = { pick, supported, EMOJI_ONLY, EMOJI_PICT, EMAIL_PROPS, EMAIL_PLAIN, patchOpenpgpSource, patchOpenpgp, MARK };
