/* Seal Chat 1.0.1 self-test: PCs whose clocks disagree.   node test/clock-test.js */
const assert = require('assert');
const openpgp = require('openpgp');
const { Identity, describePublic } = require('../src/main/identity');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };

(async () => {
  const ahead = new Date(Date.now() + 10 * 60e3);   // PC A's clock: 10 minutes fast
  // a key made on PC A just now (its timestamps are "in the future" for PC B)
  const { privateKey: aKey } = await openpgp.generateKey({ type: 'curve25519', userIDs: [{ name: 'PC A' }], passphrase: 'pass-aaaa-1', format: 'armored', date: ahead });
  const A = await new Identity().load(aKey, 'pass-aaaa-1');
  const B = await new Identity().load(await Identity.generate({ name: 'PC B', passphrase: 'pass-bbbb-1' }), 'pass-bbbb-1');

  ok((await describePublic(A.pubArmored)).canEncrypt, 'PC B accepts a key made on a PC whose clock is 10 min ahead (was: "key cannot encrypt")');
  ok((await Identity.inspectPrivate(aKey, 'pass-aaaa-1')).name === 'PC A', 'that key can also be imported on PC B');

  // PC A signs + encrypts with ITS clock (10 min ahead)
  const fromA = Buffer.from(await openpgp.encrypt({
    message: await openpgp.createMessage({ text: JSON.stringify({ k: 'text', text: 'hi from A' }) }),
    encryptionKeys: B.pub, signingKeys: A.priv, format: 'binary', date: ahead })).toString('base64');
  const r = await B.open(fromA, A.pubArmored);
  ok(r.valid && r.obj.text === 'hi from A', 'PC B verifies a message signed on the fast PC');

  const sig = Buffer.from(await openpgp.sign({ message: await openpgp.createMessage({ text: 'auth-text' }), signingKeys: A.priv, detached: true, format: 'binary', date: ahead })).toString('base64');
  ok(await B.verifyText('auth-text', sig, A.pubArmored), 'connection proof from the fast PC is accepted');

  const toA = await B.sealFor(A.pubArmored, { k: 'text', text: 'hi from B' });
  ok((await A.open(toA, B.pubArmored)).obj.text === 'hi from B', 'PC B can encrypt to the fast PC\'s brand-new key');

  // still strict where it matters
  const C = await new Identity().load(await Identity.generate({ name: 'C', passphrase: 'pass-cccc-1' }), 'pass-cccc-1');
  ok(!(await B.open(fromA, C.pubArmored)).valid, 'a message is still refused if signed by someone else');
  ok(!(await B.verifyText('other-text', sig, A.pubArmored)), 'a proof over different text is still refused');
  const far = new Date(Date.now() + 5 * 864e5);
  const { privateKey: farKey } = await openpgp.generateKey({ type: 'curve25519', userIDs: [{ name: 'Far' }], passphrase: 'pass-ffff-1', format: 'armored', date: far });
  ok(!(await describePublic((await openpgp.readPrivateKey({ armoredKey: farKey })).toPublic().armor())).canEncrypt, 'a clock 5 days off is still refused (limit is 2 days)');
  const { privateKey: expKey } = await openpgp.generateKey({ type: 'curve25519', userIDs: [{ name: 'Old' }], passphrase: 'pass-eeee-1', format: 'armored', date: new Date(Date.now() - 10 * 864e5), keyExpirationTime: 86400 });
  ok(!(await describePublic((await openpgp.readPrivateKey({ armoredKey: expKey })).toPublic().armor())).canEncrypt, 'an expired key is still refused');
  const nk = await openpgp.readPrivateKey({ armoredKey: await Identity.generate({ name: 'New', passphrase: 'pass-nnnn-1' }) });
  ok(nk.getCreationTime().getTime() < Date.now() - 23 * 3600e3, 'new keys are dated a day back, so slower clocks accept them at once');

  console.log(`\nClock tests: ${passed} passed`);
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
