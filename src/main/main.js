/* =====================================================================
 * Seal Chat — main.js   (the app's main process, 1.5.0)
 * ---------------------------------------------------------------------
 * Starts everything and connects the window (UI) to the chat engine.
 *
 * Sections:
 *   1. Startup: one copy only, data folder, Windows protection
 *   2. Window, tray icon, taskbar
 *   3. Tor + chat engine lifecycle
 *   4. Notifications
 *   5. IPC: the calls the window may make (all others are refused)
 *      5a. app / updates   5b. setup + identity   5c. me + Tor
 *      5d. contacts        5e. chats              5f. settings
 *      5g. app lock        5h. backup / export / reset
 *      5i. files (1.1.0): send, download, open, save, storage
 *      5k. QR codes + profile pictures (1.2.0)
 *      5l. automatic update checks (1.3.0) — see updater.js
 *      5m. web access (1.4.0) — use Seal Chat from a phone browser,
 *          see webaccess.js
 *   5j. scfile:// — shows photos / plays audio + video straight from the
 *       encrypted store (1.1.0)
 *   6. App lock timer (idle + Windows lock)
 *   7. Quit
 *   8. Web access (1.4.0): what the web interface may see and do
 *   9. macOS (1.5.0): app menu (copy/paste shortcuts), dock, menu-bar icon
 * ===================================================================== */

const { app, BrowserWindow, ipcMain, dialog, shell, safeStorage, clipboard, ClipboardItem, Menu, Tray, nativeImage, Notification, powerMonitor, protocol } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { Readable } = require('stream');
const { Store } = require('./store');
const { TorService } = require('./tor');
const { Identity, describePublic, prettyFp, safetyNumber } = require('./identity');
const { Peer, parseId, fmtSize, cleanAvatar } = require('./peer');
const QRCode = require('qrcode');
const { Updater } = require('./updater');
const { WebAccess } = require('./webaccess');
const { WebFiles, WEB_FILE_MAX } = require('./webfiles');   // 1.7.0: files in Seal Chat Web
const names = require('./names');                            // 1.8.0: name@domain
const invites = require('./invites');                        // 1.8.0: invite codes
const linking = require('./linking');                        // 1.9.0: linking another device to your ID
const jsQR = require('jsqr');
const { FileVault, isRisky, safeName } = require('./files');
const lockLib = require('./applock');
const { createBackup, readBackup } = require('./backup');
const { readPackageJson, fs: ofs } = require('./asarinfo');

/* =================================================================
 * 1. STARTUP
 * ================================================================= */
app.setName('Seal Chat');
app.setAppUserModelId('com.sealchat.app');            // Windows notifications show "Seal Chat"
if (process.env.SEALCHAT_DATA_DIR) app.setPath('userData', process.env.SEALCHAT_DATA_DIR); // developers / tests
const IS_MAC = process.platform === 'darwin';
const IS_ANDROID = process.platform === 'android';   // 1.9.0: the Android app runs this same file (Electron answered by its shim; it takes the same update files)
void IS_ANDROID;
// started at sign-in → start in the tray / menu bar (Windows/Linux pass --hidden; macOS reports it)
const startHidden = process.argv.includes('--hidden') || (IS_MAC && (() => { try { return app.getLoginItemSettings().wasOpenedAtLogin; } catch { return false; } })());
// 1.1.0: scfile:// lets the window show photos and play audio/video from the encrypted store
protocol.registerSchemesAsPrivileged([{ scheme: 'scfile', privileges: { standard: true, secure: true, stream: true, supportFetchAPI: true } }]);

if (!app.requestSingleInstanceLock()) { app.quit(); }
else app.on('second-instance', () => showWindow());

const VERSION = process.env.SEALCHAT_RUNNING_VERSION || app.getVersion();
let store, tor, peer, files, win = null, tray = null;
const OPEN_DIR = path.join(os.tmpdir(), 'Seal Chat open');   // decrypted copies for "Open" (emptied on start + quit)
const identity = new Identity();
let appLocked = false, lastActivity = Date.now(), quitting = false;
let peerStarting = null;

function protector() {
  const ok = safeStorage.isEncryptionAvailable();
  let weak = false;
  try { weak = process.platform === 'linux' && /basic_text|unknown/.test(safeStorage.getSelectedStorageBackend()); } catch { /* ignore */ }
  return {
    strong: ok && !weak,
    encrypt: b => safeStorage.encryptString(b.toString('base64')),
    decrypt: b => Buffer.from(safeStorage.decryptString(b), 'base64')
  };
}

const S = () => store.settings;
const lockCfg = () => S().appLock || null;
const lockEnabled = () => !!(lockCfg() && lockCfg().enabled);

/* =================================================================
 * 2. WINDOW, TRAY, TASKBAR
 * ================================================================= */
function createWindow(show = true) {
  const b = S().bounds || { width: 1080, height: 720 };
  win = new BrowserWindow({
    ...b, minWidth: 760, minHeight: 500, show: false,
    title: 'Seal Chat', backgroundColor: '#121418',
    icon: path.join(__dirname, '..', 'renderer', process.platform === 'win32' ? 'app-icon.ico' : 'icon.png'),
    autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true, spellcheck: true }
  });
  // Windows/Linux: no menu bar. macOS (1.5.0): a standard menu — it is what makes
  // ⌘C / ⌘V / ⌘A / ⌘Z / ⌘Q work there.
  Menu.setApplicationMenu(IS_MAC ? macMenu() : null);
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  win.once('ready-to-show', () => { if (show) { win.show(); if (S().maximized) win.maximize(); } });
  // links in chats open in the normal browser, never inside Seal Chat
  win.webContents.setWindowOpenHandler(({ url }) => { if (/^https?:/i.test(url)) shell.openExternal(url); return { action: 'deny' }; });
  win.webContents.on('will-navigate', e => e.preventDefault());
  win.webContents.on('context-menu', (e, p) => {
    const items = [];
    if (p.misspelledWord) { for (const s of p.dictionarySuggestions.slice(0, 5)) items.push({ label: s, click: () => win.webContents.replaceMisspelling(s) }); if (items.length) items.push({ type: 'separator' }); }
    if (p.isEditable) items.push({ role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' });
    else if (p.selectionText) items.push({ role: 'copy' });
    if (items.length) Menu.buildFromTemplate(items).popup();
  });
  const saveBounds = () => { if (!win || win.isDestroyed()) return; const max = win.isMaximized(); store.setSettings({ maximized: max, ...(max || win.isMinimized() ? {} : { bounds: win.getBounds() }) }); };
  win.on('resize', debounce(saveBounds, 500)); win.on('move', debounce(saveBounds, 500));
  win.on('focus', () => { win.flashFrame(false); send('focus'); });
  win.on('close', e => {
    if (quitting || S().closeToTray === false) return;
    e.preventDefault();
    win.hide();
    if (!S().trayHintShown) {
      store.setSettings({ trayHintShown: true });
      notify('Seal Chat is still running', IS_MAC ? 'It keeps receiving messages in the background. Quit it from the seal icon in the menu bar, or with ⌘Q.' : 'It keeps receiving messages in the background. Right-click the seal icon near the clock to quit.');
    }
  });
  win.on('closed', () => { win = null; });
  win.on('session-end', () => { quitting = true; if (store) store.flush(); });   // Windows sign-out / shutdown
}

function showWindow() {
  if (!win) createWindow(true);
  if (win.isMinimized()) win.restore();
  win.show(); win.focus();
}

function createTray() {
  // macOS (1.5.0): a black "template" icon the menu bar tints for light/dark mode
  const img = nativeImage.createFromPath(path.join(__dirname, '..', 'renderer', IS_MAC ? 'trayTemplate.png' : 'tray.png'));
  if (IS_MAC) img.setTemplateImage(true);
  tray = new Tray(img);
  tray.setToolTip('Seal Chat');
  tray.on('click', () => showWindow());
  updateTray();
}

function updateTray() {
  if (!tray || !peer) return;
  const c = peer.counts();
  const t = tor ? tor.status() : { ready: false };
  const state = t.ready ? (peer.running ? 'Online' : 'Starting…') : (t.summary || 'Offline');
  tray.setToolTip(`Seal Chat — ${state}${c.unread ? ` · ${c.unread} unread` : ''}${c.queued ? ` · ${c.queued} waiting to send` : ''}`);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Open Seal Chat', click: () => showWindow() },
    { label: state, enabled: false },
    { type: 'separator' },
    { label: 'Lock now', enabled: lockEnabled() && !appLocked, click: () => lockApp('locked from tray') },
    // 1.4.0: web access on/off from the tray
    { label: 'Web access (phone browser)', type: 'checkbox', checked: !!S().webEnabled, enabled: !!(web && store.vault.web && store.vault.web.box),
      click: m => { try { web.setEnabled(m.checked); } catch (e) { notify('Web access', e.message); } updateTray(); } },
    { type: 'separator' },
    { label: 'Quit Seal Chat', click: () => quitApp() }
  ]));
  if (win && !win.isDestroyed()) win.setTitle(c.unread ? `(${c.unread}) Seal Chat` : 'Seal Chat');
  if (IS_MAC && app.dock) app.dock.setBadge(c.unread ? String(c.unread) : '');   // 1.5.0: unread count on the dock icon
}

function send(type, data) { if (win && !win.isDestroyed()) win.webContents.send('evt', { type, data }); }

/* =================================================================
 * 3. TOR + CHAT ENGINE
 * ================================================================= */
function setupTor() {
  tor = new TorService({
    dataDir: path.join(app.getPath('userData'), 'tor'),
    resourcesPath: process.resourcesPath,
    bridges: S().bridges || [],
    lyrebirdPath: S().lyrebirdPath || null
  });
  tor.on('status', st => { send('tor', st); updateTray(); });
  // 1.6.0: a new installation gets the latest version straight away (section 5l-b); otherwise the usual check in ~1.5 min
  tor.on('ready', () => { startPeer(); if (firstRunPending()) firstRunUpdate(); else scheduleUpdateCheck(90e3); if (web) web.kick(); });
  tor.on('exit', async info => {
    // Tor stopped by itself: take the chat engine down too, so it re-publishes
    // your address when Tor is back
    try { if (peer) await peer.stop(); } catch { /* ignore */ }
    send('tor', { ...tor.status(), error: info.log.slice(-4).join('\n') });
    if (!quitting) setTimeout(() => startTor(), 10000);   // try again
  });
}

async function startTor() {
  try { await tor.start(); }
  catch (e) { console.error('tor:', e.message); send('tor', { ...tor.status(), error: e.message }); setTimeout(() => !quitting && !tor.proc && startTor(), 15000); }
}

/** Starts the chat engine once Tor is connected AND your key is unlocked. */
async function startPeer() {
  if (!tor.ready || !identity.unlocked || !store.vault.identity) return;
  if (peer.running) return;
  if (peerStarting) return peerStarting;
  peerStarting = (async () => {
    try { await peer.start(); send('me', meInfo()); setTimeout(() => syncMailbox().then(() => fetchMailbox()), 4000); if (web) setTimeout(() => web.shareNow(), 5000); setTimeout(() => recheckHandles().catch(() => {}), 60e3); }   // 1.8.0: mailbox, names · 1.9.3: web access to your other devices
    catch (e) { console.error('peer start:', e.message); send('tor', { ...tor.status(), error: 'Could not publish your address: ' + e.message }); }
    finally { peerStarting = null; updateTray(); }
  })();
  return peerStarting;
}

function setupPeer() {
  files = new FileVault(path.join(app.getPath('userData'), 'files'));
  files.cleanParts();
  peer = new Peer({ store, identity, tor, files, allowHttpMailbox: !!process.env.SEALCHAT_WEB_ALLOW_HTTP, log: l => console.log('[peer]', l),   // (http mailbox: developer tests only)
    webShare: () => (web ? web.shareable() : null) });                  // 1.9.3: a newly linked device gets web access too
  // 1.9.3: web access shared by your linked devices (webaccess.js section 9)
  peer.on('syncweb', w => { if (web) web.applyShared(w).then(() => updateTray()).catch(e => console.log('web access sync:', e.message)); });
  let webSibs = null;
  peer.on('devices', () => {
    if (!web) return;
    if (store.vault.unlinked) { web.forgetLocal('this device was removed from your ID'); return; }
    // a device was linked (or its address changed): make sure it has web access — only on a change, not every sync
    const k = peer.siblings().map(d => d.id + ':' + d.onion).join(',');
    if (k !== webSibs) { webSibs = k; web.shareNow(); }
  });
  peer.on('transfer', d => { send('transfer', d); webPushTransfer(d); });   // 1.7.0: also to Seal Chat Web
  peer.on('contacts', debounce(() => { send('contacts'); updateTray(); }, 100));
  peer.on('contacts', debounce(() => webPushContacts(), 1000));          // 1.4.0
  peer.on('contacts', debounce(() => { if (mbState.on || mbState.worker.on) sendMailboxStatus(); }, 1500));   // 1.8.1: "given to N of M contacts"
  peer.on('receipts', d => { send('receipts', d); webPushStates(d.contactId); });
  peer.on('status', () => send('me', meInfo()));
  // 1.8.0: a reaction (or a reply's quote) changed on a message → the window + phones redraw it
  peer.on('msgupdate', ({ contactId, msg }) => { send('msgupdate', { contactId, msg: forWindow(msg) }); if (web) web.push({ t: 'msg', cid: contactId, msg: webMsg(msg, contactId), update: true }); });
  peer.on('reacted', ({ contactId, msg, e }) => onReactionNotify(contactId, msg, e));
  peer.on('message', ({ contactId, msg, via }) => {
    send('message', { contactId, msg: forWindow(msg) });
    if (web) web.push({ t: 'msg', cid: contactId, msg: webMsg(msg, contactId) });   // 1.4.0
    updateTray();
    onIncomingNotify(contactId, msg, via);
  });
  peer.on('request', c => {
    send('request', { id: c.id });
    if (web) web.notify({ kind: 'request', name: c.name || '' });   // 1.6.0
    notify('New contact request', `${c.name || 'Someone'} wants to chat with you.`, () => { showWindow(); send('open', { contactId: c.id }); });
  });
  peer.on('invites', debounce(() => send('invites', peer.invites.list()), 100));             // 1.8.0
  peer.on('invite', e => {
    if (e.kind === 'used') notify(e.multi ? 'Invite code used' : 'Contact added', e.multi ? `${e.name || 'Someone'} used your invite code${e.label ? ' "' + e.label + '"' : ''} — accept their request to chat.` : `${e.name || 'Someone'} used your invite code${e.label ? ' "' + e.label + '"' : ''} and is now a contact.`, () => { showWindow(); send('open', { contactId: e.fp }); });
    if (e.kind === 'closed') notify('Invite code closed', `Your invite code${e.label ? ' "' + e.label + '"' : ''} was closed after 3 wrong tries. Make a new one if you still need it.`, () => showWindow());
  });
  // 1.9.0: your other devices
  peer.on('link', e => {
    send('link', e);
    if (e.kind === 'linked') notify('Device linked', `"${e.name}" is now linked to your Seal Chat ID. Your contacts and chats are being copied to it.`, () => showWindow());
  });
  peer.on('devices', debounce(() => { if (peer.running) send('devices', peer.devicesStatus()); }, 300));
  peer.on('settings', debounce(() => send('me', meInfo()), 300));
  peer.on('accepted', c => notify('Contact added', `${displayName(c)} accepted your request.`, () => { showWindow(); send('open', { contactId: c.id }); }));
}

function displayName(c) { return (c && (c.nick || c.name || c.keyName)) || 'Contact'; }

function meInfo() {
  const id = store.vault.identity;
  return {
    hasIdentity: !!id,
    unlocked: identity.unlocked,
    name: S().displayName || identity.name || '',
    keyName: identity.name,
    fp: identity.fp, prettyFp: prettyFp(identity.fp),
    onion: peer && peer.onion,
    sealId: peer && peer.myId(),
    online: !!(peer && peer.running),
    tor: tor ? tor.status() : null,
    protectedByOs: store.protectedByOs,
    platform: process.platform,
    avatar: (store.vault.me || {}).avatar || null,                 // 1.2.0
    shareAvatar: (store.vault.me || {}).shareAvatar !== false,
    handle: S().myHandle || ''                                      // 1.8.0: your name@domain, if you set one
  };
}

/* =================================================================
 * 3b. ADDING BY NAME (1.8.0) — name@domain → Seal Chat ID
 * ================================================================= */
/** How web lookups go: through Tor; directly only if allowed (Settings → Privacy) and Tor is blocked. */
function lookupNet() {
  if (!tor || !tor.ready) throw new Error('Waiting for Tor to connect — try again in a moment');
  return { socksPort: tor.socksPort, direct: S().directIfTorBlocked === true, base: process.env.SEALCHAT_NAMES_BASE || undefined };
}
/**
 * What the Add contact box holds: a Seal Chat ID, or a name@domain (looked up).
 * Returns { kind: 'id' | 'name', id, fp, handle?, display? }.
 */
async function resolveAdd(text) {
  const t = String(text || '').trim();
  if (invites.looksLikeCode(t)) return { kind: 'invite', code: invites.parseCode(t).code };   // used only when you press Add (a wrong code costs a try)
  if (names.looksLikeHandle(t)) {
    const r = await names.lookup(t, lookupNet());
    return { kind: 'name', id: r.id, fp: r.fp, onion: r.onion, handle: r.handle, display: r.display };
  }
  const p = parseId(t);
  return { kind: 'id', id: `sealchat:${p.onion}:${p.fp}`, fp: p.fp, onion: p.onion };
}
/** Adds by ID or name; a name is remembered ("pinned") with the contact. */
async function addByText(text, { nick, note } = {}) {
  if (invites.looksLikeCode(text)) {                          // 1.8.0: an invite code → their real ID, proven by the code
    const r = await peer.invites.join(text);
    const have = store.contact(r.fp);
    if (have && have.status === 'accepted') return have;
    const c = peer.addContact(r.id, { nick: nick || '', note });
    c.viaInvite = { multi: !!r.multi, at: Date.now() };
    if (!c.name && r.name) c.name = r.name;
    store.putContact(c);
    return c;
  }
  const r = await resolveAdd(text);
  const c = peer.addContact(r.id, { nick: nick || r.display || '', note });
  if (r.handle) { c.handle = r.handle; c.handleFp = r.fp; c.handleChecked = Date.now(); c.handleWarning = null; store.putContact(c); }
  return c;
}
/** Once a day: does each contact's name@domain still point to them? (Never switches — only warns.) */
async function recheckHandles() {
  if (!peer || !peer.running || !tor.ready) return;
  for (const c of store.contacts()) {
    if (!c.handle || Date.now() - (c.handleChecked || 0) < 24 * 3600e3) continue;
    try {
      const r = await names.lookup(c.handle, lookupNet());
      c.handleWarning = r.fp === c.fp ? null : `${c.handle} now points to a DIFFERENT Seal Chat ID (fingerprint ${prettyFp(r.fp)}). Your contact is unchanged — check with them before trusting the name again.`;
    } catch (e) { /* website unreachable: try again later; keep the last result */ }
    c.handleChecked = Date.now(); store.putContact(c);
  }
  send('contacts');
}

/* =================================================================
 * 4. NOTIFICATIONS
 * ================================================================= */
function notify(title, body, onClick) {
  if (S().notifications === false || !Notification.isSupported()) return;
  const n = new Notification({ title, body, silent: S().sound === false, icon: path.join(__dirname, '..', 'renderer', 'icon.png') });
  if (onClick) n.on('click', onClick);
  n.show();
}

function onIncomingNotify(contactId, msg, via) {
  const c = store.contact(contactId);
  if (!c || c.muted) return;
  const focusedOnIt = win && !win.isDestroyed() && win.isFocused() && currentChat === contactId && !appLocked;
  if (focusedOnIt) return;
  // 1.6.0: phones with Seal Chat Web notifications on (skipped for any that have it open right now)
  // 1.9.3: not for a message passed on by your other device — that one has notified the phones already
  if (web && msg.dir !== 'out' && via !== 'sync') web.notify({ kind: 'msg', name: displayName(c) });
  if (win && !win.isDestroyed() && !win.isFocused()) win.flashFrame(true);
  // while locked (or if previews are off) only say that something arrived
  const preview = S().notifyPreview !== false && !appLocked;
  const body = msg.kind === 'file' ? `📎 ${msg.file.name} (${fmtSize(msg.file.size)})` : msg.text.slice(0, 200);
  notify(preview ? displayName(c) : 'Seal Chat', preview ? body : 'New message', () => { showWindow(); send('open', { contactId }); });
}
let currentChat = null;

/** 1.8.0: "Alice reacted 👍 to your message" (same rules as messages; nothing while you're looking at that chat). */
function onReactionNotify(contactId, msg, e) {
  const c = store.contact(contactId);
  if (!c || c.muted || S().notifications === false) return;
  if (win && !win.isDestroyed() && win.isFocused() && currentChat === contactId && !appLocked) return;
  const preview = S().notifyPreview !== false && !appLocked;
  const what = msg.kind === 'file' ? '📎 ' + msg.file.name : String(msg.text || '').slice(0, 80);
  notify(preview ? displayName(c) : 'Seal Chat', preview ? `Reacted ${e} to “${what}”` : 'New reaction', () => { showWindow(); send('open', { contactId }); });
}

/* =================================================================
 * 5. IPC
 * ================================================================= */
const OPEN_WHILE_LOCKED = new Set(['app:info', 'lock:status', 'lock:unlockPin', 'lock:unlockHello', 'lock:activity', 'setup:state', 'tor:status']);

function handle(channel, fn) {
  ipcMain.handle(channel, async (e, ...args) => {
    if (e.senderFrame && !/^file:/.test(e.senderFrame.url)) return { ok: false, error: 'Not allowed' };
    if (appLocked && !OPEN_WHILE_LOCKED.has(channel)) return { ok: false, error: 'Seal Chat is locked', code: 'LOCKED' };
    try { return { ok: true, data: await fn(...args) }; }
    catch (err) { return { ok: false, error: err.message, code: err.code }; }
  });
}

function registerIpc() {
  /* ---------- 5a. app / updates ---------- */
  handle('app:info', () => ({ version: VERSION, installedVersion: app.getVersion(), fromUpdate: !!process.env.SEALCHAT_UPDATE_FILE, platform: process.platform }));
  handle('app:openExternal', url => { if (/^https?:\/\//i.test(url)) shell.openExternal(url); return true; });
  handle('clipboard:write', text => { clipboard.writeText(String(text)); return true; });
  handle('app:restart', () => { quitting = true; app.relaunch(); app.exit(0); });

  /* ---------- 5l. automatic updates (1.3.0) ---------- */
  handle('update:status', () => updateStatus());
  handle('update:check', async () => { await updater.check(); store.setSettings({ updateLastCheck: Date.now() }); return updateStatus(); });
  handle('update:install', async () => {
    let last = 0;
    const r = await updater.downloadAndInstall((d, t) => {
      if (Date.now() - last > 250 || d === t) { last = Date.now(); send('updateProgress', { done: d, total: t }); }
    });
    send('update', updateStatus());
    return r;
  });
  handle('update:first', () => firstUpd);                      // 1.6.0
  handle('update:firstSkip', () => { if (firstUpd) { firstUpd.skipped = true; store.setSettings({ firstUpdateFor: app.getVersion() }); send('update', updateStatus()); } return firstUpd; });
  handle('update:skip', v => { store.setSettings({ skipVersion: String(v || '') }); if (updater.state.available) updater.state.available.skipped = true; send('update', updateStatus()); return true; });
  handle('app:installUpdate', async () => {
    const r = await dialog.showOpenDialog(win, { title: 'Choose a Seal Chat update file', properties: ['openFile'], filters: [{ name: 'Seal Chat update', extensions: ['sealchat'] }] });
    if (r.canceled || !r.filePaths[0]) return null;
    const dir = path.join(app.getPath('userData'), 'updates');
    fs.mkdirSync(dir, { recursive: true });
    const incoming = path.join(dir, 'incoming-' + Date.now() + '.tmp');
    ofs.copyFileSync(r.filePaths[0], incoming);
    let pkg;
    try {
      pkg = readPackageJson(incoming);
      if (pkg.name !== 'sealchat') throw new Error('not a Seal Chat package');
      if (!pkg.__hasMain) throw new Error('app code missing');
    } catch (e) { try { ofs.unlinkSync(incoming); } catch { /* ignore */ } throw new Error('That file is not a valid Seal Chat update (' + e.message + ')'); }
    if (cmpVersion(pkg.version, VERSION) <= 0) { try { ofs.unlinkSync(incoming); } catch { /* ignore */ } throw new Error(`This update is version ${pkg.version}; you already have ${VERSION}.`); }
    const finalPath = path.join(dir, 'sealchat-' + pkg.version + '.asar');
    try { ofs.unlinkSync(finalPath); } catch { /* none */ }
    ofs.renameSync(incoming, finalPath);
    try { const badFile = path.join(dir, 'bad-versions.json'); ofs.writeFileSync(badFile, JSON.stringify(JSON.parse(ofs.readFileSync(badFile, 'utf8')).filter(v => v !== pkg.version))); } catch { /* none */ }
    return { version: pkg.version, from: VERSION };
  });

  /* ---------- 5b. setup + identity ---------- */
  handle('setup:state', () => ({ stage: !store.vault.identity ? 'welcome' : identity.unlocked ? 'ready' : 'unlock', locked: appLocked }));

  const adopt = async (armored, passphrase, remember, displayNameIn) => {
    await identity.load(armored, passphrase);
    store.vault.identity = { armored, passphrase: remember ? passphrase : null, remember: !!remember, fp: identity.fp };
    store.saveVault(); store.flush();
    if (displayNameIn) store.setSettings({ displayName: String(displayNameIn).slice(0, 80) });
    startPeer();
    return meInfo();
  };

  handle('setup:generate', async ({ name, passphrase, remember }) => {
    if (store.vault.identity) throw new Error('You already have an identity');
    const armored = await Identity.generate({ name, passphrase });
    return adopt(armored, passphrase, remember !== false, name);
  });
  handle('setup:pickKeyFile', async () => {
    const r = await dialog.showOpenDialog(win, { title: 'Choose your PGP private key', properties: ['openFile'], filters: [{ name: 'PGP keys', extensions: ['asc', 'gpg', 'pgp', 'key', 'txt'] }, { name: 'All files', extensions: ['*'] }] });
    if (r.canceled || !r.filePaths[0]) return null;
    const buf = fs.readFileSync(r.filePaths[0]);
    if (buf.length > 1024 * 1024) throw new Error('That file is too large to be a key');
    // binary keys are converted to text (armored) so they can be checked the same way
    if (!/-----BEGIN PGP/.test(buf.toString('latin1'))) {
      const openpgp = require('openpgp');
      try { const k = await openpgp.readPrivateKey({ binaryKey: buf }); return k.armor(); }
      catch { throw new Error('That file does not contain a PGP private key'); }
    }
    return buf.toString('utf8');
  });
  handle('setup:inspectKey', ({ armored, passphrase }) => Identity.inspectPrivate(armored, passphrase));
  handle('setup:importKey', async ({ armored, passphrase, remember, displayName: dn }) => {
    if (store.vault.identity) throw new Error('You already have an identity');
    const info = await Identity.inspectPrivate(armored, passphrase);
    return adopt(String(armored).trim(), passphrase, remember !== false, dn || info.name);
  });
  handle('setup:restore', async ({ password }) => {
    if (store.vault.identity) throw new Error('You already have an identity');
    const r = await dialog.showOpenDialog(win, { title: 'Choose your Seal Chat backup', properties: ['openFile'], filters: [{ name: 'Seal Chat backup', extensions: ['sealchat-backup'] }, { name: 'All files', extensions: ['*'] }] });
    if (r.canceled || !r.filePaths[0]) return null;
    const b = readBackup(fs.readFileSync(r.filePaths[0]), password);
    if (!b || !b.identity || !b.identity.armored) throw new Error('That backup has no identity in it');
    if (!b.identity.passphrase) throw new Error('This backup was made without the key passphrase. Import your key instead.');
    store.vault.onionKey = b.onionKey || null;
    store.vault.contacts = b.contacts || {};
    store.vault.ctl = [];
    for (const [id, chat] of Object.entries(b.chats || {})) { store.chats.set(id, chat); store.saveChat(id); }
    if (b.settings) store.setSettings({ displayName: b.settings.displayName, readReceipts: b.settings.readReceipts, allowRequests: b.settings.allowRequests });
    return adopt(b.identity.armored, b.identity.passphrase, b.identity.remember !== false);
  });
  // 1.9.0: this computer becomes another device of your Seal Chat ID (welcome screen → Link)
  handle('setup:link', async ({ code, passphrase, name, remember }) => {
    if (store.vault.identity) throw new Error('You already have an identity on this computer');
    if (!tor || !tor.ready) throw new Error('Wait until Seal Chat is connected to Tor (shown at the bottom of this window), then try again');
    const pass = String(passphrase || '');
    if (!pass) throw new Error('Type your key passphrase (the same as on your other device)');
    const r = await linking.join({ code: String(code || ''), socksPort: tor.socksPort, name: String(name || ''), unlock: async b => { await new Identity().load(b.armored, pass); } });
    linking.adoptLink(store, r);
    return adopt(r.bundle.armored, pass, remember !== false, store.settings.displayName);
  });
  handle('identity:unlock', async ({ passphrase, remember }) => {
    const v = store.vault.identity;
    if (!v) throw new Error('No identity yet');
    await identity.load(v.armored, passphrase);
    if (remember) { v.passphrase = passphrase; v.remember = true; store.saveVault(); }
    startPeer();
    return meInfo();
  });
  handle('identity:setRemember', async ({ remember, passphrase }) => {
    const v = store.vault.identity;
    if (remember) {
      await new Identity().load(v.armored, passphrase);   // checks it
      v.passphrase = passphrase; v.remember = true;
    } else { v.passphrase = null; v.remember = false; }
    store.saveVault();
    return { remember: !!v.remember };
  });

  /* ---------- 5c. me + Tor ---------- */
  handle('me:get', () => ({ ...meInfo(), remember: !!(store.vault.identity && store.vault.identity.remember) }));
  handle('me:copyId', () => { const id = peer.myId(); if (!id) throw new Error('Your ID appears once Seal Chat is connected to Tor'); clipboard.writeText(id); return id; });
  handle('tor:status', () => ({ ...tor.status(), lyrebird: tor.lyrebird || null }));
  handle('tor:restart', async () => {
    await peer.stop();
    await tor.restart({ bridges: S().bridges || [], lyrebirdPath: S().lyrebirdPath || null });
    return tor.status();
  });
  handle('tor:log', () => tor.logTail.slice(-60).join('\n'));

  /* ---------- 5d. contacts ---------- */
  const contactView = c => {
    const chat = store.chat(c.id);
    const queued = chat.messages.filter(m => m.state === 'queued').length;
    return {
      id: c.id, fp: c.fp, prettyFp: prettyFp(c.fp), onion: c.onion, status: c.status,
      name: displayName(c), theirName: c.name || c.keyName || '', nick: c.nick || '', note: c.note || '',
      verified: !!c.verified, muted: !!c.muted, unread: c.unread || 0, queued,
      lastAt: c.lastAt || c.addedAt || 0, lastText: c.lastText || '', lastDir: c.lastDir || '',
      lastSeen: c.lastSeen || 0, lastReached: c.lastReached || 0, lastError: c.lastError || null,
      requested: !!c.requested, failReason: c.failReason || null, nextTry: peer.nextAttempt(c.id),
      handle: c.handle || '', handleWarning: c.handleWarning || null,                         // 1.8.0: name@domain
      invite: c.invite && c.status === 'pending-in' ? c.invite.label || 'an invite code' : null,  // 1.8.0: their request came with your invite
      viaInvite: c.viaInvite && c.status === 'pending-out' ? { multi: !!c.viaInvite.multi } : null,
      mailbox: !!c.mailbox, mailboxError: c.mailboxError || null,                            // 1.8.0: they have a mailbox
      linked: peer.links.has(c.id),
      // 1.2.0 pictures: avatarMode 'theirs' (default) | 'custom' | 'none'
      avatar: avatarOf(c), avatarMode: c.avatarMode || 'theirs', hasShared: !!c.sharedAvatar, hasCustom: !!c.customAvatar
    };
  };
  handle('contacts:list', () => store.contacts().map(contactView).sort((a, b) => (b.lastAt || 0) - (a.lastAt || 0)));
  handle('contacts:parse', text => parseId(text));
  handle('contacts:add', async ({ id, nick, note }) => contactView(await addByText(id, { nick, note })));   // 1.8.0: ID or name@domain
  handle('contacts:resolve', text => resolveAdd(text));                                               // 1.8.0: live check in Add contact
  // ---- 1.8.0: invite codes you made ----
  handle('invite:list', () => (peer ? peer.invites.list() : []));
  handle('invite:create', opts => peer.invites.create(opts || {}));
  handle('invite:cancel', id => peer.invites.cancel(String(id)).then(() => peer.invites.list()));
  handle('me:setHandle', async text => {                                                             // 1.8.0: your own name@domain
    const t = String(text || '').trim();
    if (!t) { store.setSettings({ myHandle: undefined }); return meInfo(); }
    const r = await names.lookup(t, lookupNet());
    if (r.fp !== identity.fp) throw new Error(`${r.handle} points to a different Seal Chat ID (fingerprint ${prettyFp(r.fp)}) — add YOUR ID for that name on your website first`);
    store.setSettings({ myHandle: r.handle });
    return meInfo();
  });
  handle('contacts:accept', id => contactView(peer.accept(id)));
  handle('contacts:decline', id => { peer.decline(id); return true; });
  handle('contacts:block', id => { peer.block(id); return true; });
  handle('contacts:unblock', id => { peer.unblock(id); return true; });
  handle('contacts:remove', id => { peer.remove(id); return true; });
  handle('contacts:rename', (id, nick) => { peer.rename(id, nick); return true; });
  handle('contacts:verify', (id, v) => { peer.setVerified(id, v); return true; });
  handle('contacts:mute', (id, v) => { const c = store.contact(id); if (c) { c.muted = !!v; store.putContact(c); } return true; });
  handle('contacts:retry', id => {
    const c = store.contact(id);
    if (c && c.status === 'failed') { c.status = 'pending-out'; c.requested = false; c.failReason = null; c.publicKey = null; store.putContact(c); }
    peer.retryNow(id); return true;
  });
  handle('contacts:details', async id => {
    const c = store.contact(id);
    if (!c) throw new Error('Unknown contact');
    let key = null;
    if (c.publicKey) { try { const d = await describePublic(c.publicKey); key = { name: d.name, email: d.email, created: d.created }; } catch { /* ignore */ } }
    return { ...contactView(c), key, safety: safetyNumber(identity.fp, c.fp), myPrettyFp: prettyFp(identity.fp), sealId: `sealchat:${c.onion}:${c.fp}`,
      devices: c.devices ? c.devices.devices.map(d => ({ id: d.id, name: d.name })) : null };   // 1.8.0
  });
  // 1.8.0: this installation's device (groundwork for one ID on several devices)
  handle('mailbox:status', () => mailboxStatus());                       // 1.8.0
  handle('mailbox:check', async () => { await syncMailbox(); await fetchMailbox(); return mailboxStatus(); });
  handle('mailbox:workerScript', () => { clipboard.writeText(workerScript()); return true; });   // 1.8.5: Cloudflare Worker mailbox (1.8.6: copied here — the window may not use the clipboard itself)
  handle('mailbox:workerConnect', url => workerConnect(String(url || '')));
  handle('mailbox:workerRemove', () => workerRemove());
  handle('device:get', () => { const d = peer ? peer.myDevices()[0] : (store.vault.device || null); return d ? { id: d.id, name: d.name } : null; });
  handle('devices:status', () => peer.running ? peer.devicesStatus() : { devices: [], link: null, offline: true });   // 1.9.0
  handle('devices:link', () => peer.linker.start());
  handle('devices:linkCancel', async () => { await peer.linker.cancel(); return true; });
  handle('devices:remove', id => peer.removeDevice(String(id || '')).then(() => {
    // 1.9.3: the removed device had the web access token: give the website a new one (your other devices get it by sync)
    if (web && store.vault.web && store.vault.web.box) web.rekey().catch(() => {});
    return peer.devicesStatus();
  }));
  handle('device:rename', name => { const d = peer.renameDevice(String(name || '')); return { id: d.id, name: d.name }; });
  handle('contacts:exportKey', async id => {
    const c = store.contact(id);
    if (!c || !c.publicKey) throw new Error('No key for that contact yet');
    const r = await dialog.showSaveDialog(win, { title: 'Save public key', defaultPath: `${displayName(c).replace(/[\\/:*?"<>|]/g, '_')}-public.asc`, filters: [{ name: 'PGP key', extensions: ['asc'] }] });
    if (r.canceled || !r.filePath) return null;
    fs.writeFileSync(r.filePath, c.publicKey); return r.filePath;
  });

  /* ---------- 5e. chats ---------- */
  handle('chat:history', id => { const c = store.contact(id); if (!c) throw new Error('Unknown contact'); return peer.history(id).slice(-2000).map(forWindow); });
  handle('chat:open', id => { currentChat = id; peer.markRead(id); updateTray(); return true; });
  handle('chat:close', () => { currentChat = null; return true; });
  handle('chat:send', (id, text, opts) => { const m = peer.send(id, text, { re: opts && opts.re }); send('contacts'); updateTray(); if (web) web.push({ t: 'msg', cid: id, msg: webMsg(m, id) }); return m; });   // 1.8.0: opts.re = reply
  handle('chat:react', (id, msgId, emoji) => forWindow(peer.react(id, msgId, String(emoji || ''))));     // 1.8.0

  /* ---------- 5i. files (1.1.0) ---------- */
  /** Starts sending; resolves as soon as the message is in the chat ("Preparing…"). */
  const startSend = (id, source, info) => new Promise((resolve, reject) => {
    let added = false;
    peer.sendFile(id, source, info, m => { added = true; if (web) web.push({ t: 'msg', cid: id, msg: webMsg(m, id) }); resolve(forWindow(m)); })   // 1.7.0: web.push
      .then(() => { send('contacts'); updateTray(); })
      .catch(e => { if (!added) reject(e); else console.error('send file:', e.message); });
  });
  const sendPaths = async (id, paths, re) => {   // 1.8.0: re = reply to (first file only)
    const sent = [], skipped = [];
    for (const p of paths) {
      let st; try { st = fs.statSync(p); } catch { skipped.push(path.basename(p) + ' (not found)'); continue; }
      if (!st.isFile()) { skipped.push(path.basename(p) + ' (folders can\'t be sent — zip it first)'); continue; }
      try { sent.push(await startSend(id, { path: p }, { name: path.basename(p), mime: mimeOf(p), thumb: thumbFor(nativeImage.createFromPath(p), p), re: sent.length ? undefined : re })); }
      catch (e) { skipped.push(e.message); }
    }
    return { sent, skipped };
  };
  handle('file:pick', async (id, re) => {
    const r = await dialog.showOpenDialog(win, { title: 'Send files', properties: ['openFile', 'multiSelections'] });
    if (r.canceled || !r.filePaths.length) return { sent: [], skipped: [] };
    return sendPaths(id, r.filePaths, re);
  });
  handle('file:sendPaths', (id, paths, re) => sendPaths(id, (Array.isArray(paths) ? paths : []).slice(0, 50).map(String), re));
  handle('file:sendData', async (id, { name, mime, bytes, re }) => {
    const buf = Buffer.from(bytes || []);
    if (!buf.length || buf.length > 100 * 1024 * 1024) throw new Error('Nothing to send');
    const d = new Date(), two = n => String(n).padStart(2, '0');
    const nm = safeName(name || `Pasted image ${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())} ${two(d.getHours())}.${two(d.getMinutes())}.${two(d.getSeconds())}.png`);
    return startSend(id, { buffer: buf }, { name: nm, mime: mime || mimeOf(nm), thumb: thumbFor(nativeImage.createFromBuffer(buf), nm), re });
  });
  handle('file:download', (id, msgId) => forWindow(peer.download(id, msgId)));
  handle('file:pause', (id, msgId) => { peer.pauseDownload(id, msgId); return true; });
  handle('file:decline', (id, msgId) => { peer.declineFile(id, msgId); return true; });
  handle('file:save', async (id, msgId) => {
    const ref = peer.fileRef(id, msgId);
    const r = await dialog.showSaveDialog(win, { title: 'Save file', defaultPath: path.join(app.getPath('downloads'), ref.meta.name) });
    if (r.canceled || !r.filePath) return null;
    await files.exportTo(ref.where, msgId, ref.meta, r.filePath);
    return r.filePath;
  });
  handle('file:showSaved', p => { if (p && fs.existsSync(p)) shell.showItemInFolder(p); return true; });
  handle('file:open', async (id, msgId) => {
    const ref = peer.fileRef(id, msgId);
    // program files are never started from Seal Chat
    if (isRisky(ref.meta.name)) { const e = new Error('This is a program or script file. For your safety Seal Chat won\'t open it — use "Save as…" if you trust it.'); e.code = 'RISKY'; throw e; }
    const dir = path.join(OPEN_DIR, crypto.randomBytes(6).toString('hex'));
    fs.mkdirSync(dir, { recursive: true });
    const out = await files.exportTo(ref.where, msgId, ref.meta, path.join(dir, ref.meta.name));
    const err = await shell.openPath(out);
    if (err) throw new Error(err);
    return true;
  });
  handle('storage:usage', () => files.usage());

  /* ---------- 5k. QR codes + profile pictures (1.2.0) ---------- */
  const myQr = async () => {
    const id = peer.myId();
    if (!id) throw new Error('Your QR code appears once Seal Chat is connected to Tor');
    return { id, dataUrl: await QRCode.toDataURL(id, { errorCorrectionLevel: 'M', width: 560, margin: 3, color: { dark: '#000000', light: '#ffffff' } }) };
  };
  handle('qr:mine', () => myQr());
  // (Electron 44's clipboard works like the web one: ClipboardItem + Blob)
  handle('qr:copy', async () => {
    const q = await myQr();
    const png = nativeImage.createFromDataURL(q.dataUrl).toPNG();
    await clipboard.write([new ClipboardItem({ 'image/png': new Blob([png], { type: 'image/png' }) })]);
    return true;
  });
  handle('qr:save', async () => {
    const q = await myQr();
    const nm = (S().displayName || identity.name || 'my').replace(/[\\/:*?"<>|]/g, '_');
    const r = await dialog.showSaveDialog(win, { title: 'Save your Seal Chat QR code', defaultPath: path.join(app.getPath('pictures'), `${nm} Seal Chat QR.png`), filters: [{ name: 'PNG image', extensions: ['png'] }] });
    if (r.canceled || !r.filePath) return null;
    fs.writeFileSync(r.filePath, nativeImage.createFromDataURL(q.dataUrl).toPNG());
    return r.filePath;
  });
  handle('qr:readFile', async () => {
    const r = await dialog.showOpenDialog(win, { title: 'Choose a picture of a Seal Chat QR code', properties: ['openFile'], filters: [{ name: 'Pictures', extensions: ['png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp'] }] });
    if (r.canceled || !r.filePaths[0]) return null;
    return readQr(nativeImage.createFromPath(r.filePaths[0]));
  });
  handle('qr:readClipboard', async () => {
    for (const item of await clipboard.read()) {
      const type = item.types.find(t => /^image\//.test(t));
      if (!type) continue;
      const blob = await item.getType(type);
      return readQr(nativeImage.createFromBuffer(Buffer.from(await blob.arrayBuffer())));
    }
    throw new Error('There is no picture on the clipboard. Copy a picture of the QR code first.');
  });

  // your own picture
  const setMyAvatar = img => {
    const url = squareAvatar(img);
    if (!url) throw new Error('That picture could not be read (use a JPG or PNG)');
    store.vault.me = { ...(store.vault.me || { shareAvatar: true }), avatar: url, avatarAt: Date.now() };
    store.saveVault();
    if (peer.running) peer.shareProfileAll();
    return meInfo();
  };
  handle('me:pickAvatar', async () => {
    const r = await dialog.showOpenDialog(win, { title: 'Choose your picture', properties: ['openFile'], filters: [{ name: 'Pictures', extensions: ['jpg', 'jpeg', 'png', 'bmp', 'gif', 'webp'] }] });
    if (r.canceled || !r.filePaths[0]) return null;
    return setMyAvatar(nativeImage.createFromPath(r.filePaths[0]));
  });
  handle('me:removeAvatar', () => {
    store.vault.me = { ...(store.vault.me || {}), avatar: null, avatarAt: Date.now() };
    store.saveVault();
    if (peer.running) peer.shareProfileAll();
    return meInfo();
  });
  handle('me:setShareAvatar', on => {
    store.vault.me = { ...(store.vault.me || {}), shareAvatar: !!on };
    store.saveVault();
    if (peer.running) peer.shareProfileAll();
    return meInfo();
  });
  // the picture YOU see for a contact
  handle('contacts:setAvatarMode', (id, mode) => {
    const c = store.contact(id); if (!c) throw new Error('Unknown contact');
    if (!['theirs', 'custom', 'none'].includes(mode)) throw new Error('bad mode');
    c.avatarMode = mode; store.putContact(c); send('contacts');
    return contactView(c);
  });
  handle('contacts:pickAvatar', async id => {
    const c = store.contact(id); if (!c) throw new Error('Unknown contact');
    const r = await dialog.showOpenDialog(win, { title: `Choose a picture for ${displayName(c)}`, properties: ['openFile'], filters: [{ name: 'Pictures', extensions: ['jpg', 'jpeg', 'png', 'bmp', 'gif', 'webp'] }] });
    if (r.canceled || !r.filePaths[0]) return null;
    const url = squareAvatar(nativeImage.createFromPath(r.filePaths[0]));
    if (!url) throw new Error('That picture could not be read (use a JPG or PNG)');
    c.customAvatar = url; c.avatarMode = 'custom'; store.putContact(c); send('contacts');
    return contactView(c);
  });
  handle('storage:free', days => { const n = peer.freeFileSpace(Math.max(0, Number(days) || 0)); return { removed: n, ...files.usage() }; });
  handle('chat:delete', (id, msgId) => { peer.deleteMessage(id, msgId); return true; });
  handle('chat:clear', id => { peer.clearChat(id); send('contacts'); return true; });
  handle('chat:export', async id => {
    const c = store.contact(id);
    const r = await dialog.showSaveDialog(win, { title: 'Save conversation', defaultPath: `Chat with ${displayName(c).replace(/[\\/:*?"<>|]/g, '_')}.txt`, filters: [{ name: 'Text', extensions: ['txt'] }] });
    if (r.canceled || !r.filePath) return null;
    const me = S().displayName || identity.name || 'Me';
    const lines = peer.history(id).map(m => `[${new Date(m.at).toLocaleString()}] ${m.dir === 'out' ? me : displayName(c)}: ${m.text}`);
    fs.writeFileSync(r.filePath, '﻿' + lines.join('\r\n'), 'utf8');
    return r.filePath;
  });

  /* ---------- 5m. web access (1.4.0) ---------- */
  handle('web:status', () => web.status());
  handle('web:connect', async link => { const st = await web.connect(link); updateTray(); return st; });
  handle('web:disconnect', async () => { const st = await web.disconnect(); updateTray(); return st; });
  handle('web:enable', (on, hours) => { const st = web.setEnabled(!!on, Number(hours) || 0); updateTray(); return st; });
  handle('web:pair', async () => {
    const p = await web.startPairing();
    return { ...p, qr: await QRCode.toDataURL(p.link, { errorCorrectionLevel: 'M', width: 520, margin: 3, color: { dark: '#000000', light: '#ffffff' } }) };
  });
  handle('web:copyPairLink', link => { clipboard.writeText(String(link)); return true; });
  handle('web:approve', tid => web.approvePairing(String(tid)));
  handle('web:decline', tid => web.declinePairing(String(tid)));
  handle('web:cancelPair', () => { web.cancelPairing(); return web.status(); });
  handle('web:removeDevice', id => web.removeDevice(String(id)));
  handle('web:devicePush', (id, patch) => web.setDevicePush(String(id), { ...(patch && 'on' in patch ? { on: !!patch.on } : {}), ...(patch && 'names' in patch ? { names: !!patch.names } : {}) }));   // 1.6.0

  /* ---------- 5f. settings ---------- */
  const SETTABLE = ['displayName', 'readReceipts', 'allowRequests', 'notifications', 'notifyPreview', 'sound', 'closeToTray', 'enterToSend', 'emojiConvert', 'theme', 'autoDownloadMB', 'maxFileMB',
    'updateAuto', 'updateViaTor', 'updateUrl',    // 1.3.0
    'webIdleSec', 'webViaTor',                    // 1.4.0
    'mailboxOn', 'directIfTorBlocked',               // 1.8.0
    'contactMailbox'];                               // 1.8.5
  const publicSettings = () => {
    const s = S(); const out = {};
    for (const k of SETTABLE) out[k] = s[k];
    out.startWithWindows = process.platform === 'win32' ? app.getLoginItemSettings({ args: ['--hidden'] }).openAtLogin
      : IS_MAC ? app.getLoginItemSettings().openAtLogin : linuxAutostart(null);
    out.bridges = (s.bridges || []).join('\n');
    out.lyrebirdPath = s.lyrebirdPath || '';
    return out;
  };
  handle('settings:get', () => publicSettings());
  handle('settings:set', patch => {
    const clean = {};
    for (const k of SETTABLE) if (k in patch) clean[k] = patch[k];
    if ('displayName' in clean) clean.displayName = String(clean.displayName || '').slice(0, 80);
    if ('autoDownloadMB' in clean) clean.autoDownloadMB = Math.max(0, Math.min(4096, Number(clean.autoDownloadMB) || 0));
    if ('maxFileMB' in clean) clean.maxFileMB = Math.max(1, Math.min(4096, Number(clean.maxFileMB) || 2048));
    if ('webIdleSec' in clean) clean.webIdleSec = Math.max(10, Math.min(900, Number(clean.webIdleSec) || 30));
    if ('webViaTor' in clean) clean.webViaTor = !!clean.webViaTor;
    if ('mailboxOn' in clean) clean.mailboxOn = !!clean.mailboxOn;          // 1.8.0
    if ('directIfTorBlocked' in clean) clean.directIfTorBlocked = !!clean.directIfTorBlocked;
    if ('contactMailbox' in clean) clean.contactMailbox = !!clean.contactMailbox;   // 1.8.5
    if ('updateUrl' in clean) {
      clean.updateUrl = String(clean.updateUrl || '').trim();
      if (clean.updateUrl && !/^https:\/\/[^\s/]+\/\S*$/i.test(clean.updateUrl)) throw new Error('The update address must start with https://');
      if (!clean.updateUrl) clean.updateUrl = undefined;
    }
    const nameChanged = 'displayName' in clean && clean.displayName !== S().displayName;
    store.setSettings(clean);
    if (web && ('webIdleSec' in clean || 'webViaTor' in clean)) { web.kick(); send('web', web.status()); }
    if (nameChanged && peer.running) peer.shareProfileAll();       // 1.2.0: contacts get the new name
    if ('mailboxOn' in clean) syncMailbox().then(() => fetchMailbox());   // 1.8.0
    if ('contactMailbox' in clean) sendMailboxStatus();                    // 1.8.5
    if ('startWithWindows' in patch && process.platform === 'win32') app.setLoginItemSettings({ openAtLogin: !!patch.startWithWindows, args: ['--hidden'] });
    if ('startWithWindows' in patch && process.platform === 'linux') linuxAutostart(!!patch.startWithWindows);
    if ('startWithWindows' in patch && IS_MAC) app.setLoginItemSettings({ openAtLogin: !!patch.startWithWindows });   // 1.5.0
    return publicSettings();
  });
  handle('settings:setBridges', async ({ bridges, lyrebirdPath }) => {
    const lines = String(bridges || '').split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#'));
    for (const l of lines) if (!/^(Bridge\s+)?((obfs4|webtunnel|meek_lite|snowflake|scramblesuit)\s+)?[\[\]0-9a-fA-F.:]+:\d+(\s|$)/i.test(l)) throw new Error('This doesn\'t look like a bridge line: ' + l.slice(0, 60));
    store.setSettings({ bridges: lines, lyrebirdPath: String(lyrebirdPath || '').trim() || undefined });
    await peer.stop();
    await tor.restart({ bridges: lines, lyrebirdPath: S().lyrebirdPath || null });
    return { ...publicSettings(), lyrebird: tor.lyrebird || null };
  });
  handle('settings:pickLyrebird', async () => {
    const r = await dialog.showOpenDialog(win, { title: 'Find lyrebird.exe (in Tor Browser\'s folder)', properties: ['openFile'], filters: [{ name: 'lyrebird', extensions: ['exe'] }] });
    return r.canceled ? null : r.filePaths[0];
  });

  /* ---------- 5g. app lock (from Sealpost) ---------- */
  const lockPublic = () => { const c = lockCfg() || {}; return { enabled: lockEnabled(), locked: appLocked, hello: !!c.hello, idleMinutes: Number(c.idleMinutes) || 0, platform: process.platform }; };
  const unlockNow = () => { appLocked = false; lastActivity = Date.now(); lockLib.recordSuccess(); updateTray(); send('lock', lockPublic()); return true; };
  handle('lock:status', () => lockPublic());
  handle('lock:helloAvailable', () => lockLib.helloAvailability());
  handle('lock:setup', ({ pin, hello, idleMinutes }) => {
    if (!/^\d{4,12}$/.test(String(pin || ''))) throw new Error('PIN must be 4 to 12 digits');
    store.setSettings({ appLock: { enabled: true, ...lockLib.hashPin(pin), hello: !!hello, idleMinutes: Math.max(0, Number(idleMinutes) || 0) } });
    updateTray(); return lockPublic();
  });
  handle('lock:update', ({ hello, idleMinutes }) => {
    const c = lockCfg(); if (!c || !c.enabled) throw new Error('App lock is off');
    store.setSettings({ appLock: { ...c, hello: !!hello, idleMinutes: Math.max(0, Number(idleMinutes) || 0) } }); return lockPublic();
  });
  handle('lock:changePin', (oldPin, newPin) => {
    const c = lockCfg();
    if (!lockLib.checkPin(oldPin, c)) throw new Error('Current PIN is wrong');
    if (!/^\d{4,12}$/.test(String(newPin || ''))) throw new Error('PIN must be 4 to 12 digits');
    store.setSettings({ appLock: { ...c, ...lockLib.hashPin(newPin) } }); return true;
  });
  handle('lock:disable', pin => { if (!lockLib.checkPin(pin, lockCfg())) throw new Error('PIN is wrong'); store.setSettings({ appLock: null }); updateTray(); return lockPublic(); });
  handle('lock:lockNow', () => { lockApp('locked by you'); return true; });
  handle('lock:activity', () => { lastActivity = Date.now(); return true; });
  handle('lock:unlockPin', pin => {
    lockLib.attemptAllowed();
    if (!lockLib.checkPin(pin, lockCfg())) { lockLib.recordFailure(); throw new Error('Wrong PIN'); }
    return unlockNow();
  });
  handle('lock:unlockHello', async () => {
    const c = lockCfg();
    if (!c || !c.hello) throw new Error('Windows Hello is not turned on for Seal Chat');
    if (win && !win.isDestroyed()) win.focus();
    const r = await lockLib.helloVerify('Unlock Seal Chat');
    if (!r.verified) throw new Error('Windows Hello: ' + r.result);
    return unlockNow();
  });

  /* ---------- 5h. backup / export / reset ---------- */
  handle('backup:create', async ({ password, keyPassphrase }) => {
    const v = store.vault.identity;
    if (!v) throw new Error('Nothing to back up yet');
    // the backup needs your key passphrase inside it (so a restore can unlock the key)
    const passphrase = v.passphrase || keyPassphrase;
    if (!passphrase) { const e = new Error('Enter your key passphrase to include it in the backup'); e.code = 'NEED_PASSPHRASE'; throw e; }
    if (!v.passphrase) await new Identity().load(v.armored, passphrase);   // checks it
    if (!password || String(password).length < 8) throw new Error('Backup password must be at least 8 characters');
    const r = await dialog.showSaveDialog(win, { title: 'Save Seal Chat backup', defaultPath: `Seal Chat backup ${new Date().toISOString().slice(0, 10)}.sealchat-backup`, filters: [{ name: 'Seal Chat backup', extensions: ['sealchat-backup'] }] });
    if (r.canceled || !r.filePath) return null;
    const chats = {};
    for (const c of store.contacts()) chats[c.id] = store.chat(c.id);
    const buf = createBackup({ v: 1, made: new Date().toISOString(), identity: { armored: v.armored, passphrase, remember: v.remember !== false }, onionKey: store.vault.onionKey, contacts: store.vault.contacts, chats, settings: { displayName: S().displayName, readReceipts: S().readReceipts, allowRequests: S().allowRequests } }, password);
    fs.writeFileSync(r.filePath, buf, { mode: 0o600 });
    return r.filePath;
  });
  handle('identity:copyPublic', () => { clipboard.writeText(identity.pubArmored); return true; });
  handle('identity:exportPrivate', async ({ passphrase }) => {
    const v = store.vault.identity;
    await new Identity().load(v.armored, passphrase);       // proves it's you
    const r = await dialog.showSaveDialog(win, { title: 'Save your PRIVATE key', defaultPath: `seal-chat-private-key-${identity.fp.slice(-8)}.asc`, filters: [{ name: 'PGP key', extensions: ['asc'] }] });
    if (r.canceled || !r.filePath) return null;
    fs.writeFileSync(r.filePath, v.armored, { mode: 0o600 }); return r.filePath;
  });
  handle('app:reset', async confirmText => {
    if (confirmText !== 'DELETE') throw new Error('Type DELETE to confirm');
    if (web) { await Promise.race([web.disconnect().catch(() => {}), new Promise(r => setTimeout(r, 8000))]); web.stop(); }
    await peer.stop();
    store.wipe();
    store.setSettings({ appLock: null, displayName: undefined });
    try { fs.rmSync(path.join(app.getPath('userData'), 'tor'), { recursive: true, force: true }); } catch { /* ignore */ }
    quitting = true; app.relaunch(); app.exit(0);
  });
}

/* =================================================================
 * 6. APP LOCK TIMER
 * ================================================================= */
function lockApp(reason) {
  if (!lockEnabled() || appLocked) return;
  appLocked = true;
  console.log('app locked:', reason);
  send('lock', { enabled: true, locked: true, hello: !!(lockCfg() || {}).hello });
  updateTray();
}
setInterval(() => {
  if (!store || !lockEnabled() || appLocked) return;
  const mins = Number(lockCfg().idleMinutes) || 0;
  if (mins > 0 && Date.now() - lastActivity > mins * 60e3) lockApp('idle');
}, 15000);

/* =================================================================
 * 7. QUIT
 * ================================================================= */
async function quitApp() {
  quitting = true;
  try { fs.rmSync(OPEN_DIR, { recursive: true, force: true }); } catch { /* a file may still be open */ }
  if (web) web.stop();
  try { await Promise.race([(async () => { if (peer) await peer.stop(); if (tor) await tor.stop(); })(), new Promise(r => setTimeout(r, 4000))]); } catch { /* ignore */ }
  if (store) store.flush();
  app.exit(0);
}

/* =================================================================
 * STARTUP SEQUENCE
 * ================================================================= */
app.whenReady().then(async () => {
  store = new Store(app.getPath('userData'), protector());
  lockLib.setAttemptStore({ load: () => S().lockAttempts, save: a => store.setSettings({ lockAttempts: a }) });
  appLocked = lockEnabled();
  setupTor();
  setupPeer();
  setupUpdater();
  setupWeb();
  registerIpc();
  // 1.6.0: update checks that don't use Tor can look for a newer version straight away (Tor ones: on 'ready')
  if (S().updateViaTor === false && firstRunPending()) setTimeout(firstRunUpdate, 3000);
  registerFileProtocol();
  // 1.2.0: the camera may be used (video only, our own window) to scan QR codes
  const { session } = require('electron');
  session.defaultSession.setPermissionRequestHandler((wc, perm, cb, details) => {
    const ok = perm === 'media' && (details.mediaTypes || []).every(t => t === 'video') && /^file:/.test(details.requestingUrl || '');
    cb(ok);
  });
  session.defaultSession.setPermissionCheckHandler((wc, perm, origin, details) => perm === 'media' && (!details || !details.mediaType || details.mediaType === 'video'));
  try { fs.rmSync(OPEN_DIR, { recursive: true, force: true }); } catch { /* still in use */ }
  createWindow(!startHidden);
  createTray();
  powerMonitor.on('lock-screen', () => lockApp('Windows locked'));
  powerMonitor.on('resume', () => { if (peer && peer.running) for (const c of store.contacts()) peer.retryNow(c.id); });

  // unlock your key automatically when its passphrase is remembered
  const v = store.vault.identity;
  if (v && v.passphrase) { try { await identity.load(v.armored, v.passphrase); } catch (e) { console.error('auto-unlock failed:', e.message); } }
  startTor();
});

app.on('window-all-closed', () => { /* keep running in the tray */ });
app.on('activate', () => { if (store) showWindow(); });      // macOS: clicking the dock icon opens the window
process.on('SIGTERM', () => quitApp());
process.on('SIGINT', () => quitApp());
app.on('before-quit', e => { if (!quitting) { e.preventDefault(); quitApp(); } });

/* =================================================================
 * 5j. scfile://f/<contactId>/<messageId>  (1.1.0)
 * Streams a finished file, decrypted piece by piece, to <img>/<audio>/
 * <video> in the window — with "Range" support so videos can be scrubbed.
 * Only types the window shows inline are served; never while locked.
 * ================================================================= */
const INLINE = /^(image\/(jpeg|png|gif|webp|bmp|avif)|audio\/[a-z0-9.+-]+|video\/(mp4|webm|ogg|quicktime|x-m4v))$/;
function registerFileProtocol() {
  protocol.handle('scfile', async req => {
    try {
      if (appLocked) return new Response('locked', { status: 403 });
      const u = new URL(req.url);
      const [cid, mid] = u.pathname.split('/').filter(Boolean).map(decodeURIComponent);
      const ref = peer.fileRef(cid || '', mid || '');
      const type = INLINE.test(ref.meta.mime) ? ref.meta.mime : 'application/octet-stream';
      const size = ref.meta.size;
      const headers = { 'Content-Type': type, 'Accept-Ranges': 'bytes', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' };
      let start = 0, end = size - 1, status = 200;
      const m = /bytes=(\d*)-(\d*)/.exec(req.headers.get('range') || '');
      if (m && size > 0) {
        if (m[1] === '' && m[2] !== '') { start = Math.max(0, size - Number(m[2])); }
        else { start = Number(m[1] || 0); if (m[2] !== '') end = Math.min(Number(m[2]), size - 1); }
        if (start > end || start >= size) return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${size}` } });
        status = 206; headers['Content-Range'] = `bytes ${start}-${end}/${size}`;
      }
      headers['Content-Length'] = String(size ? end - start + 1 : 0);
      if (!size) return new Response('', { status: 200, headers });
      return new Response(Readable.toWeb(files.plainStream(ref.where, mid, ref.meta, start, end)), { status, headers });
    } catch (e) { return new Response(String(e.message), { status: 404 }); }
  });
}

/* =================================================================
 * 1.3.0: AUTOMATIC UPDATE CHECKS
 * First check ~1.5 minutes after Tor connects, then once a day.
 * ================================================================= */
let updater = null, updateTimer = null, updateNotified = null;
function setupUpdater() {
  updater = new Updater({
    currentVersion: VERSION,
    updatesDir: path.join(app.getPath('userData'), 'updates'),
    settings: () => S(),
    socksPort: () => (tor && tor.ready ? tor.socksPort : null),
    // developers only: a test server's certificate / plain http
    ca: process.env.SEALCHAT_UPDATE_CA ? fs.readFileSync(process.env.SEALCHAT_UPDATE_CA) : undefined,
    allowHttp: !!process.env.SEALCHAT_UPDATE_ALLOW_HTTP,
    publicKey: process.env.SEALCHAT_UPDATE_PUBKEY ? fs.readFileSync(process.env.SEALCHAT_UPDATE_PUBKEY, 'utf8') : undefined
  });
  setInterval(() => scheduleUpdateCheck(0), 3600e3);      // hourly look: is a daily check due?
}
/* ---------- 5l-b. "Install once, then update" (1.6.0) ----------
 * The first time an installed copy starts (a new installation, or an
 * installer of another version), Seal Chat looks for an update as soon
 * as it can reach the website — through Tor once Tor is connected, or
 * right away if update checks go direct. A newer signed update is
 * downloaded and verified exactly like any other update, the window shows
 * "Updating to x.y.z…", and Seal Chat restarts into it (you can say
 * "Not now"). So the installers on the website don't need rebuilding for
 * every release — only when Electron or Tor themselves need updating,
 * which a .sealchat update file can't change.
 * Once done (or skipped) for this installed version it doesn't run again;
 * if the check fails (offline), it tries again at the next start. */
let firstUpd = null;   // { stage: 'checking'|'none'|'downloading'|'ready'|'failed', version, done, total, skipped, error }
function firstRunPending() {
  if (S().updateAuto === false) return false;              // you switched automatic updates off
  if (process.env.SEALCHAT_UPDATE_FILE) return false;      // already running from an update file
  if (firstUpd && firstUpd.stage !== 'failed') return false;
  return S().firstUpdateFor !== app.getVersion();          // app.getVersion() = the INSTALLED version
}
function sendFirst() { send('firstUpdate', firstUpd); }
async function firstRunUpdate() {
  if (!firstRunPending()) return;
  firstUpd = { stage: 'checking' }; sendFirst();
  try {
    await updater.check();
    store.setSettings({ updateLastCheck: Date.now() });
    const a = updater.state.available;
    if (!a) { firstUpd = { stage: 'none' }; store.setSettings({ firstUpdateFor: app.getVersion() }); sendFirst(); return; }
    firstUpd = { stage: 'downloading', version: a.version, done: 0, total: 0, skipped: false };
    sendFirst();
    let last = 0;
    await updater.downloadAndInstall((d, t) => {
      firstUpd.done = d; firstUpd.total = t;
      if (Date.now() - last > 250 || d === t) { last = Date.now(); sendFirst(); send('updateProgress', { done: d, total: t }); }
    });
    store.setSettings({ firstUpdateFor: app.getVersion() });
    firstUpd.stage = 'ready';
    sendFirst();
    send('update', updateStatus());
  } catch (e) {
    console.log('first-run update:', e.message);
    firstUpd = { stage: 'failed', error: e.message };
    sendFirst();
    scheduleUpdateCheck(90e3);                             // the normal checks carry on
  }
}

function updateStatus() {
  const st = updater.state;
  return { ...st, current: VERSION, auto: S().updateAuto !== false, viaTor: S().updateViaTor !== false, url: updater.checkUrl(), lastCheck: S().updateLastCheck || null };
}
function scheduleUpdateCheck(delay) {
  if (S().updateAuto === false) return;
  if (Date.now() - (S().updateLastCheck || 0) < 23 * 3600e3 && delay === 0) return;
  clearTimeout(updateTimer);
  updateTimer = setTimeout(async () => {
    try {
      await updater.check();
      store.setSettings({ updateLastCheck: Date.now() });
      const a = updater.state.available;
      if (a && !a.skipped && updateNotified !== a.version) {
        updateNotified = a.version;
        send('update', updateStatus());
        notify('Seal Chat ' + a.version + ' is available', 'Open Seal Chat to download and install it.', () => { showWindow(); send('update', { ...updateStatus(), open: true }); });
      }
    } catch (e) { console.log('update check:', e.message); }
  }, delay);
}

/* ---------- 1.2.0: start at sign-in on Linux (~/.config/autostart) ----------
 * on === null: just report whether it's on. */
function linuxAutostart(on) {
  const file = path.join(os.homedir(), '.config', 'autostart', 'sealchat.desktop');
  if (on === null) return fs.existsSync(file);
  if (!on) { try { fs.unlinkSync(file); } catch { /* not there */ } return false; }
  const exe = process.env.APPIMAGE || process.execPath;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `[Desktop Entry]\nType=Application\nName=Seal Chat\nExec="${exe.replace(/"/g, '\\"')}" --hidden\nIcon=sealchat\nX-GNOME-Autostart-enabled=true\nComment=Private chat over Tor\n`);
  return true;
}

/* ---------- 1.2.0: pictures + QR helpers ---------- */
/** The picture you see for a contact (your choice > their shared one > none). */
function avatarOf(c) {
  const mode = c.avatarMode || 'theirs';
  if (mode === 'custom' && c.customAvatar) return c.customAvatar;
  if (mode === 'theirs' && c.sharedAvatar) return cleanAvatar(c.sharedAvatar);
  return null;
}

/** Centre-crops a picture to a square and makes a small JPEG (256 px). */
function squareAvatar(img) {
  if (!img || img.isEmpty()) return null;
  const { width, height } = img.getSize();
  const side = Math.min(width, height);
  const sq = img.crop({ x: Math.floor((width - side) / 2), y: Math.floor((height - side) / 2), width: side, height: side }).resize({ width: 256, height: 256, quality: 'best' });
  for (const q of [85, 70, 55, 40]) { const url = 'data:image/jpeg;base64,' + sq.toJPEG(q).toString('base64'); if (url.length < 100000) return url; }
  return null;
}

/** Finds a Seal Chat ID in a picture of a QR code (tries a few sizes). */
function readQr(img) {
  if (!img || img.isEmpty()) throw new Error('No picture found (copy or choose a picture of the QR code)');
  const { width, height } = img.getSize();
  for (const target of [1000, 1600, 700, 2400]) {
    const scale = Math.min(1, target / Math.max(width, height));
    const im = scale < 1 ? img.resize({ width: Math.round(width * scale), height: Math.round(height * scale), quality: 'best' }) : img;
    const { width: w, height: h } = im.getSize();
    const bgra = im.toBitmap();
    const rgba = new Uint8ClampedArray(w * h * 4);
    for (let i = 0; i < rgba.length; i += 4) { rgba[i] = bgra[i + 2]; rgba[i + 1] = bgra[i + 1]; rgba[i + 2] = bgra[i]; rgba[i + 3] = 255; }
    const code = jsQR(rgba, w, h, { inversionAttempts: 'attemptBoth' });
    if (code && code.data) {
      try { parseId(code.data); return code.data.trim(); }
      catch { throw new Error('That QR code is not a Seal Chat ID'); }
    }
    if (scale === 1 && target >= Math.max(width, height)) break;
  }
  throw new Error('No QR code found in that picture. Try a sharper or closer picture.');
}

/** Message as the window sees it: the file's secret key never leaves the main process. */
function forWindow(m) {
  if (!m || m.kind !== 'file') return m;
  const { key, nonce, ...file } = m.file; void key; void nonce;
  return { ...m, file: { ...file, risky: isRisky(file.name), inline: INLINE.test(file.mime) } };
}

/** Small JPEG preview (max 360 px) of a photo, or null. */
function thumbFor(img, name) {
  try {
    if (!/\.(jpe?g|png|gif|bmp|webp)$/i.test(name) || !img || img.isEmpty()) return null;
    const { width, height } = img.getSize();
    const scale = Math.min(1, 360 / Math.max(width, height));
    const small = img.resize({ width: Math.max(1, Math.round(width * scale)), height: Math.max(1, Math.round(height * scale)), quality: 'good' });
    for (const q of [70, 50, 35]) { const url = 'data:image/jpeg;base64,' + small.toJPEG(q).toString('base64'); if (url.length < 88000) return url; }
  } catch { /* no preview */ }
  return null;
}

const MIME = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp', avif: 'image/avif', heic: 'image/heic', svg: 'image/svg+xml',
  mp3: 'audio/mpeg', m4a: 'audio/mp4', aac: 'audio/aac', wav: 'audio/wav', ogg: 'audio/ogg', oga: 'audio/ogg', opus: 'audio/ogg', flac: 'audio/flac', wma: 'audio/x-ms-wma',
  mp4: 'video/mp4', m4v: 'video/x-m4v', webm: 'video/webm', mov: 'video/quicktime', mkv: 'video/x-matroska', avi: 'video/x-msvideo', wmv: 'video/x-ms-wmv', ogv: 'video/ogg',
  pdf: 'application/pdf', txt: 'text/plain', doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', ppt: 'application/vnd.ms-powerpoint',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', zip: 'application/zip', '7z': 'application/x-7z-compressed', csv: 'text/csv' };
const mimeOf = p => MIME[path.extname(p).slice(1).toLowerCase()] || 'application/octet-stream';

/* ---------- helpers ---------- */
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
function cmpVersion(a, b) {
  const pa = String(a).split('.').map(n => parseInt(n, 10) || 0), pb = String(b).split('.').map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
  return 0;
}

/* =================================================================
 * 8. WEB ACCESS (1.4.0)
 * The web interface on your website is a remote screen for this app.
 * It sees only what these functions hand it: your contacts (names,
 * small pictures, last message) and chats (text; files as name + size).
 * It can send text messages and mark chats read — nothing else (no
 * keys, no settings, no deleting).
 * Off by default; see webaccess.js for how it stays quiet when idle.
 * ================================================================= */
let web = null, webFiles = null;
function setupWeb() {
  // 1.7.0: files to / from the phone (pieces waiting are kept in <data>/web-up, deleted when done)
  webFiles = new WebFiles({
    peer, files, dir: path.join(app.getPath('userData'), 'web-up'), mimeOf, webMsg: (m, cid) => webMsg(m, cid),
    thumbFor: (p, name) => thumbFor(nativeImage.createFromPath(p), name),
    onSent: (cid, m) => { send('message', { contactId: cid, msg: forWindow(m) }); send('contacts'); updateTray(); web.push({ t: 'msg', cid, msg: webMsg(m, cid) }); }
  });
  web = new WebAccess({
    state: () => { if (!store.vault.web) store.vault.web = {}; return store.vault.web; },
    save: () => store.saveVault(),
    settings: () => S(),
    setSettings: p => store.setSettings(p),
    socksPort: () => (tor && tor.ready ? tor.socksPort : null),
    handler: {
      me: () => ({ name: S().displayName || identity.name || '', avatar: smallAvatar((store.vault.me || {}).avatar) }),
      contacts: () => webContacts(),
      history: (cid, before) => {
        if (!store.contact(cid)) throw new Error('Unknown contact');
        const all = peer.history(cid);
        const end = before ? Math.max(0, all.findIndex(m => m.id === before)) : all.length;
        return { msgs: all.slice(Math.max(0, end - 60), end).map(m => webMsg(m, cid)), more: end > 60 };
      },
      send: (cid, text, re) => {
        const m = peer.send(cid, text, { re });          // 1.8.0: re = reply
        send('contacts'); send('receipts', { contactId: cid }); updateTray();   // the window shows it too
        web.push({ t: 'msg', cid, msg: webMsg(m, cid) });
        return webMsg(m, cid);
      },
      read: cid => { peer.markRead(cid); send('contacts'); updateTray(); },
      react: (cid, mid, e) => { const m = peer.react(cid, mid, e); send('msgupdate', { contactId: cid, msg: forWindow(m) }); return webMsg(m, cid); },   // 1.8.0
      // ---- 1.6.0: contacts from the phone (same actions as this window's) ----
      myId: async () => {
        const id = peer && peer.myId();
        if (!id) throw new Error('Your ID appears once Seal Chat on your computer is connected to Tor');
        return { id, handle: S().myHandle || '', qr: await QRCode.toDataURL(id, { errorCorrectionLevel: 'M', width: 600, margin: 3, color: { dark: '#000000', light: '#ffffff' } }) };
      },
      checkId: async text => {
        const rs = await resolveAdd(text);                 // 1.8.0: also name@domain
        if (rs.kind === 'invite') return { invite: rs.code }; // 1.8.0: an invite code — checked when you press Add
        const { onion, fp } = rs;
        const mine = peer && peer.myId() && peer.myId().toLowerCase() === `sealchat:${onion}:${fp}`.toLowerCase();
        const have = store.contacts().find(c => c.onion === onion);
        return { id: `sealchat:${onion}:${fp}`, onion, prettyFp: prettyFp(fp), mine: !!mine, existing: have ? { id: have.id, name: displayName(have), status: have.status } : null, handle: rs.handle || '', display: rs.display || '' };
      },
      addContact: async (id, nick) => {
        const c = await addByText(id, { nick: nick || undefined });   // 1.8.0: ID or name@domain
        send('contacts'); updateTray();
        return webContacts().find(x => x.id === c.id) || null;
      },
      contactDetails: async cid => {
        const c = store.contact(cid);
        if (!c) throw new Error('Unknown contact');
        let key = null;
        if (c.publicKey) { try { const d = await describePublic(c.publicKey); key = { name: d.name, email: d.email, created: d.created }; } catch { /* ignore */ } }
        return { contact: webContacts().find(x => x.id === cid), theirName: c.name || c.keyName || '', nick: c.nick || '', key, safety: c.fp ? safetyNumber(identity.fp, c.fp) : null, prettyFp: prettyFp(c.fp), sealId: `sealchat:${c.onion}:${c.fp}`, failReason: c.failReason || null };
      },
      contactAct: (cid, act, value) => {
        const c = store.contact(cid);
        if (!c) throw new Error('Unknown contact');
        switch (act) {
          case 'accept': peer.accept(cid); break;
          case 'decline': peer.decline(cid); break;
          case 'block': peer.block(cid); break;
          case 'unblock': peer.unblock(cid); break;
          case 'remove': peer.remove(cid); break;
          case 'rename': peer.rename(cid, String(value || '').trim()); break;
          case 'verify': peer.setVerified(cid, !!value); break;
          case 'mute': c.muted = !!value; store.putContact(c); peer.emit('contacts'); break;
          case 'retry':
            if (c.status === 'failed') { c.status = 'pending-out'; c.requested = false; c.failReason = null; c.publicKey = null; store.putContact(c); }
            peer.retryNow(cid); break;
          default: throw new Error('Unknown action');
        }
        send('contacts'); updateTray();
        return webContacts().find(x => x.id === cid) || null;   // null = removed / declined
      },
      // ---- 1.7.0: files (webfiles.js) ----
      fileMax: WEB_FILE_MAX,
      fileUp: (dev, m) => webFiles.upStart(dev, m),
      fileUpPart: (dev, m) => webFiles.upPart(dev, m),
      fileUpEnd: (dev, m) => webFiles.upEnd(dev, m),
      fileUpStop: (dev, m) => webFiles.upStop(dev, m),
      fileGet: m => webFiles.get(m),
      fileThumb: m => webFiles.thumb(m),
      fileFetch: m => { const r = webFiles.fetch(m); send('transfer', { contactId: m.cid, id: m.id, transfer: r.msg.file ? r.msg.file.transfer : null }); return r; }
    },
    // developers only (tests against a local website)
    allowHttp: !!process.env.SEALCHAT_WEB_ALLOW_HTTP,
    // 1.9.3: shared by your linked devices
    node: () => (peer && peer.device ? peer.device.id : null),
    siblings: () => (peer ? peer.siblings().length : 0),
    nodeName: id => { const d = peer && peer.myDevices().find(x => x.id === id); return d ? d.name : null; },
    syncOut: w => { if (peer) peer.syncWeb(w); }
  });
  web.on('status', st => { send('web', st); updateTray(); if (peer && peer.running && !!web.mailboxPlace() !== !!mbState.place) syncMailbox(); });
  web.on('woken', () => fetchMailbox());              // 1.8.0: a contact left something just now
  setInterval(() => fetchMailbox(), 10 * 60e3);
  setInterval(() => recheckHandles().catch(() => {}), 6 * 3600e3);    // 1.8.0
  web.on('log', l => console.log(l));
  web.on('pairRequest', r => {
    showWindow();
    send('webPair', r);
    notify('Pair a device?', `"${r.name}" wants to use Seal Chat. Check the code ${r.code} matches, then approve.`, () => showWindow());
  });
  web.start();
  // "turn off after…" is checked every minute, even while idle
  setInterval(() => { if (S().webEnabled && !web.enabled()) web.kick(); }, 60e3);
}

/* =================================================================
 * 8b. YOUR MAILBOX (1.8.0 · 1.8.5)
 * Two places contacts can leave sealed messages while this PC is off:
 *   - your website (Seal Chat Web) — "Mailbox" under Settings → Web access
 *   - 1.8.5: a free Cloudflare Worker (Settings → Mailbox) — for web hosts
 *     that block or challenge visitors that come through Tor
 * Contacts are given ONE address: the Worker when it's set up, otherwise
 * the website. Both are checked (contacts who haven't heard about the
 * change yet still use the old one). Seal Chat picks messages up when it
 * starts, every 10 minutes, and when the website says one arrived. Either
 * place only ever holds PGP-encrypted messages it can't read; who sent
 * each one is inside the encryption.
 * With no mailbox at all, contacts you both have can pass messages on
 * (the contact mailbox, peer.js 6d).
 * ================================================================= */
const workerbox = require('./workerbox');                    // 1.8.5
const mbState = { on: false, place: null, lastCheck: 0, lastError: null, got: 0,
  worker: { on: false, url: null, lastCheck: 0, lastError: null } };   // 1.8.5
const wbOpts = () => ({ socksPort: tor && tor.ready ? tor.socksPort : null, direct: S().directIfTorBlocked === true, allowHttp: !!process.env.SEALCHAT_WEB_ALLOW_HTTP });
function mailboxStatus() {
  const v = store.vault || {};
  return { ...mbState, worker: { ...mbState.worker, url: v.workerBox ? v.workerBox.url : null }, using: v.workerBox ? 'worker' : 'website',
    enabled: S().mailboxOn !== false, connected: !!(web && web.mailboxPlace()), shared: peer && peer.running ? peer.mailboxShared() : null,   // 1.8.1: shared
    contactMailbox: S().contactMailbox !== false, holding: peer && peer.running ? peer.holdingCount() : 0 };   // 1.8.5
}
function sendMailboxStatus() { send('mailbox', mailboxStatus()); }

/** Turns your mailbox(es) on/off and tells your contacts where to leave messages. */
async function syncMailbox() {
  if (!peer || !peer.running) return;
  const v = store.vault;
  let give = null;                                    // the address contacts get
  if (!v.mailboxDrop) { v.mailboxDrop = crypto.randomBytes(24).toString('base64url'); store.saveVault(); }
  const dropKey = crypto.createHash('sha256').update(v.mailboxDrop).digest('hex').slice(0, 16);

  // 1.8.5: the Cloudflare Worker
  const wb = v.workerBox;
  if (wb) {
    try {
      const key = 'w|' + wb.url + '|' + dropKey;
      if (v.workerSetFor !== key) { await workerbox.setDrop(wb, v.mailboxDrop, wbOpts()); v.workerSetFor = key; store.saveVault(); }
      give = { url: wb.url, box: wb.box, drop: v.mailboxDrop };
      mbState.worker.on = true; mbState.worker.lastError = null;
    } catch (e) {
      mbState.worker.on = false; mbState.worker.lastError = e.message;
      if (v.workerSetFor) give = { url: wb.url, box: wb.box, drop: v.mailboxDrop };   // it worked before: keep it (Tor may just be slow)
    }
  } else { mbState.worker.on = false; mbState.worker.lastError = null; }

  // your website (Seal Chat Web)
  const place = web ? web.mailboxPlace() : null;
  const want = S().mailboxOn !== false && !!place;
  // 1.9.3: web access shared by your linked devices — the website's mailbox is set up by the device that
  // connected it (its drop token is the one contacts have); the others only pick up from it
  if (place && !web.ownsMailbox()) {
    mbState.on = true; mbState.place = place; mbState.lastError = null;
    peer.setMailbox(give);                            // (contacts get the other device's address through it: sibMailbox)
    sendMailboxStatus();
    return;
  }
  try {
    if (want) {
      const key = place.box + '|' + dropKey;
      if (v.mailboxSetFor !== key) { await web.mboxSet(v.mailboxDrop); v.mailboxSetFor = key; store.saveVault(); }
      if (!give) give = { url: place.url, box: place.box, drop: v.mailboxDrop };
    } else {
      if (v.mailboxSetFor && place) await web.mboxSet(null).catch(() => {});
      if (v.mailboxSetFor) { v.mailboxSetFor = null; store.saveVault(); }
    }
    mbState.on = want; mbState.place = place; mbState.lastError = null;
  } catch (e) {
    mbState.on = false; mbState.place = place;
    mbState.lastError = /Unknown action/i.test(e.message) ? 'Your website needs Seal Chat Web 1.3.0 or newer for the mailbox (its setup page → Updates)' : e.message;
  }
  peer.setMailbox(give);
  sendMailboxStatus();
}

let mbBusy = false;
/** Picks up what contacts left in your mailbox(es). */
async function fetchMailbox() {
  if (mbBusy || !peer || !peer.running || !identity.unlocked) return;
  mbBusy = true;
  let n = 0;
  /** one place: get(ack) → { items, more } */
  const pick = async get => {
    let ack = 0;
    for (let round = 0; round < 25; round++) {
      const r = await get(ack);
      const items = r.items || [];
      for (const it of items) {
        const res = await peer.fromMailbox(it.d);
        if (res.ok) n++; else console.log('mailbox item ignored:', res.why);
        ack = Math.max(ack, Number(it.id) || 0);
      }
      if (!r.more || !items.length) break;
    }
    if (ack) await get(ack);                          // deletes what was picked up
  };
  try {
    const wb = store.vault.workerBox;                 // 1.8.5
    if (wb && store.vault.workerSetFor) {
      try { await pick(ack => workerbox.get(wb, ack, wbOpts())); mbState.worker.lastCheck = Date.now(); mbState.worker.lastError = null; mbState.worker.on = true; }
      catch (e) { mbState.worker.lastError = e.message; }
    }
    if (web && mbState.on) {
      try { await pick(ack => web.mboxGet(ack)); mbState.lastCheck = Date.now(); mbState.lastError = null; }
      catch (e) { mbState.lastError = e.message; }
    }
    mbState.got += n;
    if (n) { send('contacts'); updateTray(); }
  } finally { mbBusy = false; sendMailboxStatus(); }
}

/* ---------- 1.8.5: setting up the Cloudflare Worker (Settings → Mailbox) ---------- */
/** The Worker script for this PC (a new mailbox key the first time; the same one until connected). */
function workerScript() {
  const v = store.vault;
  if (!v.workerSetup) { v.workerSetup = v.workerBox ? { owner: v.workerBox.owner, box: v.workerBox.box } : workerbox.newSetup(); store.saveVault(); }
  return workerbox.makeScript(v.workerSetup);
}
/** Checks the Worker at that address has this PC's script, then makes it your mailbox. */
async function workerConnect(text) {
  const v = store.vault;
  if (!tor || !tor.ready) throw new Error('Wait until Seal Chat shows "Connected", then try again');
  const url = workerbox.cleanUrl(text, !!process.env.SEALCHAT_WEB_ALLOW_HTTP);
  const setup = v.workerSetup || (v.workerBox && { owner: v.workerBox.owner, box: v.workerBox.box });
  if (!setup) throw new Error('Copy the Worker script first and paste it into your Worker');
  const wb = { url, owner: setup.owner, box: setup.box };
  if (!v.mailboxDrop) { v.mailboxDrop = crypto.randomBytes(24).toString('base64url'); store.saveVault(); }
  await workerbox.setDrop(wb, v.mailboxDrop, wbOpts());           // throws a clear message if it's the wrong script / no database
  const old = v.workerBox;
  v.workerBox = wb; v.workerSetFor = 'w|' + wb.url + '|' + crypto.createHash('sha256').update(v.mailboxDrop).digest('hex').slice(0, 16);
  delete v.workerSetup;
  store.saveVault();
  if (old && old.url !== wb.url) workerbox.setDrop(old, null, wbOpts()).catch(() => {});   // the old Worker: off
  await syncMailbox();
  fetchMailbox().catch(() => {});
  return mailboxStatus();
}
/** Stops using the Worker (turns it off there too; what's waiting there is picked up first). */
async function workerRemove() {
  const v = store.vault, wb = v.workerBox;
  if (wb) {
    await fetchMailbox().catch(() => {});
    await workerbox.setDrop(wb, null, wbOpts()).catch(() => {});
  }
  delete v.workerBox; delete v.workerSetFor; delete v.workerSetup;
  store.saveVault();
  await syncMailbox();
  return mailboxStatus();
}

function webContacts() {
  return store.contacts().filter(c => c.status !== 'declined').map(c => ({
    id: c.id, name: displayName(c), status: c.status, verified: !!c.verified, muted: !!c.muted, failReason: c.failReason || null,   // 1.6.0: muted, failReason
    avatar: smallAvatar(avatarOf(c)),
    unread: c.unread || 0, lastAt: c.lastAt || c.addedAt || 0, lastText: c.lastText || '', lastDir: c.lastDir || '',
    online: !!(peer && peer.links.has(c.id)) || !!(c.lastSeen && Date.now() - c.lastSeen < 5 * 60e3 && !c.lastError),
    lastSeen: c.lastSeen || 0
  }));
}

/** A message as the web interface sees it (no file keys; the preview is asked for separately). */
function webMsg(m, cid) {
  if (!m) return m;
  const o = { id: m.id, dir: m.dir, text: m.text || '', at: m.at, state: m.state, read: m.read };
  if (m.re) o.re = { id: m.re.id, dir: m.re.dir || '', snip: m.re.snip || '' };                    // 1.8.0
  if (m.reactions && (m.reactions.me || m.reactions.them)) o.reactions = { me: m.reactions.me || '', them: m.reactions.them || '' };
  if (m.kind === 'file' && m.file) {
    o.kind = 'file';
    // 1.7.0: thumb (a preview exists), ready (complete on this computer → the phone can open it), transfer progress
    o.file = { name: m.file.name, size: m.file.size, mime: m.file.mime, thumb: !!m.file.thumb, risky: isRisky(m.file.name), removed: !!m.removed,
      ready: !!(cid && !m.removed && m.file.key && files && files.isComplete(cid + '|' + m.id, m.file)),   // same key as peer.js fileKey()
      transfer: webTransfer(m.transfer) };
  }
  return o;
}
/** Only the parts of a transfer the phone shows. */
function webTransfer(t) { return t ? { state: t.state || '', done: Number(t.done) || 0, total: Number(t.total) || 0, err: t.err || null } : null; }
/** 1.7.0: file progress → phones looking at that chat (at most twice a second per file). */
const webTransferAt = new Map();
function webPushTransfer(d) {
  if (!web || !web.hasViewers() || !d || !d.contactId) return;
  const st = d.transfer && d.transfer.state, now = Date.now(), last = webTransferAt.get(d.id) || 0;
  if (now - last < 500 && /^(uploading|downloading|preparing)$/.test(st || '')) return;
  webTransferAt.set(d.id, now);
  const m = peer.history(d.contactId).find(x => x.id === d.id);
  if (m) web.push({ t: 'msg', cid: d.contactId, msg: webMsg(m, d.contactId), update: true });
}

function webPushContacts() { if (web && web.hasViewers()) web.push({ t: 'contacts', list: webContacts() }); }
function webPushStates(cid) {
  if (!web || !web.hasViewers() || !cid) return;
  const states = peer.history(cid).filter(m => m.dir === 'out').slice(-100).map(m => [m.id, m.state]);
  web.push({ t: 'states', cid, states });
}

/** Pictures go to the web interface small (96 px, a few KB). */
const smallCache = new Map();
function smallAvatar(url) {
  if (!url) return null;
  const key = crypto.createHash('sha1').update(url).digest('hex');
  if (smallCache.has(key)) return smallCache.get(key);
  let out = null;
  try { const img = nativeImage.createFromDataURL(url); if (!img.isEmpty()) out = 'data:image/jpeg;base64,' + img.resize({ width: 96, height: 96, quality: 'good' }).toJPEG(75).toString('base64'); } catch { /* none */ }
  if (smallCache.size > 300) smallCache.clear();
  smallCache.set(key, out);
  return out;
}

/* =================================================================
 * 9. macOS (1.5.0)
 * The standard menu: without it the usual shortcuts (⌘C, ⌘V, ⌘X, ⌘A,
 * ⌘Z, ⌘Q, ⌘W, ⌘M) do nothing in a Mac app.
 * ================================================================= */
function macMenu() {
  return Menu.buildFromTemplate([
    { label: 'Seal Chat', submenu: [
      { role: 'about', label: 'About Seal Chat' },
      { type: 'separator' },
      { label: 'Settings…', accelerator: 'Cmd+,', click: () => { showWindow(); send('openSettings'); } },
      { type: 'separator' },
      { role: 'hide', label: 'Hide Seal Chat' }, { role: 'hideOthers' }, { role: 'unhide' },
      { type: 'separator' },
      { label: 'Quit Seal Chat', accelerator: 'Cmd+Q', click: () => quitApp() }
    ] },
    { role: 'editMenu' },
    { label: 'View', submenu: [{ role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { type: 'separator' }, { role: 'togglefullscreen' }] },
    { role: 'windowMenu' }
  ]);
}
