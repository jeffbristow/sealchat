/* =====================================================================
 * Seal Chat — app.js   (the window's logic, 1.0.0 · 1.8.0)
 * ---------------------------------------------------------------------
 * Sections:
 *   1. Helpers (calls, toast, pop-up, menu, text, time, avatars)
 *   2. Which screen to show
 *   3. App lock screen
 *   4. Setup (own key / new key / restore)
 *   5. Unlock key
 *   6. Sidebar: connection pill, your ID, contact list
 *   7. Chat: open, messages, sending, banners, menus
 *   7b. Files (1.1.0): file bubbles, progress, attach / drag / paste,
 *       photo viewer
 *   7c. Replies + reactions (1.8.0): quote, reaction badges, hover
 *       buttons, "Replying to…" bar
 *   8. Add contact (paste, QR picture, webcam scan) + contact details
 *      (safety number, picture choice)
 *   9. Settings
 *  10. Events from Seal Chat's engine
 *  11. Start
 * ===================================================================== */
'use strict';

/* =================================================================
 * 1. HELPERS
 * ================================================================= */
const $ = id => document.getElementById(id);
// window.api (from preload.js) is available here as "api"

/** Calls the main process; throws a normal Error on failure. */
async function call(ch, ...args) {
  const r = await api.call(ch, ...args);
  if (!r.ok) { if (r.code === 'LOCKED') showLock(); const e = new Error(r.error || 'Something went wrong'); e.code = r.code; throw e; }
  return r.data;
}

let toastTimer = null;
function toast(text, bad = false) {
  const t = $('toast'); t.textContent = text; t.className = 'toast' + (bad ? ' bad' : '');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.add('hidden'), bad ? 5000 : 2600);
}

function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

/** Escapes text and turns web links into links that open in your browser. */
function linkify(text) {
  return esc(text).replace(/\bhttps?:\/\/[^\s<>"']+[^\s<>"'.,;:!?)\]]/g, u => `<a href="#" data-ext="${u}">${u}</a>`);
}

/* ---------- pop-up (one at a time) ---------- */
let modalOk = null, modalCancel = null;
function modal({ title, html, ok = 'OK', cancel = 'Cancel', onOk, onCancel = null, danger = false, wide = false }) {
  $('mTitle').textContent = title;
  $('mBody').innerHTML = html;
  $('mErr').textContent = '';
  $('mOk').textContent = ok; $('mOk').className = 'btn ' + (danger ? 'danger' : 'primary'); $('mOk').classList.toggle('hidden', !ok);
  $('mCancel').textContent = cancel;
  document.querySelector('.modal-box').style.width = wide ? '640px' : '';
  modalOk = onOk || (() => true);
  modalCancel = onCancel;
  $('modal').classList.remove('hidden');
  const first = $('mBody').querySelector('input:not([type=checkbox]):not([type=radio]), textarea');
  if (first) setTimeout(() => first.focus(), 30);
}
function closeModal() { $('modal').classList.add('hidden'); modalOk = null; modalCancel = null; }
/** Cancel / Esc: closes the pop-up and tells whoever opened it (1.4.0). */
function cancelModal() { const f = modalCancel; closeModal(); if (f) f(); }
$('mCancel').onclick = cancelModal;
$('mOk').onclick = async () => {
  if (!modalOk) return closeModal();
  $('mOk').disabled = true;
  try { const r = await modalOk(); if (r !== false) closeModal(); }
  catch (e) { $('mErr').textContent = e.message; }
  finally { $('mOk').disabled = false; }
};
$('modal').addEventListener('keydown', e => {
  if (e.key === 'Escape') { cancelModal(); e.stopPropagation(); }   // closes only the pop-up
  if (e.key === 'Enter' && e.target.tagName === 'INPUT') $('mOk').click();
});

/* ---------- small menu ---------- */
function menu(items, x, y) {
  const m = $('menu');
  m.innerHTML = '';
  for (const it of items) {
    if (it === '-') { m.appendChild(document.createElement('hr')); continue; }
    const b = document.createElement('button');
    b.textContent = it.label; if (it.danger) b.className = 'danger';
    b.onclick = () => { hideMenu(); it.run(); };
    m.appendChild(b);
  }
  m.classList.remove('hidden');
  const r = m.getBoundingClientRect();
  m.style.left = Math.min(x, innerWidth - r.width - 8) + 'px';
  m.style.top = Math.min(y, innerHeight - r.height - 8) + 'px';
}
function hideMenu() { $('menu').classList.add('hidden'); }
document.addEventListener('mousedown', e => { if (!$('menu').contains(e.target)) hideMenu(); });

/* ---------- time ---------- */
const sameDay = (a, b) => new Date(a).toDateString() === new Date(b).toDateString();
function timeOf(ts) { return new Date(ts).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }); }
function shortWhen(ts) {
  if (!ts) return '';
  if (sameDay(ts, Date.now())) return timeOf(ts);
  if (Date.now() - ts < 6 * 864e5) return new Date(ts).toLocaleDateString([], { weekday: 'short' });
  return new Date(ts).toLocaleDateString([], { month: 'short', day: 'numeric' });
}
function dayLabel(ts) {
  if (sameDay(ts, Date.now())) return 'Today';
  if (sameDay(ts, Date.now() - 864e5)) return 'Yesterday';
  return new Date(ts).toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' });
}
function ago(ts) {
  if (!ts) return 'never';
  const s = (Date.now() - ts) / 1000;
  if (s < 90) return 'just now';
  if (s < 3600) return Math.round(s / 60) + ' min ago';
  if (s < 86400) return Math.round(s / 3600) + ' h ago';
  return shortWhen(ts);
}

/* ---------- avatars: initials on a colour picked from the fingerprint ---------- */
const COLORS = ['#3ccf91', '#5aa9ff', '#f0b445', '#c58af9', '#ff8f6b', '#4fd1d9', '#e7d36f', '#ff7aa8', '#8fd18a'];
function avatarHtml(c, cls = '') {
  const initials = (c.name || '?').trim().split(/\s+/).map(w => (/[\p{L}\p{N}]/u.exec(w) || [''])[0]).join('').slice(0, 2).toUpperCase() || '?';
  const color = COLORS[parseInt(String(c.fp || '0').slice(-4), 16) % COLORS.length];
  const online = c.linked || (c.lastSeen && Date.now() - c.lastSeen < 5 * 60e3 && !c.lastError);
  // 1.2.0: a picture when there is one (theirs, or the one you chose for them)
  if (c.avatar && /^data:image\/(jpeg|png);base64,/.test(c.avatar)) return `<div class="avatar ${cls}" style="background:${color}"><img src="${c.avatar}" alt=""><i class="pres ${online ? 'on' : ''}"></i></div>`;
  return `<div class="avatar ${cls}" style="background:${color}">${esc(initials)}<i class="pres ${online ? 'on' : ''}"></i></div>`;
}

// links inside chats / settings open in the normal browser
document.addEventListener('click', e => {
  const a = e.target.closest('[data-ext]');
  if (a) { e.preventDefault(); call('app:openExternal', a.dataset.ext).catch(() => {}); }
});

/* ---------- 1.2.0: Linux wording (the window text is written for Windows) ---------- */
let platform = 'win32';
function osFix(root = document.body) {
  if (platform === 'win32') return;
  const swaps = platform === 'darwin'
    // 1.5.0: macOS wording
    ? [[/your Windows account/g, 'your Mac account (Keychain)'], [/this PC's Windows account/g, 'this Mac\'s account'], [/sign in to Windows/g, 'log in to this Mac'], [/Windows locks/g, 'the screen locks'],
      [/in the tray/g, 'in the menu bar'], [/\bthis PC\b/g, 'this Mac'], [/\byour PC\b/g, 'your Mac'], [/\bnew PC\b/g, 'new Mac'], [/\bthe PC\b/g, 'the Mac'], [/\bPCs\b/g, 'computers']]
    : [[/your Windows account/g, 'your Linux account (keyring)'], [/this PC's Windows account/g, 'this computer\'s account'], [/sign in to Windows/g, 'sign in'], [/Windows locks/g, 'the screen locks']];
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let n = w.nextNode(); n; n = w.nextNode()) { let t = n.nodeValue; for (const [a, b] of swaps) t = t.replace(a, b); if (t !== n.nodeValue) n.nodeValue = t; }
}

/* =================================================================
 * 2. SCREENS
 * ================================================================= */
const SCREENS = ['lockScreen', 'setupScreen', 'unlockScreen', 'mainScreen', 'settingsScreen'];
function show(id) { for (const s of SCREENS) $(s).classList.toggle('hidden', s !== id); }

let me = null;
async function route() {
  const lk = await call('lock:status');
  if (lk.locked) return showLock(lk);
  const st = await call('setup:state');
  if (st.stage === 'welcome') { show('setupScreen'); setupStep('stWelcome'); return; }
  if (st.stage === 'unlock') { show('unlockScreen'); setTimeout(() => $('ukPass').focus(), 50); return; }
  show('mainScreen');
  await refreshMe();
  await refreshContacts();
  if (currentId) openChat(currentId, { keepScroll: true });
}

/* =================================================================
 * 3. APP LOCK
 * ================================================================= */
async function showLock(lk) {
  lk = lk || await api.call('lock:status').then(r => r.data || {});
  show('lockScreen');
  $('lockErr').textContent = '';
  $('lockHello').classList.toggle('hidden', !lk.hello);
  $('lockPin').value = '';
  setTimeout(() => $('lockPin').focus(), 50);
}
$('lockGo').onclick = async () => {
  try { await call('lock:unlockPin', $('lockPin').value); route(); }
  catch (e) { $('lockErr').textContent = e.message; $('lockPin').select(); }
};
$('lockPin').onkeydown = e => { if (e.key === 'Enter') $('lockGo').click(); };
$('lockHello').onclick = async () => {
  try { await call('lock:unlockHello'); route(); } catch (e) { $('lockErr').textContent = e.message; }
};

/* =================================================================
 * 4. SETUP
 * ================================================================= */
function setupStep(id) {
  // 1.9.4: the steps are read from the page (the list here had no 'stLink', so "Link to my Seal Chat on another
  // device" showed an empty screen — thanks to the developer who found it); a new step can't be forgotten again
  for (const s of document.querySelectorAll('#setupScreen .card.setup > div[id^="st"]')) s.classList.toggle('hidden', s.id !== id);
  const f = $(id).querySelector('textarea, input'); if (f) setTimeout(() => f.focus(), 30);
}
document.querySelectorAll('.choice').forEach(b => b.onclick = () => setupStep(b.dataset.step));
document.querySelectorAll('#setupScreen .back').forEach(b => b.onclick = () => setupStep('stWelcome'));

async function busy(btn, fn) {
  const label = btn.textContent; btn.disabled = true; btn.textContent = 'Working…';
  try { return await fn(); } finally { btn.disabled = false; btn.textContent = label; }
}

$('impFile').onclick = async () => {
  try { const t = await call('setup:pickKeyFile'); if (t) { $('impKey').value = t; $('impInfo').textContent = 'Key loaded from file.'; $('impPass').focus(); } }
  catch (e) { $('impErr').textContent = e.message; }
};
$('impGo').onclick = () => busy($('impGo'), async () => {
  $('impErr').textContent = '';
  try {
    await call('setup:importKey', { armored: $('impKey').value, passphrase: $('impPass').value, remember: $('impRemember').checked, displayName: $('impName').value.trim() });
    $('impKey').value = ''; $('impPass').value = '';
    route();
  } catch (e) { $('impErr').textContent = e.message; }
});
$('newGo').onclick = () => busy($('newGo'), async () => {
  $('newErr').textContent = '';
  if ($('newPass').value !== $('newPass2').value) { $('newErr').textContent = 'The passphrases are different'; return; }
  try {
    await call('setup:generate', { name: $('newName').value, passphrase: $('newPass').value, remember: $('newRemember').checked });
    $('newPass').value = $('newPass2').value = '';
    route();
    toast('Your key is ready. Make a backup in Settings once you\'re connected.');
  } catch (e) { $('newErr').textContent = e.message; }
});
// 1.9.0: link this computer to your Seal Chat on another device
$('lnkGo').onclick = () => busy($('lnkGo'), async () => {
  $('lnkErr').textContent = '';
  try {
    const r = await call('setup:link', { code: $('lnkCode').value, passphrase: $('lnkPass').value, name: $('lnkName').value.trim(), remember: $('lnkRemember').checked });
    if (r) { $('lnkPass').value = ''; $('lnkCode').value = ''; route(); toast('Linked — your contacts and chats are on their way'); }
  } catch (e) { $('lnkErr').textContent = e.message; }
});
$('resGo').onclick = () => busy($('resGo'), async () => {
  $('resErr').textContent = '';
  try { const r = await call('setup:restore', { password: $('resPass').value }); if (r) { $('resPass').value = ''; route(); toast('Backup restored'); } }
  catch (e) { $('resErr').textContent = e.message; }
});

/* =================================================================
 * 5. UNLOCK KEY
 * ================================================================= */
$('ukGo').onclick = () => busy($('ukGo'), async () => {
  try { await call('identity:unlock', { passphrase: $('ukPass').value, remember: $('ukRemember').checked }); $('ukPass').value = ''; route(); }
  catch (e) { $('ukErr').textContent = e.message; $('ukPass').select(); }
});
$('ukPass').onkeydown = e => { if (e.key === 'Enter') $('ukGo').click(); };

/* =================================================================
 * 6. SIDEBAR
 * ================================================================= */
async function refreshMe() {
  me = await call('me:get');
  netPill(me.tor, me.online);
  $('myIdShort').textContent = me.sealId ? me.sealId.slice(0, 22) + '…' : (me.tor && me.tor.ready ? 'Publishing your address…' : 'Waiting for Tor…');
  $('idBox').textContent = me.sealId || 'Your ID appears once Seal Chat is connected to Tor (usually under a minute).';
  $('btnCopyId').disabled = !me.sealId;
  $('btnQrSave').disabled = $('btnQrCopy').disabled = !me.sealId;
  if (me.sealId && $('qrBox').dataset.id !== me.sealId) {
    try { const q = await call('qr:mine'); $('qrImg').src = q.dataUrl; $('qrBox').dataset.id = q.id; $('qrBox').classList.remove('hidden'); document.querySelector('#emptyPane .hero-icon').classList.add('hidden'); } catch { /* not yet */ }
  }
  osFix();
  $('idFp').textContent = me.fp ? 'Your key fingerprint: ' + me.prettyFp : '';
  $('idHandle').textContent = me.handle ? 'Or they can add you by your name: ' + me.handle : '';   // 1.8.0
  $('idHandle').classList.toggle('hidden', !me.handle);
}

function netPill(t, online) {
  const p = $('netPill');
  p.classList.toggle('on', !!online);
  p.classList.toggle('err', !!(t && t.error));
  $('netText').textContent = online ? 'Online via Tor' : t ? (t.error ? 'Tor problem — click for details' : `${t.summary || 'Connecting…'}${t.progress && t.progress < 100 ? ` (${t.progress}%)` : ''}`) : 'Starting…';
}
$('netPill').onclick = () => { openSettings('tStatus'); };

async function copyMyId() {
  try { await call('me:copyId'); toast('Your Seal Chat ID is copied — paste it to your contact'); } catch (e) { toast(e.message, true); }
}
/* 1.2.1: back to the home screen (your ID + QR code) — the ID box at the
 * bottom left, the Seal Chat logo, or Esc while a chat is open */
function goHome() {
  if (!$('settingsScreen').classList.contains('hidden')) { show('mainScreen'); refreshContacts(); }
  if (currentId) closeChat();
  refreshMe().catch(() => {});
}
$('btnMyId').onclick = goHome;
$('brandHome').onclick = e => { if (!e.target.closest('#btnSettings')) goHome(); };
$('btnCopyId').onclick = copyMyId;
$('btnQrSave').onclick = () => call('qr:save').then(p => p && toastAction('QR picture saved', 'Show in folder', () => call('file:showSaved', p))).catch(e => toast(e.message, true));
$('btnQrCopy').onclick = () => call('qr:copy').then(() => toast('QR picture copied — paste it into an email or message')).catch(e => toast(e.message, true));

let contacts = [];
let currentId = null;
async function refreshContacts() {
  contacts = await call('contacts:list');
  renderContacts();
  if (currentId) {
    const c = contacts.find(x => x.id === currentId);
    if (!c) closeChat(); else renderChatHead(c);
  }
}

function renderContacts() {
  const q = $('search').value.trim().toLowerCase();
  const list = contacts.filter(c => !q || c.name.toLowerCase().includes(q) || c.fp.toLowerCase().includes(q));
  const req = list.filter(c => c.status === 'pending-in');
  const rest = list.filter(c => c.status !== 'pending-in');
  let html = '';
  if (req.length) {
    html += `<div class="sec-label">Contact requests</div>`;
    for (const c of req) html += contactRow(c, 'Wants to chat with you');
  }
  if (rest.length) {
    if (req.length) html += `<div class="sec-label">Chats</div>`;
    for (const c of rest) html += contactRow(c);
  }
  if (!list.length) html = `<p class="muted small" style="padding:10px 8px">${q ? 'No match.' : 'No contacts yet. Click <b>＋ Add contact</b> and paste someone\'s Seal Chat ID, or send them yours.'}</p>`;
  $('contactList').innerHTML = html;
}

function contactRow(c, override) {
  let last = override || '';
  if (!last) {
    if (c.status === 'pending-out') last = c.requested ? 'Waiting for them to accept' : 'Sending your request…';
    else if (c.status === 'blocked') last = 'Blocked';
    else if (c.status === 'failed') last = '⚠ ' + (c.failReason || 'Could not add');
    else last = (c.lastDir === 'out' ? 'You: ' : '') + (c.lastText || '');
    if (c.queued && c.status === 'accepted') last = `⏱ ${c.queued} waiting · ` + last;
  }
  return `<div class="contact ${c.id === currentId ? 'active' : ''} ${c.status === 'pending-in' ? 'request' : ''}" data-id="${c.id}">
    ${avatarHtml(c)}
    <div class="meta"><div class="top"><span class="nm">${esc(c.name)}</span><span class="when">${shortWhen(c.lastAt)}</span></div>
    <div class="row gap"><span class="last grow">${esc(last)}</span>${c.unread ? `<span class="unread">${c.unread}</span>` : ''}</div></div></div>`;
}

$('search').oninput = renderContacts;
$('contactList').onclick = e => { const row = e.target.closest('.contact'); if (row) openChat(row.dataset.id); };
$('contactList').oncontextmenu = e => {
  const row = e.target.closest('.contact'); if (!row) return;
  e.preventDefault(); contactMenu(row.dataset.id, e.clientX, e.clientY);
};

/* =================================================================
 * 7. CHAT
 * ================================================================= */
let messages = [];
async function openChat(id, { keepScroll = false } = {}) {
  const c = contacts.find(x => x.id === id);
  if (!c) return;
  const switching = currentId !== id;
  currentId = id;
  renderContacts();
  $('emptyPane').classList.add('hidden');
  $('chatPane').classList.remove('hidden');
  renderChatHead(c);
  messages = await call('chat:history', id);
  renderMessages(!keepScroll || switching);
  await call('chat:open', id);
  if (c.unread) { c.unread = 0; renderContacts(); }
  if (switching) { endReply(); $('msgInput').value = drafts.get(id) || ''; autoSize(); $('msgInput').focus(); }
}

function closeChat() {
  currentId = null; messages = [];
  $('chatPane').classList.add('hidden'); $('emptyPane').classList.remove('hidden');
  call('chat:close').catch(() => {});
  renderContacts();
}

function renderChatHead(c) {
  $('chAvatar').outerHTML = avatarHtml(c).replace('class="avatar ', 'id="chAvatar" class="avatar ');
  $('chName').textContent = c.name;
  $('chVerified').classList.toggle('hidden', !c.verified);
  let sub;
  if (c.linked) sub = 'Online — connected';
  else if (c.lastSeen && Date.now() - c.lastSeen < 5 * 60e3 && !c.lastError) sub = 'Online';
  else if (c.lastReached || c.lastSeen) sub = 'Last reachable ' + ago(Math.max(c.lastReached || 0, c.lastSeen || 0));
  else sub = 'Not reached yet';
  if (c.queued && c.status === 'accepted') sub += ` · ${c.queued} waiting to send${c.nextTry ? ', next try ' + (c.nextTry - Date.now() < 15e3 ? 'now' : 'in ' + Math.max(1, Math.round((c.nextTry - Date.now()) / 60e3)) + ' min') : ''}`;
  $('chSub').textContent = sub;

  // banner explaining the state of this contact
  const b = $('chBanner');
  b.className = 'banner hidden'; b.innerHTML = '';
  const set = (cls, html) => { b.className = 'banner ' + cls; b.innerHTML = html; };
  if (c.status === 'pending-in') {
    set('info', `<span class="grow"><b>${esc(c.theirName || c.name)}</b> wants to chat with you.${c.invite ? ` 🎟 They used your invite code “${esc(c.invite)}”.` : ''}${c.note ? ` Their note: “${esc(c.note)}”` : ''} Check the fingerprint (ⓘ) if you're not sure it's them.</span>
      <button class="btn primary" data-act="accept">Accept</button><button class="btn" data-act="decline">Decline</button><button class="btn danger" data-act="block">Block</button>`);
  } else if (c.status === 'pending-out') {
    set('', c.requested ? `<span class="grow">${c.viaInvite ? (c.viaInvite.multi ? '🎟 Invite code accepted. ' : '🎟 Invite code accepted — adding you both… ') : ''}Request sent. Messages you write now are delivered once ${esc(c.name)} accepts.</span>`
      : `<span class="grow">Sending your contact request… ${esc(c.lastError ? '(' + c.lastError + ')' : '')}</span><button class="btn" data-act="retry">Try now</button>`);
  } else if (c.status === 'failed') {
    set('bad', `<span class="grow">⚠ ${esc(c.failReason || 'Could not add this contact')}</span><button class="btn" data-act="retry">Try again</button><button class="btn danger" data-act="remove">Remove</button>`);
  } else if (c.status === 'blocked') {
    set('bad', `<span class="grow">You blocked this contact. Their messages are refused.</span><button class="btn" data-act="unblock">Unblock</button>`);
  } else if (c.handleWarning) {                                       // 1.8.0
    set('bad', `<span class="grow">⚠ ${esc(c.handleWarning)}</span>`);
  } else if (c.queued && c.lastError) {
    set('', `<span class="grow">⏱ ${c.queued} message${c.queued > 1 ? 's' : ''} waiting: ${esc(c.lastError)}. They'll be sent automatically when ${esc(c.name)} is online.</span><button class="btn" data-act="retry">Try now</button>`);
  }
  const canWrite = c.status === 'accepted' || c.status === 'pending-out';
  $('msgInput').disabled = !canWrite; $('msgSend').disabled = !canWrite; $('msgEmoji').disabled = !canWrite;
  $('msgInput').placeholder = canWrite ? `Message ${c.name}` : c.status === 'pending-in' ? 'Accept the request to reply' : 'You can\'t send messages to this contact';
}

$('chBanner').onclick = async e => {
  const act = e.target.dataset && e.target.dataset.act; if (!act || !currentId) return;
  const id = currentId;
  try {
    if (act === 'accept') { await call('contacts:accept', id); toast('Accepted — you can chat now'); }
    if (act === 'decline') { await call('contacts:decline', id); closeChat(); }
    if (act === 'block') { await call('contacts:block', id); }
    if (act === 'unblock') { await call('contacts:unblock', id); }
    if (act === 'retry') { await call('contacts:retry', id); toast('Trying now…'); }
    if (act === 'remove') { await call('contacts:remove', id); closeChat(); }
    refreshContacts();
  } catch (err) { toast(err.message, true); }
};

function tickHtml(m) {
  if (m.dir !== 'out' || m.state === 'preparing' || m.state === 'failed') return '';
  if (m.state === 'queued') return '<span class="tick" title="Waiting to send — will go when they are online">⏱</span>';
  if (m.state === 'mailbox' && m.heldBy && m.heldBy.length) return `<span class="tick" title="Left with ${esc(m.heldBy.join(', '))} ${m.mailboxAt ? new Date(m.mailboxAt).toLocaleString() : ''} — passed on when they're both online (they can't read it)">📬</span>`;   // 1.8.5: contact mailbox
  if (m.state === 'mailbox') return `<span class="tick" title="Left in their mailbox ${m.mailboxAt ? new Date(m.mailboxAt).toLocaleString() : ''} — they get it when their Seal Chat starts">📬</span>`;   // 1.8.0
  if (m.state === 'read') return `<span class="tick read" title="Read ${m.readAt ? new Date(m.readAt).toLocaleString() : ''}">✓✓</span>`;
  return `<span class="tick" title="Delivered ${m.deliveredAt ? new Date(m.deliveredAt).toLocaleString() : ''}">✓</span>`;
}

/**
 * Draws the conversation. Bubbles that haven't changed are kept as they are
 * (so a playing video or a half-scrolled photo isn't reloaded when a new
 * message arrives).
 */
function renderMessages(scrollToEnd = true) {
  const list = $('msgList');
  const nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 80;
  if (!messages.length) {
    list.innerHTML = `<p class="muted small" style="align-self:center;margin-top:30px">No messages yet. Everything you send — text or files — is signed and encrypted for this contact only.</p>`;
    return;
  }
  const old = new Map([...list.children].filter(n => n.dataset && n.dataset.key).map(n => [n.dataset.key, n]));
  const nodes = [];
  let prev = null;
  for (const m of messages) {
    if (!prev || !sameDay(prev.at, m.at)) {
      const key = 'day-' + new Date(m.at).toDateString();
      nodes.push(old.get(key) || htmlNode(`<div class="day" data-key="${key}">${dayLabel(m.at)}</div>`));
    }
    const same = prev && prev.dir === m.dir && m.at - prev.at < 120e3 && sameDay(prev.at, m.at);
    const sig = [m.id, m.state, m.transfer && m.transfer.state, m.removed ? 'r' : '', same ? 's' : '', reactSig(m), m.re ? m.re.dir + m.re.snip : ''].join('|');
    const keep = old.get('m-' + m.id);
    if (keep && keep.dataset.sig === sig) nodes.push(keep);
    else nodes.push(htmlNode(m.kind === 'file' ? fileBubble(m, same, sig) : `<div class="bubble ${m.dir} ${m.state === 'queued' ? 'queued' : ''} ${same ? 'same' : ''} ${window.SCEmoji && SCEmoji.isJumbo(m.text) ? 'jumbo' : ''}" data-key="m-${m.id}" data-sig="${esc(sig)}" data-id="${m.id}">${quoteHtml(m)}<div class="txt">${linkify(m.text)}</div><div class="ft"><span title="${new Date(m.at).toLocaleString()}">${timeOf(m.at)}</span>${tickHtml(m)}</div>${reactsHtml(m)}${actsHtml(m)}</div>`));
    prev = m;
  }
  // put the nodes in place, moving only what changed
  [...list.children].forEach(n => { if (!nodes.includes(n)) n.remove(); });
  nodes.forEach((n, i) => { if (list.children[i] !== n) list.insertBefore(n, list.children[i] || null); });
  if (scrollToEnd || nearBottom) {
    list.scrollTop = list.scrollHeight;
    // photos and videos get their height once loaded: stay at the bottom
    for (const el of list.querySelectorAll('img.fimg:not([data-stick]), video:not([data-stick])')) {
      el.dataset.stick = '1';
      el.addEventListener(el.tagName === 'IMG' ? 'load' : 'loadedmetadata', () => { if (list.scrollHeight - list.scrollTop - list.clientHeight < 600) list.scrollTop = list.scrollHeight; }, { once: true });
    }
  }
}
function htmlNode(html) { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; }

$('msgList').oncontextmenu = e => {
  const b = e.target.closest('.bubble'); if (!b) return;
  e.preventDefault();
  const m = messages.find(x => x.id === b.dataset.id); if (!m) return;
  const sel = String(getSelection());
  const items = [];
  // 1.8.0: reply + react (only where you can write)
  if (canReact()) {
    items.push({ label: '↩ Reply', run: () => startReply(m) });
    items.push({ label: (m.reactions && m.reactions.me ? 'Change reaction… (' + m.reactions.me + ')' : '🙂 React…'), run: () => reactPicker(m, e.clientX, e.clientY) });
    if (m.reactions && m.reactions.me) items.push({ label: 'Remove my reaction', run: () => sendReaction(m, '') });
    items.push('-');
  }
  if (m.kind === 'file') {
    if (fileReady(m)) {
      if (!m.file.risky) items.push({ label: 'Open', run: () => openFile(m) });
      items.push({ label: 'Save as…', run: () => saveFile(m) });
    }
    if (m.text) items.push({ label: 'Copy caption', run: () => call('clipboard:write', m.text) });
  } else items.push({ label: sel ? 'Copy selection' : 'Copy text', run: () => call('clipboard:write', sel || m.text) });
  items.push({ label: m.kind === 'file' ? 'Delete (message and file) from this PC' : 'Delete from this PC', danger: true, run: async () => { await call('chat:delete', currentId, m.id); messages = messages.filter(x => x !== m); renderMessages(false); } });
  menu(items, e.clientX, e.clientY);
};

/* ---------- composer ---------- */
const drafts = new Map();
let enterToSend = true;
let emojiConvert = false;   // 1.6.1: ":)" → 🙂 while typing (Settings → App)
function autoSize() { const t = $('msgInput'); t.style.height = 'auto'; t.style.height = Math.min(180, t.scrollHeight + 2) + 'px'; }
$('msgInput').oninput = () => { autoSize(); if (currentId) drafts.set(currentId, $('msgInput').value); };
$('msgInput').onkeydown = e => {
  if (e.key === 'Enter' && !e.shiftKey && (enterToSend || e.ctrlKey)) { e.preventDefault(); sendNow(); }
};
$('msgSend').onclick = sendNow;
// 1.6.1: emoji — the 😊 picker, ":smile" suggestions, optional ":)" → 🙂 (emoji-picker.js)
const emoji = SCEmoji.attach({ input: $('msgInput'), button: $('msgEmoji'), dataUrl: 'emoji-data.js', convert: () => emojiConvert, onError: e => toast(e.message, true) });
async function sendNow() {
  const text = $('msgInput').value;
  if (!text.trim() || !currentId) return;
  try {
    const m = await call('chat:send', currentId, text, { re: replyTo && replyTo.id });   // 1.8.0
    $('msgInput').value = ''; drafts.delete(currentId); autoSize(); endReply();
    messages.push(m); renderMessages(true);
  } catch (e) { toast(e.message, true); }
}

/* =================================================================
 * 7c. REPLIES + REACTIONS (1.8.0)
 * Hover a message (or right-click it) → ↩ Reply / 🙂 React. A reply shows
 * the quoted excerpt above it (click it to jump to the original). Each
 * person can put one emoji on a message; click your own to take it back.
 * ================================================================= */
const QUICK_REACTS = ['👍', '❤️', '😂', '😮', '😢', '🙏'];
let replyTo = null;          // the message being answered, or null

function canReact() { const c = contacts.find(x => x.id === currentId); return !!c && c.status === 'accepted'; }
function contactName() { const c = contacts.find(x => x.id === currentId); return c ? c.name : 'Them'; }
function reactSig(m) { const r = m.reactions || {}; return (r.me || '') + '/' + (r.them || ''); }

function quoteHtml(m) {
  if (!m.re) return '';
  const who = m.re.dir === 'out' ? 'You' : m.re.dir === 'in' ? contactName() : '';
  return `<div class="quote" data-act="jump" data-jump="${esc(m.re.id)}" title="Show the original">${who ? `<b>${esc(who)}</b>` : ''}<span>${esc(m.re.snip || 'Message')}</span></div>`;
}
function reactsHtml(m) {
  const r = m.reactions || {};
  if (!r.me && !r.them) return '';
  const chip = (e, who, mine) => `<button class="react${mine ? ' mine' : ''}" ${mine ? 'data-act="unreact"' : ''} title="${esc(who)}${mine ? ' — click to remove' : ''}">${esc(e)}</button>`;
  return `<div class="reacts">${r.them ? chip(r.them, contactName(), false) : ''}${r.me ? chip(r.me, 'You', true) : ''}</div>`;
}
function actsHtml(m) {
  if (!canReact() || m.state === 'preparing') return '';
  return `<div class="bacts"><button data-act="reply" title="Reply">↩</button><button data-act="react" title="React">🙂</button></div>`;
}

function startReply(m) {
  replyTo = m;
  const who = m.dir === 'out' ? 'yourself' : contactName();
  const snip = m.kind === 'file' ? '📎 ' + m.file.name : String(m.text || '').replace(/\s+/g, ' ').slice(0, 140);
  $('replyBar').innerHTML = `<span class="grow"><b>↩ Replying to ${esc(who)}</b><span class="muted"> ${esc(snip)}</span></span><button class="icon-btn" id="replyCancel" title="Cancel reply">✕</button>`;
  $('replyBar').classList.remove('hidden');
  $('replyCancel').onclick = endReply;
  $('msgInput').focus();
}
function endReply() { replyTo = null; const b = $('replyBar'); if (b) { b.classList.add('hidden'); b.innerHTML = ''; } }

async function sendReaction(m, e) {
  try { const upd = await call('chat:react', currentId, m.id, e); const i = messages.findIndex(x => x.id === m.id); if (i >= 0) messages[i] = upd; renderMessages(false); }
  catch (err) { toast(err.message, true); }
}
function reactPicker(m, x, y) {
  const mine = m.reactions && m.reactions.me;
  menu(QUICK_REACTS.map(e => ({ label: (e === mine ? '✓ ' : '') + e, run: () => sendReaction(m, e === mine ? '' : e) })), x, y);
  $('menu').classList.add('react-menu');
  setTimeout(() => document.addEventListener('mousedown', () => $('menu').classList.remove('react-menu'), { once: true }), 0);
}
function jumpTo(id) {
  const el = $('msgList').querySelector(`.bubble[data-id="${CSS.escape(id)}"]`);
  if (!el) return toast('The original message is no longer in this chat');
  el.scrollIntoView({ block: 'center', behavior: 'smooth' });
  el.classList.add('flash'); setTimeout(() => el.classList.remove('flash'), 1400);
}
// (Esc while replying: handled with the other Esc keys in section 7 — it cancels the reply, not the chat)

/* =================================================================
 * 7b. FILES (1.1.0)
 * ================================================================= */
function fmtSize(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' bytes';
  const u = ['KB', 'MB', 'GB', 'TB']; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return (n >= 100 ? Math.round(n) : n.toFixed(1)) + ' ' + u[i];
}
const fileUrl = m => `${window.SC_FILE_BASE || 'scfile://f/'}${encodeURIComponent(currentId)}/${encodeURIComponent(m.id)}`;   // (1.9.0: the Android app serves them from its local bridge)
/** The file's data is complete on this PC. */
const fileReady = m => !m.removed && (m.dir === 'in' ? m.transfer && m.transfer.state === 'done' : !['preparing', 'failed'].includes(m.state));
const kindOf = m => { const t = m.file.mime || ''; return t.startsWith('image/') ? 'image' : t.startsWith('video/') ? 'video' : t.startsWith('audio/') ? 'audio' : 'doc'; };
function fileIcon(m) {
  const n = m.file.name.toLowerCase(), k = kindOf(m);
  if (m.file.risky) return '⚠️';
  if (k === 'image') return '🖼️'; if (k === 'video') return '🎬'; if (k === 'audio') return '🎵';
  if (/\.pdf$/.test(n)) return '📕'; if (/\.(docx?|odt|rtf|txt|md)$/.test(n)) return '📄'; if (/\.(xlsx?|csv|ods)$/.test(n)) return '📊';
  if (/\.(pptx?|odp|key)$/.test(n)) return '📽️'; if (/\.(zip|7z|rar|tar|gz)$/.test(n)) return '🗜️';
  return '📎';
}

/** One file message (photo / video / audio / document). */
function fileBubble(m, same, sig) {
  const f = m.file, k = kindOf(m), ready = fileReady(m);
  let media = '';
  if (ready && f.inline && k === 'image') media = `<img class="fimg" src="${fileUrl(m)}" alt="" data-act="view" loading="lazy">`;
  else if (ready && f.inline && k === 'video') media = `<video class="fvid" src="${fileUrl(m)}" controls preload="metadata"></video>`;
  else if (ready && f.inline && k === 'audio') media = `<audio class="faud" src="${fileUrl(m)}" controls preload="metadata"></audio>`;
  else if (f.thumb && !m.removed) media = `<div class="fthumb-wrap"><img class="fthumb" src="${esc(f.thumb)}" alt=""></div>`;
  const card = `<div class="fcard"><span class="ficon">${fileIcon(m)}</span><div class="fmeta"><div class="fname" title="${esc(f.name)}">${esc(f.name)}</div><div class="muted small">${fmtSize(f.size)}${f.risky ? ' · program file' : ''}</div></div></div>`;
  return `<div class="bubble file ${m.dir} ${m.state === 'queued' ? 'queued' : ''} ${same ? 'same' : ''}" data-key="m-${m.id}" data-sig="${esc(sig)}" data-id="${m.id}">
    ${quoteHtml(m)}${media}${k === 'image' && ready && f.inline ? '' : card}
    <div class="fstat" data-fid="${m.id}">${fileStatus(m)}</div>
    ${m.text ? `<div class="txt">${linkify(m.text)}</div>` : ''}
    <div class="ft"><span title="${new Date(m.at).toLocaleString()}">${timeOf(m.at)}</span>${tickHtml(m)}</div>${reactsHtml(m)}${actsHtml(m)}</div>`;
}

const speeds = new Map();   // msgId -> { t, done, rate }
function progressHtml(m, verb) {
  const t = m.transfer || {}, total = t.total || m.file.size || 1, done = Math.min(t.done || 0, total);
  const pct = Math.floor(done / total * 100);
  const sp = speeds.get(m.id);
  const rate = sp && sp.rate ? `${fmtSize(sp.rate)}/s` : '';
  const eta = sp && sp.rate ? ` · ${fmtEta((total - done) / sp.rate)} left` : '';
  return `<div class="pbar"><i style="width:${pct}%"></i></div><div class="frow"><span class="muted small grow">${verb} ${pct}% · ${fmtSize(done)} of ${fmtSize(total)}${rate ? ' · ' + rate + eta : ''}</span>`;
}
function fmtEta(s) { s = Math.round(s); if (s < 60) return s + ' s'; if (s < 3600) return Math.round(s / 60) + ' min'; return (s / 3600).toFixed(1) + ' h'; }

/** The status line + buttons under a file. */
function fileStatus(m) {
  const t = m.transfer || {}, f = m.file;
  const btn = (act, label, cls = '') => `<button class="btn mini ${cls}" data-act="${act}">${label}</button>`;
  const actions = () => fileReady(m) ? (f.risky ? btn('save', 'Save as…') : btn('open', 'Open') + btn('save', 'Save as…')) : '';
  const c = contacts.find(x => x.id === currentId); const who = c ? esc(c.name) : 'they';
  if (m.removed) return `<div class="frow"><span class="muted small grow">File removed from this PC</span></div>`;
  if (m.dir === 'in') {
    switch (t.state) {
      case 'offered': return `<div class="frow"><span class="muted small grow">${f.risky ? '⚠ Program file — only download it if you expected it. ' : ''}Not downloaded yet</span>${btn('download', 'Download ' + fmtSize(f.size), 'primary')}${btn('decline', 'Decline')}</div>`;
      case 'downloading': return progressHtml(m, 'Downloading') + btn('pause', 'Pause') + '</div>';
      case 'queued': return `<div class="frow"><span class="muted small grow">${esc(t.err || 'Starting download…')}${t.got ? ` · ${fmtSize(Math.min(t.got * 262144, f.size))} of ${fmtSize(f.size)} so far` : ''}</span>${btn('download', 'Try now')}${btn('pause', 'Pause')}</div>`;
      case 'paused': return `<div class="frow"><span class="muted small grow">Paused${t.err ? ' — ' + esc(t.err) : ''}</span>${btn('download', 'Resume', 'primary')}${btn('decline', 'Cancel')}</div>`;
      case 'failed': return `<div class="frow"><span class="small grow" style="color:var(--red)">${esc(t.err || 'Download failed')}</span>${btn('download', 'Try again')}</div>`;
      case 'declined': return `<div class="frow"><span class="muted small grow">You declined this file</span>${btn('download', 'Download anyway')}</div>`;
      case 'done': return `<div class="frow"><span class="muted small grow">${f.risky ? '⚠ Program file — Seal Chat won\'t open it' : ''}</span>${actions()}</div>`;
    }
    return '';
  }
  if (m.state === 'preparing') return progressHtml({ ...m, transfer: { ...t, total: t.total || f.size } }, 'Preparing') + '</div>';
  if (m.state === 'failed') return `<div class="frow"><span class="small grow" style="color:var(--red)">${esc(t.err || 'Could not send')}</span></div>`;
  switch (t.state) {
    case 'uploading': return progressHtml(m, 'Sending') + '</div>';
    case 'done': return `<div class="frow"><span class="small grow" style="color:var(--accent)">✓ ${who} downloaded it</span>${actions()}</div>`;
    case 'declined': return `<div class="frow"><span class="muted small grow">${who} declined this file</span>${actions()}</div>`;
    case 'waiting': return `<div class="frow"><span class="muted small grow">Waiting for ${who} to download</span>${actions()}</div>`;
  }
  return `<div class="frow"><span class="muted small grow">Waiting to send — goes when ${who} is online</span>${actions()}</div>`;
}

/** Live progress from the engine: patch just that file's status line. */
function onTransfer(d) {
  if (d.contactId !== currentId) return;
  const m = messages.find(x => x.id === d.id); if (!m) return;
  const before = [m.state, m.transfer && m.transfer.state].join('|');
  m.transfer = { ...(m.transfer || {}), ...d.transfer };
  if (d.state) m.state = d.state;
  if (m.state === 'preparing' && d.state === undefined && m.transfer.state === 'offered') m.state = 'queued';
  // speed: smoothed bytes per second
  if (typeof m.transfer.done === 'number') {
    const now = Date.now(), sp = speeds.get(m.id);
    if (sp && now - sp.t >= 700) { const r = (m.transfer.done - sp.done) / ((now - sp.t) / 1000); speeds.set(m.id, { t: now, done: m.transfer.done, rate: sp.rate ? sp.rate * 0.6 + r * 0.4 : r }); }
    else if (!sp) speeds.set(m.id, { t: now, done: m.transfer.done, rate: 0 });
  }
  const after = [m.state, m.transfer.state].join('|');
  if (before !== after) { renderMessages(false); if (m.transfer.state === 'done' && m.dir === 'in') refreshContactsSoon(); return; }
  const el = document.querySelector(`.fstat[data-fid="${m.id}"]`);
  if (el) el.innerHTML = fileStatus(m);
}

async function openFile(m) {
  try { await call('file:open', currentId, m.id); }
  catch (e) { if (e.code === 'RISKY') modal({ title: 'Program file', html: `<p>${esc(e.message)}</p>`, ok: 'Save as…', onOk: () => saveFile(m) }); else toast(e.message, true); }
}
async function saveFile(m) {
  try { const p = await call('file:save', currentId, m.id); if (p) toastAction('Saved', 'Show in folder', () => call('file:showSaved', p)); }
  catch (e) { toast(e.message, true); }
}
function toastAction(text, label, fn) {
  toast(text);
  const b = document.createElement('a'); b.href = '#'; b.textContent = ' ' + label; b.style.marginLeft = '10px';
  b.onclick = e => { e.preventDefault(); fn(); $('toast').classList.add('hidden'); };
  $('toast').appendChild(b);
}

// buttons inside file bubbles
$('msgList').addEventListener('click', async e => {
  const el = e.target.closest('[data-act]'); if (!el) return;
  const b = el.closest('.bubble'); if (!b) return;
  const m = messages.find(x => x.id === b.dataset.id); if (!m) return;
  const act = el.dataset.act;
  try {
    if (act === 'reply') return startReply(m);                         // 1.8.0
    if (act === 'react') { const rc = el.getBoundingClientRect(); return reactPicker(m, rc.left, rc.bottom + 4); }
    if (act === 'unreact') return sendReaction(m, '');
    if (act === 'jump') return jumpTo(el.dataset.jump);
    if (act === 'view') return viewImage(m);
    if (act === 'open') return openFile(m);
    if (act === 'save') return saveFile(m);
    if (act === 'download') { if (m.file.risky && m.transfer.state === 'offered' && !confirm(`"${m.file.name}" is a program or script file. Only download it if you were expecting it. Download?`)) return; const r = await call('file:download', currentId, m.id); Object.assign(m, r); renderMessages(false); }
    if (act === 'pause') { await call('file:pause', currentId, m.id); }
    if (act === 'decline') { await call('file:decline', currentId, m.id); }
  } catch (err) { toast(err.message, true); }
});

/* ---------- sending: 📎, drag & drop, paste ---------- */
function afterSend(r) {
  if (r.sent && r.sent.length) endReply();                            // 1.8.0: the reply went with the first file
  if (r.skipped && r.skipped.length) toast(r.skipped.join(' · '), true);
  for (const m of r.sent || []) if (!messages.some(x => x.id === m.id)) messages.push(m);
  renderMessages(true); refreshContactsSoon();
}
$('msgAttach').onclick = async () => { if (!currentId) return; try { afterSend(await call('file:pick', currentId, replyTo && replyTo.id)); } catch (e) { toast(e.message, true); } };

let dragDepth = 0;
const canDrop = () => currentId && !$('msgInput').disabled && !$('mainScreen').classList.contains('hidden');
$('chatPane').addEventListener('dragenter', e => { if (!canDrop() || !e.dataTransfer.types.includes('Files')) return; e.preventDefault(); dragDepth++; $('dropZone').classList.remove('hidden'); });
$('chatPane').addEventListener('dragover', e => { if (canDrop() && e.dataTransfer.types.includes('Files')) { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; } });
$('chatPane').addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; $('dropZone').classList.add('hidden'); } });
$('chatPane').addEventListener('drop', async e => {
  e.preventDefault(); dragDepth = 0; $('dropZone').classList.add('hidden');
  if (!canDrop()) return;
  const paths = [...e.dataTransfer.files].map(f => api.pathForFile(f)).filter(Boolean);
  if (!paths.length) return toast('Those items can\'t be sent (only files from your PC)', true);
  try { afterSend(await call('file:sendPaths', currentId, paths, replyTo && replyTo.id)); } catch (err) { toast(err.message, true); }
});
// never let a dropped file open inside the window
document.addEventListener('dragover', e => e.preventDefault());
document.addEventListener('drop', e => e.preventDefault());

// paste a screenshot / copied picture into the message box
$('msgInput').addEventListener('paste', async e => {
  const items = [...(e.clipboardData && e.clipboardData.items || [])].filter(i => i.kind === 'file');
  if (!items.length || !currentId) return;
  e.preventDefault();
  for (const it of items) {
    const f = it.getAsFile(); if (!f) continue;
    const p = api.pathForFile(f);
    try {
      if (p) afterSend(await call('file:sendPaths', currentId, [p], replyTo && replyTo.id));
      else afterSend({ sent: [await call('file:sendData', currentId, { name: f.name && f.name !== 'image.png' ? f.name : null, mime: f.type, bytes: new Uint8Array(await f.arrayBuffer()), re: replyTo && replyTo.id })] });
    } catch (err) { toast(err.message, true); }
  }
});

/* ---------- photo viewer ---------- */
let viewing = null;
function viewImage(m) {
  viewing = m;
  $('vName').textContent = `${m.file.name} · ${fmtSize(m.file.size)}`;
  $('vImg').src = fileUrl(m);
  $('viewer').classList.remove('hidden');
}
function closeViewer() { $('viewer').classList.add('hidden'); $('vImg').removeAttribute('src'); viewing = null; }
$('vClose').onclick = closeViewer;
$('viewer').onclick = e => { if (e.target.id === 'viewer' || e.target.classList.contains('viewer-img')) closeViewer(); };
$('vSave').onclick = () => viewing && saveFile(viewing);
$('vOpen').onclick = () => viewing && openFile(viewing);
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  if (viewing) return closeViewer();
  // Esc in an open chat (with no pop-up, menu or scanner showing) goes home
  const busy = !$('modal').classList.contains('hidden') || !$('menu').classList.contains('hidden') || !$('scanner').classList.contains('hidden');
  if (!busy && replyTo) return endReply();                           // 1.8.0: first Esc cancels the reply
  if (!busy && currentId && !$('mainScreen').classList.contains('hidden')) goHome();
});

/* ---------- menus ---------- */
$('chMore').onclick = e => { const r = e.target.getBoundingClientRect(); contactMenu(currentId, r.left - 160, r.bottom + 4); };
$('chInfo').onclick = () => contactDetails(currentId);

function contactMenu(id, x, y) {
  const c = contacts.find(k => k.id === id); if (!c) return;
  const items = [{ label: 'Contact details & safety number', run: () => contactDetails(id) }];
  if (c.status === 'pending-in') items.push({ label: 'Accept request', run: () => call('contacts:accept', id).then(refreshContacts) });
  items.push({ label: 'Rename…', run: () => renameContact(c) });
  items.push({ label: c.muted ? 'Unmute notifications' : 'Mute notifications', run: () => call('contacts:mute', id, !c.muted).then(refreshContacts) });
  if (c.status === 'accepted' || c.status === 'pending-out') items.push({ label: 'Try sending now', run: () => call('contacts:retry', id).then(() => toast('Trying now…')) });
  items.push({ label: 'Save conversation as text…', run: () => call('chat:export', id).then(p => p && toast('Saved')) });
  items.push('-');
  items.push({ label: 'Clear conversation…', danger: true, run: () => modal({ title: 'Clear conversation?', html: `<p>Deletes all messages with <b>${esc(c.name)}</b> from this PC. Their copy is not affected.</p>`, ok: 'Clear', danger: true, onOk: async () => { await call('chat:clear', id); if (currentId === id) openChat(id); } }) });
  if (c.status === 'blocked') items.push({ label: 'Unblock', run: () => call('contacts:unblock', id).then(refreshContacts) });
  else items.push({ label: 'Block…', danger: true, run: () => modal({ title: 'Block ' + c.name + '?', html: '<p>Their messages and requests will be refused. You can unblock later.</p>', ok: 'Block', danger: true, onOk: async () => { await call('contacts:block', id); refreshContacts(); } }) });
  items.push({ label: 'Remove contact…', danger: true, run: () => modal({ title: 'Remove ' + c.name + '?', html: '<p>Removes the contact and the conversation from this PC. Messages still waiting to be sent are discarded.</p>', ok: 'Remove', danger: true, onOk: async () => { await call('contacts:remove', id); if (currentId === id) closeChat(); refreshContacts(); } }) });
  menu(items, x, y);
}

function renameContact(c) {
  modal({ title: 'Rename contact', html: `<label>Name on this PC<input id="rnName" maxlength="80" value="${esc(c.nick || c.name)}"></label><p class="muted small">Their own name: ${esc(c.theirName || '—')}. Leave empty to use it.</p>`, ok: 'Save',
    onOk: async () => { await call('contacts:rename', c.id, $('rnName').value.trim()); refreshContacts(); } });
}

/* =================================================================
 * 8. ADD CONTACT + DETAILS
 * ================================================================= */
$('btnAdd').onclick = () => {
  modal({
    title: 'Add contact',
    html: `<p class="muted small">Paste the Seal Chat ID they sent you (<span class="mono">sealchat:abc…xyz:1A2B…</span>), type their name if they have one, like <span class="mono">ann@example.com</span>, or the invite code they gave you, like <span class="mono">482-crystal-orange-river</span>.</p>
      <textarea id="acId" rows="3" class="mono small" spellcheck="false" placeholder="sealchat:…   or   ann@example.com   or   482-crystal-orange-river"></textarea>
      <div class="row gap wrap qr-actions"><span class="muted small">Or use their QR code:</span><button class="btn mini" id="acScan">📷 Scan with camera</button><button class="btn mini" id="acQrFile">Open QR picture…</button><button class="btn mini" id="acQrPaste">Paste QR picture</button></div>
      <div id="acCheck" class="small muted"></div>
      <label>Name on this PC (optional)<input id="acNick" maxlength="80" placeholder="e.g. Ann"></label>
      <label>Note with your request (optional)<input id="acNote" maxlength="300" placeholder="e.g. Hi, it's Sam from work"></label>
      <p class="muted small">Seal Chat checks that the key at their address matches the fingerprint in the ID before sending anything. Your request travels encrypted, straight to their PC.</p>
      ${me && me.sealId ? `<hr style="border:none;border-top:1px solid var(--line)"><p class="muted small">Your own ID, to send them: <a href="#" id="acCopyMine">copy my ID</a> · or <a href="#" id="acInvite">make an invite code</a></p>` : ''}`,
    ok: 'Send request',
    onOk: async () => {
      const isCode = looksLikeInvite($('acId').value);
      if (isCode) { $('mOk').textContent = 'Using the code…'; $('acCheck').innerHTML = '<span class="muted">Reaching the invite through Tor — this can take up to a minute…</span>'; }
      try {
        const c = await call('contacts:add', { id: $('acId').value, nick: $('acNick').value.trim(), note: $('acNote').value.trim() });
        await refreshContacts(); openChat(c.id);
        toast(!isCode ? 'Request on its way' : c.viaInvite && c.viaInvite.multi ? 'Code accepted ✓ — they accept your request next' : c.status === 'accepted' ? 'Already a contact' : 'Code accepted ✓ — you are now contacts');
      } finally { $('mOk').textContent = 'Send request'; }
    }
  });
  let acSeq = 0, acTimer = null;
  $('acId').oninput = async () => {
    const v = $('acId').value.trim();
    clearTimeout(acTimer);
    if (!v) { $('acCheck').textContent = ''; return; }
    const pretty = fp => esc(fp.replace(/(.{4})/g, '$1 ').trim());
    if (looksLikeInvite(v)) {                                         // 1.8.0: an invite code — only used when you press the button
      $('acCheck').innerHTML = '<span style="color:var(--accent)">🎟 Invite code</span> — press <b>Use code</b>. The person who made it must have Seal Chat open. A wrong code uses one of its 3 tries.';
      $('mOk').textContent = 'Use code';
      return;
    }
    $('mOk').textContent = 'Send request';
    if (/^@?[^\s@:]+@[^\s@]+\.[a-z]{2,}$/i.test(v)) {              // 1.8.0: name@domain → looked up (through Tor)
      $('acCheck').innerHTML = '<span class="muted">Looking up ' + esc(v) + '…</span>';
      const seq = ++acSeq;
      acTimer = setTimeout(async () => {
        const r = await api.call('contacts:resolve', v);
        if (seq !== acSeq) return;
        $('acCheck').innerHTML = r.ok ? `<span style="color:var(--accent)">✓ ${esc(r.data.handle)}</span>${r.data.display ? ' (' + esc(r.data.display) + ')' : ''} — fingerprint <span class="mono">${pretty(r.data.fp)}</span><br><span class="muted">Check the fingerprint with them if you can — the name only finds the ID.</span>`
          : `<span style="color:var(--amber)">${esc(r.error)}</span>`;
        if (r.ok && r.data.display && !$('acNick').value) $('acNick').placeholder = r.data.display;
      }, 600);
      return;
    }
    const r = await api.call('contacts:parse', v);
    $('acCheck').innerHTML = r.ok ? `<span style="color:var(--accent)">✓ Valid ID</span> — fingerprint <span class="mono">${pretty(r.data.fp)}</span>` : `<span style="color:var(--amber)">${esc(r.error)}</span>`;
  };
  const cm = $('acCopyMine'); if (cm) cm.onclick = e => { e.preventDefault(); copyMyId(); };
  const ai = $('acInvite'); if (ai) ai.onclick = e => { e.preventDefault(); closeModal(); openInvites(); };
  const useId = id => { if (!id) return; $('acId').value = id; $('acId').oninput(); toast('QR code read ✓'); $('acNick').focus(); };
  $('acQrFile').onclick = () => call('qr:readFile').then(useId).catch(e => toast(e.message, true));
  $('acQrPaste').onclick = () => call('qr:readClipboard').then(useId).catch(e => toast(e.message, true));
  $('acScan').onclick = () => scanQr(useId);
};

/* ---------- 8b. 1.8.0: invite codes you make ----------
 * A short code instead of the long ID. Your Seal Chat must be open (and
 * online) for someone to use it. Single use: you're both added at once.
 * Several people: each request waits for you to accept it. */
function looksLikeInvite(t) { return /^\s*\d{3}([\s.\-_]+[a-z]{3,8}){3,4}\s*$/i.test(String(t || '')); }
const LIFE_TEXT = { '1h': '1 hour', '24h': '24 hours', '7d': '7 days', '30d': '30 days' };
function untilText(ts) {
  const m = Math.max(0, Math.round((ts - Date.now()) / 60e3));
  return m < 60 ? m + ' min' : m < 48 * 60 ? Math.round(m / 60) + ' hours' : Math.round(m / 1440) + ' days';
}
function invitesHtml(list) {
  if (!list.length) return '<p class="muted small">No invite codes open.</p>';
  return list.map(i => `<div class="invite-item">
      <div class="invite-code mono selectable">${esc(i.code)}</div>
      <div class="muted small">${i.label ? '<b>' + esc(i.label) + '</b> · ' : ''}${i.multi ? 'several people' + (i.uses ? ' · used ' + i.uses + '×' : '') : 'one person'} · works for ${untilText(i.expires)} more · ${i.triesLeft} wrong ${i.triesLeft === 1 ? 'try' : 'tries'} left${i.open ? '' : ' · <span style="color:var(--amber)">offline until Tor connects</span>'}</div>
      <div class="row gap"><button class="btn mini" data-icopy="${esc(i.code)}">Copy</button><button class="btn mini danger" data-icancel="${esc(i.id)}">Cancel</button></div>
    </div>`).join('');
}
async function openInvites() {
  modal({
    title: 'Invite codes', wide: true, ok: 'Make code', cancel: 'Close',
    html: `<p class="muted small">Give someone a short code to read out, text or write down. They type it in <b>＋ Add contact</b>. Keep Seal Chat open until they've used it — the code only works while your Seal Chat is online.</p>
      <div class="fields-row">
        <label>Works for<select id="ivLife"><option value="1h">1 hour</option><option value="24h" selected>24 hours</option><option value="7d">7 days</option><option value="30d">30 days (one more word)</option></select></label>
        <label>Label (only you see it)<input id="ivLabel" maxlength="60" placeholder="e.g. For Mom, Book club"></label>
      </div>
      <label class="check"><input type="checkbox" id="ivMulti"> Several people can use it (you accept each request yourself)</label>
      <p class="muted small">One person (the default): you're both added as soon as they use it. Each code allows 3 wrong tries, then it closes. Up to 5 codes open at once.</p>
      <h4>Open codes</h4><div id="ivList">${invitesHtml(await call('invite:list'))}</div>`,
    onOk: async () => {
      const i = await call('invite:create', { lifetime: $('ivLife').value, multi: $('ivMulti').checked, label: $('ivLabel').value.trim() });
      $('ivList').innerHTML = invitesHtml(await call('invite:list'));
      $('ivLabel').value = '';
      toast('Invite code ' + i.code + ' is ready');
      return false;                                                    // keep the window open to show it
    }
  });
  $('ivList').onclick = async e => {
    const cp = e.target.closest('[data-icopy]'), cn = e.target.closest('[data-icancel]');
    if (cp) { await call('clipboard:write', cp.dataset.icopy); toast('Copied'); }
    if (cn) { $('ivList').innerHTML = invitesHtml(await call('invite:cancel', cn.dataset.icancel)); toast('Invite cancelled'); }
  };
}
$('btnInvite').onclick = () => openInvites();

/* ---------- 1.2.0: scanning a QR code with the webcam ---------- */
let scan = null;
async function scanQr(onFound) {
  if (typeof jsQR !== 'function') return toast('QR scanner not available', true);
  $('scanner').classList.remove('hidden');
  $('scanMsg').textContent = 'Starting camera…';
  scan = { onFound, stream: null, timer: null, canvas: document.createElement('canvas') };
  try {
    const cams = (await navigator.mediaDevices.enumerateDevices()).filter(d => d.kind === 'videoinput');
    const sel = $('scanCam');
    sel.innerHTML = cams.map((d, i) => `<option value="${esc(d.deviceId)}">${esc(d.label || 'Camera ' + (i + 1))}</option>`).join('');
    sel.classList.toggle('hidden', cams.length < 2);
    await startCam(sel.value || undefined);
  } catch (e) {
    $('scanMsg').textContent = /NotFound|Requested device/i.test(e.name + e.message) ? 'No camera found. Use "Open QR picture…" instead (a photo or screenshot of the code).' : 'Camera not available: ' + e.message;
  }
}
async function startCam(deviceId) {
  stopCam(false);
  const stream = await navigator.mediaDevices.getUserMedia({ video: deviceId ? { deviceId: { exact: deviceId } } : { facingMode: 'environment', width: { ideal: 1280 } }, audio: false });
  if (!scan) { stream.getTracks().forEach(t => t.stop()); return; }
  scan.stream = stream;
  const v = $('scanVideo'); v.srcObject = stream; await v.play();
  $('scanMsg').textContent = 'Hold the QR code up to your camera.';
  const tick = () => {
    if (!scan) return;
    if (v.videoWidth) {
      const c = scan.canvas, w = Math.min(960, v.videoWidth), h = Math.round(v.videoHeight * w / v.videoWidth);
      c.width = w; c.height = h;
      const ctx = c.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(v, 0, 0, w, h);
      const code = jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: 'attemptBoth' });
      if (code && code.data) {
        api.call('contacts:parse', code.data).then(r => {
          if (!scan) return;
          if (r.ok) { const fn = scan.onFound; stopCam(true); fn(code.data.trim()); }
          else $('scanMsg').textContent = 'That QR code is not a Seal Chat ID.';
        });
      }
    }
    scan.timer = setTimeout(tick, 180);
  };
  tick();
}
function stopCam(close) {
  if (scan) { clearTimeout(scan.timer); if (scan.stream) scan.stream.getTracks().forEach(t => t.stop()); scan.stream = null; }
  $('scanVideo').srcObject = null;
  if (close) { scan = null; $('scanner').classList.add('hidden'); }
}
$('scanClose').onclick = () => stopCam(true);
$('scanCam').onchange = () => startCam($('scanCam').value).catch(e => { $('scanMsg').textContent = e.message; });

async function contactDetails(id) {
  let d;
  try { d = await call('contacts:details', id); } catch (e) { return toast(e.message, true); }
  modal({
    title: d.name, wide: true, ok: d.verified ? 'Mark as NOT verified' : 'Mark as verified', cancel: 'Close',
    html: `
      <div class="kv"><span>Status</span><span>${esc({ accepted: 'Contact', 'pending-in': 'Wants to chat with you', 'pending-out': d.requested ? 'Waiting for them to accept' : 'Request not sent yet', blocked: 'Blocked', failed: 'Could not add' }[d.status] || d.status)}${d.verified ? ' · <span class="badge ok">✔ Verified</span>' : ' · <span class="badge warn">Not verified</span>'}</span></div>
      <div class="kv"><span>Their key</span><span>${esc(d.key ? d.key.name + (d.key.email ? ' <' + d.key.email + '>' : '') : '—')}</span></div>
      <div class="kv"><span>Fingerprint</span><span class="mono small selectable">${esc(d.prettyFp)}</span></div>
      <div class="kv"><span>Their Seal Chat ID</span><span class="mono small selectable">${esc(d.sealId)}</span></div>
      ${d.handle ? `<div class="kv"><span>Their name</span><span class="selectable">${esc(d.handle)}${d.handleWarning ? ' <span class="badge warn">⚠ changed</span>' : ''}</span></div>` : ''}
      ${d.handleWarning ? `<p class="small" style="color:var(--amber)">⚠ ${esc(d.handleWarning)}</p>` : ''}
      ${d.mailbox ? `<div class="kv"><span>Mailbox</span><span>📬 They have one — messages can be left for them while they're offline${d.mailboxError ? ' <span class="muted small">(last try: ' + esc(d.mailboxError) + ')</span>' : ''}</span></div>` : ''}
      <div class="kv"><span>Last reachable</span><span>${esc(ago(Math.max(d.lastReached || 0, d.lastSeen || 0)))}</span></div>
      ${d.devices ? `<div class="kv"><span>Their devices</span><span>${esc(d.devices.map(x => x.name).join(', '))}</span></div>` : ''}
      <h3 style="margin-top:14px">Picture</h3>
      <div class="pic-choice">
        ${avatarHtml(d, 'big')}
        <div>
          <label class="check"><input type="radio" name="cdPic" value="theirs" ${d.avatarMode === 'theirs' ? 'checked' : ''} ${d.hasShared ? '' : 'disabled'}> The picture ${esc(d.name)} shares ${d.hasShared ? '' : '<span class="muted small">(they haven\'t shared one)</span>'}</label>
          <label class="check"><input type="radio" name="cdPic" value="custom" ${d.avatarMode === 'custom' ? 'checked' : ''} ${d.hasCustom ? '' : 'disabled'}> My own picture for them <a href="#" id="cdPick">${d.hasCustom ? 'change…' : 'choose…'}</a></label>
          <label class="check"><input type="radio" name="cdPic" value="none" ${d.avatarMode === 'none' ? 'checked' : ''}> Initials only</label>
        </div>
      </div>
      <h3 style="margin-top:14px">Safety number</h3>
      <div class="safety selectable">${d.safety.split(' ').reduce((a, g, i) => a + (i && i % 4 === 0 ? '<br>' : i ? ' ' : '') + g, '')}</div>
      <p class="muted small">Compare this number with ${esc(d.name)} by phone or in person. If it's the same on both PCs, nobody is in the middle — mark them as verified.</p>
      <div class="row gap wrap"><button class="btn" id="cdCopy">Copy their ID</button>${d.key ? '<button class="btn" id="cdKey">Save their public key…</button>' : ''}</div>`,
    onOk: async () => { await call('contacts:verify', id, !d.verified); refreshContacts(); toast(d.verified ? 'Marked as not verified' : 'Marked as verified ✔'); }
  });
  $('cdCopy').onclick = () => call('clipboard:write', d.sealId).then(() => toast('Copied'));
  // 1.2.0: which picture you see for this contact
  const repaint = v => { const a = document.querySelector('.pic-choice .avatar'); if (a && v) a.outerHTML = avatarHtml(v, 'big'); refreshContacts(); };
  document.querySelectorAll('input[name=cdPic]').forEach(r => r.onchange = () => call('contacts:setAvatarMode', id, r.value).then(repaint).catch(e => toast(e.message, true)));
  $('cdPick').onclick = e => {
    e.preventDefault();
    call('contacts:pickAvatar', id).then(v => { if (!v) return; repaint(v); const r = document.querySelector('input[name=cdPic][value=custom]'); r.disabled = false; r.checked = true; $('cdPick').textContent = 'change…'; }).catch(err => toast(err.message, true));
  };
  if ($('cdKey')) $('cdKey').onclick = () => call('contacts:exportKey', id).then(p => p && toast('Saved'));
}

/* =================================================================
 * 9. SETTINGS
 * ================================================================= */
$('btnSettings').onclick = () => openSettings();
// 1.8.0: your own name@domain (checked: it must point to YOUR ID)
$('sHandleSave').onclick = async () => {
  $('sHandleMsg').textContent = $('sHandle').value.trim() ? 'Checking…' : '';
  try { const m = await call('me:setHandle', $('sHandle').value); $('sHandle').value = m.handle; $('sHandleMsg').textContent = m.handle ? '✓ Checked — people can add you as ' + m.handle : 'Removed'; me = { ...me, ...m }; }
  catch (e) { $('sHandleMsg').textContent = '⚠ ' + e.message; }
};
// 1.8.0: name this device (shown to your contacts in their contact details)
$('sDeviceRename').onclick = async e => {
  e.preventDefault();
  const cur = ($('sDevice').textContent || '').split(' · ')[0];
  modal({
    title: 'Name this device', ok: 'Save',
    html: `<label>Name (your contacts see it in your contact details)<input id="devName" maxlength="40" value="${esc(cur)}"></label>`,
    onOk: async () => {
      const name = $('devName').value.trim();
      if (!name) throw new Error('Type a name');
      const d = await call('device:rename', name);
      $('sDevice').textContent = d.name + ' · ' + d.id.slice(0, 8); toast('Renamed');
    }
  });
};
$('setBack').onclick = () => { show('mainScreen'); refreshContacts(); };

async function openSettings(scrollTo) {
  show('settingsScreen');
  const [s, m, info, lk, t] = await Promise.all([call('settings:get'), call('me:get'), call('app:info'), call('lock:status'), call('tor:status')]);
  $('sName').value = s.displayName || m.keyName || '';
  renderMyPic(m);
  $('sId').textContent = m.sealId || '(appears once connected to Tor)';
  $('sFp').textContent = m.prettyFp || '';
  $('sHandle').value = m.handle || '';                                   // 1.8.0
  call('device:get').then(d => { $('sDevice').textContent = d ? d.name + ' · ' + d.id.slice(0, 8) : '—'; }).catch(() => {});   // 1.8.0
  loadDevices();                                                         // 1.9.0
  $('sRemember').checked = !!m.remember;
  $('sReceipts').checked = s.readReceipts !== false;
  $('sRequests').checked = s.allowRequests !== false;
  $('sMbDirect').checked = s.directIfTorBlocked === true;                   // 1.8.0
  $('wMailbox').checked = s.mailboxOn !== false;
  $('sHold').checked = s.contactMailbox !== false;                       // 1.8.5
  call('mailbox:status').then(renderMailbox).catch(() => {});
  $('sNotify').checked = s.notifications !== false;
  $('sPreview').checked = s.notifyPreview !== false;
  $('sSound').checked = s.sound !== false;
  $('sEnter').checked = s.enterToSend !== false;
  $('sEmojiConvert').checked = !!s.emojiConvert;
  $('sTray').checked = s.closeToTray !== false;
  $('sStartup').checked = !!s.startWithWindows;
  $('sStartup').closest('label').classList.toggle('hidden', !['win32', 'linux', 'darwin'].includes(info.platform));
  $('tBridges').value = s.bridges || '';
  $('tLyre').value = s.lyrebirdPath || '';
  $('tLyre').placeholder = t.lyrebird ? 'Using ' + t.lyrebird : 'lyrebird.exe (found automatically if Tor Browser is installed)';
  torStatusText(t);
  $('aVer').textContent = info.version + (info.fromUpdate ? ` (installed ${info.installedVersion}, updated)` : '');
  call('update:status').then(renderUpdateSettings).catch(() => {});
  loadWeb();   // 1.4.0
  $('aProt').textContent = m.protectedByOs ? (info.platform === 'darwin' ? 'Encrypted and locked to your Mac account (Keychain)' : 'Encrypted and locked to your Windows account')
    : info.platform === 'win32' ? 'Encrypted (Windows protection not available on this system)'
    : 'Encrypted (no desktop keyring found — unlock GNOME Keyring or KWallet for stronger protection)';
  renderLock(lk);
  osFix($('settingsScreen'));
  setSelect($('fAuto'), s.autoDownloadMB ?? 25, v => v + ' MB');
  setSelect($('fMax'), s.maxFileMB ?? 2048, v => v + ' MB');
  showUsage();
  if (scrollTo && $(scrollTo)) $(scrollTo).scrollIntoView({ block: 'center' });
}

function torStatusText(t) {
  $('tStatus').textContent = t.ready ? `Connected${t.usingBridges ? ' (using bridges)' : ''}` : `${t.summary || 'Not connected'}${t.progress && t.progress < 100 ? ` — ${t.progress}%` : ''}`;
}

// saved as soon as they change
const settingBoxes = { sHold: 'contactMailbox', sMbDirect: 'directIfTorBlocked', sReceipts: 'readReceipts', sRequests: 'allowRequests', sNotify: 'notifications', sPreview: 'notifyPreview', sSound: 'sound', sEnter: 'enterToSend', sEmojiConvert: 'emojiConvert', sTray: 'closeToTray', sStartup: 'startWithWindows' };
for (const [id, key] of Object.entries(settingBoxes)) $(id).onchange = async () => {
  try { const s = await call('settings:set', { [key]: $(id).checked }); enterToSend = s.enterToSend !== false; emojiConvert = !!s.emojiConvert; toast('Saved'); } catch (e) { toast(e.message, true); }
};
$('sName').onchange = async () => { await call('settings:set', { displayName: $('sName').value.trim() }); toast('Saved — contacts see it on new requests'); };
$('sCopyId').onclick = copyMyId;
/* ---------- 1.2.0: your picture ---------- */
function renderMyPic(m) {
  $('sAvatar').outerHTML = avatarHtml({ name: m.name || m.keyName || '?', fp: m.fp, avatar: m.avatar }, 'big').replace('class="avatar ', 'id="sAvatar" class="avatar ');
  $('sRemoveAvatar').disabled = !m.avatar;
  $('sShareAvatar').checked = m.shareAvatar !== false;
}
$('sPickAvatar').onclick = () => call('me:pickAvatar').then(m => { if (m) { renderMyPic(m); toast(m.shareAvatar ? 'Picture set — your contacts will see it' : 'Picture set'); } }).catch(e => toast(e.message, true));
$('sRemoveAvatar').onclick = () => call('me:removeAvatar').then(m => { renderMyPic(m); toast('Picture removed'); });
$('sShareAvatar').onchange = () => call('me:setShareAvatar', $('sShareAvatar').checked).then(m => { renderMyPic(m); toast(m.shareAvatar ? 'Your contacts will see your picture' : 'Your picture is no longer shared'); });
$('sCopyPub').onclick = () => call('identity:copyPublic').then(() => toast('Public key copied'));
$('sExportPriv').onclick = () => modal({
  title: 'Export your private key',
  html: '<p class="muted small">The file stays protected by your key passphrase. Keep it somewhere safe — anyone with the file AND the passphrase can read your messages.</p><label>Key passphrase<input id="xpPass" type="password"></label>',
  ok: 'Save…', onOk: async () => { const p = await call('identity:exportPrivate', { passphrase: $('xpPass').value }); if (p) toast('Saved'); }
});
$('sRemember').onchange = () => {
  if (!$('sRemember').checked) {
    call('identity:setRemember', { remember: false }).then(() => toast('Seal Chat will ask for your passphrase when it starts'));
    return;
  }
  $('sRemember').checked = false;
  modal({ title: 'Remember passphrase', html: '<label>Key passphrase<input id="rmPass" type="password"></label>', ok: 'Remember',
    onOk: async () => { await call('identity:setRemember', { remember: true, passphrase: $('rmPass').value }); $('sRemember').checked = true; toast('Remembered on this PC'); } });
};

/* ---------- app lock ---------- */
function renderLock(lk) {
  $('lkState').textContent = lk.enabled ? 'On — Seal Chat asks for your PIN when it opens and after Windows locks.' : 'Off — anyone using this PC\'s Windows account can open Seal Chat.';
  $('lkOff').classList.toggle('hidden', lk.enabled);
  $('lkOnBox').classList.toggle('hidden', !lk.enabled);
  $('lkHello').checked = !!lk.hello;
  $('lkHello').closest('label').classList.toggle('hidden', lk.platform !== 'win32');
  $('lkIdle').value = String(lk.idleMinutes || 0);
  $('lkErr').textContent = '';
}
$('lkOn').onclick = async () => {
  if ($('lkPin').value !== $('lkPin2').value) { $('lkErr').textContent = 'The PINs are different'; return; }
  try { renderLock(await call('lock:setup', { pin: $('lkPin').value, hello: false, idleMinutes: 15 })); $('lkPin').value = $('lkPin2').value = ''; toast('App lock is on'); }
  catch (e) { $('lkErr').textContent = e.message; }
};
const lkUpdate = async () => { try { renderLock(await call('lock:update', { hello: $('lkHello').checked, idleMinutes: Number($('lkIdle').value) })); toast('Saved'); } catch (e) { $('lkErr').textContent = e.message; } };
$('lkHello').onchange = async () => {
  if ($('lkHello').checked) {
    const a = await call('lock:helloAvailable').catch(() => 'Unsupported');
    if (a !== 'Available') { $('lkHello').checked = false; $('lkErr').textContent = 'Windows Hello is not set up on this PC (' + a + ')'; return; }
  }
  lkUpdate();
};
$('lkIdle').onchange = lkUpdate;
$('lkNow').onclick = () => call('lock:lockNow').then(() => showLock());
$('lkChange').onclick = () => modal({ title: 'Change PIN', html: '<label>Current PIN<input id="cpOld" type="password" inputmode="numeric"></label><label>New PIN<input id="cpNew" type="password" inputmode="numeric"></label>', ok: 'Change',
  onOk: async () => { await call('lock:changePin', $('cpOld').value, $('cpNew').value); toast('PIN changed'); } });
$('lkOffBtn').onclick = () => modal({ title: 'Turn off app lock', html: '<label>PIN<input id="loPin" type="password" inputmode="numeric"></label>', ok: 'Turn off', danger: true,
  onOk: async () => { renderLock(await call('lock:disable', $('loPin').value)); toast('App lock is off'); } });

/* ---------- Tor ---------- */
$('tLyrePick').onclick = async () => { const p = await call('settings:pickLyrebird'); if (p) $('tLyre').value = p; };
$('tSave').onclick = () => busy($('tSave'), async () => {
  $('tErr').textContent = '';
  try { await call('settings:setBridges', { bridges: $('tBridges').value, lyrebirdPath: $('tLyre').value }); toast('Reconnecting to Tor…'); }
  catch (e) { $('tErr').textContent = e.message; }
});
$('tRestart').onclick = () => busy($('tRestart'), async () => { try { await call('tor:restart'); toast('Reconnecting to Tor…'); } catch (e) { $('tErr').textContent = e.message; } });
$('tLog').onclick = async () => { const box = $('tLogBox'); if (!box.classList.contains('hidden')) { box.classList.add('hidden'); return; } box.textContent = await call('tor:log') || '(empty)'; box.classList.remove('hidden'); box.scrollTop = box.scrollHeight; };

/* ---------- backup ---------- */
$('bGo').onclick = async () => {
  $('bErr').textContent = '';
  if ($('bPass').value !== $('bPass2').value) { $('bErr').textContent = 'The passwords are different'; return; }
  const make = async keyPassphrase => { const p = await call('backup:create', { password: $('bPass').value, keyPassphrase }); if (p) { toast('Backup saved'); $('bPass').value = $('bPass2').value = ''; } };
  try { await make(); }
  catch (e) {
    if (e.code !== 'NEED_PASSPHRASE') { $('bErr').textContent = e.message; return; }
    modal({ title: 'Key passphrase', html: '<p class="muted small">The backup includes your key passphrase so a restore can unlock it.</p><label>Key passphrase<input id="bkKp" type="password"></label>', ok: 'Continue', onOk: () => make($('bkKp').value) });
  }
};

/* ---------- updates + reset ---------- */
$('aUpdate').onclick = async () => {
  try {
    const r = await call('app:installUpdate');
    if (r) modal({ title: 'Update ready', html: `<p>Seal Chat ${esc(r.version)} is installed. Restart now to use it?</p>`, ok: 'Restart now', cancel: 'Later', onOk: () => call('app:restart') });
  } catch (e) { toast(e.message, true); }
};
/* ---------- 1.3.0: automatic updates ---------- */
let upd = null;
function showUpdate(st) {
  upd = st;
  const a = st && st.available;
  $('updBar').classList.toggle('hidden', !a || a.skipped || st.ready === a.version);
  if (a) $('updText').textContent = `Seal Chat ${a.version} is available`;
  if (st && st.ready && !$('updBar').dataset.ready) { $('updBar').dataset.ready = '1'; $('updBar').classList.remove('hidden'); $('updText').textContent = `Restart to finish updating to ${st.ready}`; }
  if (!$('settingsScreen').classList.contains('hidden')) renderUpdateSettings(st);
}
function renderUpdateSettings(st) {
  upd = st;
  $('uAuto').checked = st.auto; $('uTor').checked = st.viaTor;
  $('uUrl').value = st.url;
  let t;
  if (st.ready) t = `Version ${st.ready} is downloaded — restart Seal Chat to use it.`;
  else if (st.available) t = `Version ${st.available.version} is available.`;
  else if (st.error) t = 'Last check failed: ' + st.error;
  else if (st.lastCheck) t = `You have the newest version (checked ${ago(st.lastCheck)}).`;
  else t = 'Not checked yet.';
  $('uStatus').textContent = t;
  $('uCheck').textContent = st.ready ? 'Restart now' : st.available ? `Install ${st.available.version}…` : 'Check for updates now';
}
function openUpdate() {
  const st = upd; const a = st && st.available;
  if (st && st.ready) return modal({ title: 'Update ready', html: `<p>Seal Chat ${esc(st.ready)} is downloaded and checked. Restart now to use it?</p>`, ok: 'Restart now', cancel: 'Later', onOk: () => call('app:restart') });
  if (!a) return;
  // 1.9.0 Android: this update needs a newer Android app (APK) first
  if (a.needsApk) return modal({ title: `Seal Chat ${a.version} is available`, html: `<p>This update needs a newer Seal Chat Android app. Install the new Seal Chat APK — your ID, contacts and chats stay — and it updates from there.</p>${a.notes.length ? '<h3>What\'s new</h3><ul class="upd-notes">' + a.notes.map(n => '<li>' + esc(n) + '</li>').join('') + '</ul>' : ''}`, ok: 'OK', cancel: 'Close' });
  modal({
    title: `Seal Chat ${a.version} is available`,
    html: `<p class="muted small">You have ${esc(st.current)}.${a.released ? ' Released ' + esc(a.released) + '.' : ''}${a.size ? ' Download: ' + esc(a.size) + '.' : ''}</p>
      ${a.notes.length ? '<h3>What\'s new</h3><ul class="upd-notes">' + a.notes.map(n => '<li>' + esc(n) + '</li>').join('') + '</ul>' : ''}
      <div id="updProg" class="hidden"><div class="pbar"><i id="updBarFill"></i></div><p id="updProgText" class="muted small">Starting…</p></div>
      <p class="muted small">The update is checked against Seal Chat's signing key before it is installed. Your chats, contacts and ID are not touched.</p>
      <p class="small"><a href="#" id="updSkip">Skip this version</a></p>`,
    ok: 'Download and install', cancel: 'Later',
    onOk: async () => {
      $('updProg').classList.remove('hidden'); $('mOk').disabled = true;
      const r = await call('update:install');
      upd = await call('update:status'); showUpdate(upd);
      closeModal();
      modal({ title: 'Update ready', html: `<p>Seal Chat ${esc(r.version)} is installed and verified. Restart now to use it?</p>`, ok: 'Restart now', cancel: 'Later', onOk: () => call('app:restart') });
      return false;
    }
  });
  $('updSkip').onclick = e => { e.preventDefault(); call('update:skip', a.version).then(() => { closeModal(); toast('You won\'t be reminded about ' + a.version); }); };
}
function updateProgress(p) {
  const el = $('updBarFill'); if (!el) return;
  const pct = p.total ? Math.floor(p.done / p.total * 100) : 0;
  el.style.width = pct + '%';
  $('updProgText').textContent = `Downloading… ${fmtSize(p.done)}${p.total ? ' of ' + fmtSize(p.total) + ' (' + pct + '%)' : ''}`;
}
$('updBar').onclick = () => openUpdate();
$('uCheck').onclick = () => busy($('uCheck'), async () => {
  if (upd && upd.ready) return call('app:restart');
  if (upd && upd.available) return openUpdate();
  try { const st = await call('update:check'); renderUpdateSettings(st); showUpdate(st); if (st.available) openUpdate(); else toast('You have the newest version'); }
  catch (e) { const st = await call('update:status'); renderUpdateSettings(st); toast(e.message, true); }
});
$('uAuto').onchange = () => call('settings:set', { updateAuto: $('uAuto').checked }).then(() => toast('Saved'));
$('uTor').onchange = () => call('settings:set', { updateViaTor: $('uTor').checked }).then(() => toast('Saved'));
$('uUrlSave').onclick = () => call('settings:set', { updateUrl: $('uUrl').value }).then(() => { toast('Saved'); return call('update:status'); }).then(renderUpdateSettings).catch(e => toast(e.message, true));
call('update:status').then(showUpdate).catch(() => {});

$('rGo').onclick = () => modal({
  title: 'Reset Seal Chat', danger: true, ok: 'Delete everything',
  html: '<p>This deletes your key, your Seal Chat ID, contacts and chats from this PC. Your contacts will no longer be able to reach you at this ID unless you restore a backup.</p><label>Type DELETE to confirm<input id="rsTxt" autocomplete="off"></label>',
  onOk: () => call('app:reset', $('rsTxt').value)
});

/* ---------- 1.4.0: web access (phone browser) ---------- */
let webSt = null, pairing = null;
const WEB_MODE = {
  off: 'Off — no requests to your website',
  idle: 'On — waiting (checks every %s)',
  active: 'On — the web interface is in use',
  'waiting-tor': 'On — waiting for Tor to connect',
  standby: 'On — your phone is using %d right now',     // 1.9.3
  other: 'On — answered by %o (the device that connected it)',
  error: 'Problem: %e'
};
function fmtSecs(s) { return s >= 60 ? (s / 60) + ' min' : s + ' s'; }
function renderWeb(st) {
  webSt = st;
  if (!st) return;
  $('wNoLink').classList.toggle('hidden', st.linked);
  $('wLinked').classList.toggle('hidden', !st.linked);
  $('wTor').checked = st.viaTor;
  // 1.4.1: the host blocks visitors coming through Tor → offer the direct way
  $('wTorFix').classList.toggle('hidden', !(st.viaTor && st.errorCode === 'TOR_BLOCKED'));
  const on = st.enabled;
  $('wBadge').textContent = !st.linked ? 'Off' : on ? (st.mode === 'active' ? 'In use' : 'On') : 'Off';
  $('wBadge').className = 'badge' + (on ? (st.mode === 'error' ? ' warn' : ' ok') : '');
  if (!st.linked) return;
  $('wSite').textContent = st.base;
  let text = on ? (WEB_MODE[st.mode] || st.mode) : WEB_MODE.off;
  text = text.replace('%s', fmtSecs(st.idleSec)).replace('%e', st.error || 'unknown')
    .replace('%d', st.shared && st.shared.standbyBy ? '"' + st.shared.standbyBy + '"' : 'your other device')
    .replace('%o', st.shared && st.shared.owner ? '"' + st.shared.owner + '"' : 'your other device');
  // 1.9.3: shared by your linked devices — the phone works with whichever of them is running
  $('wSharedRow').classList.toggle('hidden', !st.shared);
  if (st.shared) $('wShared').textContent = st.shared.lease
    ? 'Shared — your paired phones work with whichever of your devices is running.'
    : 'Shared, but only ' + (st.shared.owner ? '"' + st.shared.owner + '"' : 'the device that connected it') + ' answers the phone. Update Seal Chat Web to 1.3.2 (its setup page → Updates) so any of your devices can.';
  if (on && st.until) text += ` · turns off at ${new Date(st.until).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}`;
  if (on && st.lastCheck && st.mode !== 'error') text += ` · last check ${ago(st.lastCheck)}`;
  $('wStatus').textContent = text;
  $('wToggle').textContent = on ? 'Turn off' : 'Turn on';
  $('wToggle').className = 'btn ' + (on ? '' : 'primary');
  $('wFor').classList.toggle('hidden', on);
  setSelect($('wIdle'), st.idleSec, v => fmtSecs(Number(v)));
  $('wTor').checked = st.viaTor;
  $('wPair').disabled = !on;
  $('wPair').title = on ? '' : 'Turn web access on first';
  // 1.6.0: each device has its own notification switches (set up on the device first)
  const pushRow = d => !d.push
    ? `<div class="web-push muted small">🔕 Notifications not set up — turn them on on the device (menu ⋯ → Notifications).</div>`
    : `<div class="web-push"><label class="check"><input type="checkbox" data-webpush="${esc(d.id)}" data-k="on" ${d.push.on ? 'checked' : ''}> 🔔 Notifications</label>`
      + `<label class="check"><input type="checkbox" data-webpush="${esc(d.id)}" data-k="names" ${d.push.names ? 'checked' : ''} ${d.push.on ? '' : 'disabled'}> Show who it's from</label>`
      + `<span class="muted small">${d.push.lastErr ? '<span class="bad">' + esc(d.push.lastErr) + '</span>' : d.push.lastOk ? 'Last sent ' + ago(d.push.lastOk) : 'Text: "New message" (never the message itself)'}</span></div>`;
  $('wDevices').innerHTML = st.devices.length ? st.devices.map(d => `<div class="web-dev-box"><div class="web-dev"><i class="dot ${d.connected ? 'on' : ''}"></i><div class="grow"><b>${esc(d.name)}</b><div class="muted small">${d.connected ? 'Connected now' : d.lastUsed ? 'Last used ' + ago(d.lastUsed) : 'Paired ' + ago(d.added)}</div></div><button class="btn" data-webrm="${esc(d.id)}">Remove</button></div>${pushRow(d)}</div>`).join('')
    : '<p class="muted small">No devices yet. Turn web access on, then "Pair a device…".</p>';
}
async function loadWeb() { try { renderWeb(await call('web:status')); } catch { /* locked */ } }

/* ---------- 1.9.0: your devices (Settings → Your devices) ---------- */
function renderDevices(st) {
  if (!st || !$('dvList')) return;
  const list = st.devices || [];
  $('dvList').innerHTML = st.offline ? '<p class="muted small">Shown once Seal Chat is connected.</p>'
    : (st.unlinked ? '<p class="bad small">This device was removed from your ID on another device. It no longer gets messages that arrive there.</p>' : '')
      + list.map(d => `<div class="web-dev-box"><div class="web-dev"><i class="dot ${d.self || (d.lastSync && Date.now() - d.lastSync < 10 * 60e3) ? 'on' : ''}"></i><div class="grow"><b>${esc(d.name)}</b>${d.self ? ' <span class="muted small">(this device)</span>' : ''}`
        + `<div class="muted small mono selectable">${d.onion ? esc(d.onion.slice(0, 16)) + '….onion' : 'address not known yet'}</div>`
        + `<div class="muted small">${d.self ? 'Added ' + ago(d.added) : (d.lastSync ? 'Last in touch ' + ago(d.lastSync) : 'Not in touch yet') + (d.waiting ? ` · ${d.waiting} update${d.waiting === 1 ? '' : 's'} waiting for it` : ' · up to date')}</div></div>`
        + `${d.self ? '' : `<button class="btn" data-devrm="${esc(d.id)}" data-devname="${esc(d.name)}">Remove…</button>`}</div></div>`).join('')
      + (list.length < 2 && !st.unlinked ? '<p class="muted small">Only this device so far.</p>' : '');
  if ($('lkLinkState') && st.link) $('lkLinkState').textContent = st.link.state === 'linking' ? `Linking "${st.link.name}"…` : 'Waiting for the new device…';
}
function loadDevices() { call('devices:status').then(renderDevices).catch(() => {}); }
$('dvList').onclick = e => {
  const b = e.target.closest('[data-devrm]'); if (!b) return;
  modal({
    title: 'Remove "' + b.dataset.devname + '"?', danger: true, ok: 'Remove',
    html: '<p>Your contacts are told it is no longer one of your devices, and your other devices stop passing messages to it. Messages it was still sending are sent from this device.</p><p class="muted small">That device still has your key. If it was lost or stolen, make a new Seal Chat ID instead and tell your contacts.</p>',
    onOk: () => call('devices:remove', b.dataset.devrm).then(st => { renderDevices(st); toast('Removed'); }).catch(err => toast(err.message, true))
  });
};
$('dvLink').onclick = async () => {
  $('dvErr').textContent = '';
  let st;
  try { st = await call('devices:link'); } catch (e) { $('dvErr').textContent = e.message; return; }
  modal({
    title: 'Link a new device',
    html: `<p>On the new computer, install Seal Chat 1.9 or newer and choose <b>Link to my Seal Chat on another device</b>. Type this code there, with your key passphrase:</p>`
      + `<p class="mono" style="font-size:20px;text-align:center;margin:14px 0" id="lkLinkCode">${esc(st.code)}</p>`
      + `<p class="muted small" id="lkLinkState">Waiting for the new device…</p>`
      + `<p class="muted small">The code works once, for 10 minutes. Keep Seal Chat open and online here until it's done. Anyone with this code and your passphrase can link a device — only type it on your own computer.</p>`,
    ok: 'Close', cancel: 'Cancel code',
    onOk: () => call('devices:status').then(s => { if (s.link) call('devices:linkCancel'); loadDevices(); }),
    onCancel: () => { call('devices:linkCancel').then(loadDevices); }
  });
};
function onLinkEvent(e) {
  const el = $('lkLinkState');
  if (e.kind === 'linked') { if (el) el.textContent = `✓ "${e.name}" is linked. Your contacts and chats are being copied to it.`; toast(`"${e.name}" linked`); loadDevices(); }
  else if (e.kind === 'wrong') { if (el) el.textContent = `Someone typed a wrong code (${e.left} ${e.left === 1 ? 'try' : 'tries'} left).`; }
  else if (e.kind === 'failed') { if (el) el.textContent = 'The new device couldn\'t open your key (wrong passphrase?). The code still works — try again there.'; }
  else if (e.kind === 'closed') { if (el) el.textContent = e.why || 'The code closed.'; loadDevices(); }
}

/* ---------- 1.8.0: your mailbox (Settings → Web access) ---------- */
function sharedText(sh) {
  // 1.8.1: contacts learn the mailbox address the next time you're both online
  return sh && sh.of ? ` · ${sh.have} of ${sh.of} contacts know about it` + (sh.have < sh.of ? ' (the rest learn it the next time you\'re both online' + (sh.older ? `; ${sh.older} need Seal Chat 1.8 or newer` : '') + ')' : '') : '';
}
function renderMailbox(st) {
  if (!st || !$('wMbStatus')) return;
  // 1.8.5: the Cloudflare Worker
  const w = st.worker || {};
  $('mbwNo').classList.toggle('hidden', !!w.url);
  $('mbwYes').classList.toggle('hidden', !w.url);
  if (w.url) {
    $('mbwSite').textContent = w.url;
    $('mbwStatus').textContent = w.lastError ? '⚠ ' + w.lastError
      : !w.on ? 'Starting…'
        : 'On' + (w.lastCheck ? ` · checked ${ago(w.lastCheck)}` : '') + (st.got ? ` · ${st.got} picked up since Seal Chat started` : '') + sharedText(st.shared);
  }
  $('mbHolding').textContent = st.contactMailbox && st.holding ? `Holding ${st.holding} message${st.holding === 1 ? '' : 's'} for your contacts right now.` : '';
  let t;
  if (!st.enabled) t = 'Off — messages wait on your contacts\' PCs until you\'re both online.';
  else if (!st.connected) t = 'Connect to your website above to use the mailbox.';
  else if (st.lastError) t = '⚠ ' + st.lastError;
  else if (!st.on) t = 'Starting…';
  else {
    t = 'On' + (st.lastCheck ? ` · checked ${ago(st.lastCheck)}` : '') + (st.got && st.using !== 'worker' ? ` · ${st.got} picked up since Seal Chat started` : '');
    if (st.using === 'worker') t += ' · contacts are now given your Cloudflare mailbox (Settings → Mailbox); this one is still checked for anyone who hasn\'t heard yet';
    else t += sharedText(st.shared);
  }
  $('wMbStatus').textContent = t;
}
$('wMailbox').onchange = () => call('settings:set', { mailboxOn: $('wMailbox').checked }).then(() => { toast('Saved'); setTimeout(() => call('mailbox:status').then(renderMailbox), 1500); }).catch(e => toast(e.message, true));
/* 1.8.5: the Cloudflare Worker mailbox */
const copyWorker = () => call('mailbox:workerScript').then(() => toast('Worker script copied — paste it into your Cloudflare Worker and deploy')).catch(e => toast(e.message, true));
$('mbwCopy').onclick = copyWorker;
$('mbwCopy2').onclick = copyWorker;
$('mbwConnect').onclick = async () => {
  $('mbwErr').textContent = '';
  const b = $('mbwConnect'); b.disabled = true; b.textContent = 'Connecting…';
  try { renderMailbox(await call('mailbox:workerConnect', $('mbwUrl').value)); $('mbwUrl').value = ''; toast('Your Cloudflare mailbox is on — contacts learn about it the next time you\'re online together'); }
  catch (e) { $('mbwErr').textContent = e.message; }
  finally { b.disabled = false; b.textContent = 'Connect'; }
};
$('mbwCheck').onclick = () => { $('mbwErr').textContent = ''; $('mbwStatus').textContent = 'Checking…'; call('mailbox:check').then(renderMailbox).catch(e => toast(e.message, true)); };
$('mbwRemove').onclick = () => modal({
  title: 'Stop using the Cloudflare mailbox?',
  html: '<p>Seal Chat picks up anything waiting there, then turns it off. Contacts are told to use your website\'s mailbox instead (if you have one). You can delete the Worker in Cloudflare afterwards.</p>',
  ok: 'Stop using it', danger: true,
  onOk: () => call('mailbox:workerRemove').then(renderMailbox).then(() => toast('Stopped')).catch(e => toast(e.message, true))
});
$('wMbCheck').onclick = () => { $('wMbStatus').textContent = 'Checking…'; call('mailbox:check').then(renderMailbox).catch(e => toast(e.message, true)); };

const webConnect = async () => {
  $('wErr').textContent = ''; $('wTorFix').classList.add('hidden');
  try { renderWeb(await call('web:connect', $('wLink').value)); $('wLink').value = ''; toast('Connected to your website — now turn web access on'); }
  catch (e) {
    $('wErr').textContent = e.message;
    if (e.code === 'TOR_BLOCKED') $('wTorFix').classList.remove('hidden');
  }
};
$('wConnect').onclick = () => busy($('wConnect'), webConnect);
// 1.4.1: "Connect directly instead" — turns off Tor for web access, then retries
$('wDirect').onclick = () => busy($('wDirect'), async () => {
  await call('settings:set', { webViaTor: false });
  $('wTorFix').classList.add('hidden'); $('wErr').textContent = '';
  if (webSt && webSt.linked) { toast('Connecting directly…'); loadWeb(); }
  else await webConnect();
});
$('wToggle').onclick = () => busy($('wToggle'), async () => {
  $('wErr').textContent = '';
  try { const st = await call('web:enable', !webSt.enabled, Number($('wFor').value)); renderWeb(st); toast(st.enabled ? 'Web access is on' : 'Web access is off'); }
  catch (e) { $('wErr').textContent = e.message; }
});
$('wIdle').onchange = () => call('settings:set', { webIdleSec: Number($('wIdle').value) }).then(() => { toast('Saved'); loadWeb(); });
$('wTor').onchange = () => call('settings:set', { webViaTor: $('wTor').checked }).then(() => { toast('Saved'); loadWeb(); });
// 1.6.0: notification switches per device
$('wDevices').onchange = async e => {
  const c = e.target.closest('[data-webpush]'); if (!c) return;
  try { renderWeb(await call('web:devicePush', c.dataset.webpush, { [c.dataset.k]: c.checked })); toast('Saved'); }
  catch (err) { c.checked = !c.checked; toast(err.message); }
};
$('wDevices').onclick = e => {
  const b = e.target.closest('[data-webrm]'); if (!b) return;
  const d = webSt.devices.find(x => x.id === b.dataset.webrm);
  modal({ title: 'Remove this device?', danger: true, ok: 'Remove', html: `<p>"${esc(d ? d.name : 'Device')}" will no longer be able to use Seal Chat. You can pair it again later.</p>`,
    onOk: async () => { renderWeb(await call('web:removeDevice', b.dataset.webrm)); toast('Device removed'); } });
};
$('wDisconnect').onclick = () => modal({
  title: 'Disconnect from your website?', danger: true, ok: 'Disconnect',
  html: '<p>Removes this PC\'s mailbox from your website, unpairs all devices and turns web access off. To use it again, paste the connection link and pair your devices again.</p>',
  onOk: async () => { renderWeb(await call('web:disconnect')); toast('Disconnected'); }
});

// pairing: QR code → (device sends request) → compare code → approve
$('wPair').onclick = async () => {
  $('wErr').textContent = '';
  let p;
  try { p = await call('web:pair'); } catch (e) { $('wErr').textContent = e.message; return; }
  pairing = p;
  modal({
    title: 'Pair a device',
    html: `<p class="muted small">On your phone: scan this with the <b>Camera</b> app and open the link — or open the web interface and tap "Scan the QR code".</p>
      <img class="pair-qr" src="${p.qr}" alt="Pairing QR code">
      <p class="muted small">Works once, for 10 minutes. Anyone who scans it could ask to pair — you approve each device on the next step.</p>
      <p class="small"><a href="#" id="wCopyPair">Copy the pairing link</a> (to open it on a computer's browser)</p>`,
    ok: '', cancel: 'Cancel',
    onCancel: () => { pairing = null; call('web:cancelPair').then(renderWeb).catch(() => {}); }
  });
  $('wCopyPair').onclick = e => { e.preventDefault(); call('web:copyPairLink', p.link).then(() => toast('Pairing link copied — it contains a secret, paste it only on your own device')); };
};

function onWebPair(r) {
  modal({
    title: 'Approve this device?',
    html: `<p><b>${esc(r.name)}</b> asks to use Seal Chat through your website.</p>
      <p class="muted small">Approve only if the device shows exactly this code:</p>
      <div class="pair-code">${esc(r.code)}</div>
      <p class="muted small">It will see your contacts and chats and can send messages. You can remove it any time in Settings → Web access.</p>`,
    ok: 'Approve', cancel: 'Decline',
    onOk: async () => { renderWeb(await call('web:approve', r.tid)); pairing = null; toast(`"${r.name}" is paired`); },
    onCancel: () => { call('web:decline', r.tid).then(renderWeb).catch(() => {}); pairing = null; toast('Pairing declined'); }
  });
}

/* ---------- files (1.1.0) ---------- */
/** Selects a value, adding it to the list if it isn't one of the usual choices. */
function setSelect(sel, v, label) {
  v = String(v);
  if (![...sel.options].some(o => o.value === v)) { const o = document.createElement('option'); o.value = v; o.textContent = label(v); sel.appendChild(o); }
  sel.value = v;
}
async function showUsage() { try { const u = await call('storage:usage'); $('fUsage').textContent = `${fmtSize(u.bytes)} (${u.files} file${u.files === 1 ? '' : 's'})`; } catch { /* ignore */ } }
$('fAuto').onchange = () => call('settings:set', { autoDownloadMB: Number($('fAuto').value) }).then(() => toast('Saved'));
$('fMax').onchange = () => call('settings:set', { maxFileMB: Number($('fMax').value) }).then(() => toast('Saved'));
$('fFree30').onclick = async () => { const r = await call('storage:free', 30); toast(`Removed ${r.removed} file${r.removed === 1 ? '' : 's'}`); showUsage(); };
$('fFreeAll').onclick = () => modal({ title: 'Remove all stored files?', danger: true, ok: 'Remove all',
  html: '<p>Deletes every sent and received file from this PC. The messages stay, marked "File removed from this PC". Files still waiting to be sent are kept.</p>',
  onOk: async () => { const r = await call('storage:free', 0); toast(`Removed ${r.removed} file${r.removed === 1 ? '' : 's'}`); showUsage(); } });

/* =================================================================
 * 10. EVENTS FROM THE ENGINE
 * ================================================================= */
const refreshContactsSoon = (() => { let t; return () => { clearTimeout(t); t = setTimeout(() => refreshContacts().catch(() => {}), 120); }; })();

api.on(async ev => {
  switch (ev.type) {
    case 'tor': {
      netPill(ev.data, me && me.online && ev.data.ready);
      if (!$('settingsScreen').classList.contains('hidden')) torStatusText(ev.data);
      if (!ev.data.ready && me) me.online = false;
      break;
    }
    case 'me': if (!$('mainScreen').classList.contains('hidden') || !$('settingsScreen').classList.contains('hidden')) refreshMe().catch(() => {}); break;
    case 'contacts': case 'request': refreshContactsSoon(); break;
    case 'invites': if ($('ivList')) $('ivList').innerHTML = invitesHtml(ev.data || []); break;   // 1.8.0
    case 'message': {
      if (ev.data.contactId === currentId && !$('mainScreen').classList.contains('hidden')) {
        messages.push(ev.data.msg); renderMessages(false);
        if (document.hasFocus()) call('chat:open', currentId).catch(() => {});
      }
      refreshContactsSoon();
      break;
    }
    case 'receipts':
      if (ev.data.contactId === currentId) { messages = await call('chat:history', currentId); renderMessages(false); }
      refreshContactsSoon();
      break;
    case 'transfer': onTransfer(ev.data); break;
    case 'msgupdate': {                                                  // 1.8.0: a reaction changed
      if (ev.data.contactId === currentId) { const i = messages.findIndex(x => x.id === ev.data.msg.id); if (i >= 0) { messages[i] = ev.data.msg; renderMessages(false); } }
      break;
    }
    case 'update': showUpdate(ev.data); if (ev.data.open) openUpdate(); break;
    case 'updateProgress': updateProgress(ev.data); break;
    case 'open': if ($('mainScreen').classList.contains('hidden')) { await route(); } if (!$('mainScreen').classList.contains('hidden')) { await refreshContacts(); openChat(ev.data.contactId); } break;
    case 'focus': if (currentId && !$('mainScreen').classList.contains('hidden')) call('chat:open', currentId).then(refreshContactsSoon).catch(() => {}); break;
    case 'lock': if (ev.data.locked) showLock(ev.data); break;
    case 'openSettings': if (!$('mainScreen').classList.contains('hidden')) openSettings(); break;   // 1.5.0: macOS ⌘,
    case 'web': if (!$('settingsScreen').classList.contains('hidden')) renderWeb(ev.data); else webSt = ev.data; break;   // 1.4.0
    case 'mailbox': renderMailbox(ev.data); break;
    case 'devices': renderDevices(ev.data); break;                     // 1.9.0
    case 'link': onLinkEvent(ev.data); break;                     // 1.8.0
    case 'webPair': onWebPair(ev.data); break;
    case 'firstUpdate': onFirstUpdate(ev.data); break;   // 1.6.0
  }
});

/* ---------- 1.6.0: a new installation getting the latest version ----------
 * Main checks as soon as it can; we only show something once a newer
 * version is actually downloading. "Not now": it installs at the next start. */
let fuTimer = null;
function onFirstUpdate(f) {
  const box = $('firstUpd');
  if (!f || f.skipped || !['downloading', 'ready'].includes(f.stage)) { box.classList.add('hidden'); clearInterval(fuTimer); fuTimer = null; return; }
  box.classList.remove('hidden');
  const pct = f.total ? Math.floor(f.done / f.total * 100) : 0;
  if (f.stage === 'downloading') {
    $('fuTitle').textContent = `Updating to Seal Chat ${f.version}…`;
    $('fuText').textContent = 'This new installation is getting the latest version. It is checked against Seal Chat\'s signature before it is used, then Seal Chat restarts by itself.';
    $('fuFill').style.width = pct + '%';
    $('fuProg').textContent = f.total ? `${fmtSize(f.done)} of ${fmtSize(f.total)} (${pct}%)` : 'Starting…';
    $('fuGo').classList.add('hidden'); $('fuSkip').textContent = 'Not now';
  } else if (!fuTimer) {
    $('fuTitle').textContent = `Seal Chat ${f.version} is ready`;
    $('fuText').textContent = 'Downloaded and verified. Restarting to use it…';
    $('fuFill').style.width = '100%';
    let n = 5;
    const tickDown = () => { $('fuProg').textContent = `Restarting in ${n} s`; if (n-- <= 0) { clearInterval(fuTimer); call('app:restart'); } };
    tickDown(); fuTimer = setInterval(tickDown, 1000);
    $('fuGo').classList.remove('hidden'); $('fuSkip').textContent = 'Not now';
  }
}
$('fuGo').onclick = () => call('app:restart');
$('fuSkip').onclick = async () => {
  clearInterval(fuTimer); fuTimer = null; $('firstUpd').classList.add('hidden');
  const f = await call('update:firstSkip');
  toast(f && f.stage === 'ready' ? `Seal Chat ${f.version} will be used the next time Seal Chat starts` : 'The update keeps downloading in the background — it\'s used the next time Seal Chat starts');
};

// activity keeps the idle lock away
let lastPing = 0;
const activity = () => { if (Date.now() - lastPing > 20000) { lastPing = Date.now(); api.call('lock:activity'); } };
document.addEventListener('mousemove', activity); document.addEventListener('keydown', activity);

// keep "last reachable … ago" fresh
setInterval(() => { if (currentId && !$('mainScreen').classList.contains('hidden')) { const c = contacts.find(x => x.id === currentId); if (c) renderChatHead(c); } }, 30000);

/* =================================================================
 * 11. START
 * ================================================================= */
(async () => {
  try { const s = await call('settings:get'); enterToSend = s.enterToSend !== false; emojiConvert = !!s.emojiConvert; } catch { /* locked */ }
  try { platform = (await call('app:info')).platform; osFix(); } catch { /* ignore */ }
  document.body.classList.add('os-' + platform);   // 1.6.1: Windows + Linux use the bundled colour emoji font (styles.css section 13)
  route().catch(e => toast(e.message, true));
  try { onFirstUpdate(await call('update:first')); } catch { /* ignore */ }   // 1.6.0
})();

// 1.1.0: a video/sound format Seal Chat can't play inline (e.g. some .mov / .wma):
// hide the player — "Open" plays it in your normal app instead
document.addEventListener('error', e => {
  const t = e.target;
  if (t && t.matches && t.matches('video.fvid, audio.faud')) t.classList.add('hidden');
}, true);
