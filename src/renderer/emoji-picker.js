/* =====================================================================
   Seal Chat — emoji-picker.js   (1.6.1, the same file in Seal Chat Web 1.1.1)
   ---------------------------------------------------------------------
   Emoji for the message box, with no outside services:
     • a 😊 button that opens a picker (search, groups, recently used,
       skin tone) — a pop-over on a computer, a bottom sheet on a phone
     • ":shortcode" suggestions while typing  (:smile → 😄, :+1 → 👍);
       Tab / Enter picks, typing the closing ":" completes an exact match
     • optional ":)" → 🙂 while typing (a short, safe list only)
     • isJumbo(text): a message that is only 1–3 emoji (shown bigger)
   Emoji are ordinary text, so messages stay readable by any version of
   Seal Chat. The list (emoji-data.js, ~185 KB) loads the first time the
   picker or a suggestion is needed.

   Use:  SCEmoji.attach({ input, button, dataUrl, mobile, convert() })
         SCEmoji.isJumbo(text)

   Sections:
     1. Data loading + search
     2. Inserting into the message box
     3. The picker panel
     4. Shortcode suggestions + ":)" conversion
     5. Emoji-only messages (big emoji)
   ===================================================================== */
(function (root) {
  'use strict';

  var RECENT_KEY = 'sc-emoji-recent', TONE_KEY = 'sc-emoji-tone', RECENT_MAX = 24;
  // the only emoticons turned into emoji (when that is switched on): common and unlikely in normal text
  var SAFE_EMOTICONS = { ':)': '🙂', ':-)': '🙂', ':D': '😄', ':-D': '😄', ';)': '😉', ';-)': '😉', ':(': '🙁', ':-(': '🙁', ':P': '😛', ':-P': '😛', ':p': '😛', '<3': '❤️', ":'(": '😢' };
  var TONES = ['', '🏻', '🏼', '🏽', '🏾', '🏿'];

  function store(k, v) { try { if (v === undefined) return root.localStorage.getItem(k); root.localStorage.setItem(k, v); } catch (e) { return null; } }
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }

  /* =================================================================
     1. DATA + SEARCH
     ================================================================= */
  var dataP = null;
  function load(url) {
    if (root.SC_EMOJI) return Promise.resolve(root.SC_EMOJI);
    if (!dataP) dataP = new Promise(function (res, rej) {
      var s = document.createElement('script'); s.src = url;
      s.onload = function () { res(root.SC_EMOJI); };
      s.onerror = function () { dataP = null; rej(new Error('Could not load the emoji list')); };
      document.head.appendChild(s);
    });
    return dataP;
  }
  /** [char, group, name, keywords, shortcodes[], skins[]?] → the emoji in the chosen skin tone */
  function withTone(row, tone) { return tone && row[5] ? row[5][tone - 1] : row[0]; }
  function search(D, q, max) {
    q = q.toLowerCase().trim(); if (!q) return [];
    var a = [], b = [], c = [];
    for (var i = 0; i < D.list.length; i++) {
      var r = D.list[i], name = r[2].toLowerCase();
      if (r[4].some(function (s) { return s === q; }) || name === q) a.push(r);
      else if (r[4].some(function (s) { return s.indexOf(q) === 0; }) || name.indexOf(q) === 0) b.push(r);
      else if (name.indexOf(q) >= 0 || (' ' + r[3] + ' ').indexOf(' ' + q) >= 0) c.push(r);
      if (a.length + b.length >= (max || 400)) break;
    }
    return a.concat(b, c).slice(0, max || 400);
  }
  function byChar(D, ch) { for (var i = 0; i < D.list.length; i++) { var r = D.list[i]; if (r[0] === ch || (r[5] && r[5].indexOf(ch) >= 0)) return r; } return null; }

  /* =================================================================
     2. INSERT INTO THE MESSAGE BOX
     The app's own "input" handler runs afterwards (resize, draft).
     ================================================================= */
  function insert(input, text, from, to) {
    var s = from != null ? from : (input.selectionStart != null ? input.selectionStart : input.value.length);
    var e = to != null ? to : (input.selectionEnd != null ? input.selectionEnd : s);
    input.setRangeText(text, s, e, 'end');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  }
  function remember(ch) {
    var r = []; try { r = JSON.parse(store(RECENT_KEY) || '[]'); } catch (e) { r = []; }
    r = [ch].concat(r.filter(function (x) { return x !== ch; })).slice(0, RECENT_MAX);
    store(RECENT_KEY, JSON.stringify(r));
  }
  function recent() { try { return JSON.parse(store(RECENT_KEY) || '[]'); } catch (e) { return []; } }

  /* =================================================================
     3. THE PICKER PANEL (one per message box)
     ================================================================= */
  function Picker(o) {
    this.o = o; this.open = false; this.D = null; this.tone = Number(store(TONE_KEY)) || 0; this.group = -1;
    var self = this;
    this.box = el('div', 'sc-emoji-panel' + (o.mobile ? ' mobile' : '') + ' hidden');
    this.box.setAttribute('role', 'dialog'); this.box.setAttribute('aria-label', 'Emoji');
    var head = el('div', 'sc-emoji-head');
    this.q = el('input', 'sc-emoji-search'); this.q.type = 'search'; this.q.placeholder = 'Search emoji'; this.q.setAttribute('autocomplete', 'off'); this.q.setAttribute('aria-label', 'Search emoji');
    this.toneBtn = el('button', 'sc-emoji-tone'); this.toneBtn.type = 'button'; this.toneBtn.title = 'Skin tone'; this.toneBtn.setAttribute('aria-label', 'Skin tone');
    head.appendChild(this.q); head.appendChild(this.toneBtn);
    if (o.mobile) { this.closeBtn = el('button', 'sc-emoji-close', 'Done'); this.closeBtn.type = 'button'; head.appendChild(this.closeBtn); this.closeBtn.onclick = function () { self.hide(); }; }
    this.tones = el('div', 'sc-emoji-tones hidden');
    TONES.forEach(function (t, i) { var b = el('button', 'sc-emoji-toneopt', '👋' + t); b.type = 'button'; b.dataset.tone = i; b.setAttribute('aria-label', i ? 'Skin tone ' + i : 'Default skin tone'); self.tones.appendChild(b); });
    this.tabs = el('div', 'sc-emoji-tabs');
    this.grid = el('div', 'sc-emoji-grid');
    this.label = el('div', 'sc-emoji-label');
    this.box.appendChild(head); this.box.appendChild(this.tones); this.box.appendChild(this.tabs); this.box.appendChild(this.label); this.box.appendChild(this.grid);
    (o.container || document.body).appendChild(this.box);

    this.q.oninput = function () { self.render(); };
    this.toneBtn.onclick = function () { self.tones.classList.toggle('hidden'); };
    this.tones.onclick = function (e) { var b = e.target.closest('[data-tone]'); if (!b) return; self.tone = Number(b.dataset.tone); store(TONE_KEY, String(self.tone)); self.tones.classList.add('hidden'); self.render(); };
    this.tabs.onclick = function (e) { var b = e.target.closest('[data-g]'); if (!b) return; self.group = Number(b.dataset.g); self.q.value = ''; self.render(); self.grid.scrollTop = 0; };
    this.grid.onclick = function (e) {
      var b = e.target.closest('[data-e]'); if (!b) return;
      insert(o.input, b.dataset.e); remember(b.dataset.e);
      if (!o.mobile && !e.shiftKey) self.hide();      // computer: one pick closes (Shift-click to pick several); phone: stays open until Done
    };
    this.grid.onmouseover = function (e) { var b = e.target.closest('[data-e]'); if (b) self.label.textContent = b.title; };
    // Esc closes only the picker (not the app's own Esc action, e.g. closing the chat)
    this.box.onkeydown = function (e) { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); self.hide(); o.input.focus(); } };
    document.addEventListener('mousedown', function (e) { if (self.open && !self.box.contains(e.target) && e.target !== o.button && !o.button.contains(e.target)) self.hide(); }, true);
    if (o.mobile) o.input.addEventListener('focus', function () { if (self.open) self.hide(); });
  }
  Picker.prototype.show = function () {
    var self = this;
    load(this.o.dataUrl).then(function (D) {
      self.D = D;
      if (!self.tabs.childNodes.length) {
        var rb = el('button', 'sc-emoji-tab', '🕘'); rb.type = 'button'; rb.dataset.g = -1; rb.title = 'Recently used'; self.tabs.appendChild(rb);
        D.groups.forEach(function (g, i) { var b = el('button', 'sc-emoji-tab', g[1]); b.type = 'button'; b.dataset.g = i; b.title = g[0]; b.setAttribute('aria-label', g[0]); self.tabs.appendChild(b); });
      }
      if (self.group === -1 && !recent().length) self.group = 0;
      self.q.value = ''; self.render();
      self.box.classList.remove('hidden'); self.open = true;
      // phone: the page makes room above the sheet (like a keyboard), so the message box stays visible
      if (self.o.mobile) { document.documentElement.style.setProperty('--sc-emoji-h', self.box.offsetHeight + 'px'); document.body.classList.add('sc-emoji-open'); }
      if (self.o.button) self.o.button.setAttribute('aria-expanded', 'true');
      self.place();
      if (!self.o.mobile) self.q.focus();
    }).catch(function (e) { if (self.o.onError) self.o.onError(e); });
  };
  Picker.prototype.hide = function () { document.body.classList.remove('sc-emoji-open'); this.box.classList.add('hidden'); this.tones.classList.add('hidden'); this.open = false; if (this.o.button) this.o.button.setAttribute('aria-expanded', 'false'); };
  Picker.prototype.toggle = function () { if (this.open) this.hide(); else this.show(); };
  /** computer: just above the 😊 button, kept inside the window */
  Picker.prototype.place = function () {
    if (this.o.mobile || !this.o.button) return;
    var r = this.o.button.getBoundingClientRect(), w = this.box.offsetWidth, h = this.box.offsetHeight;
    this.box.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, r.left)) + 'px';
    this.box.style.top = Math.max(8, r.top - h - 8) + 'px';
  };
  Picker.prototype.render = function () {
    var D = this.D, self = this; if (!D) return;
    this.toneBtn.textContent = '👋' + TONES[this.tone];
    [].forEach.call(this.tabs.childNodes, function (b) { b.classList.toggle('on', !self.q.value && Number(b.dataset.g) === self.group); });
    var rows, title;
    if (this.q.value.trim()) { rows = search(D, this.q.value, 300); title = rows.length ? 'Search results' : 'No emoji found'; }
    else if (this.group === -1) { rows = recent().map(function (ch) { return byChar(D, ch) ? [ch, -1, (byChar(D, ch) || [])[2] || ch, '', []] : null; }).filter(Boolean); title = rows.length ? 'Recently used' : 'Emoji you use will show here'; }
    else { rows = D.list.filter(function (r) { return r[1] === self.group; }); title = D.groups[this.group][0]; }
    this.label.textContent = title;
    var frag = document.createDocumentFragment();
    rows.forEach(function (r) {
      var ch = self.group === -1 && !self.q.value.trim() ? r[0] : withTone(r, self.tone);
      var b = el('button', 'sc-emoji-btn', ch); b.type = 'button'; b.dataset.e = ch; b.title = r[2] + (r[4] && r[4][0] ? '  :' + r[4][0] + ':' : '');
      b.setAttribute('aria-label', r[2]);
      frag.appendChild(b);
    });
    this.grid.textContent = ''; this.grid.appendChild(frag);
  };

  /* =================================================================
     4. SHORTCODE SUGGESTIONS + ":)" CONVERSION
     ================================================================= */
  function Suggest(o) {
    this.o = o; this.items = []; this.sel = 0; this.range = null;
    var self = this;
    this.box = el('div', 'sc-emoji-suggest hidden'); this.box.setAttribute('role', 'listbox');
    (o.container || document.body).appendChild(this.box);
    this.box.onmousedown = function (e) { e.preventDefault(); };   // keep the focus in the message box
    this.box.onclick = function (e) { var b = e.target.closest('[data-i]'); if (b) self.pick(Number(b.dataset.i)); };
    o.input.addEventListener('input', function (e) { self.onInput(e); });
    // runs BEFORE the app's own Enter-to-send handler, so Enter/Tab pick a suggestion while the list is open
    o.input.addEventListener('keydown', function (e) {
      if (self.box.classList.contains('hidden')) return;
      if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); e.stopImmediatePropagation(); self.pick(self.sel); }
      else if (e.key === 'Escape') { e.preventDefault(); e.stopImmediatePropagation(); self.hide(); }
      else if (e.key === 'ArrowRight' || e.key === 'ArrowDown') { e.preventDefault(); self.sel = (self.sel + 1) % self.items.length; self.render(); }
      else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') { e.preventDefault(); self.sel = (self.sel - 1 + self.items.length) % self.items.length; self.render(); }
    }, true);
    o.input.addEventListener('blur', function () { setTimeout(function () { self.hide(); }, 150); });
  }
  Suggest.prototype.onInput = function (e) {
    var input = this.o.input, pos = input.selectionStart, before = input.value.slice(0, pos), self = this;
    if (e && e.isComposing) return;
    // ":)" → 🙂, only right after a space is typed (so ":)" inside a word or URL stays)
    if (this.o.convert && this.o.convert() && e && e.inputType === 'insertText' && e.data === ' ') {
      var m0 = /(^|\s)(\S{2,3}) $/.exec(before);
      if (m0 && SAFE_EMOTICONS[m0[2]]) { var st = pos - m0[2].length - 1; insert(input, SAFE_EMOTICONS[m0[2]] + ' ', st, pos); return; }
    }
    var m = /(^|[\s(])(:([a-z0-9_+\-]{2,30}))(:?)$/i.exec(before);
    if (!m) return this.hide();
    load(this.o.dataUrl).then(function (D) {
      if (input.selectionStart !== pos) return;                   // typed on meanwhile
      var q = m[3].toLowerCase(); self.q = q;
      var rows = D.list.filter(function (r) { return r[4].some(function (s) { return s.indexOf(q) === 0; }); });
      rows.sort(function (a, b) { var ea = a[4].indexOf(q) >= 0 ? 0 : 1, eb = b[4].indexOf(q) >= 0 ? 0 : 1; return ea - eb || Math.min.apply(null, a[4].map(function (s) { return s.length; })) - Math.min.apply(null, b[4].map(function (s) { return s.length; })); });
      self.range = [pos - m[2].length - m[4].length, pos];
      if (m[4] === ':') {                                          // ":smile:" typed out in full → replace straight away
        var exact = rows.find(function (r) { return r[4].indexOf(q) >= 0; });
        if (exact) { self.items = [exact]; return self.pick(0); }
        return self.hide();
      }
      self.items = rows.slice(0, 6); self.sel = 0;
      if (!self.items.length) return self.hide();
      self.render(); self.box.classList.remove('hidden'); self.place();
    }).catch(function () { self.hide(); });
  };
  Suggest.prototype.render = function () {
    var self = this, tone = Number(store(TONE_KEY)) || 0; this.box.textContent = '';
    this.items.forEach(function (r, i) {
      var shown = r[4].find(function (s) { return s.indexOf(self.q || '') === 0; }) || r[4][0];   // the shortcode that matches what was typed
      var b = el('button', 'sc-emoji-sug' + (i === self.sel ? ' on' : '')); b.type = 'button'; b.dataset.i = i; b.setAttribute('role', 'option');
      b.appendChild(el('span', 'e', withTone(r, tone))); b.appendChild(el('span', 'n', ':' + shown + ':'));
      self.box.appendChild(b);
    });
  };
  Suggest.prototype.place = function () {
    var r = this.o.input.getBoundingClientRect();
    this.box.style.left = Math.max(8, r.left) + 'px';
    this.box.style.bottom = (window.innerHeight - r.top + 6) + 'px';
    this.box.style.maxWidth = Math.max(200, r.width) + 'px';
  };
  Suggest.prototype.pick = function (i) {
    var r = this.items[i]; if (!r || !this.range) return this.hide();
    var ch = withTone(r, Number(store(TONE_KEY)) || 0);
    insert(this.o.input, ch, this.range[0], this.range[1]); remember(ch);
    this.hide();
  };
  Suggest.prototype.hide = function () { this.box.classList.add('hidden'); this.items = []; this.range = null; };

  /* =================================================================
     5. EMOJI-ONLY MESSAGES (shown bigger)
     ================================================================= */
  var seg = root.Intl && Intl.Segmenter ? new Intl.Segmenter('en', { granularity: 'grapheme' }) : null;
  var EMOJI_RE = /^(?:\p{Extended_Pictographic}|\p{Regional_Indicator}|[#*0-9]️?⃣)/u;
  function isJumbo(text) {
    var t = String(text || '').replace(/\s+/g, '');
    if (!t || t.length > 40 || !seg) return false;
    var n = 0, it = seg.segment(t)[Symbol.iterator](), s;
    while (!(s = it.next()).done) { if (!EMOJI_RE.test(s.value.segment)) return false; if (++n > 3) return false; }
    return n > 0;
  }

  /* ---------- wiring ---------- */
  function attach(o) {
    var p = new Picker(o), s = new Suggest(o);
    if (o.button) { o.button.setAttribute('aria-haspopup', 'dialog'); o.button.setAttribute('aria-expanded', 'false'); o.button.addEventListener('click', function (e) { e.preventDefault(); p.toggle(); }); }
    window.addEventListener('resize', function () { if (p.open) p.place(); });
    return { picker: p, suggest: s, hide: function () { p.hide(); s.hide(); } };
  }
  root.SCEmoji = { attach: attach, isJumbo: isJumbo, load: load, search: search, SAFE_EMOTICONS: SAFE_EMOTICONS };
})(typeof window !== 'undefined' ? window : this);
