/* =====================================================================
 * Seal Chat Mailbox — Cloudflare Worker   (Seal Chat 1.8.5)
 * ---------------------------------------------------------------------
 * Holds sealed messages your contacts leave while your Seal Chat is
 * offline. Every message is PGP-encrypted for you before it gets here:
 * this Worker (and Cloudflare) can't read it or see who sent it.
 *
 * Made for ONE Seal Chat: the two values below were created by your
 * Seal Chat (Settings → Mailbox → Copy Worker script). The first is only
 * a hash — the key itself never leaves your PC.
 *
 * Needs one D1 database bound to this Worker with the variable name DB
 * (Worker → Settings → Bindings → Add → D1 database). The tables are
 * created automatically.
 *
 * Speaks the same language as Seal Chat Web's relay.php mailbox, so
 * contacts on any Seal Chat 1.8 can leave messages here:
 *   POST ?a=mbox_set   your Seal Chat: turn on (hash of the drop token) / off
 *   POST ?a=mbox_drop  a contact: leave one sealed message (drop token)
 *   POST ?a=mbox_get   your Seal Chat: pick up (and delete what it has)
 *   GET  /             "is it working?" — open the Worker's address in a browser
 *
 * Sections:
 *   1. Settings (from your Seal Chat) and limits
 *   2. Helpers (answers, hashes, database)
 *   3. The request handler
 * ===================================================================== */

/* ---------- 1. SETTINGS AND LIMITS ---------- */
const OWNER_HASH = '__OWNER_HASH__';     // sha-256 of your Seal Chat's mailbox key
const BOX = '__BOX__';                   // this mailbox's name
const VERSION = 1;
const MAX_ITEM = 768 * 1024;             // one sealed message (text, or a file's offer + preview)
const MAX_QUEUE = 20 * 1024 * 1024;      // all waiting messages together
const MAX_ITEMS = 1000;
const KEEP_SECS = 30 * 86400;            // never picked up → deleted after 30 days
const PER_MINUTE = 120;                  // drops per minute (all senders together)
const GET_BYTES = 4 * 1024 * 1024;       // per pick-up

/* ---------- 2. HELPERS ---------- */
const out = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }
});
const fail = (status, code, error) => out({ ok: false, code, error }, status);

async function sha256hex(text) {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
}
/** Compares two hex strings without leaking how much of them matched. */
function same(a, b) {
  a = String(a || ''); b = String(b || '');
  if (a.length !== b.length || !a.length) return false;
  const e = new TextEncoder();
  return crypto.subtle.timingSafeEqual(e.encode(a), e.encode(b));
}

let ready = false;                       // tables made (once per Worker start)
async function db(env) {
  if (!env.DB) throw Object.assign(new Error('No database: add a D1 database binding named DB to this Worker (Settings → Bindings)'), { code: 'nodb' });
  if (!ready) {
    await env.DB.batch([
      env.DB.prepare('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)'),
      env.DB.prepare('CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY AUTOINCREMENT, t INTEGER NOT NULL, d TEXT NOT NULL)')
    ]);
    ready = true;
  }
  return env.DB;
}
const meta = async (D, k) => { const r = await D.prepare('SELECT v FROM meta WHERE k = ?').bind(k).first(); return r ? r.v : null; };

/** Your Seal Chat? (its key, sent in the X-SC-Owner header) */
async function isOwner(req) {
  const tok = req.headers.get('X-SC-Owner') || '';
  return /^[A-Za-z0-9_-]{30,200}$/.test(tok) && same(await sha256hex(tok), OWNER_HASH);
}

/* ---------- 3. REQUEST HANDLER ---------- */
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const a = url.searchParams.get('a') || '';

    try {
      /* "is it working?" (a browser visit) */
      if (req.method === 'GET' && !a) {
        let dbOk = true, dbErr = '';
        try { await db(env); } catch (e) { dbOk = false; dbErr = e.message; }
        return out({ ok: dbOk, app: 'sealchat-mailbox', v: VERSION, ...(dbOk ? { note: 'Seal Chat mailbox is working. Paste this address into Seal Chat → Settings → Mailbox.' } : { code: 'nodb', error: dbErr }) }, dbOk ? 200 : 500);
      }
      if (req.method !== 'POST') return fail(405, 'method', 'Use POST');
      const len = Number(req.headers.get('Content-Length') || 0);
      if (len > MAX_ITEM + 4096) return fail(413, 'big', 'That message is too large for the mailbox');
      const raw = await req.text();
      if (raw.length > MAX_ITEM + 4096) return fail(413, 'big', 'That message is too large for the mailbox');
      let input = {};
      try { input = raw ? JSON.parse(raw) : {}; } catch { return fail(400, 'json', 'Bad request'); }
      if (!input || typeof input !== 'object') input = {};
      const box = req.headers.get('X-SC-Box') || '';
      if (box && box !== BOX) return fail(404, 'nombox', 'No mailbox here (it may have been turned off)');
      const D = await db(env);
      const now = Math.floor(Date.now() / 1000);

      switch (a) {
        /* ---------- mbox_set: your Seal Chat turns the mailbox on (hash of the drop token) or off (null) ---------- */
        case 'mbox_set': {
          if (!(await isOwner(req))) return fail(403, 'owner', 'This mailbox belongs to a different Seal Chat');
          const h = input.drop ?? null;
          if (h === null) {
            await D.batch([D.prepare('DELETE FROM meta WHERE k = ?').bind('drop'), D.prepare('DELETE FROM items')]);   // off: what was waiting goes too
          } else if (/^[a-f0-9]{64}$/.test(String(h))) {
            await D.prepare('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').bind('drop', String(h)).run();
          } else return fail(400, 'drop', 'Bad drop token');
          return out({ ok: true, mailbox: h !== null, keepDays: KEEP_SECS / 86400, maxItem: MAX_ITEM, app: 'sealchat-mailbox', v: VERSION });
        }

        /* ---------- mbox_drop: a contact leaves one sealed message (needs the drop token) ---------- */
        case 'mbox_drop': {
          const drop = req.headers.get('X-SC-Drop') || String(input.drop || '');
          const want = await meta(D, 'drop');
          if (!want || !/^[A-Za-z0-9_-]{20,200}$/.test(drop) || !same(await sha256hex(drop), want)) return fail(404, 'nombox', 'No mailbox here (it may have been turned off)');
          const d = input.d;
          if (typeof d !== 'string' || !d || d.length > MAX_ITEM || !/^[A-Za-z0-9+/=]+$/.test(d)) return fail(413, 'big', 'That message is too large for the mailbox');
          await D.prepare('DELETE FROM items WHERE t < ?').bind(now - KEEP_SECS).run();
          const s = await D.prepare('SELECT COUNT(*) AS n, COALESCE(SUM(LENGTH(d)), 0) AS b, SUM(CASE WHEN t >= ? THEN 1 ELSE 0 END) AS recent FROM items').bind(now - 60).first();
          if (Number(s.recent || 0) >= PER_MINUTE) return fail(429, 'slow', 'Too many messages at once — try again in a minute');
          if (Number(s.b) + d.length > MAX_QUEUE || Number(s.n) >= MAX_ITEMS) return fail(507, 'full', 'This mailbox is full');
          const r = await D.prepare('INSERT INTO items (t, d) VALUES (?, ?)').bind(now, d).run();
          return out({ ok: true, id: Number(r.meta && r.meta.last_row_id) || 0, now });
        }

        /* ---------- mbox_get: your Seal Chat picks up (with "ack": deletes what it already has) ---------- */
        case 'mbox_get': {
          if (!(await isOwner(req))) return fail(403, 'owner', 'This mailbox belongs to a different Seal Chat');
          const ack = Math.max(0, Math.floor(Number(input.ack) || 0));
          await D.prepare('DELETE FROM items WHERE id <= ? OR t < ?').bind(ack, now - KEEP_SECS).run();
          const rows = (await D.prepare('SELECT id, t, d FROM items ORDER BY id LIMIT 200').all()).results || [];
          const items = []; let bytes = 0;
          for (const it of rows) {
            bytes += it.d.length;
            if (items.length && bytes > GET_BYTES) break;
            items.push({ id: it.id, t: it.t, d: it.d });
          }
          const left = await D.prepare('SELECT COUNT(*) AS n FROM items').first();
          return out({ ok: true, items, more: items.length < Number(left.n), mailbox: !!(await meta(D, 'drop')), now });
        }

        default:
          return fail(400, 'action', 'Unknown action');
      }
    } catch (e) {
      return fail(500, e.code || 'error', e.code === 'nodb' ? e.message : 'The mailbox had a problem: ' + (e.message || e));
    }
  }
};
