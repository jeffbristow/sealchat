/* =====================================================================
 * Seal Chat — webhttp.js   (small HTTPS client for web access, 1.4.0)
 * ---------------------------------------------------------------------
 * Talks to your website's relay.php and wake file — through Tor by
 * default (the website then never sees your home IP address), or
 * directly when "Connect through Tor" is off.
 * Note: the website does NOT need to be on the Tor network. Tor reaches
 * ordinary websites through an "exit relay"; the website just sees a
 * visitor coming from that relay. Some web hosts block such visitors —
 * those errors get code 'TOR_BLOCKED' so Seal Chat can offer to connect
 * directly instead (1.4.1).
 *
 * Remembers the TLS session per website, so the idle "has the wake file
 * changed?" check costs ~1 KB instead of a full ~5 KB handshake.
 *
 * viaFallbacks(): through Tor; if the website blocks Tor, directly — only
 * when the user allowed that (Settings → Privacy). (1.8.2 also tried a shared
 * forwarder; removed in 1.8.4.)
 *
 * Sections:
 *   1. request(): one HTTP(S) request → { status, headers, body }
 *   2. Friendly error messages
 *   3. Websites that block Tor (1.8.2 · 1.8.4)
 * ===================================================================== */

const https = require('https');
const http = require('http');
const tls = require('tls');
const net = require('net');
const { socksRaw } = require('./wire');

const tlsSessions = new Map();     // "host:port" -> last TLS session (for quick reconnects)

/* =================================================================
 * 1. REQUEST
 * opts: { method, headers, body (Buffer|string), socksPort (null = direct),
 *         ca, allowHttp, timeoutMs, maxBytes }
 * ================================================================= */
function request(url, opts = {}) {
  let u;
  try { u = new URL(url); } catch { return Promise.reject(new Error('Bad web address')); }
  const secure = u.protocol === 'https:';
  if (!secure && !(opts.allowHttp && u.protocol === 'http:')) return Promise.reject(new Error('The web interface address must start with https://'));
  const port = Number(u.port) || (secure ? 443 : 80);
  const sessKey = u.hostname + ':' + port;
  const body = opts.body == null ? null : Buffer.isBuffer(opts.body) ? opts.body : Buffer.from(String(opts.body));

  // through Tor: SOCKS connection first, then TLS on top of it
  const sockP = opts.socksPort
    ? socksRaw(opts.socksPort, u.hostname, port, opts.connectTimeoutMs || 60000).then(raw => {
      raw.on('error', () => {});
      if (!secure) return raw;
      const t = tls.connect({ socket: raw, servername: net.isIP(u.hostname) ? undefined : u.hostname, ca: opts.ca, session: tlsSessions.get(sessKey) });
      t.on('session', s => tlsSessions.set(sessKey, s));
      t.on('error', () => {});
      return t;
    })
    : Promise.resolve(null);

  return sockP.then(sock => new Promise((resolve, reject) => {
    const headers = { 'User-Agent': 'SealChat-Web', 'Accept': '*/*', 'Connection': 'close', ...(opts.headers || {}) };
    if (body) { headers['Content-Length'] = body.length; if (!headers['Content-Type']) headers['Content-Type'] = 'application/json'; }
    const reqOpts = { method: opts.method || 'GET', hostname: u.hostname, port, path: u.pathname + u.search, headers, timeout: opts.timeoutMs || 45000, ca: opts.ca };
    // 1.4.1 FIX: the request must use the socket that goes through Tor. (Before, "agent: false"
    // made Node ignore createConnection and connect DIRECTLY — the Tor socket was opened but unused.)
    // A one-off agent whose createConnection hands over our Tor socket is always honoured.
    if (sock) { const A = new (secure ? https : http).Agent({ keepAlive: false }); A.createConnection = () => sock; reqOpts.agent = A; }
    const req = (secure ? https : http).request(reqOpts, res => {
      const max = opts.maxBytes || 8 * 1024 * 1024;
      const chunks = []; let size = 0;
      res.on('data', d => { size += d.length; if (size > max) { res.destroy(new Error('The website sent too much')); return; } chunks.push(d); });
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('timeout', () => req.destroy(new Error('The website did not answer in time')));
    req.on('error', e => reject(friendly(e, !!opts.socksPort, u.hostname)));
    if (body) req.write(body);
    req.end();
  }), e => { throw friendly(e, true, u.hostname); });
}

/* =================================================================
 * 2. FRIENDLY ERRORS
 * ================================================================= */
function friendly(e, viaTor, host) {
  const m = (e && e.message) || String(e);
  const err = text => new Error(text);
  if (/ENOTFOUND|EAI_AGAIN/.test(m)) return err('Could not find the website (no internet?)');
  if (/ECONNREFUSED/.test(m) && !viaTor) return err('The website refused the connection');
  if (/certificate|CERT_|self.signed/i.test(m)) return err('The website\'s security certificate is not valid');
  if (viaTor) {
    // Tor itself isn't running / reachable on this PC
    if (/Tor connection error|Tor refused/i.test(m)) return err('Tor is not running on this PC yet — wait until Seal Chat shows "Connected", then try again');
    // the connection out of the Tor network to the website failed (or was cut by the website)
    if (/contact|reach|SOCKS|timed out|socket disconnected|socket hang up|ECONNRESET|EPIPE|closed/i.test(m)) {
      const why = m.replace(/^Could not reach contact:?\s*/, '').replace(/\s*\((offline\?|they may be offline)\)|\s*—?\s*they may be offline/g, '').trim();
      const x = err(`Tor could not connect to ${host || 'your website'}${why ? ' (' + why + ')' : ''}. Your website doesn't need to be on Tor — but some web hosts block visitors that arrive through Tor.`);
      x.code = 'TOR_BLOCKED';
      return x;
    }
  }
  return err(m);
}

/* =================================================================
 * 3. WEBSITES THAT BLOCK TOR (1.8.2 · 1.8.4)
 * ================================================================= */
/** A "this visitor is blocked" answer: an error page instead of the JSON Seal Chat expects. */
function looksBlocked(r) {
  if (![403, 429, 503].includes(r.status)) return false;
  try { JSON.parse(r.body.toString('utf8')); return false; } catch { return true; }
}

/**
 * One request that copes with Tor-blocking hosts:
 *   1. through Tor
 *   2. blocked → directly, only if opts.direct (the user allowed it)
 * Returns the response plus .via ('tor' | 'direct' | 'blocked').
 * opts: request() options + { socksPort, direct, http (tests) }
 */
async function viaFallbacks(url, opts = {}) {
  const http = opts.http || request;
  const base = { ...opts }; delete base.direct; delete base.http;
  const tries = [];
  if (opts.socksPort) tries.push(['tor', () => http(url, { ...base, socksPort: opts.socksPort })]);
  if (opts.direct || !opts.socksPort) tries.push(['direct', () => http(url, { ...base, socksPort: null })]);
  let lastErr = null, lastRes = null;
  for (let i = 0; i < tries.length; i++) {
    const [via, go] = tries[i];
    const more = i < tries.length - 1;
    try {
      const r = await go();
      if (looksBlocked(r) && more) { lastRes = r; continue; }
      r.via = via;
      return r;
    } catch (e) {
      lastErr = e;
      if (!(e.code === 'TOR_BLOCKED' && more)) throw e;
    }
  }
  if (lastRes) { lastRes.via = 'blocked'; return lastRes; }
  throw lastErr || new Error('Could not reach the website');
}

/** 1.8.4: a few words saying what a web page (instead of Seal Chat's JSON answer) was — its title or first text. */
function pageHint(r) {
  const t = (r && r.body ? r.body.toString('utf8') : '').slice(0, 20000);
  const title = /<title[^>]*>([^<]{1,120})<\/title>/i.exec(t);
  const text = (title ? title[1] : t.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
  return text ? '"' + text.slice(0, 90) + (text.length > 90 ? '…' : '') + '"' : 'an empty page';
}

module.exports = { request, viaFallbacks, looksBlocked, pageHint };
