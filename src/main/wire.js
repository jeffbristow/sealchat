/* =====================================================================
 * Seal Chat — wire.js   (connections between Seal Chat apps, 1.0.0)
 * ---------------------------------------------------------------------
 * How two Seal Chat apps talk:
 *   - Each app runs a small listener on 127.0.0.1 that Tor exposes as
 *     its .onion address (port 80 on the .onion side).
 *   - To reach a contact, the app connects through Tor's SOCKS port to
 *     <their-address>.onion:80.
 *   - Over that connection both sides exchange "frames": a 4-byte length
 *     followed by a small JSON object. Chat text is never in a frame as
 *     plain text — it is always inside a PGP-encrypted, signed block.
 *
 * Sections:
 *   1. Limits
 *   2. Frame reader / writer
 *   3. SOCKS5 connect through Tor
 * ===================================================================== */

const net = require('net');
const { EventEmitter } = require('events');

/* =================================================================
 * 1. LIMITS
 * ================================================================= */
const MAX_FRAME = 512 * 1024;        // one frame (an encrypted message / file piece) at most 512 KB
const CONNECT_TIMEOUT = 90 * 1000;   // reaching an .onion can take a while the first time

/* =================================================================
 * 2. FRAMES
 * Wraps a socket: .send(obj), emits 'frame' (obj), 'close', 'error'.
 * 1.1.0: file pieces travel as compact BINARY frames (no base64), told
 * apart from JSON frames by their first byte:
 *   0x01 | id length (1 byte) | id | piece number (4 bytes) | encrypted piece
 * They arrive as { t:'piece', id, i, data:Buffer }.
 * ================================================================= */
class FrameSocket extends EventEmitter {
  constructor(sock) {
    super();
    this.sock = sock;
    this.chunks = []; this.have = 0;    // received bytes not yet parsed (kept as a list: no big re-copies)
    this.closed = false;
    sock.setNoDelay(true);
    sock.on('data', d => this._data(d));
    sock.on('close', () => { this.closed = true; this.emit('close'); });
    sock.on('error', e => this.emit('error', e));
  }

  _take(n) {
    // removes and returns the first n buffered bytes
    const first = this.chunks[0];
    if (first.length >= n) {
      const out = first.subarray(0, n);
      if (first.length === n) this.chunks.shift(); else this.chunks[0] = first.subarray(n);
      this.have -= n; return out;
    }
    const out = Buffer.allocUnsafe(n); let o = 0;
    while (o < n) {
      const c = this.chunks[0], k = Math.min(c.length, n - o);
      c.copy(out, o, 0, k); o += k;
      if (k === c.length) this.chunks.shift(); else this.chunks[0] = c.subarray(k);
    }
    this.have -= n; return out;
  }

  _peekLen() {
    if (this.chunks[0].length >= 4) return this.chunks[0].readUInt32BE(0);
    const h = this._take(4); this.chunks.unshift(h); this.have += 4; return h.readUInt32BE(0);
  }

  _data(d) {
    if (this.closed) return;
    this.chunks.push(d); this.have += d.length;
    while (this.have >= 4) {
      const len = this._peekLen();
      if (len > MAX_FRAME || len < 1) { this.destroy(); return; }    // too big: hang up
      if (this.have < 4 + len) return;
      this._take(4);
      const body = this._take(len);
      if (body[0] === 0x01) {                                        // binary file piece
        const idLen = body[1];
        if (len < 6 + idLen) { this.destroy(); return; }
        const id = body.subarray(2, 2 + idLen).toString('latin1');
        const i = body.readUInt32BE(2 + idLen);
        this.emit('frame', { t: 'piece', id, i, data: body.subarray(6 + idLen) });
        continue;
      }
      let obj;
      try { obj = JSON.parse(body.toString('utf8')); } catch { this.destroy(); return; }
      if (!obj || typeof obj !== 'object' || typeof obj.t !== 'string' || obj.t === 'piece') { this.destroy(); return; }
      this.emit('frame', obj);
    }
  }

  /** Sends one file piece; resolves once the socket can take more (back-pressure). */
  sendPiece(id, i, data) {
    if (this.closed) return Promise.reject(Object.assign(new Error('Connection closed'), { code: 'UNREACHABLE' }));
    const idb = Buffer.from(String(id), 'latin1');
    const head = Buffer.alloc(4 + 2 + idb.length + 4);
    head.writeUInt32BE(2 + idb.length + 4 + data.length, 0);
    head[4] = 0x01; head[5] = idb.length; idb.copy(head, 6); head.writeUInt32BE(i, 6 + idb.length);
    if (head.length - 4 + data.length > MAX_FRAME) return Promise.reject(new Error('piece too large'));
    this.sock.write(head);
    if (this.sock.write(data)) return Promise.resolve();
    return new Promise((res, rej) => {
      const ok = () => { this.sock.off('close', bad); res(); };
      const bad = () => { this.sock.off('drain', ok); rej(Object.assign(new Error('Connection closed'), { code: 'UNREACHABLE' })); };
      this.sock.once('drain', ok); this.sock.once('close', bad);
    });
  }

  send(obj) {
    if (this.closed) return false;
    const body = Buffer.from(JSON.stringify(obj), 'utf8');
    if (body.length > MAX_FRAME) throw new Error('Message is too large to send');
    const head = Buffer.alloc(4); head.writeUInt32BE(body.length, 0);
    return this.sock.write(Buffer.concat([head, body]));
  }

  /** Sends a frame and waits for the first reply frame matching test(). */
  request(obj, test, timeoutMs = 60000) {
    return new Promise((res, rej) => {
      const done = (err, v) => { clearTimeout(t); this.off('frame', onF); this.off('close', onC); err ? rej(err) : res(v); };
      const onF = f => { if (test(f)) done(null, f); };
      const onC = () => done(Object.assign(new Error('Connection closed'), { code: 'UNREACHABLE' }));
      const t = setTimeout(() => done(Object.assign(new Error('No answer from contact'), { code: 'UNREACHABLE' })), timeoutMs);
      this.on('frame', onF); this.on('close', onC);
      try { this.send(obj); } catch (e) { done(e); }
    });
  }

  setIdle(ms) { this.sock.setTimeout(ms, () => this.destroy()); }
  end() { try { this.sock.end(); } catch { /* ignore */ } }
  destroy() { this.closed = true; try { this.sock.destroy(); } catch { /* ignore */ } }
}

/* =================================================================
 * 3. SOCKS5 CONNECT (through Tor)
 * ================================================================= */
const SOCKS_ERRORS = {
  1: 'Tor failure', 2: 'not allowed', 3: 'network unreachable', 4: 'contact not reachable (offline?)',
  5: 'connection refused', 6: 'timed out (offline?)', 7: 'command not supported', 8: 'address type not supported',
  // Tor's own onion-service codes
  0xf0: 'address not found (contact offline or address wrong)', 0xf1: 'address is invalid', 0xf2: 'introduction failed',
  0xf3: 'rendezvous failed', 0xf4: 'authorization required', 0xf5: 'bad authorization', 0xf6: 'contact offline (timed out)'
};

/**
 * Opens a connection to host:port through Tor's SOCKS port.
 * Resolves to a FrameSocket.
 */
function socksConnect(socksPort, host, port, timeoutMs = CONNECT_TIMEOUT, onSocket = null, wantRaw = false) {
  return new Promise((res, rej) => {
    const sock = net.connect(socksPort, '127.0.0.1');
    if (onSocket) onSocket(sock);                                   // lets the caller cancel a slow attempt
    let stage = 0, buf = Buffer.alloc(0), settled = false;
    const fail = msg => { if (settled) return; settled = true; clearTimeout(t); sock.destroy(); const e = new Error(msg); e.code = 'UNREACHABLE'; rej(e); };
    const t = setTimeout(() => fail('Could not reach contact (timed out — they may be offline)'), timeoutMs);
    sock.on('error', e => fail('Tor connection error: ' + e.message));
    sock.on('close', () => fail('Could not reach contact'));
    sock.on('connect', () => sock.write(Buffer.from([5, 1, 0])));      // SOCKS5, 1 method: no auth
    const onData = d => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0) {
        if (buf.length < 2) return;
        if (buf[0] !== 5 || buf[1] !== 0) return fail('Tor refused the connection');
        buf = buf.subarray(2); stage = 1;
        const h = Buffer.from(host, 'ascii');
        const req = Buffer.concat([Buffer.from([5, 1, 0, 3, h.length]), h, Buffer.from([port >> 8, port & 255])]);
        sock.write(req);
      }
      if (stage === 1) {
        if (buf.length < 5) return;
        if (buf[1] !== 0) return fail('Could not reach contact: ' + (SOCKS_ERRORS[buf[1]] || 'error ' + buf[1]));
        const atyp = buf[3];
        const need = atyp === 1 ? 10 : atyp === 4 ? 22 : 7 + buf[4];
        if (buf.length < need) return;
        const rest = buf.subarray(need);
        sock.off('data', onData);
        sock.removeAllListeners('close'); sock.removeAllListeners('error');
        settled = true; clearTimeout(t);
        if (wantRaw) { if (rest.length) sock.unshift(rest); res(sock); return; }   // plain socket (1.3.0: update checks)
        const fs = new FrameSocket(sock);
        res(fs);
        if (rest.length) fs._data(rest);
      }
    };
    sock.on('data', onData);
  });
}

/** 1.3.0: a plain TCP socket through Tor (for HTTPS update checks). */
const socksRaw = (socksPort, host, port, timeoutMs = 60000) => socksConnect(socksPort, host, port, timeoutMs, null, true);

module.exports = { FrameSocket, socksConnect, socksRaw, MAX_FRAME };
