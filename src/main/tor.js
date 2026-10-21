/* =====================================================================
 * Seal Chat — tor.js   (Tor service, 1.0.0)
 * ---------------------------------------------------------------------
 * Runs Seal Chat's own private copy of Tor (tor.exe, shipped inside the
 * app) and publishes this PC's .onion address.
 *
 *  - Tor runs only while Seal Chat runs, and is stopped with it
 *    (__OwningControllerProcess makes Tor quit even if Seal Chat crashes).
 *  - It listens only on 127.0.0.1 (this PC); nothing is opened on your
 *    router, and no port forwarding is needed.
 *  - The .onion address comes from a secret key kept in Seal Chat's
 *    encrypted store and handed to Tor at runtime (ADD_ONION), so the
 *    key is never written to disk in plain form.
 *
 * Sections:
 *   1. Finding tor.exe and writing its settings (torrc)
 *   2. Starting / stopping Tor
 *   3. Control connection (talking to the running Tor)
 *   4. Bootstrap progress (0–100%)
 *   5. Publishing the .onion address
 *   6. Helpers
 * ===================================================================== */

const fs = require('fs');
const path = require('path');
const net = require('net');
const { spawn } = require('child_process');
const { EventEmitter } = require('events');

/* =================================================================
 * 1. FINDING TOR + SETTINGS
 * ================================================================= */

/** Folder holding tor.exe for this platform (packaged app or source tree). */
function torFolder(resourcesPath) {
  // 1.5.0: macOS has separate Tor builds for Apple Silicon (arm64) and Intel (x64)
  const sub = process.platform === 'win32' ? 'win-x64' : process.platform === 'darwin' ? 'mac-' + (process.arch === 'arm64' ? 'arm64' : 'x64') : 'linux-x64';
  const candidates = [
    resourcesPath && path.join(resourcesPath, 'tor', sub),                      // installed app
    path.join(__dirname, '..', '..', 'resources', 'tor', sub)                   // running from source
  ].filter(Boolean);
  for (const c of candidates) if (fs.existsSync(path.join(c, process.platform === 'win32' ? 'tor.exe' : 'tor'))) return c;
  throw new Error('Tor is missing from this Seal Chat install. Please reinstall Seal Chat.');
}

/**
 * Pluggable transport (lyrebird) for bridges: Seal Chat can borrow the one
 * that ships with Tor Browser, so networks that block Tor still work.
 */
function findLyrebird(custom) {
  const list = [];
  if (custom) list.push(custom);
  if (process.platform === 'win32') {
    const roots = [process.env.USERPROFILE && path.join(process.env.USERPROFILE, 'Desktop'),
      process.env.LOCALAPPDATA, process.env.ProgramFiles, process.env['ProgramFiles(x86)'],
      process.env.USERPROFILE && path.join(process.env.USERPROFILE, 'OneDrive', 'Desktop')].filter(Boolean);
    for (const r of roots) list.push(path.join(r, 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'PluggableTransports', 'lyrebird.exe'));
  } else if (process.platform === 'darwin') {
    // 1.5.0: Tor Browser for Mac
    list.push('/Applications/Tor Browser.app/Contents/MacOS/Tor/PluggableTransports/lyrebird');
    if (process.env.HOME) list.push(path.join(process.env.HOME, 'Applications', 'Tor Browser.app', 'Contents', 'MacOS', 'Tor', 'PluggableTransports', 'lyrebird'));
    list.push('/opt/homebrew/bin/lyrebird', '/usr/local/bin/lyrebird', '/opt/homebrew/bin/obfs4proxy', '/usr/local/bin/obfs4proxy');
  } else {
    list.push('/usr/bin/lyrebird', '/usr/bin/obfs4proxy');
  }
  return list.find(p => { try { return fs.statSync(p).isFile(); } catch { return false; } }) || null;
}

/**
 * Writes torrc. opts: { dataDir, bridges: [lines], lyrebird, testConf }
 * testConf (developers only, from SEALCHAT_TOR_TESTNET) points Tor at a
 * private test network instead of the real one.
 */
function writeTorrc(opts) {
  const lines = [
    '# Written by Seal Chat on every start — changes here are overwritten.',
    `DataDirectory ${q(opts.dataDir)}`,
    'SocksPort 127.0.0.1:auto',
    'ControlPort 127.0.0.1:auto',
    `ControlPortWriteToFile ${q(path.join(opts.dataDir, 'control-port.txt'))}`,
    'CookieAuthentication 1',
    `CookieAuthFile ${q(path.join(opts.dataDir, 'control-cookie'))}`,
    `__OwningControllerProcess ${process.pid}`,
    'ClientOnly 1',
    'AvoidDiskWrites 1',
    'Log notice stdout',
    'SafeLogging 1'
  ];
  const bridges = (opts.bridges || []).map(s => String(s).trim()).filter(Boolean);
  if (bridges.length) {
    lines.push('UseBridges 1');
    for (const b of bridges) lines.push('Bridge ' + b.replace(/^Bridge\s+/i, '').replace(/[\r\n]/g, ''));
    if (opts.lyrebird && bridges.some(b => /^(Bridge\s+)?(obfs4|webtunnel|meek_lite|scramblesuit)\s/i.test(b))) {
      lines.push(`ClientTransportPlugin meek_lite,obfs2,obfs3,obfs4,scramblesuit,webtunnel exec ${q(opts.lyrebird)}`);
    }
  }
  if (opts.testConf) lines.push(`%include ${q(opts.testConf)}`);
  const file = path.join(opts.dataDir, 'torrc');
  fs.writeFileSync(file, lines.join('\n') + '\n');
  return file;
}

/* =================================================================
 * 2. START / STOP
 * ================================================================= */
class TorService extends EventEmitter {
  /**
   * @param {object} o  { dataDir, resourcesPath, bridges, lyrebirdPath, log }
   */
  constructor(o) {
    super();
    this.o = o;
    this.proc = null;
    this.ctl = null;
    this.socksPort = 0;
    this.progress = 0;
    this.summary = 'Not started';
    this.ready = false;
    this.onion = null;          // our address (without ".onion")
    this.stopping = false;
    this.logTail = [];
  }

  status() {
    return { running: !!this.proc, ready: this.ready, progress: this.progress, summary: this.summary, onion: this.onion, socksPort: this.socksPort, usingBridges: !!(this.o.bridges && this.o.bridges.length) };
  }

  _set(progress, summary) {
    this.progress = progress; this.summary = summary;
    this.emit('status', this.status());
  }

  async start() {
    if (this.proc) return;
    this.stopping = false;
    fs.mkdirSync(this.o.dataDir, { recursive: true });
    try { fs.chmodSync(this.o.dataDir, 0o700); } catch { /* Windows */ }
    for (const f of ['control-port.txt', 'control-cookie']) { try { fs.unlinkSync(path.join(this.o.dataDir, f)); } catch { /* none */ } }

    // 1.9.0: the Android app passes its own Tor (libtor.so in the app's native library folder)
    const folder = process.env.SEALCHAT_TOR_EXE ? path.dirname(process.env.SEALCHAT_TOR_EXE) : torFolder(this.o.resourcesPath);
    const exe = process.env.SEALCHAT_TOR_EXE || path.join(folder, process.platform === 'win32' ? 'tor.exe' : 'tor');
    const lyrebird = findLyrebird(this.o.lyrebirdPath);
    const torrc = writeTorrc({ dataDir: this.o.dataDir, bridges: this.o.bridges, lyrebird, testConf: process.env.SEALCHAT_TOR_TESTNET || null });
    this.lyrebird = lyrebird;

    this._set(1, 'Starting Tor…');
    const env = { ...process.env };
    if (process.platform !== 'win32') env.LD_LIBRARY_PATH = folder + (env.LD_LIBRARY_PATH ? ':' + env.LD_LIBRARY_PATH : '');
    this.proc = spawn(exe, ['-f', torrc, '--defaults-torrc', path.join(this.o.dataDir, 'no-defaults')], { cwd: folder, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const onLine = line => {
      line = String(line).trim(); if (!line) return;
      this.logTail.push(line); if (this.logTail.length > 200) this.logTail.shift();
      if (this.o.log) this.o.log(line);
      const m = /Bootstrapped (\d+)%[^:]*: (.*)$/.exec(line);
      if (m) this._set(Number(m[1]), friendlyPhase(Number(m[1]), m[2]));
    };
    lineReader(this.proc.stdout, onLine);
    lineReader(this.proc.stderr, onLine);
    const exited = new Promise(res => this.proc.once('exit', code => res(code)));
    this.proc.once('exit', code => {
      const was = this.proc; this.proc = null; this.ready = false;
      if (this.ctl) { this.ctl.close(); this.ctl = null; }
      if (!this.stopping) {
        this._set(0, 'Tor stopped unexpectedly' + (code ? ` (code ${code})` : ''));
        this.emit('exit', { code, unexpected: true, log: this.logTail.slice(-15) });
      }
      void was;
    });

    // wait for Tor to tell us its control port
    const portFile = path.join(this.o.dataDir, 'control-port.txt');
    const ctlAddr = await Promise.race([
      waitFor(() => { try { const t = fs.readFileSync(portFile, 'utf8'); const m = /PORT=([\d.]+):(\d+)/.exec(t); return m ? { host: m[1], port: Number(m[2]) } : null; } catch { return null; } }, 30000),
      exited.then(code => { throw new Error('Tor could not start (code ' + code + '): ' + this.logTail.slice(-3).join(' | ')); })
    ]);
    const cookie = fs.readFileSync(path.join(this.o.dataDir, 'control-cookie'));
    this.ctl = new TorControl();
    await this.ctl.connect(ctlAddr.host, ctlAddr.port, cookie);
    this.ctl.on('event', ev => this._event(ev));
    this.ctl.on('close', () => { if (!this.stopping && this.proc) this._set(this.progress, 'Lost contact with Tor'); });
    await this.ctl.cmd('TAKEOWNERSHIP');
    await this.ctl.cmd('SETEVENTS STATUS_CLIENT');

    // SOCKS port (for connecting out to contacts)
    const socks = await this.ctl.getinfo('net/listeners/socks');
    const sm = /:(\d+)"?\s*$/.exec(socks.trim());
    this.socksPort = sm ? Number(sm[1]) : 0;

    // current bootstrap state (events cover the rest)
    const phase = await this.ctl.getinfo('status/bootstrap-phase');
    this._phase(phase);
  }

  async stop() {
    this.stopping = true;
    this.ready = false;
    const p = this.proc;
    if (this.ctl) { try { await this.ctl.cmd('SIGNAL SHUTDOWN', 2000); } catch { /* ignore */ } this.ctl.close(); this.ctl = null; }
    this.extra = new Set();     // 1.8.0: Tor forgets every address when it stops
    if (p) {
      await Promise.race([new Promise(r => p.once('exit', r)), sleep(3000)]);
      try { p.kill(); } catch { /* gone */ }
    }
    this.proc = null;
    this._set(0, 'Stopped');
  }

  async restart(newOpts) {
    await this.stop();
    if (newOpts) Object.assign(this.o, newOpts);
    await this.start();
  }

  /* =================================================================
   * 4. BOOTSTRAP PROGRESS
   * ================================================================= */
  _event(ev) {
    // 650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=50 TAG=... SUMMARY="..."
    if (/BOOTSTRAP/.test(ev)) this._phase(ev);
  }

  _phase(text) {
    const p = /PROGRESS=(\d+)/.exec(text);
    const s = /SUMMARY="([^"]*)"/.exec(text);
    if (!p) return;
    const n = Number(p[1]);
    if (/WARN/.test(text) && /WARNING="([^"]*)"/.test(text)) {
      this._set(n, 'Having trouble reaching Tor: ' + /WARNING="([^"]*)"/.exec(text)[1]);
      return;
    }
    this._set(n, friendlyPhase(n, s ? s[1] : ''));
    if (n >= 100 && !this.ready) { this.ready = true; this.emit('ready'); }
  }

  /** Resolves when Tor is fully connected. */
  whenReady(timeoutMs = 0) {
    if (this.ready) return Promise.resolve();
    return new Promise((res, rej) => {
      const t = timeoutMs ? setTimeout(() => { this.off('ready', ok); rej(new Error('Tor is not connected yet')); }, timeoutMs) : null;
      const ok = () => { if (t) clearTimeout(t); res(); };
      this.once('ready', ok);
    });
  }

  /* =================================================================
   * 5. PUBLISHING THE .ONION ADDRESS
   * key: 'ED25519-V3:<base64>' from a previous run, or null for a new one.
   * Returns { onion, key } — save key (secretly) to keep the same address.
   * ================================================================= */
  async publish(key, localPort, virtualPort = 80) {
    if (!this.ctl) throw new Error('Tor is not running');
    const keyArg = key || 'NEW:ED25519-V3';
    const flags = key ? '' : '';
    const reply = await this.ctl.cmd(`ADD_ONION ${keyArg}${flags} Port=${virtualPort},127.0.0.1:${localPort}`);
    const id = /ServiceID=([a-z2-7]{56})/.exec(reply);
    if (!id) throw new Error('Tor did not create the .onion address: ' + reply);
    const pk = /PrivateKey=(\S+)/.exec(reply);
    this.onion = id[1];
    this.emit('status', this.status());
    return { onion: id[1], key: key || (pk ? pk[1] : null) };
  }

  async unpublish() {
    if (this.ctl && this.onion) { try { await this.ctl.cmd('DEL_ONION ' + this.onion); } catch { /* ignore */ } }
    this.onion = null;
  }

  /* ---------- 1.8.0: extra, temporary addresses (invite codes) ----------
   * key: 'ED25519-V3:<expanded key>' worked out from the code; expect: the
   * .onion that key must give (Tor's answer is checked against it). */
  async publishExtra(key, localPort, virtualPort, expect) {
    if (!this.ctl) throw new Error('Tor is not running');
    if (!this.extra) this.extra = new Set();
    if (expect && this.extra.has(expect)) { try { await this.ctl.cmd('DEL_ONION ' + expect); } catch { /* ignore */ } this.extra.delete(expect); }
    const reply = await this.ctl.cmd(`ADD_ONION ${key} Flags=DiscardPK Port=${virtualPort},127.0.0.1:${localPort}`);
    const id = /ServiceID=([a-z2-7]{56})/.exec(reply);
    if (!id) throw new Error('Tor did not create the address: ' + reply);
    if (expect && id[1] !== expect) { try { await this.ctl.cmd('DEL_ONION ' + id[1]); } catch { /* ignore */ } throw new Error('Tor gave a different address than expected'); }
    this.extra.add(id[1]);
    return { onion: id[1] };
  }
  async unpublishExtra(onion) {
    if (!this.extra || !this.extra.has(onion)) return;
    this.extra.delete(onion);
    if (this.ctl) { try { await this.ctl.cmd('DEL_ONION ' + onion); } catch { /* ignore */ } }
  }
}

/* =================================================================
 * 3. CONTROL CONNECTION
 * A tiny client for Tor's control protocol: one command at a time,
 * asynchronous "650" events passed on as 'event'.
 * ================================================================= */
class TorControl extends EventEmitter {
  constructor() { super(); this.sock = null; this.buf = ''; this.queue = []; this.lines = []; }

  connect(host, port, cookie) {
    return new Promise((res, rej) => {
      const s = net.connect(port, host);
      this.sock = s;
      s.setEncoding('utf8');
      s.once('error', rej);
      s.on('data', d => this._data(d));
      s.on('close', () => { for (const q of this.queue) q.rej(new Error('Tor control connection closed')); this.queue = []; this.emit('close'); });
      s.once('connect', async () => {
        s.off('error', rej);
        s.on('error', () => { /* close follows */ });
        try { await this.cmd('AUTHENTICATE ' + cookie.toString('hex')); res(); } catch (e) { rej(e); }
      });
    });
  }

  _data(d) {
    this.buf += d;
    let i;
    while ((i = this.buf.indexOf('\r\n')) >= 0) {
      const line = this.buf.slice(0, i); this.buf = this.buf.slice(i + 2);
      this._line(line);
    }
  }

  _line(line) {
    // multi-line data blocks ("250+key=" ... ".")
    if (this.inData) {
      if (line === '.') { this.inData = false; return; }
      this.lines.push(line.replace(/^\.\./, '.'));
      return;
    }
    const code = line.slice(0, 3), sep = line[3];
    if (code === '650') {
      if (sep === ' ') { this.emit('event', [...this.evLines || [], line.slice(4)].join('\n')); this.evLines = null; }
      else (this.evLines = this.evLines || []).push(line.slice(4));
      return;
    }
    this.lines.push(line.slice(4));
    if (sep === '+') { this.inData = true; return; }
    if (sep === ' ') {
      const q = this.queue.shift();
      const text = this.lines.join('\n'); this.lines = [];
      if (!q) return;
      clearTimeout(q.t);
      if (code[0] === '2') q.res(text); else q.rej(new Error(`Tor: ${code} ${text}`));
    }
  }

  cmd(line, timeoutMs = 60000) {
    return new Promise((res, rej) => {
      if (!this.sock || this.sock.destroyed) return rej(new Error('Tor control connection is closed'));
      const t = setTimeout(() => { const i = this.queue.findIndex(x => x.t === t); if (i >= 0) this.queue.splice(i, 1); rej(new Error('Tor did not answer: ' + line.split(' ')[0])); }, timeoutMs);
      this.queue.push({ res, rej, t });
      this.sock.write(line + '\r\n');
    });
  }

  async getinfo(key) {
    const r = await this.cmd('GETINFO ' + key);
    const lines = r.split('\n').filter(l => l !== 'OK');
    return lines.join('\n').replace(new RegExp('^' + key.replace(/[/.]/g, '\\$&') + '='), '');
  }

  close() { try { this.sock && this.sock.destroy(); } catch { /* ignore */ } this.sock = null; }
}

/* =================================================================
 * 6. HELPERS
 * ================================================================= */
function q(p) { return '"' + String(p).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; }
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function waitFor(fn, ms) {
  const end = Date.now() + ms;
  for (;;) { const v = fn(); if (v) return v; if (Date.now() > end) throw new Error('Tor did not start in time'); await sleep(100); }
}
function lineReader(stream, cb) {
  let b = '';
  stream.setEncoding('utf8');
  stream.on('data', d => { b += d; let i; while ((i = b.indexOf('\n')) >= 0) { cb(b.slice(0, i)); b = b.slice(i + 1); } });
}
function friendlyPhase(n, summary) {
  if (n >= 100) return 'Connected to Tor';
  if (n < 10) return 'Connecting to Tor…';
  if (n < 50) return 'Getting the Tor network directory…';
  if (n < 90) return 'Joining the Tor network…';
  return summary || 'Almost connected…';
}

module.exports = { TorService, TorControl, findLyrebird, torFolder };
