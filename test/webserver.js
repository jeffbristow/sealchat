/* =====================================================================
 * Seal Chat — test/webserver.js   (test helper, 1.4.0)
 * Serves a copy of Seal Chat Web for the tests:
 *   - Apache + mod_php when installed (like real shared hosting: .htaccess,
 *     304 answers for the wake file, one PHP process per request)
 *   - otherwise php -S (note: php -S can make a request wait behind a long
 *     poll on the same worker, so timings are rougher)
 * start(siteDir) → { base, requests() → access-log lines, stop() }
 * ===================================================================== */
const fs = require('fs');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

const sleep = ms => new Promise(r => setTimeout(r, ms));
const hasApache = () => process.env.WEB_SERVER !== 'php' && fs.existsSync('/usr/sbin/apache2') && fs.existsSync('/etc/apache2/mods-enabled/php8.3.load');

async function start(site, tmp) {
  const port = 18000 + Math.floor(Math.random() * 1500);
  if (hasApache()) {
    const run = path.join(tmp, 'apache');
    fs.mkdirSync(run, { recursive: true });
    const conf = `ServerRoot "/etc/apache2"
Listen 127.0.0.1:${port}
ServerName localhost
PidFile ${run}/apache.pid
Mutex file:${run}
User www-data
Group www-data
ErrorLog ${run}/error.log
LogFormat "%h \\"%r\\" %>s %b" short
CustomLog ${run}/access.log short
TypesConfig /etc/mime.types
Include /etc/apache2/mods-enabled/*.load
Include /etc/apache2/mods-enabled/*.conf
LoadModule rewrite_module /usr/lib/apache2/modules/mod_rewrite.so
LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so
StartServers 4
MaxRequestWorkers 30
DocumentRoot ${site}
<Directory ${site}>
  AllowOverride All
  Require all granted
</Directory>
`;
    fs.writeFileSync(run + '/httpd.conf', conf);
    execFileSync('chown', ['-R', 'www-data:www-data', tmp]);
    fs.chmodSync(tmp, 0o755);
    execFileSync('/usr/sbin/apache2', ['-f', run + '/httpd.conf', '-k', 'start'], { env: { ...process.env, APACHE_RUN_DIR: run, APACHE_LOCK_DIR: run, APACHE_LOG_DIR: run } });
    await sleep(800);
    const log = run + '/access.log';
    return {
      kind: 'apache', base: `http://127.0.0.1:${port}/`,
      requests: () => { try { return fs.readFileSync(log, 'utf8').split('\n').filter(Boolean); } catch { return []; } },
      stop: () => { try { execFileSync('/usr/sbin/apache2', ['-f', run + '/httpd.conf', '-k', 'stop'], { env: { ...process.env, APACHE_RUN_DIR: run, APACHE_LOCK_DIR: run, APACHE_LOG_DIR: run } }); } catch { /* gone */ } }
    };
  }
  const lines = [];
  const php = spawn('php', ['-S', '127.0.0.1:' + port, '-t', site], { env: { ...process.env, PHP_CLI_SERVER_WORKERS: '8' } });
  php.stderr.on('data', d => lines.push(...d.toString().split('\n').filter(l => /\[\d{3}\]: /.test(l))));
  await sleep(700);
  return { kind: 'php -S', base: `http://127.0.0.1:${port}/`, requests: () => lines.slice(), stop: () => php.kill() };
}

module.exports = { start };
