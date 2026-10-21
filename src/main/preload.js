/* =====================================================================
 * Seal Chat — preload.js
 * The only bridge between the window and the main process: a fixed list
 * of calls exposed as window.api.call('<channel>', ...args), each
 * resolving to { ok:true, data } or { ok:false, error, code }.
 * Events from the main process arrive through window.api.on(fn).
 * ===================================================================== */
const { contextBridge, ipcRenderer, webUtils } = require('electron');

const channels = new Set([
  'app:info', 'app:openExternal', 'app:restart', 'app:installUpdate', 'app:reset', 'clipboard:write',
  'setup:state', 'setup:generate', 'setup:pickKeyFile', 'setup:inspectKey', 'setup:importKey', 'setup:restore',
  'identity:unlock', 'identity:setRemember', 'identity:copyPublic', 'identity:exportPrivate',
  'me:get', 'me:copyId', 'tor:status', 'tor:restart', 'tor:log',
  'contacts:list', 'contacts:parse', 'contacts:add', 'contacts:accept', 'contacts:decline', 'contacts:block', 'contacts:unblock',
  'contacts:remove', 'contacts:rename', 'contacts:verify', 'contacts:mute', 'contacts:retry', 'contacts:details', 'contacts:exportKey',
  'device:get', 'device:rename', 'devices:status', 'devices:link', 'devices:linkCancel', 'devices:remove', 'setup:link', 'contacts:resolve', 'me:setHandle', 'mailbox:status', 'mailbox:check', 'mailbox:workerScript', 'mailbox:workerConnect', 'mailbox:workerRemove',
  'invite:list', 'invite:create', 'invite:cancel',   // 1.8.0 invite codes
  'chat:history', 'chat:open', 'chat:close', 'chat:send', 'chat:react', 'chat:delete', 'chat:clear', 'chat:export',
  'settings:get', 'settings:set', 'settings:setBridges', 'settings:pickLyrebird',
  'lock:status', 'lock:helloAvailable', 'lock:setup', 'lock:update', 'lock:changePin', 'lock:disable', 'lock:lockNow', 'lock:activity', 'lock:unlockPin', 'lock:unlockHello',
  'backup:create',
  // 1.1.0 files
  'file:pick', 'file:sendPaths', 'file:sendData', 'file:download', 'file:pause', 'file:decline', 'file:save', 'file:showSaved', 'file:open',
  'storage:usage', 'storage:free',
  // 1.2.0 QR codes + pictures
  'qr:mine', 'qr:copy', 'qr:save', 'qr:readFile', 'qr:readClipboard',
  'me:pickAvatar', 'me:removeAvatar', 'me:setShareAvatar', 'contacts:setAvatarMode', 'contacts:pickAvatar',
  // 1.3.0 automatic updates
  'update:status', 'update:check', 'update:install', 'update:skip',
  // 1.4.0 web access
  'web:status', 'web:connect', 'web:disconnect', 'web:enable', 'web:pair', 'web:copyPairLink', 'web:approve', 'web:decline', 'web:cancelPair', 'web:removeDevice',
  'web:devicePush',  // 1.6.0 notifications per device
  'update:first', 'update:firstSkip'   // 1.6.0 first-run update
]);

contextBridge.exposeInMainWorld('api', {
  call: (channel, ...args) => channels.has(channel) ? ipcRenderer.invoke(channel, ...args) : Promise.resolve({ ok: false, error: 'Unknown call ' + channel }),
  on: fn => ipcRenderer.on('evt', (_e, ev) => fn(ev)),
  // 1.1.0: the real path of a file dragged into the window
  pathForFile: file => { try { return webUtils.getPathForFile(file) || null; } catch { return null; } }
});
