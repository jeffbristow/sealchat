/* =====================================================================
 * Seal Chat — build/afterPack.js
 * electron-builder hook: stamps Seal Chat's icon and version details into
 * SealChat.exe. Uses pure-JavaScript "resedit", so building the Windows
 * installer works from Windows, Mac or Linux (no Wine needed).
 * ===================================================================== */
const fs = require('fs');
const path = require('path');

exports.default = async function afterPack(context) {
  if (context.electronPlatformName !== 'win32') return;
  const ResEdit = await import('resedit');
  const { NtExecutable, NtExecutableResource, Resource, Data } = ResEdit;

  const exe = path.join(context.appOutDir, context.packager.appInfo.productFilename + '.exe');   // "Seal Chat.exe"
  const version = context.packager.appInfo.version;
  const exeData = NtExecutable.from(fs.readFileSync(exe), { ignoreCert: true });
  const res = NtExecutableResource.from(exeData);

  // --- icon
  const iconFile = Data.IconFile.from(fs.readFileSync(path.join(__dirname, 'icon.ico')));
  Resource.IconGroupEntry.replaceIconsForResource(
    res.entries, 1, 1033, iconFile.icons.map(i => i.data)
  );

  // --- version info shown in File Properties / Task Manager
  const vi = Resource.VersionInfo.fromEntries(res.entries)[0] || Resource.VersionInfo.createEmpty();
  const [ma, mi, pa] = version.split('.').map(Number);
  vi.setFileVersion(ma, mi, pa, 0, 1033);
  vi.setProductVersion(ma, mi, pa, 0, 1033);
  vi.setStringValues({ lang: 1033, codepage: 1200 }, {
    FileDescription: 'Seal Chat',
    ProductName: 'Seal Chat',
    CompanyName: 'Seal Chat',
    LegalCopyright: 'Seal Chat',
    OriginalFilename: 'Seal Chat.exe',
    InternalName: 'SealChat'
  });
  vi.outputToResourceEntries(res.entries);

  res.outputResource(exeData);
  fs.writeFileSync(exe, Buffer.from(exeData.generate()));
  console.log('  • afterPack: icon + version info written to', path.basename(exe));
};
