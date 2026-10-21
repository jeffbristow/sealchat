# Seal Chat

Private chat that goes straight from your PC to your contact's PC over Tor — no server in the middle. Every message is signed and encrypted with PGP.

**Website and downloads:** [jeffbristow.com/sealchat](https://jeffbristow.com/sealchat/) · **Latest release:** [Releases → Latest](https://github.com/jeffbristow/sealchat/releases/latest)

## Download

| Platform | File |
| --- | --- |
| Windows | `SealChat-Setup-<version>.exe` |
| macOS 13+ (Apple silicon / Intel) | `SealChat-<version>-arm64.dmg` / `SealChat-<version>-x64.dmg` |
| macOS 12 | `SealChat-<version>-macOS12-arm64.dmg` / `SealChat-<version>-macOS12-x64.dmg` |
| Linux | `SealChat-<version>-x86_64.AppImage` / `SealChat-<version>-amd64.deb` |
| Android | `SealChat-<version>.apk` |
| Seal Chat Web (your own website) | `SealChat-Web-<version>.zip` |

Installed apps update themselves from signed `.sealchat` update files, so an installer older than the newest version is fine: it updates on first start. Update files are published to [jeffbristow/sealchat-updates](https://github.com/jeffbristow/sealchat-updates).

## Build from source

```sh
npm install          # also patches openpgp for the phone (build/patch-openpgp.js)
npm start            # run it
npm test             # engine tests
npm run test:node18  # the same tests on Node 18 (what the Android app runs)

npm run dist         # Windows installer   → dist/
npm run dist:linux   # AppImage + .deb     → dist/
npm run dist:mac     # macOS app           → dist/
npm run update-file  # signed .sealchat update (needs build/update-signing-key.pem)
```

The update signing key (`build/update-signing-key.pem`) is kept offline and is never committed; `.gitignore` blocks it. Only its public half, `build/update-signing-key.pub.pem`, is in this repository.

## More

[`README.txt`](README.txt) has the full guide: how Seal Chat works, every version's changes, publishing updates and Seal Chat Web.

## License

GPL-3.0 — see [LICENSE](LICENSE).
