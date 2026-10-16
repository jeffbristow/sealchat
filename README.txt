=====================================================================
 SEAL CHAT 1.4.1 — private peer-to-peer chat over Tor, with PGP
=====================================================================

WHAT'S NEW IN 1.4.1 — FIXES
  • "Through Tor" now really goes through Tor. In 1.3.0–1.4.0 a bug made
    update checks (and web access) open a Tor connection but then send the
    request DIRECTLY — so the website could see your IP address. Fixed, with
    a test that fails if a request ever bypasses Tor again.
  • Web access: your website does not need to be on Tor (Tor reaches normal
    websites through "exit relays"). If your web host blocks visitors that
    come through Tor, Seal Chat now says so clearly and offers
    "Connect directly instead". The "Connect through Tor" switch is now
    shown before you connect, too.

WHAT'S NEW IN 1.4.0 — WEB ACCESS (use Seal Chat from your phone)
  The web interface is a separate package, SEAL CHAT WEB, that you install
  on YOUR OWN web hosting (not the download/landing page site). It is a
  remote screen for Seal Chat on this computer: your key
  stays here, Seal Chat reads and sends as usual, and the phone gets what
  it shows sealed with a key only the two share. The website only passes
  on sealed messages it can't read. OFF BY DEFAULT.
  Set up once:
    1. Install Seal Chat Web on your hosting (see its README), open its
       admin.php → "Turn the web interface on" → Save → Copy link.
    2. Seal Chat: Settings → Web access → paste the link → Connect.
    3. "Turn on" (until you turn it off, or for 1 / 8 / 24 hours).
    4. "Pair a device…" shows a QR code. Scan it with the iPhone Camera app
       (or "Scan the QR code" in the web interface), choose a PIN, check
       the 6-digit code is the same on both screens, click Approve.
    iPhone tip: open the web interface in Safari, Share → "Add to Home
    Screen", and pair from that icon — it opens like an app, and Safari
    can't clear it after 7 days without use.
  Daily use: open it on the phone, type your PIN. Seal Chat notices within
  the check interval (Settings, default 30 s), then messages go both ways
  in 1–2 seconds. Text messages, read ticks and contact pictures work; files
  show as name + size (open them on the computer).
  How quiet it is: while nobody uses it, Seal Chat makes ONE tiny request
  per interval for a static "wake" file that the web server answers with
  "304 Not Modified" — no PHP runs (about 1–2 KB each, through Tor by
  default). When the web interface is opened it changes that file; Seal
  Chat then listens at relay.php until the page has been quiet for 5
  minutes, then goes back to the tiny checks. Off = no requests at all.
  Safety: 10 wrong PINs remove the device. Remove a device any time in
  Settings → Web access. The tray menu has a Web access on/off switch. The
  computer must be on and awake with Seal Chat running.


WHAT'S NEW IN 1.3.0 — AUTOMATIC UPDATES
  • Seal Chat checks https://jeffbristow.com/sealchat/update.php once a
    day (first check about 1½ minutes after start). When a newer version is
    there, a purple "Seal Chat x.y.z is available" bar appears above your
    contacts: click it → What's new → "Download and install" → Restart.
    "Skip this version" stops the reminder for that version.
  • Settings → About & updates: "Check for updates now", automatic checks
    on/off, and "Check and download through Tor" (on by default, so the
    website never sees your IP address).
  • SIGNED UPDATES: every update file comes with a .sig file made with the
    Seal Chat signing key. Seal Chat refuses any update whose signature or
    contents don't match — even if the website itself were hacked.
  • "Install update file…" still works for manual updates.
  • Also in 1.2.1: back to your ID & QR code from any chat — the box at the
    bottom left, the Seal Chat logo, or Esc.

PUBLISHING AN UPDATE (for you)
  1. Build it: npm run update-file  → dist/update/SealChat-X.Y.Z.sealchat
     and SealChat-X.Y.Z.sealchat.sig (signed automatically when
     build/update-signing-key.pem is present; or sign an existing file with
     node build/sign-update.js <file> <key.pem>).
  2. Upload BOTH files to https://jeffbristow.com/sealchat/update/
  3. In the website's admin.php → "Update file": paste the link to the
     .sealchat file, set its version, Save. Apps see it within a day (or at
     once with "Check for updates now").
  Keep update-signing-key.pem private and backed up offline. Without it no
  one (you included) can make updates the app will install automatically;
  with it, anyone can — so never put it on the web server.

WHAT'S NEW IN 1.2.0 — QR CODES, PICTURES, LINUX
  • QR code of your Seal Chat ID on the main screen: "Save QR picture…"
    or "Copy QR picture" to send it by email or text.
  • ＋ Add contact can now read a QR code: "Scan with camera" (webcam),
    "Open QR picture…" (a photo or screenshot of the code) or
    "Paste QR picture" (from the clipboard).
  • Your picture: Settings → You → "Choose picture…". Tick "Share my picture
    with my contacts" to send it to them (it updates for them whenever you
    change it; untick to take it back).
  • A picture for each contact: open ⓘ (contact details) → Picture:
    "The picture they share", "My own picture for them" (choose…), or
    "Initials only".
  • Linux: Seal Chat-1.2.0 AppImage and .deb (see LINUX below).
  • Update BOTH PCs. A contact still on 1.1 can chat and send files as
    before, but won't see your shared picture until they update.

WHAT'S NEW IN 1.1.0 — FILES
  • Send photos, videos, music, documents — any file up to 2 GB (4 GB max,
    set in Settings → Files). Click 📎, drag files onto the chat, or paste a
    screenshot (Ctrl+V) into the message box.
  • Photos show in the chat (click for full size); videos and audio play
    right in the chat; documents get Open and Save as… buttons.
  • Files up to 25 MB download by themselves; bigger ones show "Download"
    and "Decline". Program files (.exe, .bat, .ps1, .msi …) never download
    by themselves and are never opened by Seal Chat — only "Save as…".
  • Progress bar with speed and time left; Pause / Resume. A transfer that
    breaks (PC off, connection lost) carries on from where it stopped.
  • Install on BOTH PCs. A contact still on 1.0 can't receive files —
    you'll see "needs Seal Chat 1.1 or newer".

WHAT'S NEW IN 1.0.1
  • Fixed: "Request not accepted: key cannot encrypt" when the two PCs'
    clocks differ even slightly. A key or message made on a PC whose clock
    is ahead used to look "not valid yet" on the other PC. Seal Chat now
    accepts clock differences of up to 2 days, and new keys are dated a day
    back. Expired or revoked keys are still refused.
  • Install the update on BOTH PCs (Settings → About & updates →
    "Install update file…" → SealChat-1.0.1.sealchat → Restart). The waiting
    contact request then goes through by itself, or click "Try now".

WHAT IT IS
  Seal Chat sends messages straight from your PC to your contact's PC
  through the Tor network. There is no Seal Chat server: nothing is
  stored or relayed anywhere except on the two PCs.
  Every message is signed with your PGP key and encrypted to your
  contact's PGP key, inside Tor's own end-to-end encryption.

INSTALL
  1. Put all SealChat-Setup-1.0.0.N.part files and Join-SealChat-Setup.bat
     in one folder. Double-click Join-SealChat-Setup.bat.
     It rebuilds SealChat-Setup-1.0.0.exe and checks it.
  2. Run SealChat-Setup-1.0.0.exe.
     Windows SmartScreen may say "Windows protected your PC" because the
     installer isn't code-signed: click "More info" → "Run anyway".
  Tor is built in (tor.exe 0.4.9.5). You don't need Tor Browser, and you
  don't need to change anything on your router.

FIRST START
  Choose one:
   • Use my own PGP key: paste or pick your PRIVATE key (.asc) and type its
     passphrase. RSA and ECC (Curve25519) keys both work. The key needs an
     encryption subkey; most keys have one.
   • Create a new key.
   • Restore a Seal Chat backup.
  Within about a minute, Seal Chat connects to Tor and shows YOUR SEAL CHAT ID:
      sealchat:<56-character .onion address>:<40-digit key fingerprint>
  Send that ID to the people you want to chat with (email, text, in person).
  The fingerprint inside it means nobody can impersonate you, even with
  the address.

ADDING SOMEONE
  ＋ Add contact → paste their ID → Send request.
  Seal Chat connects to their .onion address, checks that the key there
  matches the fingerprint in the ID, then sends a signed and encrypted
  request. They see it under "Contact requests" and click Accept.
  Optional: open ⓘ (contact details) on both PCs and compare the 60-digit
  SAFETY NUMBER by phone or in person. If they match, click "Mark as verified".

WHEN SOMEONE IS OFFLINE
  Messages wait in your Outbox (shown with a ⏱ clock). Seal Chat retries
  after 20 s, 1, 2, 5, 10 minutes, then every 15 minutes. It also sends them
  within seconds when that contact's Seal Chat starts or reaches you.
  A message only travels when BOTH PCs are on, because there is no server
  to hold it. Ticks:  ⏱ waiting   ✓ delivered to their PC   ✓✓ read
  Closing the window keeps Seal Chat running in the tray (near the clock)
  so it can receive messages. To quit, right-click the tray icon → Quit.
  Settings → App → "Start Seal Chat when I sign in to Windows" keeps you
  reachable whenever the PC is on.

WHERE YOUR DATA IS
  %APPDATA%\Seal Chat\
    vault.dat     your key, passphrase, .onion key and contacts — encrypted
    chats\*.dat   one encrypted file per conversation
    key.bin       the encryption key for the above, locked to your Windows
                  account (Windows DPAPI)
    settings.json ordinary preferences (no secrets)
    tor\          Tor's working folder

BACKUP / NEW PC
  Settings → Backup → choose a password → Save backup. The file holds your
  key, Seal Chat ID, contacts and chats, encrypted with that password.
  On the new PC choose "Restore a Seal Chat backup". Your ID stays the same.
  Run only ONE PC with a given ID at a time.

IF YOUR NETWORK BLOCKS TOR
  Settings → Connection (Tor): paste bridge lines from
  https://bridges.torproject.org/ and click "Save & reconnect".
  obfs4 bridges need the "lyrebird" helper that comes with Tor Browser.
  If Tor Browser is installed in a normal place (Desktop, Program Files),
  Seal Chat finds it. Otherwise use Browse… to point at lyrebird.exe
  (Tor Browser\Browser\TorBrowser\Tor\PluggableTransports\lyrebird.exe).

FILES (1.1.0)
  How it works: each file gets its own random encryption key, which travels
  inside a normal signed + encrypted (PGP) message. The file itself is cut
  into 256 KB pieces, each sealed with AES-256-GCM, and your contact's PC
  pulls the pieces straight from yours over Tor. Every piece is checked as
  it arrives, so a changed, missing or out-of-order piece is caught.
  Speed: Tor onion connections usually manage 0.5–3 MB per second — a photo
  takes seconds, a song 2–10 seconds, a 500 MB video roughly 3–15 minutes.
  Both PCs must have Seal Chat running; a big file can arrive over several
  sessions. Files stay encrypted on disk (%APPDATA%\Seal Chat\files\).
  "Open" puts a temporary decrypted copy in your Temp folder (deleted when
  Seal Chat starts or quits); "Save as…" writes a normal copy wherever you
  choose. Settings → Files shows the space used and can remove old files.
  Backups do NOT include files — save the ones you want to keep.

LINUX (1.2.0)
  Two downloads, same app (Tor is built in for Linux too):
   • SealChat-1.2.0-amd64.deb  — Ubuntu, Debian, Mint, Pop!_OS:
       sudo apt install ./SealChat-1.2.0-amd64.deb
     then start "Seal Chat" from your apps menu (or run: sealchat).
   • SealChat-1.2.0-x86_64.AppImage — any 64-bit distribution:
       chmod +x SealChat-1.2.0-x86_64.AppImage && ./SealChat-1.2.0-x86_64.AppImage
  Your key and chats are protected by your desktop keyring (GNOME Keyring /
  KWallet), so have one running (normal on Ubuntu, Mint, KDE).
  Data folder: ~/.config/Seal Chat/
  Some desktops (stock GNOME) hide tray icons. If you close the window and
  can't see the tray icon, just start Seal Chat again — it brings the
  window back. Or turn off "Closing the window keeps Seal Chat running".
  Windows Hello isn't available on Linux; the PIN app lock works the same.
  "Start Seal Chat when I sign in" adds it to ~/.config/autostart/.

APP LOCK
  Settings → App lock: a PIN (and optionally Windows Hello) to open Seal
  Chat. It locks again after idle time and when Windows locks. Messages
  keep arriving while it's locked, and notifications then only say
  "New message".

UPDATES
  Settings → About & updates → "Install update file…" and pick a
  SealChat-x.y.z.sealchat file. Your key, ID, contacts and chats are not
  touched.

SECURITY NOTES
  • PGP has no "forward secrecy". If someone ever gets your private key AND
    its passphrase, they could read past messages they had recorded. Keep
    the key and backups safe. (Version 1.0 is built so session keys can be
    added later.)
  • Your contacts see your Seal Chat ID, but never your IP address or
    location (that's Tor's job).
  • Anyone who has your ID can send you a contact request. You can turn
    requests off in Settings → Privacy once your contacts are added.

FOR DEVELOPERS
  npm install · npm start · npm test (core tests, no Tor needed)
  npm run test:tor (end-to-end test; needs Tor or a private test network
  via SEALCHAT_TOR_TESTNET) · npm run test:web (1.4.0 web access against
  the Seal Chat Web files with php -S; SITE_DIR=<Seal Chat Web folder>) · npm run dist (Windows installer)
  · npm run update-file (.sealchat update file)
  Source layout:
    src/main/tor.js       runs tor.exe, publishes the .onion address
    src/main/wire.js      framed connections + SOCKS5 through Tor
    src/main/peer.js      contacts, requests, messages, outbox, receipts
    src/main/identity.js  PGP: import/create key, sign+encrypt, safety number
    src/main/store.js     encrypted files on disk
    src/main/files.js     encrypted file storage (pieces) — 1.1.0
    src/main/backup.js    password-protected backups
    src/main/webaccess.js web access: wake checks, pairing, PIN, device API (1.4.0)
    src/main/webhttp.js   HTTPS to your website through Tor (1.4.0)
    src/main/main.js      app window, tray, notifications, IPC
    src/renderer/*        the window (HTML/CSS/JS)
  Tor binaries: resources/tor/win-x64 (from the kmp-tor-resource project,
  Tor 0.4.9.5, Apache-2.0 packaging of the BSD-licensed Tor).
