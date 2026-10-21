=====================================================================
 SEAL CHAT 1.9.6 — private peer-to-peer chat over Tor, with PGP
=====================================================================

WHAT'S NEW IN 1.9.6   (an update file only)
  • Fix: with linked devices, the phone (Seal Chat Web) only worked with
    the device that connected the website — another linked device (for
    example the Android app) never answered it. A device learns what the
    website can do (Seal Chat Web 1.3.2's "lease") only when it connects,
    so a website connected before it was updated to 1.3.2 was taken to be
    an older one forever. Now a device that shares the connection but has
    no lease asks the website again every 10 minutes, and passes the
    answer to your other devices. Desktop and Android.
  • New check in npm run test:webshare: the website is updated to 1.3.2
    after it was connected.

WHAT'S NEW IN 1.9.5   (an update file only)
  • Fix (Android): a long message preview in the contact list made the
    whole screen scroll sideways. On a phone the list is one flexible
    grid column, and #sidebar had no min-width: 0, so the column grew to
    fit the preview on one line. The preview (and a long contact name)
    is now cut short with "…" instead. The desktop's fixed 290 px
    column was never affected.

WHAT'S NEW IN 1.9.4   (an update file only)
  • Fix (found by a developer testing the Android app): on the first
    start, "Link to my Seal Chat on another device" showed an empty screen
    (on the phone, back did nothing either). setupStep() in
    src/renderer/app.js switched steps from a hard-coded list that was
    missing the Link step added in 1.9.0. It now reads the steps from the
    page, so a new step can't be left out again. Desktop and Android.
  • New check: test/setup-steps-test.js runs the real setupStep() against
    the real step list for every welcome button (npm test, test:node18).

WHAT'S NEW IN 1.9.3   (an update file only · goes with Seal Chat Web 1.3.2)
  • Web access (Seal Chat Web) is shared by your linked devices: the
    website connection, the paired phones and the notification key go to
    your other devices in the encrypted device sync, so your phone works
    with whichever of them is running. Pair a phone once, on any device.
  • With Seal Chat Web 1.3.2 the website lets only ONE of your devices
    answer the phone at a time (a "lease"); the others wait on standby and
    take over in about a minute if it is switched off or asleep. The phone
    reconnects by itself. With an older Seal Chat Web, only the device that
    connected it answers (Settings → Web access says so).
  • Turning web access on/off, removing a phone, notification settings and
    wrong PINs count on all your devices. Phone notifications come from the
    device that received the message (not again from the others).
  • Removing one of your devices gives the website a new computer key, so
    the removed device can't use it; your phones stay paired.
  • If two of your devices were each connected to a website before, one
    connection is kept for all of them (the one with more phones, else the
    older one); phones paired only with the other need pairing again.
  • New test: npm run test:webshare (two devices, one phone, the real
    Seal Chat Web files).

WHAT'S NEW IN 1.9.2   (an update file only)
  • Fix: Settings → Your devices → "Link a new device…" (and making or
    using an invite code) failed on the desktop with "Digest method not
    supported". A .onion address ends with a SHA3-256 checksum, and
    Electron's crypto library has no SHA3. Seal Chat now computes SHA3-256
    itself (src/main/sha3.js, checked against the FIPS 202 test values and
    Node's own SHA3); the addresses are exactly the same as before.
  • New check: npm run test:electron runs the engine tests inside
    Electron's own runtime (plain Node.js has SHA3, which is why the tests
    missed this). It runs before every update file is built.
  • The Android fallback ranges for emoji / email checks now come from
    Electron's Unicode (17.0), so phone and desktop treat emoji the same.

WHAT'S NEW IN 1.9.1   (an update file only)
  • Android: the Android app runs this same code, and now takes these same
    signed update files (it unpacks the verified file and runs it; an update
    can say it needs a newer Android app: update.json "android":
    { "minShell": N }, or "android": false to keep it off phones).
  • Android fix (found by a developer testing the first APK): the phone's
    Node.js can't compile regular expressions with Unicode property escapes
    (\p{…}), so Seal Chat crashed on start. The emoji check (peer.js) and
    openpgp's email check now use noicu.js: the \p{…} pattern where it
    works, the same character class as explicit ranges where it doesn't.
    openpgp is patched after "npm install" (build/patch-openpgp.js) and
    again by the phone for each update it installs.
  • New release check (npm test, and before every update file is built):
    test/noicu-test.js parses all Node-side code and fails on any \p{…}
    regex literal, checks the fallbacks match, and runs openpgp and the
    emoji check as they run on the phone.
  • Nothing changes on Windows, macOS or Linux.

WHAT'S NEW IN 1.9.0   (an update file only)
  • Linked devices: use one Seal Chat ID on several computers (and, later,
    the Android app). Each device has its own address; contacts can reach
    you at any of them, so it doesn't matter which one you gave them.
      - On the computer you already use: Settings → Your devices → "Link a
        new device…" shows a one-time code (link-482-crystal-…, 10 minutes).
      - On the new computer: the welcome screen → "Link to my Seal Chat on
        another device", the code, your key passphrase and a name for it.
    The new computer gets your key (still locked with your passphrase) over
    Tor, protected by the code (SPAKE2, like invite codes; 3 wrong tries
    close it). It makes its own address and device key.
  • Your devices keep each other up to date, through Tor, sealed with your
    own key: messages contacts send you, messages you send (each one is
    sent by the device you wrote it on), read status, reactions, deleted
    messages, contacts and requests, your name and picture, and the mailbox
    address. A newly linked device gets all contacts and chats.
  • Contacts on 1.9 try your other addresses when the one they know doesn't
    answer. Contacts on older versions keep using the address they have.
  • Settings → Your devices lists your devices, when each was last in touch
    and how many updates wait for it; "Remove…" takes one off your ID
    (contacts are told; messages it was still sending are sent from here).
    A removed device still has your key — if one is lost or stolen, make a
    new ID.
  • Files you send stay on the device you sent them from; your other
    devices show the message. Files you receive can be downloaded on each.

WHAT'S NEW IN 1.8.6   (an update file only)
  • Fix: Settings → Mailbox → "Copy Worker script" failed with "Failed to
    execute 'writeText' on 'Clipboard': Write permission denied". Seal
    Chat now copies the script itself, like its other Copy buttons.

WHAT'S NEW IN 1.8.5   (an update file only)
  • Mailbox on Cloudflare (free): a small Cloudflare Worker can be your
    mailbox — for when your web host blocks or challenges visitors that
    come through Tor (Tor traffic stops at Cloudflare and never reaches
    your web host). Settings → Mailbox → "Copy Worker script", paste it
    into a new Worker, add a D1 database named DB, paste the Worker's
    address back and press Connect. The script is made for your PC (it
    holds only a hash of a key that never leaves your PC). It speaks the
    same language as Seal Chat Web's mailbox, so contacts on any Seal
    Chat 1.8 can use it. Seal Chat Web is not needed for it.
  • Contact mailbox (on by default): if a contact is offline and has no
    mailbox (or it can't be reached), Seal Chat leaves the sealed message
    with a contact you both have who's online, and they pass it on when
    they meet. They can't read it, and a contact who doesn't know them
    learns nothing (they're asked with a hash). You do the same for your
    contacts. Settings → Mailbox → "Let contacts we both know pass
    messages on". Needs Seal Chat 1.8.5 on the helper's side.
  • 📬 now says who a message was left with.

WHAT'S NEW IN 1.8.4   (an update file only)
  • The Seal Chat forwarder (1.8.2–1.8.3) is removed. Websites that block
    Tor are handled as before 1.8.2: the message waits until you're both
    online, unless you allow Settings → Privacy → "If a website blocks
    Tor, contact it directly". A website owner can also let Tor reach just
    Seal Chat's two addresses (relay.php and /.well-known/sealchat.json).
  • When a mailbox website answers with a web page instead of Seal Chat
    Web's answer (for example a "Checking your browser" security check
    for Tor visitors), the message now names that page.

WHAT'S NEW IN 1.8.3   (an update file only)
  • When a website blocks Tor and the Seal Chat forwarder can't get
    through either, the message now says where it stopped: Cloudflare
    turning the Tor request away, the forwarder refusing, or the website
    refusing the forwarder too.
  • Forwarder script v2 (build/forwarder-worker.js): marks answers that
    come from the website, and has a /diag page for troubleshooting.

WHAT'S NEW IN 1.8.2   (an update file only)
  • Websites that block Tor: when a contact's mailbox website (or a
    name@domain website) refuses visitors that come through Tor, Seal Chat
    now tries again through the Seal Chat forwarder — a small Cloudflare
    Worker — still through Tor:
        Seal Chat ──Tor──▶ forwarder ──HTTPS──▶ the website
    The website sees Cloudflare instead of Tor, so it lets the request in;
    the forwarder sees a Tor exit, never you. Mailbox messages are sealed
    with PGP before they leave, so neither can read them. The forwarder
    only passes on mailbox drops and name lookups (build/forwarder-worker.js).
    On by default; Settings → Privacy → "If a website blocks Tor, go
    through the Seal Chat forwarder" turns it off. Contacting the website
    directly stays the last resort, and only if you allow it.
  • Clearer message when a website blocks Tor and nothing gets through.

WHAT'S NEW IN 1.8.1   (an update file only)
  • Mailbox fix: if a contact was still on an older Seal Chat when you
    turned your mailbox on, 1.8.0 counted your mailbox address as "given"
    and never sent it again — so after they updated, their Seal Chat
    still didn't know you had a mailbox. 1.8.1 sends it again by itself
    as soon as they're on 1.8, and once more to every contact after this
    update.
  • Settings → Web access → Mailbox now shows how many contacts know
    about your mailbox ("3 of 5 contacts know about it").
  • When a message can't be left in a contact's mailbox, the chat now
    says why (for example, their website blocks visitors from Tor)
    instead of only "will keep trying".

WHAT'S NEW IN 1.8.0   (an update file only — the 1.7.0 installers stay)
  • Invite codes: Home → "Make an invite code…" gives a short code like
    482-crystal-orange-river to read out or write down. The other person
    types it in ＋ Add contact. "482-crystal" picks a temporary .onion
    address your Seal Chat publishes; the other words are a password that
    never crosses the network (SPAKE2 on ristretto255). 3 wrong tries
    close the code. Lifetimes 1 hour, 24 hours, 7 days or 30 days (one
    more word). One person: you're both added at once. Several people:
    each request waits for you, marked with the invite's label. Your
    Seal Chat must be open for a code to work. Up to 5 open at once.
  • Names: add people by name@domain (ann@example.com). Seal Chat reads
    https://domain/.well-known/sealchat.json through Tor, shows the key
    fingerprint, and remembers ("pins") the answer; once a day it checks
    again and warns if the name now points to someone else (it never
    switches by itself). Seal Chat Web 1.3.0: admin.php → Names writes
    that file. Set your own name in Settings → You.
  • Replies and reactions: hover a message (or right-click) for ↩ Reply
    and 🙂 React; one reaction per person per message.
  • Mailbox (with Seal Chat Web 1.3.0): Settings → Web access → Mailbox
    lets contacts leave sealed messages on your website while this PC is
    off. After a minute of not reaching you, their Seal Chat posts the
    PGP-sealed message there through Tor (📬); yours picks it up when it
    is back. The website can't read them or see who sent them; kept at
    most 30 days. Settings → Privacy → "If a website blocks Tor, contact
    it directly" (off by default).
  • Groundwork for several devices per ID: every installation has its
    own device key; your contacts receive a device list signed with your
    PGP key, and messages say which device sent them. Nothing is sent to
    more than one device yet.
  • New libraries: @noble/curves (SPAKE2) and @scure/bip39 (word list).

WHAT'S NEW IN 1.7.0   (new installers + update file)
  • New installers for Windows, Linux, Mac and macOS 12: a new installation
    gets its updates from GitHub from the first start.
  • Files from your phone (with Seal Chat Web 1.2.0): 📎 next to the message
    box sends photos, videos and files up to 100 MB. The phone passes them
    to this computer in sealed 512 KB pieces through your website's relay;
    Seal Chat then sends them to your contact over Tor like any file you
    pick here (your "largest file" setting still applies).
  • Files on your phone: photo previews in the chat; tap to open photos,
    videos and music, or Save / Share any file (up to 100 MB). A file not
    downloaded yet has a "Download" button — this computer fetches it from
    your contact first.
  • Files sent from this window now appear on a phone that has Seal Chat
    Web open straight away, with their progress.
  • Updates come from GitHub: Seal Chat 1.7.0 checks
    raw.githubusercontent.com/jeffbristow/sealchat-updates for updates —
    jeffbristow.com is no longer asked. That works through Tor even where
    a web host blocks Tor visitors. Updates must still carry Seal Chat's
    signature, so whoever controls the repository can't change what gets
    installed. If you set your own update address, only that is asked.
    Installed 1.3–1.6 copies still ask jeffbristow.com once, update to
    1.7.0, and from then on use GitHub.
  • For Seal Chat Web's "Update now": build/sign-web-update.js signs a
    SealChat-Web-x.y.z.zip with the same (offline) key.

WHAT'S NEW IN 1.6.1 — EMOJI   (an update file only; the 1.6.0 installers stay)
  • 😊 button next to the message box: search, groups, "Recently used",
    skin tone. One click picks (Shift-click to pick several); Esc closes.
  • Type ":" and a name — :smile, :+1, :tada — to get suggestions; Tab or
    Enter picks (Enter doesn't send while the list is open), and a full
    ":tada:" turns into 🎉 by itself.
  • Settings → App → "Turn :) :D ;) <3 into 🙂 😄 😉 ❤️ as I type" (off by
    default; never inside a word or a link).
  • Messages of just 1–3 emoji show big.
  • Colour emoji on every Linux desktop and all emoji on Windows 10: Seal
    Chat now brings Noto Color Emoji 2.047 (SIL Open Font License), in
    parts that load only when needed. macOS keeps Apple's emoji.
  • Emoji are ordinary text, so contacts on older versions see them too.
  • Emoji list: emojibase-data (MIT), Emoji 15.0 and older.

WHAT'S NEW IN 1.6.0
  • Phone notifications (with Seal Chat Web 1.1.0): a paired phone can turn
    on notifications (its menu ⋯ → Notifications). Seal Chat sends "New
    message" — or "New message from Alice" if that device allows names —
    never the message itself, encrypted for that phone's browser only,
    through the phone maker's push service (Apple / Google / Mozilla),
    through Tor when "Connect through Tor" is on. Nothing is sent while
    the phone has Seal Chat open, or while web access is off. Each device
    has its own switches in Settings → Web access. iPhone: Home Screen
    version only (iOS 16.4+).
  • Contacts from the phone: add (scan their QR code, a photo of it, or
    paste the ID), "My Seal Chat ID" as a QR code, accept / decline
    requests, rename, safety number + verified, mute, block, remove — the
    same actions as this window, done here on your computer.
  • "Install once, then update": the first time an installed copy starts,
    it looks for an update as soon as it can reach the website (through
    Tor once connected, or straight away if update checks go direct). A
    newer signed update is downloaded, verified, and Seal Chat restarts
    into it ("Updating to x.y.z…", with "Not now"). So the installers on
    the website only need rebuilding when Electron or Tor change — a
    .sealchat update file can't change those. Suggested: a new installer
    every 2–3 months, or straight away for an important Electron (Chromium)
    security fix or a Tor update.
  • Mac: the regular Mac build needs macOS 13 Ventura or newer (Electron
    44 does). Macs on macOS 12 Monterey use the separate "legacy" build
    (Electron 43): make-sealchat-legacy-dmg.sh, SealChat-1.6.0-macOS12-…
    It gets the same .sealchat updates. 1.5.0 said "macOS 12" by mistake;
    on macOS 12 it now shows Apple's "requires macOS 13" message instead
    of failing.

WHAT'S NEW IN 1.5.0 — macOS
  • Seal Chat for Mac: Apple Silicon (M1/M2/M3/M4…) and Intel, macOS 13 or
    newer (1.5.0 said 12 — wrong; see 1.6.0). Same features, same Seal Chat
    ID format, same update files.
  • Mac details: a standard menu bar (⌘C/⌘V/⌘A/⌘Z work, ⌘, opens Settings,
    ⌘Q quits), a seal icon in the menu bar, unread count on the dock icon,
    "Start Seal Chat when I log in", data locked with your Mac's Keychain.
  • Tor for Mac is built in (Tor 0.4.9.5, Apple Silicon and Intel builds).
  • Windows/Linux: no changes besides the version number.

MAC: MAKING THE .DMG (on any Mac, no Xcode or Apple account needed)
  1. Put all the SealChat-1.6.0-mac-…tar.gz.N.part files and
     make-sealchat-dmg.sh in one folder. (macOS 12: the
     SealChat-1.6.0-legacy-mac-… parts and make-sealchat-legacy-dmg.sh.)
  2. Terminal:  cd <that folder>   then   bash make-sealchat-dmg.sh
  3. You get SealChat-1.6.0-arm64.dmg (Apple Silicon) and/or
     SealChat-1.6.0-x64.dmg (Intel) — or SealChat-1.6.0-macOS12-….dmg. The script checks the parts, signs the
     app "ad-hoc" (free; Apple Silicon needs at least that) and makes the
     .dmg with an Applications shortcut.
MAC: INSTALLING (unsigned app — one extra step the first time)
  Open the .dmg, drag Seal Chat to Applications, open it. macOS says it
  can't verify the developer → OK. Then System Settings → Privacy &
  Security → "Open Anyway" next to Seal Chat → confirm. Only needed once.
  Which one? Apple menu → About This Mac: "Chip: Apple M…" = arm64,
  "Processor: Intel" = x64.

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
