# Hallow Authenticator

Your 2FA codes on your phone - a replacement for Microsoft Authenticator in the Hallow family. It's an installable web app (PWA) that [Hallow Remote](https://github.com/Dom428/hallow-remote) 1.19+ delivers to your phone; once installed, it works on its own, with your PC off and no internet.

- **Codes live on the phone, not the PC.** Encrypted at rest (IndexedDB, AES-256-GCM) with a key from your own Authenticator passcode (PBKDF2-SHA256, 600,000 rounds, random salt) - separate from Hallow Keys' master password.
- **Fingerprint / face unlock** with a passkey's PRF extension (Android Chrome; iPhone with iOS 18+), the passcode always works too. Auto-lock after 1-30 idle minutes and as soon as you switch away.
- **TOTP** (SHA-1 / 256 / 512, 6 / 8 digits, 30 / 60 s), **HOTP** and **Steam Guard** codes. Add them by scanning a QR code with the camera (BarcodeDetector on Android; this app's own QR reader elsewhere), from a picture, or by typing a setup key.
- **Import:** Google Authenticator's export QR codes (several in a row), `otpauth://` lists, Aegis (plain or encrypted), 2FAS (plain or encrypted), and **Hallow Keys** 2.11 (copy or move its 2FA codes, end-to-end encrypted).
- **Big codes, tap to copy**, countdown ring, next code, search, pin to the top, a letter tile per service (no logos fetched from the internet), light / dark following the phone, the Hallow accent.
- **Encrypted backups** with a separate backup password: save the file on the phone, or send it to the PC, where Hallow Remote stores it without being able to open it (`%APPDATA%\HallowAuthenticator\backups`, copy it to your NAS). Restore on a new phone from the file or the PC.
- **Nothing secret goes to the PC** unless you turn on the PC mirror (off by default; a sealed read-only copy of the accounts you pick, shown by Hallow Keys while it's unlocked - convenience over strength).

## Install on your Android phone (Chrome)

1. On the PC: Hallow Remote 1.19 or newer, with **HTTPS on** (Remote's window shows how: turn on HTTPS certificates in the Tailscale admin console, then run the `tailscale cert` command it shows). Without HTTPS the app can't run (phones only allow encryption, the camera, passkeys and offline apps on secure pages).
2. On the phone: Tailscale on, open your Hallow Remote link in **Chrome**, then **Home > Authenticator > Open Hallow Authenticator**.
3. Tap **Install** in the banner (or Chrome's menu > **Add to Home screen** / **Install app**). From now on open it from its own icon - it starts even with the PC off.
4. Choose your Authenticator passcode (a passphrase of 8+ characters is best). Then **Settings > Turn on fingerprint / face unlock** (Chrome saves a passkey for it in Google Password Manager).
5. Add accounts with **+**. Then **Settings > Save a backup file** or **Back up to my PC**, and keep the backup password somewhere safe.

iPhone: open the link in Safari, **Share > Add to Home Screen first**, and set the app up from the Home Screen icon (Safari and the Home Screen app keep separate data on iOS). Fingerprint / face unlock needs iOS 18+.

## Moving from Microsoft Authenticator

Microsoft Authenticator can't export, so each account is moved by setting it up again (the app has this guide built in: **+ > Moving from Microsoft Authenticator**):

1. Sign in to the site (on a computer is easiest) and open its security / two-step verification settings.
2. Add (or change) the authenticator app - it shows a QR code.
3. In Hallow Authenticator: **+ > Scan a QR code**, scan it, and type the code it shows back into the site.
4. Only then remove Microsoft Authenticator from that account. Keep the old app until every account is done.

Your **Microsoft account itself** works with normal codes: account.microsoft.com > Security > Manage how I sign in > Add a new way to sign in > "Use an app" > "Set up a different authenticator app". Microsoft's push "Approve sign-in?" prompts and passwordless phone sign-in can't be replicated by any other app; with Hallow you type the 6-digit code instead. Work or school accounts may require Microsoft Authenticator.

Accounts in **Google Authenticator**: on the old phone, Transfer accounts > Export, and scan each QR code (the app counts "1 of 3"...). In **Hallow Keys**: Settings > Hallow Authenticator > Send my 2FA codes to my phone.

## Steam Guard

Steam Guard codes need your account's shared secret, which Steam only gives out during its own mobile authenticator setup. If you already have it (for example a `.maFile` you made yourself), add it with + > Type a setup key > Steam Guard. This app never logs in to Steam or automates that; trade confirmations stay in the Steam app.

## What works offline

Everything on the phone: codes, copy, search, editing, scanning, saving a backup file, fingerprint unlock - with the PC off, Tailscale off or no internet (after the app has been opened once). Needs the PC (Hallow Remote over Tailscale): backup to / restore from the PC, receiving codes from Hallow Keys, the PC mirror, and app updates. Codes follow the phone's clock - keep automatic time on.

## Security model

- The vault: a random 256-bit data key encrypts the accounts (AES-256-GCM, authenticated - a changed byte is refused). The data key is stored only wrapped: by a key from your passcode (PBKDF2-SHA256, 600,000 rounds) and, if you turn it on, by a key derived (HKDF-SHA256) from the passkey's PRF output, which the phone's authenticator only releases after your fingerprint / face. Nothing readable is written to the phone's storage; `localStorage` holds only the accent colour. Locked = the key is dropped from memory and the page is cleared.
- A short passcode only slows down someone who has copied the phone's browser data (5 tries are free, then waits of 30 s growing to 15 min in the app; offline guessing is limited only by PBKDF2) - your phone's own screen lock is the first line. Use a passphrase.
- The page has a strict Content-Security-Policy (no inline script or style, only this PC), never puts anything from a QR code or file into the page as HTML, and calls only its own PC.
- Backups: their own password, the same PBKDF2 + AES-GCM; Hallow Remote checks only the outer shape and stores the bytes as they came.
- Hallow Keys transfer: Keys makes a one-time 160-bit code it shows on the PC screen; the codes are sealed with a key derived from it; Remote gets only a lookup id and the sealed blob (memory only, given out once, 10 minutes). The phone proves receipt with an HMAC only the code's holder can make; only then does a move take the keys out of Hallow Keys.
- PC mirror: sealed with a 256-bit key Hallow Keys shows once as a QR code and keeps inside its encrypted vault; Remote stores the sealed file; Keys opens it only while unlocked. It puts codes back on the PC next to the passwords, so it's weaker 2FA - leave important accounts out.

## Honest limits

- HTTPS through Tailscale's certificate is required (Remote's home-network mode has no HTTPS, so the app can't run there).
- If you change Remote's link (New link), open the new link once; the installed app keeps working offline and your data stays (it's kept per site, not per link).
- No push "approve" sign-ins, no cloud sync between phones (use backups), no automatic Steam setup.
- On iPhone there's no BarcodeDetector, so QR codes are read by this app's own reader (tested on generated images; real camera conditions vary - a picture or typing the key always works), and Safari may clear website data of sites you don't use for weeks unless the app is on the Home Screen.
- Encrypted 2FAS files are supported as documented by 2FAS but weren't tested against a real 2FAS export; Aegis files were tested against fixtures built from Aegis' published format.

## Build and test

There is nothing to build: `app/` is the app. Hallow Remote embeds a copy (`tools/sync-to-remote.ps1` copies `app/` into Remote's `src/web/auth`; the version is in `app/sw.js`). `tools/make-icons.ps1` draws the icons. Tests (Node 18+, no packages): `node test/unit.mjs` - RFC 4226 / 6238 vectors, Steam Guard vectors, scrypt RFC 7914 vectors, Google export protobuf, Aegis / 2FAS fixtures, the vault (round trip, wrong passcode, tamper, PRF wrap), backups, auto-lock, the Keys transfer and mirror formats, and the QR reader on generated images (all EC levels, masks, versions 1-40, rotation, perspective, noise, blur, inverted).

Made-up test data only - never real accounts or secrets.
