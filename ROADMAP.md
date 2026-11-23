# Hallow Authenticator roadmap

## Done

| Version | What it added |
|---|---|
| **1.0** | Phone-first 2FA app delivered by Hallow Remote 1.19 (PWA, service worker cache-first, works offline): vault in IndexedDB (random DEK, AES-256-GCM; DEK wrapped by PBKDF2-SHA256 600k from the passcode and optionally by HKDF of a WebAuthn PRF output - fingerprint / face); auto-lock (idle 1-30 min, on hide); TOTP SHA-1/256/512, 6/8 digits, any period, HOTP, Steam Guard; otpauth:// parse / build; QR by camera (BarcodeDetector, else its own reader: finder / alignment patterns, perspective, format bits, RS error correction, versions 1-40) or a picture; import of Google Authenticator export (protobuf, batches), otpauth lists, Aegis plain / encrypted (scrypt), 2FAS plain / encrypted; Hallow Keys 2.11 transfer (copy / move, sealed with a one-time 160-bit code, HMAC receipt); encrypted backups (own password) to a file or to the PC through Remote, restore from either; optional PC mirror for Hallow Keys; Microsoft Authenticator move guide; strict CSP, light / dark, Hallow accent |
| **1.1** | Don't lose access: `navigator.storage.persist()` at setup and every start until granted, shown in Settings (with what still wipes it); backup reminders (none yet / N accounts not in the latest backup by per-account fingerprints kept in the vault / older than 14 days); automatic backup to the PC through Hallow Remote 1.21 (on after the first backup, after changes, at most once a day; the backup password's PBKDF2 key kept in the vault, or the passcode wrap + DEK-sealed accounts; Remote keeps the last 10 unopened); exports: Aegis vault file (scrypt slot + AES-256-GCM, notes as Aegis notes), Google `otpauth-migration` transfer QR codes (protobuf, batches of 8), plain `otpauth://` list (passcode + warning); one account's QR code (own QR encoder, penalty-chosen mask, SVG); Hide codes until tapped; per-account backup codes / notes (encrypted); service worker 1.1.0 caches the new files |

## Next

- ~~Show an account's QR code (to move it to another app)~~ -> 1.1
- Reorder accounts by hand, folders / tags
- ~~Encrypted export to other apps' formats (Aegis JSON)~~ -> 1.1 (also Google transfer QR codes and a plain list)
- ~~A reminder when no backup was made in a while~~ -> 1.1 (plus automatic backups to the PC)
- Haptic feedback and a "code copied" countdown on Android

## Gaps vs Microsoft Authenticator / Aegis / 2FAS
- Push "approve sign-in" (Microsoft's own protocol - not possible for any other app)
- Cloud sync between phones (by design: backups instead)
- Not tested on a real phone by the developer tests (headless Edge as an Android phone, a fake camera and a virtual passkey instead)
