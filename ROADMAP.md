# Hallow Authenticator roadmap

## Done

| Version | What it added |
|---|---|
| **1.0** | Phone-first 2FA app delivered by Hallow Remote 1.19 (PWA, service worker cache-first, works offline): vault in IndexedDB (random DEK, AES-256-GCM; DEK wrapped by PBKDF2-SHA256 600k from the passcode and optionally by HKDF of a WebAuthn PRF output - fingerprint / face); auto-lock (idle 1-30 min, on hide); TOTP SHA-1/256/512, 6/8 digits, any period, HOTP, Steam Guard; otpauth:// parse / build; QR by camera (BarcodeDetector, else its own reader: finder / alignment patterns, perspective, format bits, RS error correction, versions 1-40) or a picture; import of Google Authenticator export (protobuf, batches), otpauth lists, Aegis plain / encrypted (scrypt), 2FAS plain / encrypted; Hallow Keys 2.11 transfer (copy / move, sealed with a one-time 160-bit code, HMAC receipt); encrypted backups (own password) to a file or to the PC through Remote, restore from either; optional PC mirror for Hallow Keys; Microsoft Authenticator move guide; strict CSP, light / dark, Hallow accent |

## Next

- Show an account's QR code (to move it to another app) - needs a QR encoder in the app
- Reorder accounts by hand, folders / tags
- Encrypted export to other apps' formats (Aegis JSON)
- A reminder when no backup was made in a while
- Haptic feedback and a "code copied" countdown on Android

## Gaps vs Microsoft Authenticator / Aegis / 2FAS
- Push "approve sign-in" (Microsoft's own protocol - not possible for any other app)
- Cloud sync between phones (by design: backups instead)
- Not tested on a real phone by the developer tests (headless Edge as an Android phone, a fake camera and a virtual passkey instead)
