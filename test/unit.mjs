// Hallow Authenticator - unit tests (Node 18+, no packages): node test/unit.mjs [folder of extra QR images from another encoder]
// Only made-up secrets and accounts - never real ones.
import * as otp from '../app/otp.js';
import * as V from '../app/vault.js';
import * as Q from '../app/qr.js';
import * as I from '../app/importers.js';
import { scrypt } from '../app/scrypt.js';
import { encode, render } from './qrgen.mjs';
import fs from 'fs'; import path from 'path';
const subtle = globalThis.crypto.subtle, te = new TextEncoder();
let passes = 0, fails = 0;
const check = (name, ok, info) => { if (ok) { passes++; console.log('PASS ' + name); } else { fails++; console.log('FAIL ' + name + (info !== undefined ? '  ' + JSON.stringify(info).slice(0, 300) : '')); } };
const ascii = s => te.encode(s);
const hex = I.hex;

// ---- RFC 4226 (HOTP) appendix D
const k20 = ascii('12345678901234567890');
const hv = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
for (let c = 0; c < 10; c++) check('RFC 4226 HOTP count ' + c, (await otp.hotp(k20, c)) === hv[c]);
// ---- RFC 6238 (TOTP) appendix B, 8 digits
const seeds = { SHA1: k20, SHA256: ascii('12345678901234567890123456789012'), SHA512: ascii('1234567890123456789012345678901234567890123456789012345678901234') };
const tv = [[59, '94287082', '46119246', '90693936'], [1111111109, '07081804', '68084774', '25091201'], [1111111111, '14050471', '67062674', '99943326'],
  [1234567890, '89005924', '91819424', '93441116'], [2000000000, '69279037', '90698825', '38618901'], [20000000000, '65353130', '77737706', '47863826']];
for (const [t, a, b, c] of tv) {
  check('RFC 6238 SHA1 t=' + t, (await otp.totp(seeds.SHA1, t, 30, 8, 'SHA1')) === a);
  check('RFC 6238 SHA256 t=' + t, (await otp.totp(seeds.SHA256, t, 30, 8, 'SHA256')) === b);
  check('RFC 6238 SHA512 t=' + t, (await otp.totp(seeds.SHA512, t, 30, 8, 'SHA512')) === c);
}
check('6 digits = last 6 of the 8 (t=59)', (await otp.totp(k20, 59, 30, 6)) === '287082');
check('60 s period: t=59 and t=0 share a code, t=60 differs', (await otp.totp(k20, 59, 60)) === (await otp.totp(k20, 0, 60)) && (await otp.totp(k20, 60, 60)) !== (await otp.totp(k20, 59, 60)));
// ---- Steam Guard (the vectors in ValvePython/steam's tests: secret b'superdupersecret')
const ss = ascii('superdupersecret');
check('Steam Guard t=3000030 -> YRGQJ', (await otp.steam(ss, 3000030)) === 'YRGQJ', await otp.steam(ss, 3000030));
check('Steam Guard t=3000029 -> 94R9D', (await otp.steam(ss, 3000029)) === '94R9D', await otp.steam(ss, 3000029));
const steamE = { type: 'steam', secret: otp.bytesToB64(ss), secretFormat: 'base64', label: 'made-up' }; otp.normalize(steamE);
check('Steam entry from a base64 shared_secret', (await otp.codeFor(steamE, 3000030)) === 'YRGQJ');
const steamUri = otp.parseOtpauth('otpauth://totp/Steam:made-up?secret=' + otp.base32Encode(ss) + '&issuer=Steam&encoder=steam');
check('otpauth with encoder=steam -> Steam code', steamUri.entry && steamUri.entry.type === 'steam' && (await otp.codeFor(steamUri.entry, 3000029)) === '94R9D');
check('Steam alphabet has no vowels or look-alikes', !/[AEIOU01LSZ]/.test(otp.STEAM_ALPHABET) && otp.STEAM_ALPHABET.length === 26);

// ---- base32 and otpauth links
check('base32 RFC 4648 "foobar"', otp.base32Encode(ascii('foobar')) === 'MZXW6YTBOI' && new TextDecoder().decode(otp.base32Decode('mzxw 6ytb-oi======')) === 'foobar');
check('base32 rejects 0/1/8', otp.base32Decode('ABC1') === null && otp.base32Decode('ABC8') === null);
const p1 = otp.parseOtpauth('otpauth://totp/ACME%20Co:jo%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60');
check('otpauth: issuer, label, SHA256, 8 digits, 60 s', p1.entry && p1.entry.issuer === 'ACME Co' && p1.entry.label === 'jo@example.com' && p1.entry.algo === 'SHA256' && p1.entry.digits === 8 && p1.entry.period === 60, p1);
const p2 = otp.parseOtpauth('otpauth://hotp/Made%20Up?secret=GEZDGNBVGY3TQOJQ&counter=7');
check('otpauth hotp with counter', p2.entry && p2.entry.type === 'hotp' && p2.entry.counter === 7 && p2.entry.label === 'Made Up');
check('otpauth: no secret -> error', !!otp.parseOtpauth('otpauth://totp/x?issuer=y').error);
check('otpauth: MD5 refused', !!otp.parseOtpauth('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5').error);
check('otpauth: bad base32 refused', !!otp.parseOtpauth('otpauth://totp/x?secret=JBSW0Y3DP').error);
const rt = otp.parseOtpauth(otp.toOtpauth(p1.entry)).entry;
check('otpauth round trip', rt && rt.secret === p1.entry.secret && rt.issuer === 'ACME Co' && rt.label === 'jo@example.com' && rt.digits === 8 && rt.period === 60 && rt.algo === 'SHA256');
const lst = otp.parseOtpauthList('otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP\n junk \notpauth://totp/B:b?secret=GEZDGNBVGY3TQOJQ&issuer=B\notpauth://totp/C?issuer=C');
check('otpauth list: 2 good, 1 error', lst.entries.length === 2 && lst.errors.length === 1);
check('label with odd % does not throw', !!otp.parseOtpauth('otpauth://totp/50%off?secret=JBSWY3DPEHPK3PXP').entry);

// ---- Google Authenticator export (made-up fixtures)
const pbV = n => { const o = []; n = BigInt(n); do { let b = Number(n & 127n); n >>= 7n; if (n) b |= 128; o.push(b); } while (n); return o; };
const pbF = (f, bytes) => [...pbV((f << 3) | 2), ...pbV(bytes.length), ...bytes];
const pbI = (f, v) => [...pbV(f << 3), ...pbV(v)];
const otpParam = o => [...pbF(1, o.secret), ...pbF(2, [...ascii(o.name)]), ...pbF(3, [...ascii(o.issuer)]), ...pbI(4, o.algo), ...pbI(5, o.digits), ...pbI(6, o.type), ...(o.counter ? pbI(7, o.counter) : [])];
const gm = (params, idx, size, id) => 'otpauth-migration://offline?data=' + encodeURIComponent(otp.bytesToB64(new Uint8Array([...params.flatMap(p => pbF(1, otpParam(p))), ...pbI(2, 1), ...pbI(3, size), ...pbI(4, idx), ...pbI(5, id)])));
const g1 = gm([{ secret: [...k20], name: 'MadeUp:alex@example.com', issuer: 'MadeUp', algo: 1, digits: 1, type: 2 }, { secret: [...seeds.SHA256], name: 'bob@example.net', issuer: 'Fakebank', algo: 2, digits: 2, type: 2 },
  { secret: [...k20], name: 'counter-thing', issuer: '', algo: 0, digits: 0, type: 1, counter: 5 }, { secret: [...k20], name: 'old', issuer: 'Md5Site', algo: 4, digits: 1, type: 2 }], 0, 2, 4242);
const gr = I.parseGoogleMigration(g1);
check('Google export: 3 entries, MD5 one skipped', gr.entries.length === 3 && gr.skipped.length === 1, gr);
check('Google export: issuer / label split, secret round trip', gr.entries[0].issuer === 'MadeUp' && gr.entries[0].label === 'alex@example.com' && gr.entries[0].secret === otp.base32Encode(k20));
check('Google export: SHA256 + 8 digits', gr.entries[1].algo === 'SHA256' && gr.entries[1].digits === 8 && gr.entries[1].issuer === 'Fakebank');
check('Google export: HOTP with counter 5', gr.entries[2].type === 'hotp' && gr.entries[2].counter === 5);
check('Google export: batch 1 of 2, id 4242', gr.batch.index === 0 && gr.batch.size === 2 && gr.batch.id === 4242);
check('Google export: codes are right', (await otp.codeFor(gr.entries[1], 59)) === '46119246');
const g2 = I.parseGoogleMigration(gm([{ secret: [...k20], name: 'second', issuer: 'Batch2', algo: 1, digits: 1, type: 2 }], 1, 2, 4242));
check('Google export: second QR of the batch', g2.batch.index === 1 && g2.entries[0].issuer === 'Batch2');
let gerr = null; try { I.parseGoogleMigration('otpauth-migration://offline?data=CgUKAw'); } catch (x) { gerr = x.message; }
check('Google export: a cut-off code is refused, not crashed on', !!gerr && /damaged/.test(gerr), gerr);
check('parseAny sees a Google export', (await I.parseAny(g1)).kind === 'google');

// ---- scrypt (RFC 7914 section 12)
check('scrypt RFC 7914 vector 1 ("", "", 16, 1, 1)', hex(await scrypt('', new Uint8Array(0), 16, 1, 1, 64)) === '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906');
check('scrypt RFC 7914 vector 2 (password, NaCl, 1024, 8, 16)', hex(await scrypt('password', ascii('NaCl'), 1024, 8, 16, 64)) === 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640');

// ---- Aegis plain and encrypted (made up, built here the way Aegis documents it)
const aegisDb = { version: 2, entries: [{ type: 'totp', uuid: 'u1', name: 'sam@example.org', issuer: 'MadeUpMail', favorite: true, info: { secret: 'JBSWY3DPEHPK3PXP', algo: 'SHA1', digits: 6, period: 30 } },
  { type: 'steam', uuid: 'u2', name: 'made-up-steam', issuer: 'Steam', info: { secret: otp.base32Encode(ss), algo: 'SHA1', digits: 5, period: 30 } },
  { type: 'hotp', uuid: 'u3', name: 'h', issuer: 'HotpCo', info: { secret: 'GEZDGNBVGY3TQOJQ', algo: 'SHA1', digits: 6, counter: 3 } },
  { type: 'yandex', uuid: 'u4', name: 'y', issuer: 'Yandex', info: { secret: 'GEZDGNBVGY3TQOJQ', pin: '1234' } }] };
const ap = await I.parseAny(JSON.stringify({ version: 1, header: { slots: null, params: null }, db: aegisDb }));
check('Aegis plain: 3 in, Yandex skipped, Steam kept, favourite kept', ap.entries.length === 3 && ap.skipped.length === 1 && ap.entries[1].type === 'steam' && ap.entries[0].fav, ap);
check('Aegis Steam code right', (await otp.codeFor(ap.entries[1], 3000030)) === 'YRGQJ');
async function aegisEncrypted(pw, N) {
  const master = crypto.getRandomValues(new Uint8Array(32)), salt = crypto.getRandomValues(new Uint8Array(32));
  const kk = await scrypt(pw, salt, N, 8, 1, 32), sn = crypto.getRandomValues(new Uint8Array(12));
  const skey = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: sn }, await subtle.importKey('raw', kk, 'AES-GCM', false, ['encrypt']), master));
  const dn = crypto.getRandomValues(new Uint8Array(12));
  const body = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: dn }, await subtle.importKey('raw', master, 'AES-GCM', false, ['encrypt']), te.encode(JSON.stringify(aegisDb))));
  return JSON.stringify({ version: 1, header: { slots: [{ type: 2, uuid: 'bio' }, { type: 1, uuid: 's', key: hex(skey.slice(0, 32)), key_params: { nonce: hex(sn), tag: hex(skey.slice(32)) }, n: N, r: 8, p: 1, salt: hex(salt), repaired: true }], params: { nonce: hex(dn), tag: hex(body.slice(body.length - 16)) } }, db: otp.bytesToB64(body.slice(0, body.length - 16)) });
}
const ae = await aegisEncrypted('made-up aegis pw', 1024);
check('Aegis encrypted: asks for the password', (await I.parseAny(ae)).needsPassword === true);
const aeo = await I.parseAny(ae, 'made-up aegis pw');
check('Aegis encrypted: opens with it (scrypt + AES-GCM)', aeo.entries && aeo.entries.length === 3 && aeo.entries[0].issuer === 'MadeUpMail');
let aw = null; try { await I.parseAny(ae, 'wrong'); } catch (x) { aw = x.message; }
check('Aegis encrypted: wrong password said plainly', aw === 'Wrong Aegis password', aw);
const t0 = Date.now(); const ae2 = await aegisEncrypted('pw2', 32768); const ae2o = await I.parseAny(ae2, 'pw2');
check('Aegis encrypted with its real settings (N=32768) opens (' + (Date.now() - t0) + ' ms in Node)', ae2o.entries.length === 3);

// ---- 2FAS
const tf = { services: [{ name: 'MadeUpGit', secret: 'JBSWY3DPEHPK3PXP', otp: { account: 'dev@example.com', issuer: 'MadeUpGit', digits: 6, period: 30, algorithm: 'SHA1', tokenType: 'TOTP' } }, { name: 'Steamy', secret: otp.base32Encode(ss), otp: { tokenType: 'STEAM', digits: 5 } }], schemaVersion: 4 };
const tp = await I.parseAny(JSON.stringify(tf));
check('2FAS plain: 2 entries incl. Steam', tp.entries.length === 2 && tp.entries[0].label === 'dev@example.com' && tp.entries[1].type === 'steam');
{
  const salt = crypto.getRandomValues(new Uint8Array(256)), iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await subtle.importKey('raw', te.encode('made-up 2fas pw'), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 10000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(tf.services))));
  const enc2 = JSON.stringify({ services: [], servicesEncrypted: [ct, salt, iv].map(otp.bytesToB64).join(':'), schemaVersion: 4 });
  check('2FAS encrypted: asks for the password', (await I.parseAny(enc2)).needsPassword === true);
  check('2FAS encrypted: opens', (await I.parseAny(enc2, 'made-up 2fas pw')).entries.length === 2);
}

// ---- the vault: encryption round trip, wrong passcode, nothing readable stored
{
  const st = V.memoryStorage(), v = new V.Vault(st, { iterations: 2000 });
  await v.create('made-up passcode 1');
  v.data.entries.push({ id: 'a', type: 'totp', issuer: 'MadeUpMail', label: 'sam@example.org', secret: 'JBSWY3DPEHPK3PXP', algo: 'SHA1', digits: 6, period: 30 });
  await v.save(); v.lock();
  check('locked: no data, no key', !v.unlocked && v.data === null && v.dekRaw === null);
  const stored = await v.storedText();
  check('stored: no secret, no account name, no issuer', !stored.includes('JBSWY3DPEHPK3PXP') && !stored.includes('sam@example.org') && !stored.includes('MadeUpMail'));
  let wrong = null; try { await v.unlock('wrong'); } catch (x) { wrong = x; }
  check('wrong passcode -> WrongPasscode, stays locked', wrong instanceof V.WrongPasscode && !v.unlocked);
  check('wrong tries are counted', (await v.meta()).fails === 1);
  await v.unlock('made-up passcode 1');
  check('right passcode -> the account is back', v.unlocked && v.data.entries[0].secret === 'JBSWY3DPEHPK3PXP' && (await v.meta()).fails === 0);
  // tampering with the stored vault is caught (AES-GCM)
  const box = await st.get('vault'); const b = otp.b64ToBytes(box.ct); b[5] ^= 1; await st.set('vault', { iv: box.iv, ct: otp.bytesToB64(b) }); v.lock();
  let tam = null; try { await v.unlock('made-up passcode 1'); } catch (x) { tam = x; }
  check('a changed byte in the stored vault is refused', !!tam && !v.unlocked);
  await st.set('vault', box);
  await v.changePasscode('made-up passcode 1', 'made-up passcode 2'); v.lock();
  let old = null; try { await v.unlock('made-up passcode 1'); } catch (x) { old = x; }
  await v.unlock('made-up passcode 2');
  check('change passcode: old one fails, new one opens the same accounts', old instanceof V.WrongPasscode && v.data.entries.length === 1);
  // fingerprint (PRF): the DEK wrapped by a key from the passkey's PRF output
  const prf = crypto.getRandomValues(new Uint8Array(32));
  await v.setPrf(new Uint8Array([1, 2, 3]), new Uint8Array(32), prf); v.lock();
  await v.unlockWithPrf(prf);
  check('PRF unlock with the same output', v.unlocked && v.data.entries.length === 1);
  v.lock(); let bp = null; try { await v.unlockWithPrf(crypto.getRandomValues(new Uint8Array(32))); } catch (x) { bp = x; }
  check('PRF unlock with a different output fails', !!bp && !v.unlocked);
  check('stored PRF record has no raw key', !(await v.storedText()).includes(otp.bytesToB64(prf)));
  await v.erase(); check('erase removes everything', !(await v.exists()) && st.raw.size === 0);
  check('waits after wrong tries: 0 for 4, 30 s at 5, capped at 15 min', V.waitAfterFails(4) === 0 && V.waitAfterFails(5) === 30 && V.waitAfterFails(30) === 900);
  const t1 = Date.now(); const st2 = V.memoryStorage(), v2 = new V.Vault(st2); await v2.create('real-strength'); v2.lock(); await v2.unlock('real-strength');
  check('full strength (600,000 PBKDF2 rounds) works: create + unlock in ' + (Date.now() - t1) + ' ms', v2.unlocked && (await v2.meta()).iter === 600000);
}

// ---- backup / restore
{
  const data = { entries: [{ id: 'x', type: 'totp', issuer: 'MadeUpMail', label: 'sam@example.org', secret: 'JBSWY3DPEHPK3PXP', algo: 'SHA1', digits: 6, period: 30 }] };
  const file = await V.makeBackup(data, 'made-up backup pw', 100000);
  check('backup file: nothing readable in it', !file.includes('JBSWY3DPEHPK3PXP') && !file.includes('sam@example.org') && JSON.parse(file).format === V.BACKUP_FORMAT);
  const back = await V.readBackup(file, 'made-up backup pw');
  check('restore with the backup password', back.length === 1 && back[0].secret === 'JBSWY3DPEHPK3PXP');
  let w = null; try { await V.readBackup(file, 'nope'); } catch (x) { w = x; } check('restore with a wrong password refused', w instanceof V.WrongPasscode);
  let nb = null; try { await V.readBackup('{"x":1}', 'a'); } catch (x) { nb = x.message; } check('not a backup -> said so', /isn't a Hallow Authenticator backup/.test(nb));
  check('parseAny recognises a backup', (await I.parseAny(file)).kind === 'backup');
}

// ---- auto-lock (a fake clock)
{
  let t = 0, why = []; const L = new V.Locker(w => why.push(w), { now: () => t });
  L.set(2, true); L.arm();
  t = 119000; L.tick(); check('not locked before 2 minutes', why.length === 0);
  L.touch(); t = 200000; L.tick(); check('a touch restarts the timer', why.length === 0);
  t = 239000 + 1000; L.tick(); check('locked after 2 idle minutes', why.join() === 'idle');
  L.arm(); L.visibility('hidden'); check('locked when hidden', why.join() === 'idle,hidden');
  L.arm(); L.set(5, false); L.visibility('hidden'); check('not locked when hidden if that setting is off', why.length === 2);
  L.disarm(); t = 1e9; L.tick(); check('a locked app does not lock again', why.length === 2);
}

// ---- Hallow Keys transfer and the PC mirror
{
  const code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const ids = await I.transferIds('abcd-efgh ijkl-mnop-qrst-uvwx-yz23-4567');
  check('transfer code: dashes / case ignored; id is 32 hex', ids.id.length === 32 && /^[0-9a-f]+$/.test(ids.id) && (await I.transferIds(code)).id === ids.id);
  check('transfer: known id and proof (the C# side uses the same)', ids.id === hex(new Uint8Array(await subtle.digest('SHA-256', te.encode('HallowAuthXferId' + code)))).slice(0, 32));
  const payload = { v: 1, mode: 'move', entries: [{ ref: 'i1|main', title: 'MadeUpMail', username: 'sam@example.org', uri: 'otpauth://totp/MadeUpMail:sam@example.org?secret=JBSWY3DPEHPK3PXP&issuer=MadeUpMail' }, { ref: 'i2|f0', title: 'BareKey', username: 'u2', uri: 'GEZD GNBV GY3T QOJQ' }, { ref: 'i3|main', title: 'Broken', uri: 'not a key 0189' }] };
  const blob = await I.sealTransfer(payload, ids);
  check('sealed transfer has no secret / name in it', !JSON.stringify(blob).includes('JBSWY3DP') && !JSON.stringify(blob).includes('MadeUpMail'));
  const op = await I.openTransfer(blob, ids);
  check('transfer opens: move, 2 entries, bad one skipped', op.mode === 'move' && op.entries.length === 2 && op.skipped.length === 1, op);
  check('transfer: a bare key gets the item title and username', op.entries[1].issuer === 'BareKey' && op.entries[1].label === 'u2');
  let wc = null; try { await I.openTransfer(blob, await I.transferIds('ABCDEFGHIJKLMNOPQRSTUVWXYZ234566')); } catch (x) { wc = x.message; }
  check('transfer: another code cannot open it', /doesn't open/.test(wc || ''));
  check('transfer: a short code is refused', await I.transferIds('ABC').then(() => false, () => true));
  const mk = crypto.getRandomValues(new Uint8Array(32));
  check('mirror code parses', hex(I.mirrorKeyFrom('HALLOWMIRROR1:' + otp.base32Encode(mk))) === hex(mk));
  const mir = JSON.parse(await I.sealMirror(mk, [{ type: 'totp', issuer: 'MadeUpMail', label: 'sam', secret: 'JBSWY3DPEHPK3PXP', algo: 'SHA1', digits: 6, period: 30 }, { type: 'hotp', issuer: 'H', label: 'h', secret: 'GEZDGNBVGY3TQOJQ', counter: 1 }, steamE]));
  const plain = JSON.parse(new TextDecoder().decode(await subtle.decrypt({ name: 'AES-GCM', iv: otp.b64ToBytes(mir.iv), additionalData: te.encode('HallowAuthMirror1') }, await subtle.importKey('raw', mk, 'AES-GCM', false, ['decrypt']), otp.b64ToBytes(mir.ct))));
  check('mirror: sealed, HOTP left out, Steam secret as base32', plain.entries.length === 2 && plain.entries[1].type === 'steam' && plain.entries[1].secret === otp.base32Encode(ss) && !JSON.stringify(mir).includes('MadeUp'));
}

// ---- QR reader
{
  // Reed-Solomon: a block with errors is fixed
  const g = encode('otpauth://totp/MadeUp:x?secret=JBSWY3DPEHPK3PXP', 'M');
  check('the test encoder output decodes cleanly', Q.decodeGrid(g.grid) === 'otpauth://totp/MadeUp:x?secret=JBSWY3DPEHPK3PXP');
  let ok = 0, total = 0;
  for (const ecl of ['L', 'M', 'Q', 'H']) for (const m of [0, 1, 2, 3, 4, 5, 6, 7]) { total++; const e = encode('Hallow test ' + ecl + m, ecl, m); if (Q.decodeGrid(e.grid) === 'Hallow test ' + ecl + m) ok++; }
  check('every EC level x every mask (32 codes) decode', ok === total, ok + '/' + total);
  let vok = 0; const vs = [1, 2, 5, 6, 7, 10, 14, 20, 27, 32, 40];
  for (const v of vs) { const txt = 'v' + v + '-' + 'x'.repeat(Math.max(1, v * 3)); const e = encode(txt, 'M', -1, v); if (e.version === v && Q.decodeGrid(e.grid) === txt) vok++; else console.log('  version ' + v + ' failed'); }
  check('versions 1-40 (' + vs.join(',') + ') decode (alignment and version blocks right)', vok === vs.length, vok);
  // damaged modules: flip some data modules - error correction fixes them
  const dm = encode('otpauth://totp/Damaged:x?secret=JBSWY3DPEHPK3PXP&issuer=Damaged', 'H');
  const grid = dm.grid.map(r => r.slice()); let flipped = 0; const fm = Q.functionMap(dm.version);
  for (let y = 0; y < dm.size && flipped < 40; y += 2) for (let x = 0; x < dm.size && flipped < 40; x += 5) if (!fm[y][x]) { grid[y][x] = !grid[y][x]; flipped++; }
  check('EC level H with 40 flipped modules still decodes', Q.decodeGrid(grid) === 'otpauth://totp/Damaged:x?secret=JBSWY3DPEHPK3PXP&issuer=Damaged');
  // images
  const longGoogle = gm([{ secret: [...k20], name: 'MadeUp:alex@example.com', issuer: 'MadeUp', algo: 1, digits: 1, type: 2 }, { secret: [...seeds.SHA512], name: 'bob@example.net', issuer: 'Fakebank', algo: 3, digits: 2, type: 2 }, { secret: [...seeds.SHA256], name: 'carol', issuer: 'Third', algo: 2, digits: 1, type: 2 }], 0, 1, 7);
  const cases = [
    ['plain, straight', 'otpauth://totp/MadeUp:sam@example.org?secret=JBSWY3DPEHPK3PXP&issuer=MadeUp', 'M', { px: 6 }],
    ['rotated 17 degrees', 'otpauth://totp/MadeUp:sam@example.org?secret=JBSWY3DPEHPK3PXP&issuer=MadeUp', 'M', { px: 6, rot: 17 }],
    ['rotated 90 degrees', 'HALLOWAUTH1:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 'L', { px: 7, rot: 90 }],
    ['upside down (180)', 'HALLOWAUTH1:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 'Q', { px: 6, rot: 180 }],
    ['perspective tilt', 'otpauth://totp/Tilted:x?secret=GEZDGNBVGY3TQOJQ', 'M', { px: 7, tilt: 0.25 }],
    ['tilt + rotation + noise', 'otpauth://totp/Noisy:x?secret=GEZDGNBVGY3TQOJQ&issuer=Noisy', 'Q', { px: 6, tilt: 0.18, rot: -12, noise: 45 }],
    ['blurred, low contrast, uneven light', 'otpauth://totp/Dim:x?secret=JBSWY3DPEHPK3PXP', 'M', { px: 6, blur: true, dark: 90, light: 170, gradient: true }],
    ['inverted (light on dark)', 'otpauth://totp/Inv:x?secret=JBSWY3DPEHPK3PXP', 'M', { px: 6, invert: true }],
    ['small modules (3 px)', 'otpauth://totp/Small:x?secret=JBSWY3DPEHPK3PXP', 'L', { px: 3 }],
    ['Google export (3 accounts), version ' + encode(longGoogle, 'M').version, longGoogle, 'M', { px: 4, rot: 6, noise: 25 }],
  ];
  for (const [name, txt, ecl, o] of cases) { const e = encode(txt, ecl); const img = render(e.grid, o); const t1 = Date.now(); const got = Q.decodeImage(img); check('QR image: ' + name + ' (v' + e.version + ', ' + img.width + 'px, ' + (Date.now() - t1) + ' ms)', got === txt, got); }
  // no QR code -> null, quickly
  const blank = render([[false]], { size: 300, noise: 60 }); check('a picture with no QR code -> nothing', Q.decodeImage(blank) === null);
  // images made by another encoder (Hallow Remote's C# Qr.cs), if given: <name>.rgba (w, h as 2 int32 then RGBA) + <name>.txt
  const extra = process.argv[2];
  if (extra && fs.existsSync(extra)) {
    let n = 0, good = 0;
    for (const f of fs.readdirSync(extra).filter(f => f.endsWith('.rgba'))) {
      const buf = fs.readFileSync(path.join(extra, f)), w = buf.readInt32LE(0), h = buf.readInt32LE(4);
      const want = fs.readFileSync(path.join(extra, f.replace('.rgba', '.txt')), 'utf8'); n++;
      const got = Q.decodeImage({ data: new Uint8ClampedArray(buf.buffer, buf.byteOffset + 8, w * h * 4), width: w, height: h });
      if (got === want) good++; else console.log('  ' + f + ' -> ' + JSON.stringify(got));
    }
    check('QR images from Hallow Remote\'s C# encoder: ' + good + ' of ' + n, n > 0 && good === n);
  }
}
// ======== 1.1 ========
{
  const X = await import('../app/exporters.js'), QE = await import('../app/qrcode.js');
  const nodeCrypto = await import('crypto');
  const E = (o) => { const e = Object.assign({ type: 'totp', algo: 'SHA1', digits: 6, period: 30, counter: 0 }, o); otp.normalize(e); e.id = e.id || Math.random().toString(36).slice(2); return e; };
  const acc = [E({ issuer: 'MadeUpMail', label: 'sam@example.org', secret: 'JBSWY3DPEHPK3PXP', notes: 'made-up backup codes: 1111-2222 3333-4444' }), E({ issuer: 'Made Up Bank', label: 'sam', secret: 'GEZDGNBVGY3TQOJQ', algo: 'SHA256', digits: 8 }),
    E({ issuer: 'SlowSite', label: 'x', secret: 'KRSXG5CTMVRXEZLU', period: 60 }), E({ type: 'hotp', issuer: 'CounterCo', label: 'c', secret: 'MFRGGZDFMZTWQ2LK', counter: 7 }), Object.assign({ id: 'st' }, steamE), E({ label: 'no issuer here', secret: 'ORSXG5AJBSWY3DP' })];

  // ---- QR encoder (app/qrcode.js): every code it makes is read back by the app's reader through the tests' own renderer
  let qrOk = 0, qrN = 0;
  for (const ecl of ['L', 'M', 'Q', 'H']) for (const len of [1, 17, 60, 140, 300, 700]) {
    const txt = 'otpauth://totp/Made%20Up:me?secret=JBSWY3DPEHPK3PXP&n=' + 'x'.repeat(len); const q = QE.encode(txt, ecl); qrN++;
    const got = Q.decodeImage(render(q.grid, { px: 3 })); if (got === txt) qrOk++; else console.log('  qr ' + ecl + ' ' + len + ' v' + q.version + ' mask ' + q.mask + ' -> ' + JSON.stringify(got).slice(0, 60));
  }
  check('QR encoder: ' + qrOk + ' of ' + qrN + ' codes (EC L/M/Q/H, up to ~750 bytes) read back by the app\'s reader', qrOk === qrN);
  const masks = new Set(); for (let i = 0; i < 30; i++) masks.add(QE.encode('mask test ' + i, 'M').mask); check('QR encoder picks masks by the penalty rules (several used: ' + [...masks].join(',') + ')', masks.size >= 3);
  check('QR encoder: the SVG path has one square per dark module', (() => { const q = QE.encode('hello', 'M'); const dark = q.grid.flat().filter(Boolean).length; return (QE.qrPath(q.grid).match(/M/g) || []).length === dark; })());
  const one = otp.toOtpauth(acc[1]); check('one account\'s QR (otpauth link) reads back and parses to the same account', (() => { const t = Q.decodeImage(render(QE.encode(one, 'M').grid, { px: 4 })); const r = otp.parseOtpauth(t); return !!r.entry && r.entry.secret === acc[1].secret && r.entry.digits === 8 && r.entry.algo === 'SHA256' && r.entry.issuer === 'Made Up Bank'; })());

  // ---- plain otpauth list
  const plain = X.otpauthList(acc), back = otp.parseOtpauthList(plain);
  check('plain list: one link per account, all parse back (TOTP / HOTP / Steam / 60 s / SHA256 8 digits)', back.entries.length === acc.length && back.errors.length === 0 && back.entries.every((e, i) => e.secret === (acc[i].secretFormat === 'base64' ? otp.base32Encode(otp.b64ToBytes(acc[i].secret)) : acc[i].secret) && e.type === acc[i].type && e.digits === acc[i].digits), back);
  check('plain list: notes are never in it', !plain.includes('1111-2222'));

  // ---- Aegis export, opened independently (node:crypto scrypt + AES-256-GCM, written from Aegis' vault.md - not the app's code)
  const aeg = await X.aegisExport(acc, 'made-up aegis pw', 1024), aj = JSON.parse(aeg);
  check('Aegis file: version 1, one password slot (type 1, scrypt n/r/p, salt), db sealed', aj.version === 1 && aj.header.slots.length === 1 && aj.header.slots[0].type === 1 && aj.header.slots[0].n === 1024 && aj.header.slots[0].r === 8 && aj.header.slots[0].p === 1 && typeof aj.db === 'string' && !aeg.includes('JBSWY3DP') && !aeg.includes('MadeUpMail'));
  const indep = (txt, pw) => {
    const j = JSON.parse(txt), s = j.header.slots[0];
    const k = nodeCrypto.scryptSync(Buffer.from(pw), Buffer.from(s.salt, 'hex'), 32, { N: s.n, r: s.r, p: s.p, maxmem: 256 * 1024 * 1024 });
    const d1 = nodeCrypto.createDecipheriv('aes-256-gcm', k, Buffer.from(s.key_params.nonce, 'hex')); d1.setAuthTag(Buffer.from(s.key_params.tag, 'hex'));
    const master = Buffer.concat([d1.update(Buffer.from(s.key, 'hex')), d1.final()]);
    const d2 = nodeCrypto.createDecipheriv('aes-256-gcm', master, Buffer.from(j.header.params.nonce, 'hex')); d2.setAuthTag(Buffer.from(j.header.params.tag, 'hex'));
    return JSON.parse(Buffer.concat([d2.update(Buffer.from(j.db, 'base64')), d2.final()]).toString('utf8'));
  };
  let db = null; try { db = indep(aeg, 'made-up aegis pw'); } catch (x) { db = { err: x.message }; }
  check('Aegis file opens with node:crypto (independent): db version 3, all accounts', !!db && db.version === 3 && Array.isArray(db.entries) && db.entries.length === acc.length, db);
  const de = (db && db.entries) || [];
  check('Aegis entries: type, name, issuer, info (secret base32, algo, digits, period / counter), note, uuid', de.length === acc.length && de[1].info.algo === 'SHA256' && de[1].info.digits === 8 && de[2].info.period === 60 && de[3].type === 'hotp' && de[3].info.counter === 7 && de[4].type === 'steam' && de[4].info.secret === otp.base32Encode(ss) && de[0].note.includes('1111-2222') && /^[0-9a-f-]{36}$/.test(de[0].uuid) && de[0].name === 'sam@example.org' && de[0].issuer === 'MadeUpMail', de);
  let wrongA = null; try { indep(aeg, 'not it'); } catch (x) { wrongA = x; } check('Aegis file: a wrong password doesn\'t open it', !!wrongA);
  const reim = await I.parseAny(aeg, 'made-up aegis pw');
  check('Aegis file re-imported by this app: same accounts and codes, notes kept', reim.entries.length === acc.length && (await otp.codeFor(reim.entries[4], 3000030)) === 'YRGQJ' && reim.entries[0].notes.includes('1111-2222') && (await otp.codeFor(reim.entries[1], 1234567890)) === (await otp.codeFor(acc[1], 1234567890)), reim.skipped);
  const t0 = Date.now(), full = await X.aegisExport(acc.slice(0, 1), 'made-up aegis pw'); const ft = Date.now() - t0;
  check('Aegis file at Aegis\' own strength (scrypt N 32768): made in ' + ft + ' ms and opens independently', JSON.parse(full).header.slots[0].n === 32768 && indep(full, 'made-up aegis pw').entries.length === 1);

  // ---- Google Authenticator transfer codes: an independent protobuf reader, and this app's importer
  const pbRead = b => { let p = 0; const out = []; const vi = () => { let r = 0, s = 0, x; do { x = b[p++]; r += (x & 127) * 2 ** s; s += 7; } while (x & 128); return r; }; while (p < b.length) { const k = vi(), f = Math.floor(k / 8), t = k & 7; if (t === 0) out.push({ f, v: vi() }); else if (t === 2) { const n = vi(); out.push({ f, b: b.slice(p, p + n) }); p += n; } else throw new Error('wire ' + t); } return out; };
  const many = []; for (let i = 0; i < 19; i++) many.push(E({ issuer: 'Made Up ' + i, label: 'u' + i + '@example.org', secret: otp.base32Encode(new Uint8Array(10).fill(i + 1)) }));
  const g = X.googleMigration(acc.concat(many), 8, 4242);
  check('transfer codes: Steam and the 60 s one left out (named), 23 accounts in 3 codes of up to 8', g.count === 23 && g.uris.length === 3 && g.skipped.length === 2 && /SlowSite/.test(g.skipped.join()) && /Steam/.test(g.skipped.join()), g);
  const pay = g.uris.map(u => pbRead(otp.b64ToBytes(decodeURIComponent(u.split('data=')[1]))));
  check('transfer codes (independent reader): version 1, batch size 3, index 0/1/2, the same batch id', pay.every((p, i) => p.find(x => x.f === 2).v === 1 && p.find(x => x.f === 3).v === 3 && (p.find(x => x.f === 4) || { v: 0 }).v === i && p.find(x => x.f === 5).v === 4242));
  const first = pbRead(pay[0].filter(x => x.f === 1)[0].b), bankP = pbRead(pay[0].filter(x => x.f === 1)[1].b), hotpP = pbRead(pay[0].filter(x => x.f === 1)[2].b);
  check('transfer codes (independent reader): secret bytes, "issuer:account" name, issuer, SHA1 / 6 digits / TOTP', Buffer.from(first.find(x => x.f === 1).b).equals(Buffer.from(otp.base32Decode('JBSWY3DPEHPK3PXP'))) && new TextDecoder().decode(first.find(x => x.f === 2).b) === 'MadeUpMail:sam@example.org' && new TextDecoder().decode(first.find(x => x.f === 3).b) === 'MadeUpMail' && first.find(x => x.f === 4).v === 1 && first.find(x => x.f === 5).v === 1 && first.find(x => x.f === 6).v === 2);
  check('transfer codes (independent reader): SHA256 + 8 digits, and HOTP with its counter', bankP.find(x => x.f === 4).v === 2 && bankP.find(x => x.f === 5).v === 2 && hotpP.find(x => x.f === 6).v === 1 && hotpP.find(x => x.f === 7).v === 7);
  const gi = g.uris.map(u => I.parseGoogleMigration(u)), all = gi.flatMap(x => x.entries);
  check('transfer codes read back by this app\'s importer (as from Google): 23 accounts, codes match', all.length === 23 && gi.every((x, i) => x.batch.index === i && x.batch.size === 3) && (await otp.codeFor(all[1], 59)) === (await otp.codeFor(acc[1], 59)) && all[2].type === 'hotp' && all[2].counter === 7, gi.map(x => x.skipped));
  check('transfer codes fit a QR code each (and read back through the app\'s reader)', g.uris.every(u => Q.decodeImage(render(QE.encode(u, 'M').grid, { px: 3 })) === u));

  // ---- backups 1.1: a kept backup-password key, a passcode-locked automatic backup
  const bk = await V.backupKeyFrom('made-up backup pw 2', 100000);
  const f1 = await V.makeBackupWithKey(acc, bk);
  check('backup with the kept key: the normal backup format, opens with the password', JSON.parse(f1).format === V.BACKUP_FORMAT && (await V.readBackup(f1, 'made-up backup pw 2')).length === acc.length && !f1.includes('JBSWY3DP') && !f1.includes('1111-2222'));
  const f1b = await V.makeBackupWithKey(acc, bk); check('two backups with the same key differ (fresh IV each time)', JSON.parse(f1).ct !== JSON.parse(f1b).ct && JSON.parse(f1).salt === JSON.parse(f1b).salt);
  const st = V.memoryStorage(), v = new V.Vault(st, { iterations: 100000 }); await v.create('made-up passcode 9'); v.data.entries = acc.map(e => Object.assign({}, e)); await v.save();
  check('checkPasscode: right yes, wrong no', (await v.checkPasscode('made-up passcode 9')) === true && (await v.checkPasscode('nope')) === false);
  const f2 = await v.passcodeBackup(), j2 = JSON.parse(f2);
  check('passcode-locked backup: format "hallow-authenticator-vault", nothing readable, the phone\'s passcode wrap', j2.format === 'hallow-authenticator-vault' && !f2.includes('JBSWY3DP') && !f2.includes('MadeUp') && !f2.includes('1111') && j2.wct === (await v.meta()).wrap.ct && V.backupKind(f2) === 'passcode' && V.backupKind(f1) === 'password');
  const r2 = await V.readAnyBackup(f2, 'made-up passcode 9'); check('passcode-locked backup opens with the passcode: all accounts, notes kept', r2.length === acc.length && r2[0].notes.includes('1111-2222'));
  let w2 = null; try { await V.readAnyBackup(f2, 'made-up passcode 1'); } catch (x) { w2 = x; } check('passcode-locked backup: a wrong passcode is refused', w2 instanceof V.WrongPasscode);
  await v.changePasscode('made-up passcode 9', 'made-up passcode 10');
  const r3 = await V.readAnyBackup(f2, 'made-up passcode 9'); check('an older passcode backup still opens with the passcode it was made with', r3.length === acc.length);
  check('parseAny knows both backup kinds', (await I.parseAny(f2)).kind === 'backup' && (await I.parseAny(f1)).kind === 'backup');
  const t2 = JSON.parse(f2); t2.ct = t2.ct.slice(0, 10) + (t2.ct[10] === 'A' ? 'B' : 'A') + t2.ct.slice(11); let tam2 = null; try { await V.readVaultBackup(JSON.stringify(t2), 'made-up passcode 9'); } catch (x) { tam2 = x; } check('a changed byte in a passcode backup is refused', !!tam2);

  // ---- reminders: none yet, N not in the latest backup, older than 14 days; automatic backup due at most once a day after changes
  const d = { entries: acc.slice(0, 3).map(e => Object.assign({}, e)) }, day = 86400000, T = Date.parse('2026-11-23T12:00:00Z');
  let s1 = V.backupStatus(d, T); check('reminder: no backup yet', s1.never && s1.notIn === 3);
  V.markBackedUp(d, 'pc', T); s1 = V.backupStatus(d, T); check('reminder: after a backup nothing is missing', !s1.never && s1.notIn === 0 && !s1.stale);
  d.entries.push(Object.assign({}, acc[3])); d.entries[0].label = 'renamed'; s1 = V.backupStatus(d, T + 1000); check('reminder: an added and a changed account -> "2 not in your latest backup"', s1.notIn === 2, s1);
  d.entries[1].notes = 'new made-up codes'; check('reminder: new backup codes / notes count as a change', V.backupStatus(d, T).notIn === 3);
  d.entries.pop(); check('reminder: a deleted account isn\'t "missing"', V.backupStatus(d, T).notIn === 2);
  V.markBackedUp(d, 'file', T); check('reminder: not stale at 14 days, stale at 15', !V.backupStatus(d, T + 14 * day).stale && V.backupStatus(d, T + 15 * day + 1000).stale && V.backupStatus(d, T + 15 * day + 1000).days === 15);
  const on = { autoBackup: true }, off = { autoBackup: false }, undecided = { autoBackup: null };
  check('auto backup: not due with nothing changed', !V.autoBackupDue(d, on, T + 1000));
  d.entries[0].label = 'changed again'; check('auto backup: due after a change (never sent before)', V.autoBackupDue(d, on, T + 1000));
  check('auto backup: never when off or not decided yet', !V.autoBackupDue(d, off, T + 1000) && !V.autoBackupDue(d, undecided, T + 1000));
  d.auto = { last: new Date(T).toISOString() }; check('auto backup: at most once a day (23 h no, 24 h yes)', !V.autoBackupDue(d, on, T + 23 * 3600000) && V.autoBackupDue(d, on, T + 24 * 3600000));
  check('auto backup: nothing to send with no accounts', !V.autoBackupDue({ entries: [] }, on, T));
  check('default settings: codes shown, auto backup undecided, backup-password mode', V.defaultSettings().hideCodes === false && V.defaultSettings().autoBackup === null && V.defaultSettings().autoMode === 'backup');

  // ---- notes stay out of the PC mirror
  const mk2 = crypto.getRandomValues(new Uint8Array(32)), mir2 = JSON.parse(await I.sealMirror(mk2, [acc[0]]));
  const pl2 = new TextDecoder().decode(await subtle.decrypt({ name: 'AES-GCM', iv: otp.b64ToBytes(mir2.iv), additionalData: te.encode('HallowAuthMirror1') }, await subtle.importKey('raw', mk2, 'AES-GCM', false, ['decrypt']), otp.b64ToBytes(mir2.ct)));
  check('per-account notes never go into the PC mirror', !pl2.includes('1111-2222') && pl2.includes('JBSWY3DPEHPK3PXP'));
  // ---- the offline list covers every app file
  const sw = fs.readFileSync(new URL('../app/sw.js', import.meta.url), 'utf8'), appFiles = fs.readdirSync(new URL('../app/', import.meta.url)).filter(f => !/\.md$/.test(f) && f !== 'sw.js');
  check('service worker caches every app file (offline): ' + appFiles.length, appFiles.every(f => sw.includes("'" + f + "'")), appFiles.filter(f => !sw.includes("'" + f + "'")));
  check('service worker version 1.1.0 (new cache, the old one dropped)', /VERSION = '1\.1\.0'/.test(sw));
}
console.log(fails ? fails + ' FAILED (' + passes + ' passed)' : 'ALL PASSED (' + passes + ')');
process.exit(fails ? 1 : 0);
