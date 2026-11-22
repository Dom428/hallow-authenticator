// Test helper: a QR code ENCODER (byte mode, any EC level, versions 1-40, a chosen or the best mask) and a renderer that draws the code
// rotated, in perspective, blurred and with noise - to feed the app's reader. Written separately from app/qr.js (own GF tables and RS).
const EXP = [], LOG = [];
{ let x = 1; for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x = (x << 1) ^ (x & 128 ? 0x11d : 0); x &= 255; } }
const mul = (a, b) => (a && b ? EXP[(LOG[a] + LOG[b]) % 255] : 0);
const ECC = { L: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  M: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  Q: [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  H: [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30] };
const NB = { L: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  M: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  Q: [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  H: [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81] };
const FMT = { L: 1, M: 0, Q: 3, H: 2 };
function raw(v) { let r = (16 * v + 128) * v + 64; if (v >= 2) { const n = Math.floor(v / 7) + 2; r -= (25 * n - 10) * n - 55; if (v >= 7) r -= 36; } return r; }
function align(v) { if (v === 1) return []; const n = Math.floor(v / 7) + 2, sz = v * 4 + 17, step = v === 32 ? 26 : Math.ceil((v * 4 + 4) / (n * 2 - 2)) * 2; const r = [6]; for (let p = sz - 7; r.length < n; p -= step) r.splice(1, 0, p); return r; }
function rsDivisor(d) { let r = new Array(d).fill(0); r[d - 1] = 1; let root = 1; for (let i = 0; i < d; i++) { for (let j = 0; j < r.length; j++) { r[j] = mul(r[j], root); if (j + 1 < r.length) r[j] ^= r[j + 1]; } root = mul(root, 2); } return r; }
function rsRem(data, div) { const r = new Array(div.length).fill(0); for (const b of data) { const f = b ^ r.shift(); r.push(0); div.forEach((c, i) => { r[i] ^= mul(c, f); }); } return r; }
export function encode(text, ecl = 'L', forceMask = -1, minVer = 1) {
  const bytes = typeof text === 'string' ? [...new TextEncoder().encode(text)] : [...text];
  let v = minVer;
  for (; v <= 40; v++) { const cap = Math.floor(raw(v) / 8) - ECC[ecl][v] * NB[ecl][v]; if (4 + (v < 10 ? 8 : 16) + bytes.length * 8 <= cap * 8) break; }
  if (v > 40) throw new Error('too long');
  const cap = Math.floor(raw(v) / 8) - ECC[ecl][v] * NB[ecl][v];
  const bits = []; const put = (x, n) => { for (let i = n - 1; i >= 0; i--) bits.push((x >>> i) & 1); };
  put(4, 4); put(bytes.length, v < 10 ? 8 : 16); bytes.forEach(b => put(b, 8));
  put(0, Math.min(4, cap * 8 - bits.length)); while (bits.length % 8) bits.push(0);
  for (let p = 0xec; bits.length < cap * 8; p ^= 0xec ^ 0x11) put(p, 8);
  const data = []; for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  const nb = NB[ecl][v], ec = ECC[ecl][v], rawCw = Math.floor(raw(v) / 8), ns = nb - rawCw % nb, sl = Math.floor(rawCw / nb), div = rsDivisor(ec);
  const blocks = []; for (let i = 0, k = 0; i < nb; i++) { const dat = data.slice(k, k + sl - ec + (i < ns ? 0 : 1)); k += dat.length; const e = rsRem(dat, div); if (i < ns) dat.push(0); blocks.push(dat.concat(e)); }
  const cw = []; for (let i = 0; i < blocks[0].length; i++) blocks.forEach((b, j) => { if (i !== sl - ec || j >= ns) cw.push(b[i]); });
  const size = v * 4 + 17, m = Array.from({ length: size }, () => new Array(size).fill(0)), fn = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, d) => { m[y][x] = d ? 1 : 0; fn[y][x] = true; };
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  const finder = (cx, cy) => { for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) { const x = cx + dx, y = cy + dy, d = Math.max(Math.abs(dx), Math.abs(dy)); if (x >= 0 && y >= 0 && x < size && y < size) set(x, y, d !== 2 && d !== 4); } };
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
  const al = align(v); al.forEach((a, i) => al.forEach((b, j) => { if ((i === 0 && j === 0) || (i === 0 && j === al.length - 1) || (i === al.length - 1 && j === 0)) return; for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(a + dx, b + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1); }));
  const fmt = (mask) => { const d = (FMT[ecl] << 3) | mask; let r = d; for (let i = 0; i < 10; i++) r = (r << 1) ^ ((r >>> 9) * 0x537); const b = ((d << 10) | r) ^ 0x5412;
    for (let i = 0; i <= 5; i++) set(8, i, (b >>> i) & 1); set(8, 7, (b >>> 6) & 1); set(8, 8, (b >>> 7) & 1); set(7, 8, (b >>> 8) & 1); for (let i = 9; i < 15; i++) set(14 - i, 8, (b >>> i) & 1);
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, (b >>> i) & 1); for (let i = 8; i < 15; i++) set(8, size - 15 + i, (b >>> i) & 1); set(8, size - 8, 1); };
  fmt(0);
  if (v >= 7) { let r = v; for (let i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1f25); const b = (v << 12) | r; for (let i = 0; i < 18; i++) { const a = size - 11 + i % 3, c = Math.floor(i / 3); set(a, c, (b >>> i) & 1); set(c, a, (b >>> i) & 1); } }
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) { if (right === 6) right = 5; for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) { const x = right - j, up = ((right + 1) & 2) === 0, y = up ? size - 1 - vert : vert; if (!fn[y][x] && i < cw.length * 8) { m[y][x] = (cw[i >>> 3] >>> (7 - (i & 7))) & 1; i++; } } }
  const mk = (k, x, y) => [(x + y) % 2 === 0, y % 2 === 0, x % 3 === 0, (x + y) % 3 === 0, (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x * y) % 2 + (x * y) % 3 === 0, ((x * y) % 2 + (x * y) % 3) % 2 === 0, ((x + y) % 2 + (x * y) % 3) % 2 === 0][k];
  const mask = forceMask >= 0 ? forceMask : (v * 3 + bytes.length) % 8;
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fn[y][x] && mk(mask, x, y)) m[y][x] ^= 1;
  fmt(mask);
  return { version: v, size, mask, grid: m.map(r => r.map(Boolean)) };
}
// draws the grid: module size px, quiet zone 4, then rotation (deg), a perspective tilt, blur and noise; returns {data,width,height}
export function render(grid, o = {}) {
  const ms = o.px || 6, q = 4, n = grid.length, W = (n + 2 * q) * ms, out = o.size || Math.round(W * 1.35);
  const rot = (o.rot || 0) * Math.PI / 180, tilt = o.tilt || 0, noise = o.noise || 0, dark = o.dark ?? 20, light = o.light ?? 235, invert = !!o.invert;
  let seed = o.seed || 1; const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  const data = new Uint8ClampedArray(out * out * 4);
  for (let y = 0; y < out; y++) for (let x = 0; x < out; x++) {
    let u = x - out / 2, v = y - out / 2;
    const w = 1 + tilt * v / out; u *= w; v *= w;   // a simple perspective: the bottom looks bigger than the top
    const ur = u * Math.cos(rot) + v * Math.sin(rot), vr = -u * Math.sin(rot) + v * Math.cos(rot);
    const gx = Math.floor((ur + W / 2) / ms) - q, gy = Math.floor((vr + W / 2) / ms) - q;
    let d = gx >= 0 && gy >= 0 && gx < n && gy < n && grid[gy][gx];
    if (invert) d = !d;
    let val = d ? dark : light; val += (rnd() - 0.5) * 2 * noise;
    if (o.gradient) val = val * (0.55 + 0.45 * x / out);
    const p = (y * out + x) * 4; data[p] = data[p + 1] = data[p + 2] = val; data[p + 3] = 255;
  }
  if (o.blur) { const c = new Uint8ClampedArray(data); for (let y = 1; y < out - 1; y++) for (let x = 1; x < out - 1; x++) { let s = 0; for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) s += c[((y + dy) * out + x + dx) * 4]; const p = (y * out + x) * 4; data[p] = data[p + 1] = data[p + 2] = s / 9; } }
  return { data, width: out, height: out };
}
