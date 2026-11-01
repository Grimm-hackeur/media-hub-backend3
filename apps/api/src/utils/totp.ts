import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s) — the profile every authenticator app supports. */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const STEP_S = 30;

export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = '';
  for (const b of buf) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}
export function base32Decode(s: string): Buffer {
  let bits = 0, value = 0; const out: number[] = [];
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    const i = ALPHABET.indexOf(c); if (i < 0) throw new Error('invalid base32');
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
export const generateSecret = () => base32Encode(randomBytes(20));

export function hotp(secretB32: string, counter: number, digits = 6): string {
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', base32Decode(secretB32)).update(buf).digest();
  const o = h[h.length - 1]! & 0xf;
  const n = ((h[o]! & 0x7f) << 24) | (h[o + 1]! << 16) | (h[o + 2]! << 8) | h[o + 3]!;
  return String(n % 10 ** digits).padStart(digits, '0');
}
export const stepOf = (t: Date) => Math.floor(t.getTime() / 1000 / STEP_S);

/** Returns the matching time step (±1 step of clock drift) or null. The caller must refuse steps <= the last used one (replay). */
export function verifyTotp(secretB32: string, code: string, t: Date, window = 1): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const cur = stepOf(t);
  let found: number | null = null;
  for (let w = -window; w <= window; w++) if (hotp(secretB32, cur + w) === code) found = cur + w; // no early exit: constant-ish time
  return found;
}
export const otpauthUri = (secretB32: string, account: string, issuer = 'Media Hub') =>
  `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=${STEP_S}`;

// The TOTP secret must be recoverable (we need it to check codes), so it is encrypted at rest with a key derived from SESSION_SECRET.
const key = (secret: string) => createHash('sha256').update(`totp-key:${secret}`).digest();
export function encryptSecret(plain: string, secret: string): string {
  const iv = randomBytes(12); const c = createCipheriv('aes-256-gcm', key(secret), iv);
  const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), enc].map((b) => b.toString('base64url')).join('.');
}
export function decryptSecret(blob: string, secret: string): string {
  const [iv, tag, enc] = blob.split('.').map((p) => Buffer.from(p, 'base64url')) as [Buffer, Buffer, Buffer];
  const d = createDecipheriv('aes-256-gcm', key(secret), iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
}
