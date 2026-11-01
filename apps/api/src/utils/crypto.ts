import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** 256-bit random opaque token, URL-safe. */
export const randomToken = (bytes = 32): string => randomBytes(bytes).toString('base64url');

/** Keyed hash so a database leak alone cannot be used to forge or look up tokens. */
export const hashToken = (token: string, secret: string): string =>
  createHmac('sha256', secret).update(token).digest('hex');

export function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}
