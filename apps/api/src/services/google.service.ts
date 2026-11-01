import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { z } from 'zod';
import { allowedOrigin, type Env } from '../config/env.js';
import { validateExternalUrl } from '../net/ipGuard.js';
import { safeFetch } from '../net/safeFetch.js';
import type { Repos, UserRecord } from '../repositories/types.js';
import { DuplicateError } from '../utils/errors.js';
import { safeEqual } from '../utils/crypto.js';
import type { SafeFn } from '../providers/facebook.js';
import type { AuthService } from './auth.service.js';

export interface GoogleClaims { sub: string; email: string; emailVerified: boolean; name: string | null; picture: string | null }
export class GoogleAuthError extends Error {
  constructor(public readonly code: 'EXCHANGE_FAILED' | 'INVALID_TOKEN' | 'EMAIL_NOT_VERIFIED' | 'NONCE_MISMATCH' | 'NOT_CONFIGURED') { super(code); }
}
export interface GoogleClient {
  readonly configured: boolean;
  authUrl(p: { state: string; nonce: string; codeChallenge: string }): string;
  /** Exchanges the code and returns identity claims that have been fully verified (signature, iss, aud, exp, nonce). */
  exchange(p: { code: string; codeVerifier: string; nonce: string }): Promise<GoogleClaims>;
}

export const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

/** Verifies an ID token: signature (JWKS), issuer, audience, expiry, nonce, and a verified e-mail. */
export async function verifyGoogleIdToken(idToken: string, p: { clientId: string; nonce: string; keys: JWTVerifyGetKey; now?: Date }): Promise<GoogleClaims> {
  let payload;
  try {
    ({ payload } = await jwtVerify(idToken, p.keys, { issuer: GOOGLE_ISSUERS, audience: p.clientId, algorithms: ['RS256'], clockTolerance: 5, ...(p.now ? { currentDate: p.now } : {}) }));
  } catch { throw new GoogleAuthError('INVALID_TOKEN'); }
  if (typeof payload.nonce !== 'string' || !safeEqual(payload.nonce, p.nonce)) throw new GoogleAuthError('NONCE_MISMATCH');
  if (typeof payload.sub !== 'string' || !payload.sub || typeof payload.email !== 'string') throw new GoogleAuthError('INVALID_TOKEN');
  const verified = payload.email_verified === true || payload.email_verified === 'true';
  if (!verified) throw new GoogleAuthError('EMAIL_NOT_VERIFIED');
  return { sub: payload.sub, email: payload.email.trim().toLowerCase(), emailVerified: true, name: typeof payload.name === 'string' ? payload.name : null, picture: typeof payload.picture === 'string' ? payload.picture : null };
}

const tokenResponse = z.object({ id_token: z.string().min(20) }).passthrough();

export function createGoogleClient(env: Env, deps: { safe?: SafeFn; keys?: JWTVerifyGetKey } = {}): GoogleClient {
  const clientId = env.GOOGLE_CLIENT_ID, secret = env.GOOGLE_CLIENT_SECRET, redirect = env.GOOGLE_CALLBACK_URL;
  const configured = !!(clientId && secret && redirect);
  const safe = deps.safe ?? safeFetch;
  const keys = deps.keys ?? createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'), { timeoutDuration: 5000 });
  return {
    configured,
    authUrl({ state, nonce, codeChallenge }) {
      if (!configured) throw new GoogleAuthError('NOT_CONFIGURED');
      const q = new URLSearchParams({ response_type: 'code', client_id: clientId!, redirect_uri: redirect!, scope: 'openid email profile', state, nonce, code_challenge: codeChallenge, code_challenge_method: 'S256', prompt: 'select_account' });
      return `https://accounts.google.com/o/oauth2/v2/auth?${q}`;
    },
    async exchange({ code, codeVerifier, nonce }) {
      if (!configured) throw new GoogleAuthError('NOT_CONFIGURED');
      let idToken: string;
      try {
        const res = await safe('https://oauth2.googleapis.com/token', {
          method: 'POST', allowedHosts: ['oauth2.googleapis.com'], timeoutMs: 10_000, maxBytes: 100_000, contentType: /json/i,
          headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
          body: new URLSearchParams({ code, client_id: clientId!, client_secret: secret!, redirect_uri: redirect!, grant_type: 'authorization_code', code_verifier: codeVerifier }).toString(),
        });
        const parsed = tokenResponse.safeParse(res.status === 200 ? res.json() : null);
        if (!parsed.success) throw new GoogleAuthError('EXCHANGE_FAILED');
        idToken = parsed.data.id_token;
      } catch (e) { throw e instanceof GoogleAuthError ? e : new GoogleAuthError('EXCHANGE_FAILED'); }
      return verifyGoogleIdToken(idToken, { clientId: clientId!, nonce, keys });
    },
  };
}

// ---- state cookie: AES-256-GCM, bound to the browser that started the flow ----
interface FlowState { s: string; n: string; v: string; m: 'login' | 'link'; u: string | null; exp: number }
const keyOf = (secret: string) => createHash('sha256').update(`oauth-flow:${secret}`).digest();
export function sealFlow(st: FlowState, secret: string): string {
  const iv = randomBytes(12); const c = createCipheriv('aes-256-gcm', keyOf(secret), iv);
  const enc = Buffer.concat([c.update(JSON.stringify(st), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64url');
}
export function openFlow(raw: string, secret: string): FlowState | null {
  try {
    const b = Buffer.from(raw, 'base64url'); if (b.length < 29) return null;
    const d = createDecipheriv('aes-256-gcm', keyOf(secret), b.subarray(0, 12)); d.setAuthTag(b.subarray(12, 28));
    const st = JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8')) as FlowState;
    return typeof st.s === 'string' && typeof st.n === 'string' && typeof st.v === 'string' && typeof st.exp === 'number' ? st : null;
  } catch { return null; }
}

export const FLOW_TTL_MS = 10 * 60_000;
export type GoogleOutcome =
  | { kind: 'session'; token: string; csrfToken: string; redirect: string }
  | { kind: 'redirect'; redirect: string };

export function createGoogleService(deps: { repos: Repos; auth: AuthService; client: GoogleClient; env: Env; now?: () => Date }) {
  const { repos, auth, client, env } = deps;
  const now = deps.now ?? (() => new Date());
  const front = allowedOrigin(env);
  const fail = (code: string): GoogleOutcome => ({ kind: 'redirect', redirect: `${front}/connexion?error=${code}` });
  const audit = (actor: string | null, action: string, target?: string | null) => repos.audit.create({ actorId: actor, action, targetId: target ?? null });

  function begin(mode: 'login' | 'link', userId: string | null) {
    const state = randomBytes(24).toString('base64url');
    const nonce = randomBytes(24).toString('base64url');
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const cookie = sealFlow({ s: state, n: nonce, v: verifier, m: mode, u: userId, exp: now().getTime() + FLOW_TTL_MS }, env.SESSION_SECRET);
    return { url: client.authUrl({ state, nonce, codeChallenge: challenge }), cookie };
  }

  async function uniqueUsername(claims: GoogleClaims): Promise<string> {
    const raw = (claims.name ?? claims.email.split('@')[0] ?? 'user').normalize('NFKC');
    let base = raw.replace(/[^\p{L}\p{N}_.-]+/gu, '').slice(0, 24);
    if (base.length < 3) base = `user${base}`;
    for (let i = 0; i < 6; i++) {
      const cand = i === 0 ? base : `${base.slice(0, 25)}${String(100 + (randomBytes(2).readUInt16BE() % 9000))}`;
      if (!(await repos.users.findByUsername(cand))) return cand;
    }
    return `user${randomBytes(5).toString('hex')}`;
  }

  return {
    configured: client.configured,
    startLogin: () => begin('login', null),
    /** Linking Google to an existing account is an explicit, authenticated action (the route requires session + CSRF). */
    startLink: (user: UserRecord) => begin('link', user.id),

    async callback(q: { code?: unknown; state?: unknown; error?: unknown }, flowCookie: string | undefined, current: UserRecord | null, userAgent: string | null): Promise<GoogleOutcome> {
      const flow = flowCookie ? openFlow(flowCookie, env.SESSION_SECRET) : null;
      if (!flow || flow.exp <= now().getTime()) return fail('google_session_expired');
      if (typeof q.error === 'string') return fail('google_denied');
      if (typeof q.state !== 'string' || typeof q.code !== 'string' || q.code.length > 2048 || !safeEqual(q.state, flow.s)) { await audit(null, 'GOOGLE_STATE_INVALID'); return fail('google_invalid_state'); }

      let claims: GoogleClaims;
      try { claims = await client.exchange({ code: q.code, codeVerifier: flow.v, nonce: flow.n }); }
      catch (e) {
        await audit(null, 'GOOGLE_LOGIN_FAILED');
        return fail(e instanceof GoogleAuthError && e.code === 'EMAIL_NOT_VERIFIED' ? 'google_email_unverified' : 'google_failed');
      }

      const owner = await repos.identities.findUserIdByProvider('GOOGLE', claims.sub);

      if (flow.m === 'link') {
        if (!current || current.id !== flow.u) return fail('google_link_session');
        if (owner && owner !== current.id) return fail('google_in_use');
        if (!owner) {
          try { await repos.identities.create({ userId: current.id, provider: 'GOOGLE', providerUserId: claims.sub }); }
          catch (e) { if (e instanceof DuplicateError) return fail('google_already_linked'); throw e; }
          await audit(current.id, 'GOOGLE_LINKED', current.id);
        }
        return { kind: 'redirect', redirect: `${front}/compte?linked=google` };
      }

      let user: UserRecord | null = owner ? await repos.users.findById(owner) : null;
      if (owner && !user) return fail('google_failed');
      if (!user) {
        // No automatic linking by e-mail: an existing account must be linked from inside that account.
        if (await repos.users.findByEmail(claims.email)) { await audit(null, 'GOOGLE_EMAIL_CONFLICT'); return fail('google_email_conflict'); }
        let avatar: string | null = null;
        if (claims.picture) { try { avatar = validateExternalUrl(claims.picture).toString().slice(0, 500); } catch { avatar = null; } }
        try { user = await auth.registerExternal({ username: await uniqueUsername(claims), email: claims.email, avatar, provider: 'GOOGLE', providerUserId: claims.sub }); }
        catch (e) { if (e instanceof DuplicateError) return fail('google_email_conflict'); throw e; }
      }
      if (user.status === 'SUSPENDED') { await audit(user.id, 'LOGIN_BLOCKED_SUSPENDED', user.id); return fail('account_suspended'); }
      if (user.status !== 'ACTIVE') return fail('google_failed');
      const r = await auth.loginExternal(user, userAgent);
      if (r.twoFactorRequired) return { kind: 'redirect', redirect: `${front}/connexion#challenge=${encodeURIComponent(r.challenge)}` };
      return { kind: 'session', token: r.token, csrfToken: r.csrfToken, redirect: `${front}/?login=google` };
    },

    /** Removes the Google identity; refused when it would leave the account without any way to sign in. */
    async unlink(user: UserRecord) {
      if (!user.passwordHash) return false;
      const ok = await repos.identities.deleteForUser(user.id, 'GOOGLE');
      if (ok) await audit(user.id, 'GOOGLE_UNLINKED', user.id);
      return ok;
    },
  };
}
export type GoogleService = ReturnType<typeof createGoogleService>;
