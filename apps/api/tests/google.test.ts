import { createHash } from 'node:crypto';
import { SignJWT, UnsecuredJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWK } from 'jose';
import request from 'supertest';
import { beforeAll, describe, expect, it } from 'vitest';
import { loadEnv } from '../src/config/env.js';
import { SafeFetchError, type SafeResponse } from '../src/net/safeFetch.js';
import { GoogleAuthError, createGoogleClient, openFlow, sealFlow, verifyGoogleIdToken, type GoogleClaims, type GoogleClient } from '../src/services/google.service.js';
import { login, makeClock, makeCtx, ORIGIN, PASSWORD, env as baseEnv, registerVerified, signedIn } from './helpers.js';

const CLIENT_ID = '1234-abc.apps.googleusercontent.com';
const NONCE = 'nonce-abc';
let priv: CryptoKey; let keys: ReturnType<typeof createLocalJWKSet>; let otherPriv: CryptoKey;

beforeAll(async () => {
  const a = await generateKeyPair('RS256'); const b = await generateKeyPair('RS256');
  priv = a.privateKey; otherPriv = b.privateKey;
  const jwk: JWK = { ...(await exportJWK(a.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  keys = createLocalJWKSet({ keys: [jwk] });
});

const sign = (claims: Record<string, unknown> = {}, o: { iss?: string; aud?: string; exp?: number | string; key?: CryptoKey; kid?: string } = {}) =>
  new SignJWT({ sub: '1001', email: 'Alice@Example.com', email_verified: true, name: 'Alice A', picture: 'https://lh3.googleusercontent.com/a.jpg', nonce: NONCE, ...claims })
    .setProtectedHeader({ alg: 'RS256', kid: o.kid ?? 'k1' }).setIssuer(o.iss ?? 'https://accounts.google.com').setAudience(o.aud ?? CLIENT_ID)
    .setIssuedAt().setExpirationTime(o.exp ?? '10m').sign(o.key ?? priv);
const verify = (t: string, nonce = NONCE) => verifyGoogleIdToken(t, { clientId: CLIENT_ID, nonce, keys });

describe('Google ID token verification (real RS256 signatures, local JWKS)', () => {
  it('accepts a valid token and normalises the e-mail', async () => {
    expect(await verify(await sign())).toEqual({ sub: '1001', email: 'alice@example.com', emailVerified: true, name: 'Alice A', picture: 'https://lh3.googleusercontent.com/a.jpg' });
  });
  it('accepts both documented issuer spellings and email_verified "true"', async () => {
    expect((await verify(await sign({}, { iss: 'accounts.google.com' }))).sub).toBe('1001');
    expect((await verify(await sign({ email_verified: 'true' }))).emailVerified).toBe(true);
  });
  it.each([
    ['wrong issuer', () => sign({}, { iss: 'https://evil.example.com' })],
    ['wrong audience', () => sign({}, { aud: 'someone-else.apps.googleusercontent.com' })],
    ['expired', () => sign({}, { exp: Math.floor(Date.now() / 1000) - 3600 })],
    ['signed by another key', () => sign({}, { key: otherPriv })],
    ['unknown kid', () => sign({}, { kid: 'nope' })],
    ['unsigned (alg none)', async () => new UnsecuredJWT({ sub: '1', email: 'a@b.com', email_verified: true, nonce: NONCE }).setIssuer('https://accounts.google.com').setAudience(CLIENT_ID).setExpirationTime('10m').encode()],
    ['HS256 algorithm confusion', async () => new SignJWT({ sub: '1', email: 'a@b.com', email_verified: true, nonce: NONCE }).setProtectedHeader({ alg: 'HS256', kid: 'k1' }).setIssuer('https://accounts.google.com').setAudience(CLIENT_ID).setExpirationTime('10m').sign(new TextEncoder().encode('x'.repeat(64)))],
    ['garbage', async () => 'not.a.jwt'],
    ['empty', async () => ''],
    ['missing sub', () => sign({ sub: undefined })],
    ['missing email', () => sign({ email: undefined })],
    ['non-string email', () => sign({ email: { $ne: 1 } })],
  ])('rejects: %s', async (_n, make) => {
    await expect(verify(await make())).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
  });
  it('rejects a token tampered after signing', async () => {
    const [h, p, s] = (await sign()).split('.');
    const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p!, 'base64url').toString()), email: 'admin@example.com' })).toString('base64url');
    await expect(verify(`${h}.${forged}.${s}`)).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
  });
  it('rejects a wrong or missing nonce (replayed token from another flow)', async () => {
    await expect(verify(await sign(), 'other-nonce')).rejects.toMatchObject({ code: 'NONCE_MISMATCH' });
    await expect(verify(await sign({ nonce: undefined }))).rejects.toMatchObject({ code: 'NONCE_MISMATCH' });
  });
  it('rejects an unverified e-mail', async () => {
    for (const v of [false, undefined, 'false', 'yes', 1]) await expect(verify(await sign({ email_verified: v }))).rejects.toMatchObject({ code: 'EMAIL_NOT_VERIFIED' });
  });
  it('honours an injected clock for expiry', async () => {
    const t = await sign({}, { exp: Math.floor(Date.now() / 1000) + 60 });
    await expect(verifyGoogleIdToken(t, { clientId: CLIENT_ID, nonce: NONCE, keys, now: new Date(Date.now() + 3_600_000) })).rejects.toBeInstanceOf(GoogleAuthError);
  });
});

const resp = (body: unknown, status = 200): SafeResponse => { const text = JSON.stringify(body); return { status, finalUrl: 'x', headers: new Headers(), body: new TextEncoder().encode(text), text: () => text, json: () => JSON.parse(text) }; };
const gEnv = loadEnv({ NODE_ENV: 'test', MONGODB_URI: 'x', SESSION_SECRET: 'x'.repeat(40), FRONTEND_URL: ORIGIN, GOOGLE_CLIENT_ID: CLIENT_ID, GOOGLE_CLIENT_SECRET: 'shh-secret', GOOGLE_CALLBACK_URL: `${ORIGIN}/api/v1/auth/google/callback` });

describe('Google client (authorization URL and code exchange)', () => {
  it('is unconfigured without credentials and refuses to work', async () => {
    const c = createGoogleClient(baseEnv);
    expect(c.configured).toBe(false);
    expect(() => c.authUrl({ state: 's', nonce: 'n', codeChallenge: 'c' })).toThrow(GoogleAuthError);
    await expect(c.exchange({ code: 'c', codeVerifier: 'v', nonce: 'n' })).rejects.toMatchObject({ code: 'NOT_CONFIGURED' });
  });
  it('builds an authorization URL with exact redirect URI, state, nonce and PKCE S256', () => {
    const u = new URL(createGoogleClient(gEnv).authUrl({ state: 'S', nonce: 'N', codeChallenge: 'C' }));
    expect(u.origin + u.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
    expect(Object.fromEntries(u.searchParams)).toMatchObject({ response_type: 'code', client_id: CLIENT_ID, redirect_uri: `${ORIGIN}/api/v1/auth/google/callback`, scope: 'openid email profile', state: 'S', nonce: 'N', code_challenge: 'C', code_challenge_method: 'S256' });
    expect(u.search).not.toContain('shh-secret');
  });
  it('exchanges the code server-to-server (pinned host, form body) then verifies the returned ID token', async () => {
    const calls: { url: string; opts: any }[] = [];
    const client = createGoogleClient(gEnv, { keys, safe: async (url, opts) => { calls.push({ url, opts }); return resp({ id_token: await sign(), access_token: 'ignored' }); } });
    const claims = await client.exchange({ code: 'CODE', codeVerifier: 'VERIFIER', nonce: NONCE });
    expect(claims.email).toBe('alice@example.com');
    expect(calls[0]!.url).toBe('https://oauth2.googleapis.com/token');
    expect(calls[0]!.opts).toMatchObject({ method: 'POST', allowedHosts: ['oauth2.googleapis.com'] });
    expect(Object.fromEntries(new URLSearchParams(calls[0]!.opts.body))).toEqual({ code: 'CODE', client_id: CLIENT_ID, client_secret: 'shh-secret', redirect_uri: `${ORIGIN}/api/v1/auth/google/callback`, grant_type: 'authorization_code', code_verifier: 'VERIFIER' });
  });
  it('maps every exchange failure to EXCHANGE_FAILED and a forged token to INVALID_TOKEN', async () => {
    const mk = (safe: any) => createGoogleClient(gEnv, { keys, safe });
    for (const safe of [async () => resp({ error: 'invalid_grant' }, 400), async () => resp({ no: 'token' }), async () => resp({ id_token: 'short' }), async () => { throw new SafeFetchError('TIMEOUT', 't'); }, async () => { throw new Error('boom'); }]) {
      await expect(mk(safe).exchange({ code: 'c', codeVerifier: 'v', nonce: NONCE })).rejects.toMatchObject({ code: 'EXCHANGE_FAILED' });
    }
    await expect(mk(async () => resp({ id_token: await sign({}, { key: otherPriv }) })).exchange({ code: 'c', codeVerifier: 'v', nonce: NONCE })).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
  });
});

describe('flow cookie sealing', () => {
  const st = { s: 'state', n: 'nonce', v: 'verifier', m: 'login' as const, u: null, exp: Date.now() + 1000 };
  it('round-trips, and rejects tampering, truncation, wrong secret and junk', () => {
    const sealed = sealFlow(st, 'k'.repeat(40));
    expect(openFlow(sealed, 'k'.repeat(40))).toEqual(st);
    expect(openFlow(sealed, 'z'.repeat(40))).toBeNull();
    const b = Buffer.from(sealed, 'base64url'); b[b.length - 1] = b[b.length - 1]! ^ 1;
    expect(openFlow(b.toString('base64url'), 'k'.repeat(40))).toBeNull();
    for (const junk of ['', 'abc', sealed.slice(0, 20), '!!!!']) expect(openFlow(junk, 'k'.repeat(40))).toBeNull();
    expect(sealed).not.toContain('verifier');
  });
});

// ---------- HTTP flow with a fake Google that still enforces PKCE + nonce ----------
function fakeGoogle() {
  let challenge = ''; let nonce = '';
  const state = { next: { sub: 'g-1', email: 'gina@example.com', emailVerified: true, name: 'Gina G', picture: 'https://lh3.googleusercontent.com/g.jpg' } as GoogleClaims | GoogleAuthError, exchanges: 0 };
  const client: GoogleClient = {
    configured: true,
    authUrl: (p) => { challenge = p.codeChallenge; nonce = p.nonce; return `https://accounts.google.com/o/oauth2/v2/auth?state=${p.state}&nonce=${p.nonce}&cc=${p.codeChallenge}`; },
    async exchange(p) {
      state.exchanges++;
      if (createHash('sha256').update(p.codeVerifier).digest('base64url') !== challenge) throw new GoogleAuthError('EXCHANGE_FAILED');
      if (p.nonce !== nonce) throw new GoogleAuthError('NONCE_MISMATCH');
      if (state.next instanceof GoogleAuthError) throw state.next;
      return state.next;
    },
  };
  return { client, state };
}
const setup = (over: { now?: () => Date } = {}) => {
  const g = fakeGoogle();
  const ctx = makeCtx({ now: over.now, env: { GOOGLE_CLIENT_ID: CLIENT_ID, GOOGLE_CLIENT_SECRET: 's', GOOGLE_CALLBACK_URL: `${ORIGIN}/api/v1/auth/google/callback` }, deps: { google: g.client } });
  return { ctx, ...g };
};
const CB = '/api/v1/auth/google/callback';
async function begin(agent: ReturnType<typeof request.agent>) {
  const r = await agent.get('/api/v1/auth/google/start');
  expect(r.status).toBe(302);
  const loc = new URL(r.headers.location!);
  return { r, loc, state: loc.searchParams.get('state')! };
}
const errOf = (loc: string) => new URL(loc).searchParams.get('error');
const hasSession = (r: request.Response) => (r.headers['set-cookie'] as unknown as string[] | undefined)?.some((c) => c.startsWith('mh_sid=') && !/Expires=Thu, 01 Jan 1970/.test(c)) ?? false;

describe('Google login flow', () => {
  it('reports configuration honestly', async () => {
    const off = makeCtx();
    expect((await request(off.app).get('/api/v1/auth/google/status')).body).toEqual({ configured: false });
    expect((await request(off.app).get('/api/v1/auth/google/start')).status).toBe(503);
    expect((await request(off.app).get(CB)).status).toBe(503);
    const { ctx } = setup();
    expect((await request(ctx.app).get('/api/v1/auth/google/status')).body).toEqual({ configured: true });
  });

  it('start sends the browser to Google with state/nonce/PKCE and sets an HttpOnly, SameSite=Lax flow cookie', async () => {
    const { ctx } = setup();
    const { r, loc } = await begin(request.agent(ctx.app));
    expect(loc.origin).toBe('https://accounts.google.com');
    expect(loc.searchParams.get('state')!.length).toBeGreaterThanOrEqual(30);
    const cookie = (r.headers['set-cookie'] as unknown as string[]).find((c) => c.startsWith('mh_oauth='))!;
    expect(cookie).toMatch(/HttpOnly/i); expect(cookie).toMatch(/SameSite=Lax/i);
    expect(cookie).not.toContain(loc.searchParams.get('state')!); // sealed, not readable
    expect(r.headers['cache-control']).toBe('no-store');
  });

  it('creates a verified account on first login, opens a session, and logs in again without duplicating', async () => {
    const { ctx, state } = setup();
    const agent = request.agent(ctx.app);
    const { state: s } = await begin(agent);
    const cb = await agent.get(`${CB}?code=abc&state=${s}`);
    expect(cb.status).toBe(302);
    expect(cb.headers.location).toBe(`${ORIGIN}/?login=google`);
    expect(hasSession(cb)).toBe(true);
    expect(cb.headers.location).not.toMatch(/code=|token|abc/);
    const me = await agent.get('/api/v1/auth/me');
    expect(me.status).toBe(200);
    expect(me.body.user).toMatchObject({ email: 'gina@example.com', emailVerified: true, hasPassword: false, role: 'USER' });
    expect(me.body.user.username).toMatch(/^Gina/);
    expect(JSON.stringify(me.body)).not.toMatch(/g-1|passwordHash/);
    const u = (await ctx.repos.users.findByEmail('gina@example.com'))!;
    expect(u.passwordHash).toBeNull();
    expect(await ctx.repos.identities.findUserIdByProvider('GOOGLE', 'g-1')).toBe(u.id);

    const agent2 = request.agent(ctx.app);
    const { state: s2 } = await begin(agent2);
    const cb2 = await agent2.get(`${CB}?code=def&state=${s2}`);
    expect(cb2.headers.location).toBe(`${ORIGIN}/?login=google`);
    expect((await ctx.repos.users.list({ page: 1, pageSize: 10 })).total).toBe(1);
    expect(state.exchanges).toBe(2);
  });

  it('clears the flow cookie after the callback (no replay with the same cookie)', async () => {
    const { ctx } = setup();
    const agent = request.agent(ctx.app);
    const { state: s } = await begin(agent);
    const cb = await agent.get(`${CB}?code=abc&state=${s}`);
    expect((cb.headers['set-cookie'] as unknown as string[]).some((c) => c.startsWith('mh_oauth=;') || /mh_oauth=[^;]*; .*Expires=Thu, 01 Jan 1970/.test(c))).toBe(true);
    const again = await agent.get(`${CB}?code=abc&state=${s}`);
    expect(errOf(again.headers.location!)).toBe('google_session_expired');
  });

  it('never links by e-mail: an existing password account with the same address is refused', async () => {
    const { ctx, state } = setup();
    state.next = { sub: 'g-9', email: 'victim@example.com', emailVerified: true, name: 'Evil', picture: null };
    await registerVerified(ctx, 'victim');
    const agent = request.agent(ctx.app);
    const { state: s } = await begin(agent);
    const cb = await agent.get(`${CB}?code=abc&state=${s}`);
    expect(errOf(cb.headers.location!)).toBe('google_email_conflict');
    expect(hasSession(cb)).toBe(false);
    expect(await ctx.repos.identities.findUserIdByProvider('GOOGLE', 'g-9')).toBeNull();
    const audit = await ctx.repos.audit.list({ page: 1, pageSize: 10, action: 'GOOGLE_EMAIL_CONFLICT' });
    expect(audit.items.length).toBe(1);
  });

  it('rejects missing, wrong, truncated and oversized state/code; missing, forged and expired flow cookies', async () => {
    const clock = makeClock();
    const { ctx, state } = setup({ now: clock.now });
    const agent = request.agent(ctx.app);
    const { state: s } = await begin(agent);
    for (const q of [`code=abc`, `state=${s}`, `code=abc&state=WRONG`, `code=abc&state=${s.slice(0, -1)}`, `code=${'x'.repeat(3000)}&state=${s}`, `code[]=a&state=${s}`, `code=abc&state[]=${s}`]) {
      const r = await agent.get(`${CB}?${q}`);
      expect(r.status).toBe(302);
      expect(errOf(r.headers.location!), q.slice(0, 40)).toMatch(/^google_(invalid_state|session_expired)$/);
      expect(hasSession(r)).toBe(false);
      await begin(agent); // the failed callback consumed the cookie
    }
    expect(state.exchanges).toBe(0); // no code was ever exchanged with a bad state
    expect(errOf((await request(ctx.app).get(`${CB}?code=a&state=${s}`)).headers.location!)).toBe('google_session_expired');
    expect(errOf((await request(ctx.app).get(`${CB}?code=a&state=${s}`).set('Cookie', 'mh_oauth=forged')).headers.location!)).toBe('google_session_expired');
    const a2 = request.agent(ctx.app);
    const { state: s2 } = await begin(a2);
    clock.advance(11 * 60_000);
    expect(errOf((await a2.get(`${CB}?code=a&state=${s2}`)).headers.location!)).toBe('google_session_expired');
  });

  it("a state from someone else's flow does not work with my cookie (login CSRF)", async () => {
    const { ctx } = setup();
    const victim = request.agent(ctx.app); const attacker = request.agent(ctx.app);
    await begin(victim);
    const { state: attackerState } = await begin(attacker);
    const r = await victim.get(`${CB}?code=abc&state=${attackerState}`);
    expect(errOf(r.headers.location!)).toBe('google_invalid_state');
    expect(hasSession(r)).toBe(false);
  });

  it('handles the user cancelling and Google-side failures without creating anything', async () => {
    const { ctx, state } = setup();
    const a = request.agent(ctx.app);
    const { state: s } = await begin(a);
    expect(errOf((await a.get(`${CB}?error=access_denied&state=${s}`)).headers.location!)).toBe('google_denied');
    for (const [err, code] of [[new GoogleAuthError('EXCHANGE_FAILED'), 'google_failed'], [new GoogleAuthError('INVALID_TOKEN'), 'google_failed'], [new GoogleAuthError('NONCE_MISMATCH'), 'google_failed'], [new GoogleAuthError('EMAIL_NOT_VERIFIED'), 'google_email_unverified']] as const) {
      state.next = err;
      const ag = request.agent(ctx.app);
      const { state: st } = await begin(ag);
      const r = await ag.get(`${CB}?code=abc&state=${st}`);
      expect(errOf(r.headers.location!)).toBe(code);
      expect(hasSession(r)).toBe(false);
    }
    expect((await ctx.repos.users.list({ page: 1, pageSize: 10 })).total).toBe(0);
  });

  it('refuses suspended accounts', async () => {
    const { ctx } = setup();
    const a1 = request.agent(ctx.app);
    const { state: s1 } = await begin(a1);
    await a1.get(`${CB}?code=abc&state=${s1}`);
    const u = (await ctx.repos.users.findByEmail('gina@example.com'))!;
    await ctx.repos.users.update(u.id, { status: 'SUSPENDED' });
    const a2 = request.agent(ctx.app);
    const { state: s2 } = await begin(a2);
    const r = await a2.get(`${CB}?code=abc&state=${s2}`);
    expect(errOf(r.headers.location!)).toBe('account_suspended');
    expect(hasSession(r)).toBe(false);
  });

  it('only ever redirects to the configured front-end origin', async () => {
    const { ctx, state } = setup();
    const targets: string[] = [];
    for (const next of [state.next, new GoogleAuthError('EXCHANGE_FAILED')]) {
      state.next = next;
      const ag = request.agent(ctx.app);
      const { state: s } = await begin(ag);
      targets.push((await ag.get(`${CB}?code=a&state=${s}`)).headers.location!);
      targets.push((await ag.get(`${CB}?code=a&state=${s}`)).headers.location!);
    }
    for (const t of targets) expect(t.startsWith(`${ORIGIN}/`)).toBe(true);
  });

  it('derives a unique, valid username and ignores unsafe avatar URLs', async () => {
    const { ctx, state } = setup();
    await signedIn(ctx, 'gina'); // takes the natural username
    state.next = { sub: 'g-2', email: 'gina2@example.com', emailVerified: true, name: 'gina', picture: 'http://127.0.0.1/evil.png' };
    const ag = request.agent(ctx.app);
    const { state: s } = await begin(ag);
    await ag.get(`${CB}?code=a&state=${s}`);
    const u = (await ctx.repos.users.findByEmail('gina2@example.com'))!;
    expect(u.username).not.toBe('gina');
    expect(u.username).toMatch(/^[\p{L}\p{N}_.-]{3,32}$/u);
    expect(u.avatar).toBeNull();
  });
});

describe('linking and unlinking Google', () => {
  it('linking needs a session and CSRF, then attaches only to the signed-in account', async () => {
    const { ctx, state } = setup();
    expect((await request(ctx.app).post('/api/v1/auth/google/link').set('Origin', ORIGIN).send({})).status).toBe(401);
    const alice = await signedIn(ctx, 'alice');
    expect((await alice.agent.post('/api/v1/auth/google/link').set('Origin', ORIGIN).send({})).status).toBe(403);
    state.next = { sub: 'g-alice', email: 'different@gmail.com', emailVerified: true, name: 'A', picture: null };
    const link = await alice.call('post', '/api/v1/auth/google/link', {});
    expect(link.status).toBe(200);
    const s = new URL(link.body.url).searchParams.get('state')!;
    const cb = await alice.agent.get(`${CB}?code=abc&state=${s}`);
    expect(cb.headers.location).toBe(`${ORIGIN}/compte?linked=google`);
    expect(await ctx.repos.identities.findUserIdByProvider('GOOGLE', 'g-alice')).toBe(alice.user.id);
    expect(hasSession(cb)).toBe(false); // linking never swaps the session
    // she can now sign in with Google, landing on HER account
    const ag = request.agent(ctx.app);
    const { state: s2 } = await begin(ag);
    await ag.get(`${CB}?code=abc&state=${s2}`);
    expect((await ag.get('/api/v1/auth/me')).body.user.email).toBe(alice.email);
  });

  it('a link flow completed in another session (or none) attaches nothing', async () => {
    const { ctx } = setup();
    const alice = await signedIn(ctx, 'alice');
    const bob = await signedIn(ctx, 'bob');
    const link = await alice.call('post', '/api/v1/auth/google/link', {});
    const cookie = (link.headers['set-cookie'] as unknown as string[]).find((c) => c.startsWith('mh_oauth='))!.split(';')[0]!;
    const s = new URL(link.body.url).searchParams.get('state')!;
    const bobLogin = await login(ctx, bob.email);
    const bobSid = (bobLogin.res.headers['set-cookie'] as unknown as string[]).find((c) => c.startsWith('mh_sid='))!.split(';')[0]!;
    const asBob = await request(ctx.app).get(`${CB}?code=abc&state=${s}`).set('Cookie', `${bobSid}; ${cookie}`);
    expect((await request(ctx.app).get('/api/v1/auth/me').set('Cookie', bobSid)).body.user.email).toBe(bob.email); // Bob really is signed in
    expect(errOf(asBob.headers.location!)).toBe('google_link_session');
    const anon = await request(ctx.app).get(`${CB}?code=abc&state=${s}`).set('Cookie', cookie);
    expect(errOf(anon.headers.location!)).toBe('google_link_session');
    expect(await ctx.repos.identities.findUserIdByProvider('GOOGLE', 'g-1')).toBeNull();
  });

  it('refuses a Google account that already belongs to someone else', async () => {
    const { ctx } = setup();
    const ag = request.agent(ctx.app);
    const { state: s0 } = await begin(ag);
    await ag.get(`${CB}?code=abc&state=${s0}`); // creates gina, owner of g-1
    const alice = await signedIn(ctx, 'alice');
    const link = await alice.call('post', '/api/v1/auth/google/link', {});
    const cb = await alice.agent.get(`${CB}?code=abc&state=${new URL(link.body.url).searchParams.get('state')}`);
    expect(errOf(cb.headers.location!)).toBe('google_in_use');
    expect(await ctx.repos.identities.hasProvider(alice.user.id, 'GOOGLE')).toBe(false);
  });

  it('unlink works with a password, is refused for Google-only accounts, and when nothing is linked', async () => {
    const { ctx } = setup();
    const alice = await signedIn(ctx, 'alice');
    expect((await alice.call('delete', '/api/v1/auth/google')).status).toBe(409);
    const link = await alice.call('post', '/api/v1/auth/google/link', {});
    await alice.agent.get(`${CB}?code=abc&state=${new URL(link.body.url).searchParams.get('state')}`);
    expect((await alice.agent.delete('/api/v1/auth/google').set('Origin', ORIGIN)).status).toBe(403); // CSRF
    expect((await alice.call('delete', '/api/v1/auth/google')).status).toBe(204);
    expect(await ctx.repos.identities.hasProvider(alice.user.id, 'GOOGLE')).toBe(false);

    const gAgent = request.agent(ctx.app);
    const { state: s } = await begin(gAgent);
    const login = await gAgent.get(`${CB}?code=abc&state=${s}`);
    expect(hasSession(login)).toBe(true);
    const csrf = (await gAgent.get('/api/v1/auth/me')).body.csrfToken as string;
    const del = await gAgent.delete('/api/v1/auth/google').set('Origin', ORIGIN).set('X-CSRF-Token', csrf);
    expect(del.status).toBe(409); // would lock the account out
    expect(await ctx.repos.identities.findUserIdByProvider('GOOGLE', 'g-1')).not.toBeNull();
  });

  it('a Google-only account can delete itself by confirming its e-mail address', async () => {
    const { ctx } = setup();
    const ag = request.agent(ctx.app);
    const { state: s } = await begin(ag);
    await ag.get(`${CB}?code=abc&state=${s}`);
    const csrf = (await ag.get('/api/v1/auth/me')).body.csrfToken as string;
    expect((await ag.delete('/api/v1/auth/account').set('Origin', ORIGIN).set('X-CSRF-Token', csrf).send({ confirmEmail: 'wrong@example.com' })).status).toBeGreaterThanOrEqual(400);
    expect((await ag.delete('/api/v1/auth/account').set('Origin', ORIGIN).set('X-CSRF-Token', csrf).send({ confirmEmail: 'gina@example.com' })).status).toBeLessThan(300);
    expect(await ctx.repos.users.findByEmail('gina@example.com')).toBeNull();
    expect(await ctx.repos.identities.findUserIdByProvider('GOOGLE', 'g-1')).toBeNull();
  });
});
void PASSWORD;
