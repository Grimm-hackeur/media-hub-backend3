import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { loadEnv } from '../src/config/env.js';
import { argon2idHasher } from '../src/services/password.js';
import { ORIGIN, PASSWORD, login, makeCtx, post, registerVerified, env } from './helpers.js';

describe('configuration', () => {
  it('rejects a weak SESSION_SECRET and missing MONGODB_URI', () => {
    expect(() => loadEnv({ MONGODB_URI: 'x', SESSION_SECRET: 'short', FRONTEND_URL: ORIGIN })).toThrow(/SESSION_SECRET/);
    expect(() => loadEnv({ SESSION_SECRET: 'x'.repeat(40), FRONTEND_URL: ORIGIN })).toThrow(/MONGODB_URI/);
  });
  it('accepts a valid configuration', () => {
    expect(loadEnv({ MONGODB_URI: 'mongodb://h/db', SESSION_SECRET: 'x'.repeat(40), FRONTEND_URL: ORIGIN }).PORT).toBe(4000);
  });
});

describe('password hashing', () => {
  it('uses Argon2id and verifies correctly', async () => {
    const h = await argon2idHasher.hash(PASSWORD);
    expect(h.startsWith('$argon2id$')).toBe(true);
    expect(h).not.toContain(PASSWORD);
    expect(await argon2idHasher.verify(h, PASSWORD)).toBe(true);
    expect(await argon2idHasher.verify(h, 'wrong-password-xx')).toBe(false);
    expect(await argon2idHasher.verify('not-a-hash', PASSWORD)).toBe(false);
  });
});

describe('platform basics', () => {
  it('serves health, JSON 404 and rejects malformed JSON', async () => {
    const ctx = makeCtx();
    expect((await request(ctx.app).get('/api/health')).body.status).toBe('ok');
    expect((await request(ctx.app).get('/api/nope')).status).toBe(404);
    const bad = await request(ctx.app).post('/api/auth/login').set('Origin', ORIGIN).set('Content-Type', 'application/json').send('{bad');
    expect(bad.status).toBe(400);
    expect(JSON.stringify(bad.body)).not.toMatch(/SyntaxError|at /);
  });
  it('allows CORS only for the front-end origin', async () => {
    const ctx = makeCtx();
    const ok = await request(ctx.app).get('/api/health').set('Origin', ORIGIN);
    expect(ok.headers['access-control-allow-origin']).toBe(ORIGIN);
    expect(ok.headers['access-control-allow-credentials']).toBe('true');
    const evil = await request(ctx.app).get('/api/health').set('Origin', 'https://evil.example');
    expect(evil.headers['access-control-allow-origin']).toBeUndefined();
    expect(ok.headers['x-powered-by']).toBeUndefined();
    expect(ok.headers['x-content-type-options']).toBe('nosniff');
  });
  it('rejects state-changing requests from other origins or without Origin', async () => {
    const ctx = makeCtx();
    const body = { email: 'a@example.com', password: PASSWORD };
    expect((await request(ctx.app).post('/api/auth/login').set('Origin', 'https://evil.example').send(body)).status).toBe(403);
    expect((await request(ctx.app).post('/api/auth/login').send(body)).status).toBe(403);
  });
});

describe('registration', () => {
  const body = { username: 'alice', email: 'Alice@Example.com', password: PASSWORD, acceptTerms: true };
  it('creates only a pending registration (no account yet) and mails a 4-digit code', async () => {
    const ctx = makeCtx();
    const res = await post(ctx, '/api/auth/register', body);
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ status: 'pending', retryAfter: 60 });
    expect(await ctx.repos.users.findByEmail('alice@example.com')).toBeNull();
    expect(await ctx.repos.pending.findByEmail('alice@example.com')).not.toBeNull();
    expect(ctx.mail.otpFrom('alice@example.com')).toMatch(/^\d{4}$/);
  });
  it('returns the same response for an already registered e-mail (no enumeration) and sends the owner a notice instead of a code', async () => {
    const ctx = makeCtx();
    await registerVerified(ctx, 'alice', 'alice@example.com');
    const before = ctx.mail.sent.length;
    const fresh = await post(ctx, '/api/auth/register', { ...body, email: 'new@example.com', username: 'newbie' });
    const again = await post(ctx, '/api/auth/register', { ...body, username: 'alice2' });
    expect(again.status).toBe(fresh.status);
    expect(again.body).toEqual(fresh.body);
    const mails = ctx.mail.sent.slice(before);
    expect(mails.find((m) => m.to === 'alice@example.com')?.subject).toMatch(/Tentative/);
    expect(mails.find((m) => m.to === 'alice@example.com')?.text).not.toMatch(/\b\d{4}\b/);
    expect(await ctx.repos.pending.findByEmail('alice@example.com')).toBeNull();
  });
  it('rejects invalid input, unknown fields (role injection) and missing terms', async () => {
    const ctx = makeCtx();
    expect((await post(ctx, '/api/auth/register', { ...body, password: 'short' })).status).toBe(400);
    expect((await post(ctx, '/api/auth/register', { ...body, email: 'nope' })).status).toBe(400);
    expect((await post(ctx, '/api/auth/register', { ...body, acceptTerms: false })).status).toBe(400);
    const inj = await post(ctx, '/api/auth/register', { ...body, role: 'ADMIN' });
    expect(inj.status).toBe(400);
    expect(await ctx.repos.pending.findByEmail('alice@example.com')).toBeNull();
  });
  it('rejects a username taken by a real account, case-insensitively', async () => {
    const ctx = makeCtx();
    await registerVerified(ctx, 'alice');
    const r = await post(ctx, '/api/auth/register', { ...body, email: 'bob@example.com', username: 'ALICE' });
    expect(r.status).toBe(409);
  });
});

/** Legacy e-mail link (used by accounts created before the OTP flow and by "resend verification"). */
async function unverifiedUser(ctx: ReturnType<typeof makeCtx>, email = 'alice@example.com') {
  await ctx.repos.users.create({ username: 'alice', email, passwordHash: `fake$${PASSWORD}` });
  const s = await login(ctx, email);
  await s.agent.post('/api/auth/resend-verification').set('Origin', ORIGIN).set('X-CSRF-Token', s.csrf);
  return ctx.mail.tokenFrom(email);
}
describe('email verification (legacy link)', () => {
  it('verifies once, then the link is dead', async () => {
    const ctx = makeCtx();
    const token = await unverifiedUser(ctx);
    expect((await post(ctx, '/api/auth/verify-email', { token })).status).toBe(200);
    expect((await ctx.repos.users.findByEmail('alice@example.com'))?.emailVerified).toBe(true);
    expect((await post(ctx, '/api/auth/verify-email', { token })).status).toBe(400);
    expect((await post(ctx, '/api/auth/verify-email', { token: 'a'.repeat(43) })).status).toBe(400);
  });
  it('rejects an expired link', async () => {
    let t = new Date('2026-01-01T00:00:00Z');
    const ctx = makeCtx({ now: () => t });
    const token = await unverifiedUser(ctx);
    t = new Date('2026-01-03T00:00:00Z');
    expect((await post(ctx, '/api/auth/verify-email', { token })).status).toBe(400);
  });
  it('stores only a hash of the token', async () => {
    const ctx = makeCtx();
    const token = await unverifiedUser(ctx);
    const stored = [...ctx.mem._state.tokens.EMAIL_VERIFICATION.values()];
    expect(stored).toHaveLength(1);
    expect(JSON.stringify(stored)).not.toContain(token);
  });
});

describe('login, session and logout', () => {
  it('gives identical errors for unknown e-mail and wrong password', async () => {
    const ctx = makeCtx();
    await registerVerified(ctx);
    const wrong = await post(ctx, '/api/auth/login', { email: 'alice@example.com', password: 'wrong-password-1' });
    const unknown = await post(ctx, '/api/auth/login', { email: 'ghost@example.com', password: 'wrong-password-1' });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(unknown.body).toEqual(wrong.body);
  });
  it('sets an HttpOnly SameSite=Lax cookie, never exposes the hash, and stores only the session hash', async () => {
    const ctx = makeCtx();
    const email = await registerVerified(ctx);
    const { res, agent } = await login(ctx, email);
    expect(res.status).toBe(200);
    const cookie = String(res.headers['set-cookie']);
    expect(cookie).toMatch(/mh_sid=/);
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/SameSite=Lax/);
    expect(JSON.stringify(res.body)).not.toMatch(/passwordHash|fake\$/);
    const raw = /mh_sid=([^;]+)/.exec(cookie)![1]!;
    expect(JSON.stringify([...ctx.mem._state.sessions.values()])).not.toContain(raw);
    const me = await agent.get('/api/auth/me');
    expect(me.body.user.email).toBe(email);
    expect(me.body.user.role).toBe('USER');
  });
  it('requires the CSRF token to log out, then the session is dead', async () => {
    const ctx = makeCtx();
    const email = await registerVerified(ctx);
    const { agent, csrf } = await login(ctx, email);
    expect((await agent.post('/api/auth/logout').set('Origin', ORIGIN)).status).toBe(403);
    expect((await agent.post('/api/auth/logout').set('Origin', ORIGIN).set('X-CSRF-Token', 'wrong')).status).toBe(403);
    expect((await agent.post('/api/auth/logout').set('Origin', ORIGIN).set('X-CSRF-Token', csrf)).status).toBe(204);
    expect((await agent.get('/api/auth/me')).status).toBe(401);
  });
  it('requires authentication on /me', async () => {
    expect((await request(makeCtx().app).get('/api/auth/me')).status).toBe(401);
  });
  it('blocks suspended accounts, including sessions opened before suspension', async () => {
    const ctx = makeCtx();
    const email = await registerVerified(ctx);
    const { agent } = await login(ctx, email);
    const u = await ctx.repos.users.findByEmail(email);
    await ctx.repos.users.update(u!.id, { status: 'SUSPENDED' });
    expect((await agent.get('/api/auth/me')).status).toBe(401);
    expect((await login(ctx, email)).res.status).toBe(403);
  });
  it('expires sessions after their lifetime', async () => {
    let t = new Date('2026-01-01T00:00:00Z');
    const ctx = makeCtx({ now: () => t });
    const email = await registerVerified(ctx);
    const { agent } = await login(ctx, email);
    expect((await agent.get('/api/auth/me')).status).toBe(200);
    t = new Date('2026-02-01T00:00:00Z');
    expect((await agent.get('/api/auth/me')).status).toBe(401);
  });
  it('rate-limits repeated login attempts', async () => {
    const lim = { windowMs: 60_000, max: 3 };
    const ctx = makeCtx({ limits: { general: { windowMs: 60_000, max: 1000 }, login: lim, register: lim, reset: lim, sensitive: lim, otp: lim, otpResend: lim } });
    const codes: number[] = [];
    for (let i = 0; i < 5; i++) codes.push((await post(ctx, '/api/auth/login', { email: 'a@example.com', password: 'wrong-password-1' })).status);
    expect(codes).toEqual([401, 401, 401, 429, 429]);
  });
});

describe('password reset', () => {
  it('answers generically for unknown and known addresses', async () => {
    const ctx = makeCtx();
    const email = await registerVerified(ctx);
    const known = await post(ctx, '/api/auth/forgot-password', { email });
    const unknown = await post(ctx, '/api/auth/forgot-password', { email: 'ghost@example.com' });
    expect(known.status).toBe(202);
    expect(unknown.status).toBe(202);
    expect(unknown.body).toEqual(known.body);
    expect(ctx.mail.last('ghost@example.com')).toBeUndefined();
  });
  it('resets once, revokes sessions, notifies, and kills the old password', async () => {
    const ctx = makeCtx();
    const email = await registerVerified(ctx);
    const { agent } = await login(ctx, email);
    await post(ctx, '/api/auth/forgot-password', { email });
    const token = ctx.mail.tokenFrom(email);
    const newPw = 'a-brand-new-passphrase';
    expect((await post(ctx, '/api/auth/reset-password', { token, password: newPw })).status).toBe(200);
    expect((await post(ctx, '/api/auth/reset-password', { token, password: 'another-passphrase-1' })).status).toBe(400);
    expect((await agent.get('/api/auth/me')).status).toBe(401);
    expect((await login(ctx, email, PASSWORD)).res.status).toBe(401);
    expect((await login(ctx, email, newPw)).res.status).toBe(200);
    expect(ctx.mail.last(email)?.subject).toMatch(/modifié|Réinitialisation/);
  });
  it('rejects expired reset links and weak new passwords', async () => {
    let t = new Date('2026-01-01T00:00:00Z');
    const ctx = makeCtx({ now: () => t });
    const email = await registerVerified(ctx);
    await post(ctx, '/api/auth/forgot-password', { email });
    const token = ctx.mail.tokenFrom(email);
    expect((await post(ctx, '/api/auth/reset-password', { token, password: 'short' })).status).toBe(400);
    t = new Date('2026-01-01T01:00:00Z');
    expect((await post(ctx, '/api/auth/reset-password', { token, password: 'a-brand-new-passphrase' })).status).toBe(400);
  });
  it('invalidates an earlier reset link when a new one is requested', async () => {
    const ctx = makeCtx();
    const email = await registerVerified(ctx);
    await post(ctx, '/api/auth/forgot-password', { email });
    const first = ctx.mail.tokenFrom(email);
    await post(ctx, '/api/auth/forgot-password', { email });
    expect((await post(ctx, '/api/auth/reset-password', { token: first, password: 'a-brand-new-passphrase' })).status).toBe(400);
  });
});

describe('account deletion', () => {
  it('requires the password, then anonymises the account and removes access', async () => {
    const ctx = makeCtx();
    const email = await registerVerified(ctx);
    const { agent, csrf } = await login(ctx, email);
    const del = (pw: string) => agent.delete('/api/auth/account').set('Origin', ORIGIN).set('X-CSRF-Token', csrf).send({ password: pw });
    expect((await del('wrong-password-1')).status).toBe(403);
    expect((await del(PASSWORD)).status).toBe(204);
    expect((await agent.get('/api/auth/me')).status).toBe(401);
    expect((await login(ctx, email)).res.status).toBe(401);
    expect(await ctx.repos.users.findByEmail(email)).toBeNull();
    expect(JSON.stringify(ctx.mem._state.audit)).not.toContain(email);
  });
});

describe('logs never contain secrets', () => {
  it('keeps passwords and tokens out of the audit log', async () => {
    const ctx = makeCtx();
    const email = await registerVerified(ctx);
    await login(ctx, email);
    await post(ctx, '/api/auth/forgot-password', { email });
    const dump = JSON.stringify(ctx.mem._state.audit);
    expect(dump).not.toContain(PASSWORD);
    expect(dump).not.toContain(ctx.mail.tokenFrom(email));
    expect(dump).not.toContain(env.SESSION_SECRET);
  });
});
