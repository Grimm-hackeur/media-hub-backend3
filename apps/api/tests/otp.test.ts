import request from 'supertest';
import { describe, expect, it } from 'vitest';
import type { Limits } from '../src/middleware/rateLimit.js';
import { ORIGIN, PASSWORD, makeCtx, post } from './helpers.js';

const reg = { username: 'alice', email: 'alice@example.com', password: PASSWORD, acceptTerms: true };
const verify = (ctx: ReturnType<typeof makeCtx>, code: string, email = reg.email) => post(ctx, '/api/auth/verify-otp', { email, code });
const wrong = (code: string) => (code === '0000' ? '1111' : '0000');
const minutes = (base: Date, m: number) => new Date(base.getTime() + m * 60_000);

describe('OTP registration', () => {
  it('creates the account, verifies the e-mail and opens a session only after a valid code', async () => {
    const ctx = makeCtx();
    await post(ctx, '/api/auth/register', reg);
    const code = ctx.mail.otpFrom(reg.email);
    const agent = request.agent(ctx.app);
    const res = await agent.post('/api/auth/verify-otp').set('Origin', ORIGIN).send({ email: reg.email, code });
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ email: reg.email, emailVerified: true, role: 'USER' });
    expect(res.body.user.passwordHash).toBeUndefined();
    expect(String(res.headers['set-cookie'])).toMatch(/HttpOnly/i);
    expect((await agent.get('/api/auth/me')).status).toBe(200);
    expect(await ctx.repos.pending.findByEmail(reg.email)).toBeNull();
    expect((await verify(ctx, code)).status).toBe(400); // used code is dead
  });

  it('stores only a keyed hash of the code, never the code, and keeps it out of the audit log', async () => {
    const ctx = makeCtx();
    await post(ctx, '/api/auth/register', reg);
    const code = ctx.mail.otpFrom(reg.email);
    const p = await ctx.repos.pending.findByEmail(reg.email);
    expect(JSON.stringify(p)).not.toContain(`"${code}"`);
    expect(p!.codeHash).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(ctx.mem._state.audit)).not.toContain(code);
    expect(p!.passwordHash).not.toBe(PASSWORD);
  });

  it('counts wrong attempts, reports what is left, then locks even for the right code', async () => {
    const ctx = makeCtx();
    await post(ctx, '/api/auth/register', reg);
    const code = ctx.mail.otpFrom(reg.email);
    const left: unknown[] = [];
    for (let i = 0; i < 4; i++) { const r = await verify(ctx, wrong(code)); expect(r.status).toBe(400); left.push(r.body.error.meta.attemptsLeft); }
    expect(left).toEqual([4, 3, 2, 1]);
    const fifth = await verify(ctx, wrong(code));
    expect(fifth.status).toBe(429);
    expect(fifth.body.error.code).toBe('OTP_LOCKED');
    expect((await verify(ctx, code)).status).toBe(429);
    expect(await ctx.repos.users.findByEmail(reg.email)).toBeNull();
  });

  it('expires the code after 10 minutes', async () => {
    const t0 = new Date('2026-03-01T10:00:00Z');
    let t = t0;
    const ctx = makeCtx({ now: () => t });
    await post(ctx, '/api/auth/register', reg);
    const code = ctx.mail.otpFrom(reg.email);
    t = minutes(t0, 10.5);
    const r = await verify(ctx, code);
    expect(r.status).toBe(400);
    expect(r.body.error.code).toBe('OTP_EXPIRED');
    expect(await ctx.repos.users.findByEmail(reg.email)).toBeNull();
  });

  it('accepts a code just before expiry', async () => {
    const t0 = new Date('2026-03-01T10:00:00Z');
    let t = t0;
    const ctx = makeCtx({ now: () => t });
    await post(ctx, '/api/auth/register', reg);
    const code = ctx.mail.otpFrom(reg.email);
    t = minutes(t0, 9.9);
    expect((await verify(ctx, code)).status).toBe(200);
  });

  it('purges abandoned pending registrations after their lifetime', async () => {
    const t0 = new Date('2026-03-01T10:00:00Z');
    let t = t0;
    const ctx = makeCtx({ now: () => t });
    await post(ctx, '/api/auth/register', reg);
    const code = ctx.mail.otpFrom(reg.email);
    t = minutes(t0, 61);
    const r = await verify(ctx, code);
    expect(r.status).toBe(400);
    expect(r.body.error.code).toBe('OTP_INVALID');
  });

  it('enforces the 60 s resend cooldown, invalidates the old code and resets the attempts', async () => {
    const t0 = new Date('2026-03-01T10:00:00Z');
    let t = t0;
    const ctx = makeCtx({ now: () => t });
    await post(ctx, '/api/auth/register', reg);
    const first = ctx.mail.otpFrom(reg.email);
    await verify(ctx, wrong(first));
    t = new Date(t0.getTime() + 20_000);
    const early = await post(ctx, '/api/auth/resend-otp', { email: reg.email });
    expect(early.status).toBe(429);
    expect(early.body.error.meta.retryAfter).toBe(40);
    expect(ctx.mail.sent).toHaveLength(1);
    t = new Date(t0.getTime() + 61_000);
    const ok = await post(ctx, '/api/auth/resend-otp', { email: reg.email });
    expect(ok.status).toBe(200);
    expect(ok.body.retryAfter).toBe(60);
    expect(ctx.mail.sent).toHaveLength(2);
    const second = ctx.mail.otpFrom(reg.email);
    if (second !== first) expect((await verify(ctx, first)).body.error.meta.attemptsLeft).toBe(4); // old code refused, attempts were reset
    expect((await verify(ctx, second)).status).toBe(200);
  });

  it('caps the number of codes per registration', async () => {
    let t = new Date('2026-03-01T10:00:00Z');
    const ctx = makeCtx({ now: () => t });
    await post(ctx, '/api/auth/register', reg);
    let last = 0;
    for (let i = 0; i < 6; i++) { t = new Date(t.getTime() + 61_000); last = (await post(ctx, '/api/auth/resend-otp', { email: reg.email })).status; }
    expect(last).toBe(429);
    expect(ctx.mail.sent.length).toBe(5);
  });

  it('answers identically for unknown addresses (no hint about pending registrations)', async () => {
    const ctx = makeCtx();
    await post(ctx, '/api/auth/register', reg);
    const code = ctx.mail.otpFrom(reg.email);
    const unknown = await verify(ctx, wrong(code), 'ghost@example.com');
    const known = await verify(ctx, wrong(code));
    expect(unknown.status).toBe(known.status);
    expect(unknown.body.error.code).toBe(known.body.error.code);
    const r = await post(ctx, '/api/auth/resend-otp', { email: 'ghost@example.com' });
    expect(r.status).toBe(200);
    expect(ctx.mail.sent.filter((m) => m.to === 'ghost@example.com')).toHaveLength(0);
  });

  it('validates the payload strictly', async () => {
    const ctx = makeCtx();
    for (const code of ['123', '12345', 'abcd', '']) expect((await verify(ctx, code)).status).toBe(400);
    expect((await post(ctx, '/api/auth/verify-otp', { email: reg.email, code: '1234', extra: 1 })).status).toBe(400);
    expect((await request(ctx.app).post('/api/auth/verify-otp').send({ email: reg.email, code: '1234' })).status).toBe(403); // no Origin
  });

  it('lets exactly one of two concurrent verifications win', async () => {
    const ctx = makeCtx();
    await post(ctx, '/api/auth/register', reg);
    const code = ctx.mail.otpFrom(reg.email);
    const [a, b] = await Promise.all([verify(ctx, code), verify(ctx, code)]);
    expect([a.status, b.status].sort()).toEqual([200, 400]);
    expect((await ctx.repos.users.list({ page: 1, pageSize: 10 })).total).toBe(1);
  });

  it('does not let a pending registration sign in', async () => {
    const ctx = makeCtx();
    await post(ctx, '/api/auth/register', reg);
    expect((await post(ctx, '/api/auth/login', { email: reg.email, password: PASSWORD })).status).toBe(401);
  });

  it('rate-limits registrations per e-mail address', async () => {
    const lim = { windowMs: 60_000, max: 2 };
    const big = { windowMs: 60_000, max: 1000 };
    const limits: Limits = { general: big, login: big, register: lim, reset: big, sensitive: big, otp: big, otpResend: big };
    const ctx = makeCtx({ limits });
    const codes: number[] = [];
    for (let i = 0; i < 4; i++) codes.push((await post(ctx, '/api/auth/register', { ...reg, username: `user${i}` })).status);
    expect(codes).toEqual([202, 202, 429, 429]);
  });

  it('rate-limits code guessing per address and per IP', async () => {
    const lim = { windowMs: 60_000, max: 3 };
    const big = { windowMs: 60_000, max: 1000 };
    const limits: Limits = { general: big, login: big, register: big, reset: big, sensitive: big, otp: lim, otpResend: big };
    const ctx = makeCtx({ limits });
    await post(ctx, '/api/auth/register', reg);
    const c = ctx.mail.otpFrom(reg.email);
    const out: number[] = [];
    for (let i = 0; i < 5; i++) out.push((await verify(ctx, wrong(c))).status);
    expect(out.slice(3)).toEqual([429, 429]);
  });
});
