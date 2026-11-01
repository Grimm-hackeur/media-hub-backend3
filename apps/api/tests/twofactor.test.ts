import { describe, expect, it } from 'vitest';
import { ORIGIN, PASSWORD, login, makeAdmin, makeCtx, post, registerVerified } from './helpers.js';
import { base32Decode, decryptSecret, hotp, stepOf, verifyTotp } from '../src/utils/totp.js';
import { env } from './helpers.js';

const codeAt = (secret: string, t: Date) => hotp(secret, stepOf(t));
type A = Awaited<ReturnType<typeof login>>;
const authed = (a: A, url: string, body: object) => a.agent.post(url).set('Origin', ORIGIN).set('X-CSRF-Token', a.csrf).send(body);

async function setup(ctx = makeCtx()) {
  const email = await registerVerified(ctx, 'root', 'root@example.com');
  await makeAdmin(ctx, email);
  const a = await login(ctx, email);
  const s = await authed(a, '/api/auth/2fa/setup', {});
  return { ctx, email, a, secret: s.body.secret as string, setupBody: s.body };
}

describe('TOTP primitives (RFC 6238 vectors)', () => {
  it('matches the RFC 6238 SHA-1 test vectors (8 digits)', () => {
    const secret = Buffer.from('12345678901234567890').toString('hex');
    expect(base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ').toString('hex')).toBe(secret);
    const s = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    expect(hotp(s, Math.floor(59 / 30), 8)).toBe('94287082');
    expect(hotp(s, Math.floor(1111111109 / 30), 8)).toBe('07081804');
    expect(hotp(s, Math.floor(20000000000 / 30), 8)).toBe('65353130');
  });
  it('accepts ±1 step of drift and nothing further', () => {
    const s = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; const t = new Date(1_700_000_000_000);
    expect(verifyTotp(s, hotp(s, stepOf(t) - 1), t)).toBe(stepOf(t) - 1);
    expect(verifyTotp(s, hotp(s, stepOf(t) + 2), t)).toBeNull();
    expect(verifyTotp(s, 'abcdef', t)).toBeNull();
  });
});

describe('two-factor authentication', () => {
  it('setup returns secret + otpauth URI, stores the secret encrypted', async () => {
    const { ctx, email, secret, setupBody } = await setup();
    expect(setupBody.otpauthUri).toContain(`secret=${secret}`);
    const u = await ctx.repos.users.findByEmail(email);
    expect(u!.totp!.enabled).toBe(false);
    expect(JSON.stringify(u!.totp)).not.toContain(secret);
    expect(decryptSecret(u!.totp!.secretEnc, env.SESSION_SECRET)).toBe(secret);
  });

  it('enable rejects a wrong code, accepts a right one and returns 8 recovery codes once (hashed at rest)', async () => {
    const { ctx, email, a, secret } = await setup();
    expect((await authed(a, '/api/auth/2fa/enable', { code: '000000' })).status).toBe(400);
    const r = await authed(a, '/api/auth/2fa/enable', { code: codeAt(secret, new Date()) });
    expect(r.status).toBe(200);
    expect(r.body.recoveryCodes).toHaveLength(8);
    const u = await ctx.repos.users.findByEmail(email);
    expect(u!.totp!.enabled).toBe(true);
    for (const c of r.body.recoveryCodes) expect(JSON.stringify(u!.totp)).not.toContain(c);
    const me = await a.agent.get('/api/auth/me');
    expect(me.body.user.twoFactorEnabled).toBe(true);
  });

  async function enabled(ctx = makeCtx(), now?: Date) {
    const s = await setup(ctx);
    const r = await authed(s.a, '/api/auth/2fa/enable', { code: codeAt(s.secret, now ?? new Date()) });
    return { ...s, recovery: r.body.recoveryCodes as string[] };
  }

  it('login becomes two-step: password alone gives no session', async () => {
    const { ctx, email } = await enabled();
    const res = await post(ctx, '/api/auth/login', { email, password: PASSWORD });
    expect(res.body.twoFactorRequired).toBe(true);
    expect(res.headers['set-cookie']).toBeUndefined();
    expect(res.body.user).toBeUndefined();
  });

  it('second step with a valid code opens a session; a replayed code is refused', async () => {
    let t = new Date();
    const ctx = makeCtx({ now: () => t });
    const { email, secret } = await enabled(ctx, t);
    t = new Date(t.getTime() + 90_000); // move on so the enrolment step is no longer "last used"
    const ch = (await post(ctx, '/api/auth/login', { email, password: PASSWORD })).body.challenge;
    const code = codeAt(secret, t);
    const ok = await post(ctx, '/api/auth/login/2fa', { challenge: ch, code });
    expect(ok.status).toBe(200);
    expect(ok.headers['set-cookie']?.[0]).toMatch(/mh_sid/);
    const ch2 = (await post(ctx, '/api/auth/login', { email, password: PASSWORD })).body.challenge;
    expect((await post(ctx, '/api/auth/login/2fa', { challenge: ch2, code })).status).toBe(401);
  });

  it('rejects forged, tampered and expired challenges', async () => {
    let t = new Date();
    const ctx = makeCtx({ now: () => t });
    const { email, secret } = await enabled(ctx, t);
    t = new Date(t.getTime() + 90_000);
    const ch = (await post(ctx, '/api/auth/login', { email, password: PASSWORD })).body.challenge as string;
    const code = codeAt(secret, t);
    expect((await post(ctx, '/api/auth/login/2fa', { challenge: ch.slice(0, -2) + 'xx', code })).status).toBe(401);
    expect((await post(ctx, '/api/auth/login/2fa', { challenge: 'someone.9999999999999.forgedsignature', code })).status).toBe(401);
    t = new Date(t.getTime() + 6 * 60_000);
    expect((await post(ctx, '/api/auth/login/2fa', { challenge: ch, code: codeAt(secret, t) })).status).toBe(401);
  });

  it('a recovery code works exactly once', async () => {
    const { ctx, email, recovery } = await enabled();
    const c1 = (await post(ctx, '/api/auth/login', { email, password: PASSWORD })).body.challenge;
    expect((await post(ctx, '/api/auth/login/2fa', { challenge: c1, code: recovery[0] })).status).toBe(200);
    const c2 = (await post(ctx, '/api/auth/login', { email, password: PASSWORD })).body.challenge;
    expect((await post(ctx, '/api/auth/login/2fa', { challenge: c2, code: recovery[0] })).status).toBe(401);
    expect((await post(ctx, '/api/auth/login/2fa', { challenge: c2, code: recovery[1] })).status).toBe(200);
  });

  it('locks after 5 wrong codes, even for a later correct code', async () => {
    let t = new Date();
    const ctx = makeCtx({ now: () => t });
    const { email, secret } = await enabled(ctx, t);
    t = new Date(t.getTime() + 90_000);
    const ch = (await post(ctx, '/api/auth/login', { email, password: PASSWORD })).body.challenge;
    for (let i = 0; i < 5; i++) expect((await post(ctx, '/api/auth/login/2fa', { challenge: ch, code: '111111' })).status).toBe(401);
    const locked = await post(ctx, '/api/auth/login/2fa', { challenge: ch, code: codeAt(secret, t) });
    expect(locked.status).toBe(429);
    expect(locked.body.error.code).toBe('TWO_FACTOR_LOCKED');
    t = new Date(t.getTime() + 16 * 60_000);
    const ch2 = (await post(ctx, '/api/auth/login', { email, password: PASSWORD })).body.challenge;
    expect((await post(ctx, '/api/auth/login/2fa', { challenge: ch2, code: codeAt(secret, t) })).status).toBe(200);
  });

  it('disable needs password AND a code', async () => {
    let t = new Date();
    const ctx = makeCtx({ now: () => t });
    const { a, secret } = await enabled(ctx, t);
    t = new Date(t.getTime() + 90_000);
    const code = codeAt(secret, t);
    expect((await authed(a, '/api/auth/2fa/disable', { password: 'wrong-password-123', code })).status).toBe(403);
    expect((await authed(a, '/api/auth/2fa/disable', { password: PASSWORD, code })).status).toBe(204);
    expect((await a.agent.get('/api/auth/me')).body.user.twoFactorEnabled).toBe(false);
  });

  it('setup requires an authenticated session and the CSRF token', async () => {
    const ctx = makeCtx();
    expect((await post(ctx, '/api/auth/2fa/setup', {})).status).toBe(401);
    const { a } = await setup(ctx);
    const noCsrf = await a.agent.post('/api/auth/2fa/setup').set('Origin', ORIGIN).send({});
    expect(noCsrf.status).toBe(403);
  });

  it('REQUIRE_ADMIN_2FA blocks /api/admin until 2FA is on', async () => {
    const ctx = makeCtx({ env: { REQUIRE_ADMIN_2FA: true } });
    const email = await registerVerified(ctx, 'root', 'root@example.com');
    await makeAdmin(ctx, email);
    const a = await login(ctx, email);
    const blocked = await a.agent.get('/api/admin/stats');
    expect(blocked.status).toBe(403);
    expect(blocked.body.error.code).toBe('TWO_FACTOR_REQUIRED');
    const s = await authed(a, '/api/auth/2fa/setup', {});
    await authed(a, '/api/auth/2fa/enable', { code: codeAt(s.body.secret, new Date()) });
    expect((await a.agent.get('/api/admin/stats')).status).toBe(200);
  });
});
