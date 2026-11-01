import request from 'supertest';
import { createApp, type AppDeps } from '../src/app.js';
import { loadEnv, type Env } from '../src/config/env.js';
import { createMemoryRepos } from '../src/repositories/memory.js';
import type { Limits } from '../src/middleware/rateLimit.js';
import type { EmailProvider, OutgoingEmail } from '../src/services/email.js';
import type { PasswordHasher } from '../src/services/password.js';

export const ORIGIN = 'https://app.example.com';
export const PASSWORD = 'correct-horse-battery';
export const env: Env = loadEnv({
  NODE_ENV: 'test', MONGODB_URI: 'mongodb://unused', SESSION_SECRET: 'x'.repeat(40),
  FRONTEND_URL: ORIGIN, REQUIRE_ADMIN_2FA: 'false', TOOLS_REQUIRE_LOGIN: 'false', TRUST_PROXY: '0', LOG_LEVEL: 'silent',
});
/** Fast stand-in for Argon2id in route tests (real Argon2id has its own test). */
export const fakeHasher: PasswordHasher = {
  hash: async (p) => `fake$${p}`,
  verify: async (h, p) => h === `fake$${p}`,
};
export class MailBox implements EmailProvider {
  readonly configured = true;
  sent: OutgoingEmail[] = [];
  async send(m: OutgoingEmail) { this.sent.push(m); }
  last(to: string) { return [...this.sent].reverse().find((m) => m.to === to); }
  otpFrom(to: string): string {
    const m = this.last(to)?.text.match(/code[^:]*:\s*(\d{4})/i);
    if (!m) throw new Error('no otp in last mail');
    return m[1]!;
  }
  tokenFrom(to: string): string {
    const m = this.last(to)?.text.match(/token=([A-Za-z0-9_-]+)/);
    if (!m) throw new Error('no token in last mail');
    return m[1]!;
  }
}
const big = { windowMs: 60_000, max: 1000 };
const open: Limits = { general: big, login: big, register: big, reset: big, sensitive: big, otp: big, otpResend: big };

export function makeCtx(opts: { limits?: Limits; now?: () => Date; hasher?: PasswordHasher; env?: Partial<Env>; deps?: Partial<AppDeps> } = {}) {
  const mem = createMemoryRepos();
  const mail = new MailBox();
  const app = createApp({ env: { ...env, ...opts.env }, repos: mem.repos, hasher: opts.hasher ?? fakeHasher, email: mail, limits: opts.limits ?? open, now: opts.now, ...opts.deps });
  return { app, mem, mail, repos: mem.repos };
}
export type Ctx = ReturnType<typeof makeCtx>;

export const post = (ctx: Ctx, url: string, body?: object) => request(ctx.app).post(url).set('Origin', ORIGIN).send(body);

export async function registerVerified(ctx: Ctx, name = 'alice', email = `${name}@example.com`) {
  await post(ctx, '/api/auth/register', { username: name, email, password: PASSWORD, acceptTerms: true });
  await post(ctx, '/api/auth/verify-otp', { email, code: ctx.mail.otpFrom(email) });
  return email;
}
/** Logs in and returns a supertest agent that carries the session cookie, plus the CSRF token. */
export async function login(ctx: Ctx, email: string, password = PASSWORD) {
  const agent = request.agent(ctx.app);
  const res = await agent.post('/api/auth/login').set('Origin', ORIGIN).send({ email, password });
  return { agent, res, csrf: res.body.csrfToken as string };
}
export async function makeAdmin(ctx: Ctx, email: string) {
  const u = await ctx.repos.users.findByEmail(email);
  await ctx.repos.users.update(u!.id, { role: 'ADMIN' });
  return u!.id;
}

/** Controllable clock for expiry/cooldown tests. */
export function makeClock(start = new Date('2026-10-17T12:00:00Z')) {
  let t = start.getTime();
  return { now: () => new Date(t), advance: (ms: number) => { t += ms; }, seconds: (s: number) => { t += s * 1000; } };
}
/** Registers a verified user and returns an authenticated agent + csrf. */
export async function signedIn(ctx: Ctx, name: string) {
  const email = await registerVerified(ctx, name);
  const s = await login(ctx, email);
  const user = (await ctx.repos.users.findByEmail(email))!;
  const call = (method: 'get' | 'post' | 'patch' | 'delete', url: string, body?: object) => {
    const r = s.agent[method](url).set('Origin', ORIGIN);
    if (method !== 'get') r.set('X-CSRF-Token', s.csrf);
    return body ? r.send(body) : r;
  };
  return { email, user, agent: s.agent, csrf: s.csrf, call };
}
export async function signedInAdmin(ctx: Ctx, name = 'boss') {
  const u = await signedIn(ctx, name);
  await makeAdmin(ctx, u.email);
  return u;
}
