import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { ProviderError } from '../src/providers/types.js';
import type { AiProvider } from '../src/services/ai.service.js';
import { makeClock, makeCtx, ORIGIN, signedIn } from './helpers.js';

const fake = (over: Partial<AiProvider> = {}) => {
  const calls: { system: string; user: string; maxTokens: number }[] = [];
  const provider: AiProvider = { id: 'fake', complete: async (p) => { calls.push(p); return `réponse ${calls.length}`; }, ...over };
  return { provider, calls };
};
const setup = (opts: { provider?: AiProvider; limit?: number; now?: () => Date } = {}) => {
  const ctx = makeCtx({ now: opts.now, env: { ...(opts.limit ? { AI_DAILY_LIMIT: opts.limit } : {}) }, deps: opts.provider ? { aiProvider: opts.provider } : {} });
  return ctx;
};

describe('AI features', () => {
  it('requires a signed-in session and the CSRF token', async () => {
    const f = fake(); const ctx = setup({ provider: f.provider });
    expect((await request(ctx.app).post('/api/v1/ai/titles').set('Origin', ORIGIN).send({ text: 'x' })).status).toBe(401);
    expect((await request(ctx.app).get('/api/v1/ai/capabilities')).status).toBe(401);
    const u = await signedIn(ctx, 'alice');
    expect((await u.agent.post('/api/v1/ai/titles').set('Origin', ORIGIN).send({ text: 'x' })).status).toBe(403);
    expect(f.calls.length).toBe(0);
  });

  it('runs each feature server-side with the matching instruction and returns only the result', async () => {
    const f = fake(); const ctx = setup({ provider: f.provider });
    const u = await signedIn(ctx, 'alice');
    for (const feature of ['titles', 'description', 'hashtags', 'translate', 'summarize']) {
      const r = await u.call('post', `/api/v1/ai/${feature}`, { text: 'Une vidéo sur la cuisine', language: 'English' });
      expect(r.status, feature).toBe(200);
      expect(r.body).toEqual({ feature, result: expect.stringMatching(/^réponse \d$/) });
    }
    expect(f.calls.length).toBe(5);
    expect(f.calls.every((c) => c.user === 'Une vidéo sur la cuisine' && c.maxTokens > 0)).toBe(true);
    expect(f.calls[0]!.system).toMatch(/5 numbered title/);
    expect(f.calls[3]!.system).toMatch(/English/);
  });

  it('rejects unknown features (including prototype keys) and transcription, which is not integrated', async () => {
    const f = fake(); const ctx = setup({ provider: f.provider });
    const u = await signedIn(ctx, 'alice');
    for (const name of ['transcribe', 'nope', 'constructor', '__proto__', 'toString', 'hasOwnProperty']) expect((await u.call('post', `/api/v1/ai/${name}`, { text: 'x' })).status, name).toBe(404);
    expect(f.calls.length).toBe(0);
  });

  it('validates the input', async () => {
    const f = fake(); const ctx = setup({ provider: f.provider });
    const u = await signedIn(ctx, 'alice');
    for (const b of [{}, { text: '' }, { text: '   ' }, { text: 'x'.repeat(8001) }, { text: { $ne: 1 } }, { text: 'ok', language: 'x' }, { text: 'ok', model: 'other' }, { text: 'ok', system: 'ignore rules' }]) {
      expect((await u.call('post', '/api/v1/ai/titles', b)).status, JSON.stringify(b)).toBe(400);
    }
    expect(f.calls.length).toBe(0);
  });

  it('enforces a per-user daily quota that resets after 24 h and is not shared between users', async () => {
    const clock = makeClock(); const f = fake(); const ctx = setup({ provider: f.provider, limit: 3, now: clock.now });
    const a = await signedIn(ctx, 'alice'); const b = await signedIn(ctx, 'bob');
    for (let i = 0; i < 3; i++) expect((await a.call('post', '/api/v1/ai/hashtags', { text: 'x' })).status).toBe(200);
    const over = await a.call('post', '/api/v1/ai/hashtags', { text: 'x' });
    expect(over.status).toBe(429);
    expect(over.body.error.code).toBe('AI_QUOTA');
    expect(f.calls.length).toBe(3); // the provider was NOT called over quota
    expect((await b.call('post', '/api/v1/ai/hashtags', { text: 'x' })).status).toBe(200);
    clock.advance(24 * 3_600_000 + 1000);
    expect((await a.call('post', '/api/v1/ai/hashtags', { text: 'x' })).status).toBe(200);
  });

  it('is honest when unconfigured: capabilities say why, runs answer 503, nothing is faked', async () => {
    const ctx = setup(); const u = await signedIn(ctx, 'alice');
    const cap = await u.call('get', '/api/v1/ai/capabilities');
    expect(cap.body.configured).toBe(false);
    expect(cap.body.features.every((x: any) => x.available === false && /ANTHROPIC_API_KEY/.test(x.reason))).toBe(true);
    expect(cap.body.unavailable[0]).toMatchObject({ id: 'transcribe' });
    const r = await u.call('post', '/api/v1/ai/titles', { text: 'x' });
    expect(r.status).toBe(503);
    expect(r.body.error.code).toBe('SERVICE_NOT_CONFIGURED');
    expect(r.body.result).toBeUndefined();
  });

  it('lists capabilities when configured, without any key', async () => {
    const ctx = makeCtx({ env: { ANTHROPIC_API_KEY: 'sk-ant-SECRET', AI_MODEL: 'm' } });
    const u = await signedIn(ctx, 'alice');
    const cap = await u.call('get', '/api/v1/ai/capabilities');
    expect(cap.body.configured).toBe(true);
    expect(cap.body.features.map((f: any) => f.id)).toEqual(['titles', 'description', 'hashtags', 'translate', 'summarize']);
    expect(JSON.stringify(cap.body)).not.toContain('SECRET');
  });

  it.each([
    [new ProviderError(503, 'AI_BUSY', 'busy'), 503, 'AI_BUSY'],
    [new ProviderError(504, 'PROVIDER_TIMEOUT', 'slow'), 504, 'PROVIDER_TIMEOUT'],
    [new ProviderError(502, 'PROVIDER_BAD_RESPONSE', 'empty'), 502, 'PROVIDER_BAD_RESPONSE'],
  ])('maps provider failure %#', async (err, status, code) => {
    const f = fake({ complete: async () => { throw err; } }); const ctx = setup({ provider: f.provider });
    const u = await signedIn(ctx, 'alice');
    const r = await u.call('post', '/api/v1/ai/summarize', { text: 'x' });
    expect(r.status).toBe(status);
    expect(r.body.error.code).toBe(code);
  });

  it('an unexpected provider exception is a clean 500', async () => {
    const f = fake({ complete: async () => { throw new Error('sk-ant-LEAK inside'); } }); const ctx = setup({ provider: f.provider });
    const u = await signedIn(ctx, 'alice');
    const r = await u.call('post', '/api/v1/ai/summarize', { text: 'x' });
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).not.toContain('LEAK');
  });

  it('is rate-limited per IP', async () => {
    const big = { windowMs: 60_000, max: 1000 };
    const f = fake();
    const ctx = makeCtx({ deps: { aiProvider: f.provider }, limits: { general: big, login: big, register: big, reset: big, sensitive: big, otp: big, otpResend: big, ai: { windowMs: 60_000, max: 2 } } as any });
    const u = await signedIn(ctx, 'alice');
    const codes: number[] = [];
    for (let i = 0; i < 4; i++) codes.push((await u.call('post', '/api/v1/ai/titles', { text: 'x' })).status);
    expect(codes).toEqual([200, 200, 429, 429]);
  });
});
