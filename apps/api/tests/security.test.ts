import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { makeCtx, ORIGIN, post, signedIn, signedInAdmin } from './helpers.js';

describe('request hardening', () => {
  it('rejects NoSQL operator objects in JSON bodies', async () => {
    const ctx = makeCtx();
    for (const body of [{ email: { $gt: '' }, password: 'x' }, { email: 'a@b.co', password: { $ne: null } }, { $where: '1' }, { email: 'a@b.co', 'a.b': 1 }]) {
      const res = await post(ctx, '/api/auth/login', body);
      expect(res.status).toBe(400);
    }
  });

  it('rejects operator keys in the query string', async () => {
    const ctx = makeCtx();
    const res = await request(ctx.app).get('/api/tools/music/search?q=a&$where=1');
    expect(res.status).toBe(400);
  });

  it('rejects prototype pollution keys', async () => {
    const ctx = makeCtx();
    const res = await request(ctx.app).post('/api/auth/login').set('Origin', ORIGIN).set('Content-Type', 'application/json').send('{"__proto__":{"admin":true},"email":"a@b.co","password":"x"}');
    expect(res.status).toBe(400);
  });

  it('limits the body size', async () => {
    const ctx = makeCtx();
    const res = await post(ctx, '/api/auth/login', { email: 'a@b.co', password: 'x'.repeat(20_000) });
    expect([400, 413]).toContain(res.status);
  });

  it('ignores a client-supplied role on registration and profile updates', async () => {
    const ctx = makeCtx();
    const res = await post(ctx, '/api/auth/register', { username: 'mallory', email: 'm@example.com', password: 'correct-horse-battery', acceptTerms: true, role: 'ADMIN' });
    expect(res.status).toBe(400); // strict schema
    const u = await signedIn(ctx, 'alice');
    expect((await u.call('patch', '/api/me/profile', { role: 'ADMIN' })).status).toBe(400);
    expect((await u.call('patch', '/api/me/profile', { username: 'alice2', role: 'ADMIN' })).status).toBe(400);
    expect((await ctx.repos.users.findById(u.user.id))!.role).toBe('USER');
  });

  it('works under the canonical /api/v1 prefix as well as /api', async () => {
    const ctx = makeCtx();
    const a = await post(ctx, '/api/v1/auth/register', { username: 'bob', email: 'bob@example.com', password: 'correct-horse-battery', acceptTerms: true });
    expect(a.status).toBe(202);
    expect((await request(ctx.app).get('/api/v1/settings/public')).status).toBe(200);
  });
});

describe('CORS and trusted origins', () => {
  const second = 'https://preview.example.com';
  it('allows only FRONTEND_URL and the explicit FRONTEND_ORIGINS list', async () => {
    const ctx = makeCtx({ env: { FRONTEND_ORIGINS: `${second}, https://other.example.com/` } });
    for (const o of [ORIGIN, second, 'https://other.example.com']) {
      const res = await request(ctx.app).get('/api/settings/public').set('Origin', o);
      expect(res.headers['access-control-allow-origin']).toBe(o);
      expect(res.headers['access-control-allow-credentials']).toBe('true');
    }
    const bad = await request(ctx.app).get('/api/settings/public').set('Origin', 'https://evil.example.com');
    expect(bad.headers['access-control-allow-origin']).toBeUndefined();
    const sub = await request(ctx.app).get('/api/settings/public').set('Origin', `${ORIGIN}.evil.com`);
    expect(sub.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('state-changing requests need a trusted Origin', async () => {
    const ctx = makeCtx({ env: { FRONTEND_ORIGINS: second } });
    const body = { email: 'a@b.co', password: 'x' };
    expect((await request(ctx.app).post('/api/auth/login').send(body)).status).toBe(403);
    expect((await request(ctx.app).post('/api/auth/login').set('Origin', 'https://evil.example.com').send(body)).status).toBe(403);
    expect((await request(ctx.app).post('/api/auth/login').set('Origin', second).send(body)).status).toBe(401);
  });
});

describe('error handling', () => {
  it('hides internals on 500 and records the error for administrators', async () => {
    const ctx = makeCtx();
    ctx.repos.settings.getAll = async () => { throw new Error('connect mongodb+srv://user:SECRETPASS@cluster0.mongodb.net failed at /srv/app/secret.js:12'); };
    const res = await request(ctx.app).get('/api/settings/public');
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('INTERNAL_ERROR');
    expect(res.body.error.requestId).toBe(res.headers['x-request-id']);
    const text = JSON.stringify(res.body);
    expect(text).not.toMatch(/SECRETPASS|mongodb|secret\.js|stack/i);
    await new Promise((r) => setTimeout(r, 20));
    ctx.repos.settings.getAll = async () => ({});
    const admin = await signedInAdmin(ctx);
    const list = await admin.call('get', '/api/admin/errors');
    expect(list.status).toBe(200);
    expect(list.body.total).toBeGreaterThan(0);
    const logged = JSON.stringify(list.body);
    expect(logged).not.toContain('SECRETPASS');
    expect(logged).not.toContain('mongodb+srv');
    expect(list.body.items[0]).toMatchObject({ source: 'http', code: 'INTERNAL_ERROR' });
  });

  it('answers unknown routes with a JSON 404', async () => {
    const res = await request(makeCtx().app).get('/api/nope');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });
});
