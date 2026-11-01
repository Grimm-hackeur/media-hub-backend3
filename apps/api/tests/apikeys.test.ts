import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { ORIGIN, login, makeAdmin, makeCtx, post, registerVerified } from './helpers.js';

type Sess = Awaited<ReturnType<typeof login>>;
const create = (s: Sess, name = 'Ma clé') => s.agent.post('/api/keys').set('Origin', ORIGIN).set('X-CSRF-Token', s.csrf).send({ name });
const del = (s: Sess, id: string) => s.agent.delete(`/api/keys/${id}`).set('Origin', ORIGIN).set('X-CSRF-Token', s.csrf);
async function setup() {
  const ctx = makeCtx();
  const a = await registerVerified(ctx, 'alice'); const b = await registerVerified(ctx, 'bob'); const boss = await registerVerified(ctx, 'boss');
  await makeAdmin(ctx, boss);
  return { ctx, alice: await login(ctx, a), bob: await login(ctx, b), admin: await login(ctx, boss), aliceEmail: a };
}

describe('API keys', () => {
  it('requires authentication, CSRF and a verified e-mail', async () => {
    const { ctx, alice } = await setup();
    expect((await request(ctx.app).get('/api/keys')).status).toBe(401);
    expect((await alice.agent.post('/api/keys').set('Origin', ORIGIN).send({ name: 'x' })).status).toBe(403);
    await ctx.repos.users.create({ username: 'carol', email: 'carol@example.com', passwordHash: 'fake$correct-horse-battery' });
    const carol = await login(ctx, 'carol@example.com');
    expect(carol.res.status).toBe(200);
    expect((await create(carol)).status).toBe(403);
  });

  it('returns the full key once and stores only a hash', async () => {
    const { ctx, alice } = await setup();
    const res = await create(alice);
    expect(res.status).toBe(201);
    const key: string = res.body.key;
    expect(key).toMatch(/^mh_live_[A-Za-z0-9_-]{43}$/);
    const stored = JSON.stringify([...ctx.mem._state.keys.values()]);
    expect(stored).not.toContain(key.slice(8));
    const list = await alice.agent.get('/api/keys');
    expect(JSON.stringify(list.body)).not.toContain(key.slice(8));
    expect(list.body.items[0].prefix).toBe(key.slice(0, 14));
  });

  it('isolates keys between users and limits active keys', async () => {
    const { alice, bob } = await setup();
    const k = (await create(alice)).body.apiKey;
    expect((await bob.agent.get('/api/keys')).body.items).toHaveLength(0);
    expect((await del(bob, k.id)).status).toBe(404);
    for (let i = 0; i < 4; i++) expect((await create(alice)).status).toBe(201);
    expect((await create(alice)).status).toBe(409);
    expect((await del(alice, k.id)).status).toBe(200);
    expect((await create(alice)).status).toBe(201);
  });

  it('rejects unknown names and extra fields', async () => {
    const { alice } = await setup();
    expect((await create(alice, '')).status).toBe(400);
    expect((await alice.agent.post('/api/keys').set('Origin', ORIGIN).set('X-CSRF-Token', alice.csrf).send({ name: 'x', userId: '1' })).status).toBe(400);
  });

  it('counts real usage, rejects revoked keys and counts rate-limited calls as errors', async () => {
    const { ctx, alice } = await setup();
    const made = (await create(alice)).body; const key = made.key as string;
    expect((await request(ctx.app).get('/api/v1/status')).status).toBe(401);
    expect((await request(ctx.app).get('/api/v1/status').set('X-API-Key', 'mh_live_nope')).status).toBe(401);
    for (let i = 0; i < 3; i++) expect((await request(ctx.app).get('/api/v1/status').set('X-API-Key', key)).status).toBe(200);
    const u = (await alice.agent.get('/api/keys/usage?range=24h')).body;
    expect(u.totals.requests).toBe(3);
    expect(u.keys[0].periodRequests).toBe(3);
    expect(u.series).toHaveLength(24);
    expect(u.series.reduce((s: number, p: { requests: number }) => s + p.requests, 0)).toBe(3);
    expect(u.series.at(-1).requests).toBe(3);
    for (let i = 0; i < 60; i++) await request(ctx.app).get('/api/v1/status').set('X-API-Key', key);
    const u2 = (await alice.agent.get('/api/keys/usage')).body;
    expect(u2.totals.errors).toBeGreaterThan(0);
    await del(alice, made.apiKey.id);
    expect((await request(ctx.app).get('/api/v1/status').set('X-API-Key', key)).status).toBe(401);
  });

  it('stops working when the owner is suspended or deletes the account', async () => {
    const { ctx, alice, bob, admin } = await setup();
    const key = (await create(alice)).body.key as string;
    const aliceId = (await ctx.repos.users.findByEmail('alice@example.com'))!.id;
    const s = await admin.agent.patch(`/api/admin/users/${aliceId}`).set('Origin', ORIGIN).set('X-CSRF-Token', admin.csrf).send({ status: 'SUSPENDED' });
    expect(s.status).toBe(200);
    expect((await request(ctx.app).get('/api/v1/status').set('X-API-Key', key)).status).toBe(401);
    const bobKey = (await create(bob)).body.key as string;
    const d = await bob.agent.delete('/api/auth/account').set('Origin', ORIGIN).set('X-CSRF-Token', bob.csrf).send({ password: 'correct-horse-battery' });
    expect(d.status).toBeLessThan(300);
    expect((await request(ctx.app).get('/api/v1/status').set('X-API-Key', bobKey)).status).toBe(401);
  });

  it('exposes global key stats to administrators only', async () => {
    const { ctx, alice, bob, admin } = await setup();
    const key = (await create(alice)).body.key as string; await create(bob);
    await request(ctx.app).get('/api/v1/status').set('X-API-Key', key);
    expect((await alice.agent.get('/api/admin/api-stats')).status).toBe(403);
    expect((await request(ctx.app).get('/api/admin/api-stats')).status).toBe(401);
    const r = await admin.agent.get('/api/admin/api-stats?range=7d');
    expect(r.status).toBe(200);
    expect(r.body.keys).toMatchObject({ total: 2, active: 2, revoked: 0, owners: 2 });
    expect(r.body.totals.requests).toBe(1);
    expect(r.body.topUsers[0]).toMatchObject({ username: 'alice', requests: 1 });
    expect(r.body.series).toHaveLength(7);
    expect(JSON.stringify(r.body)).not.toContain(key);
  });
});
