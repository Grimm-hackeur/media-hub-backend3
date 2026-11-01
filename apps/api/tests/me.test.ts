import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { LIMITS } from '../src/services/me.service.js';
import { makeClock, makeCtx, ORIGIN, PASSWORD, login, signedIn } from './helpers.js';

const track = (n: number, extra: object = {}) => ({ kind: 'TRACK', externalId: `track:${n}`, title: `Titre ${n}`, subtitle: 'Artiste', url: 'https://music.apple.com/x', imageUrl: 'https://is1-ssl.mzstatic.com/i.jpg', ...extra });
const ID = /^[a-f0-9]{24}$/;

describe('authentication required', () => {
  it('every /me route is 401 when anonymous, and 403 without CSRF', async () => {
    const ctx = makeCtx();
    const routes: [string, string][] = [['get', '/history'], ['delete', '/history'], ['get', '/favorites'], ['post', '/favorites'], ['get', '/collections'], ['post', '/collections'], ['get', '/sessions'], ['patch', '/preferences'], ['patch', '/profile']];
    for (const [m, u] of routes) expect((await (request(ctx.app) as any)[m](`/api/v1/me${u}`).set('Origin', ORIGIN).send({})).status, `${m} ${u}`).toBe(401);
    const alice = await signedIn(ctx, 'alice');
    for (const [m, u] of routes.filter(([m]) => m !== 'get')) expect((await (alice.agent as any)[m](`/api/v1/me${u}`).set('Origin', ORIGIN).send({})).status, `csrf ${m} ${u}`).toBe(403);
  });

  it('an unverified-email session cannot reach /me (no session exists before the OTP is validated)', async () => {
    const ctx = makeCtx();
    const reg = await request(ctx.app).post('/api/auth/register').set('Origin', ORIGIN).send({ username: 'carl', email: 'carl@example.com', password: PASSWORD, acceptTerms: true });
    expect(reg.headers['set-cookie']).toBeUndefined();
    expect((await login(ctx, 'carl@example.com')).res.status).toBeGreaterThanOrEqual(400);
  });
});

describe('history', () => {
  it('lists newest first, paginates, filters, deletes one and clears all', async () => {
    const clock = makeClock();
    const ctx = makeCtx({ now: clock.now });
    const u = await signedIn(ctx, 'alice');
    const { user } = u;
    for (let i = 0; i < 5; i++) { clock.seconds(1); await ctx.repos.history.create({ userId: user.id, kind: i % 2 ? 'SEARCH' : 'OPERATION', tool: i % 2 ? 'music' : 'facebook', query: `q${i}`, title: null, status: 'SUCCESS', createdAt: clock.now(), expiresAt: new Date(clock.now().getTime() + 86_400_000) }); }
    const p1 = await u.call('get', '/api/v1/me/history?pageSize=2');
    expect(p1.body.items.map((i: any) => i.query)).toEqual(['q4', 'q3']);
    expect(p1.body).toMatchObject({ page: 1, pageSize: 2, total: 5 });
    const p3 = await u.call('get', '/api/v1/me/history?pageSize=2&page=3');
    expect(p3.body.items.map((i: any) => i.query)).toEqual(['q0']);
    expect((await u.call('get', '/api/v1/me/history?kind=SEARCH')).body.items.length).toBe(2);
    expect((await u.call('get', '/api/v1/me/history?tool=facebook')).body.items.length).toBe(3);
    for (const bad of ['page=0', 'pageSize=51', 'kind=X', 'page=abc']) expect((await u.call('get', `/api/v1/me/history?${bad}`)).status, bad).toBe(400);

    // operator-style query keys are inert: they never become a filter
    const inj = await u.call('get', '/api/v1/me/history?tool[$ne]=zzz&kind[$ne]=SEARCH');
    expect([200, 400]).toContain(inj.status);
    if (inj.status === 200) expect(inj.body.total).toBe(5);
    const id = p1.body.items[0].id;
    expect(id).toMatch(ID);
    expect((await u.call('delete', `/api/v1/me/history/${id}`)).status).toBe(204);
    expect((await u.call('delete', `/api/v1/me/history/${id}`)).status).toBe(404);
    expect((await u.call('delete', '/api/v1/me/history/not-an-id')).status).toBe(400);
    const cleared = await u.call('delete', '/api/v1/me/history');
    expect(cleared.body).toEqual({ deleted: 4 });
    expect((await u.call('get', '/api/v1/me/history')).body.items).toEqual([]);
    const audit = await ctx.repos.audit.list({ page: 1, pageSize: 10, action: 'HISTORY_CLEARED' });
    expect(audit.items.length).toBe(1);
  });

  it('retention: expired entries vanish, and the retention preference drives expiry', async () => {
    const clock = makeClock();
    const ctx = makeCtx({ now: clock.now });
    const u = await signedIn(ctx, 'alice');
    expect((await u.call('patch', '/api/v1/me/preferences', { historyRetentionDays: 2 })).body.historyRetentionDays).toBe(2);
    const fresh = (await ctx.repos.users.findByEmail(u.email))!;
    const { createMeService } = await import('../src/services/me.service.js');
    await createMeService(ctx.repos, clock.now).recordHistory(fresh, { kind: 'SEARCH', tool: 'music', query: 'old', title: null, status: 'SUCCESS' });
    expect((await u.call('get', '/api/v1/me/history')).body.items.length).toBe(1);
    clock.advance(86_400_000);
    expect((await u.call('get', '/api/v1/me/history')).body.items.length).toBe(1);
    clock.advance(86_400_000 + 1000);
    expect((await u.call('get', '/api/v1/me/history')).body.items.length).toBe(0);
  });

  it('is isolated between users', async () => {
    const ctx = makeCtx();
    const a = await signedIn(ctx, 'alice');
    const b = await signedIn(ctx, 'bob');
    const e = await ctx.repos.history.create({ userId: a.user.id, kind: 'SEARCH', tool: 'music', query: 'secret', title: null, status: 'SUCCESS', createdAt: new Date(), expiresAt: new Date(Date.now() + 1e9) });
    expect((await b.call('get', '/api/v1/me/history')).body.items).toEqual([]);
    expect((await b.call('delete', `/api/v1/me/history/${e.id}`)).status).toBe(404);
    expect((await b.call('delete', '/api/v1/me/history')).body.deleted).toBe(0);
    expect((await a.call('get', '/api/v1/me/history')).body.items.length).toBe(1);
  });
});

describe('favourites', () => {
  it('adds, lists, rejects duplicates, deletes', async () => {
    const ctx = makeCtx();
    const u = await signedIn(ctx, 'alice');
    const r = await u.call('post', '/api/v1/me/favorites', track(1));
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ kind: 'TRACK', key: 'track:1', title: 'Titre 1' });
    expect(r.body.id).toMatch(ID);
    expect(r.body.userId).toBeUndefined();
    expect((await u.call('post', '/api/v1/me/favorites', track(1))).status).toBe(409);
    await u.call('post', '/api/v1/me/favorites', { kind: 'LINK', title: 'Vidéo', url: 'https://www.facebook.com/watch?v=1' });
    const all = await u.call('get', '/api/v1/me/favorites');
    expect(all.body.total).toBe(2);
    expect((await u.call('get', '/api/v1/me/favorites?kind=LINK')).body.items.length).toBe(1);
    expect((await u.call('post', '/api/v1/me/favorites', { kind: 'LINK', title: 'dup', url: 'https://www.facebook.com/watch?v=1' })).status).toBe(409);
    expect((await u.call('delete', `/api/v1/me/favorites/${r.body.id}`)).status).toBe(204);
    expect((await u.call('delete', `/api/v1/me/favorites/${r.body.id}`)).status).toBe(404);
    expect((await u.call('get', '/api/v1/me/favorites')).body.total).toBe(1);
  });

  it('validates input strictly (no operators, no private/insecure URLs, no foreign fields)', async () => {
    const ctx = makeCtx();
    const u = await signedIn(ctx, 'alice');
    const bad: object[] = [
      {}, { kind: 'TRACK', title: 'x' }, { kind: 'LINK', title: 'x' }, { kind: 'NOPE', externalId: 'a', title: 'x' },
      track(1, { url: 'http://insecure.example.com' }), track(1, { url: 'https://127.0.0.1/x' }), track(1, { imageUrl: 'https://169.254.169.254/' }), track(1, { url: 'javascript:alert(1)' }),
      track(1, { externalId: { $ne: 'a' } }), track(1, { title: '' }), track(1, { title: 'x'.repeat(201) }), track(1, { externalId: 'bad id!' }),
      track(1, { userId: 'someone' }), track(1, { $where: '1' }),
    ];
    for (const b of bad) expect((await u.call('post', '/api/v1/me/favorites', b)).status, JSON.stringify(b)).toBe(400);
  });

  it('enforces the per-user limit', async () => {
    const ctx = makeCtx();
    const u = await signedIn(ctx, 'alice');
    for (let i = 0; i < LIMITS.favorites; i++) await ctx.repos.favorites.create({ userId: u.user.id, kind: 'TRACK', key: `track:${i}`, title: 't', subtitle: null, url: null, imageUrl: null, createdAt: new Date() } as any);
    const r = await u.call('post', '/api/v1/me/favorites', track(99999));
    expect(r.status).toBe(409);
    expect(r.body.error.code).toBe('LIMIT_REACHED');
  });

  it('is isolated between users (same item allowed, ids not shared)', async () => {
    const ctx = makeCtx();
    const a = await signedIn(ctx, 'alice');
    const b = await signedIn(ctx, 'bob');
    const fa = await a.call('post', '/api/v1/me/favorites', track(1));
    expect((await b.call('post', '/api/v1/me/favorites', track(1))).status).toBe(201);
    expect((await b.call('delete', `/api/v1/me/favorites/${fa.body.id}`)).status).toBe(404);
    expect((await a.call('get', '/api/v1/me/favorites')).body.total).toBe(1);
  });
});

describe('collections', () => {
  it('creates, renames, adds/removes items, deletes', async () => {
    const ctx = makeCtx();
    const u = await signedIn(ctx, 'alice');
    const c = await u.call('post', '/api/v1/me/collections', { name: 'Road trip', description: 'Été' });
    expect(c.status).toBe(201);
    expect(c.body).toMatchObject({ name: 'Road trip', items: [] });
    const id = c.body.id;
    expect((await u.call('patch', `/api/v1/me/collections/${id}`, { name: 'Roadtrip 2' })).body.name).toBe('Roadtrip 2');
    const add = await u.call('post', `/api/v1/me/collections/${id}/items`, track(1));
    expect(add.status).toBe(201);
    expect((await u.call('post', `/api/v1/me/collections/${id}/items`, track(1))).status).toBe(409);
    await u.call('post', `/api/v1/me/collections/${id}/items`, track(2));
    const got = await u.call('get', `/api/v1/me/collections/${id}`);
    expect(got.body.items.length).toBe(2);
    const itemId = got.body.items[0].id;
    expect(itemId).toMatch(ID);
    expect((await u.call('delete', `/api/v1/me/collections/${id}/items/${itemId}`)).status).toBe(204);
    expect((await u.call('delete', `/api/v1/me/collections/${id}/items/${itemId}`)).status).toBe(404);
    expect((await u.call('get', '/api/v1/me/collections')).body.items.length).toBe(1);
    expect((await u.call('delete', `/api/v1/me/collections/${id}`)).status).toBe(204);
    expect((await u.call('get', `/api/v1/me/collections/${id}`)).status).toBe(404);
  });

  it('validates names and patches', async () => {
    const ctx = makeCtx();
    const u = await signedIn(ctx, 'alice');
    for (const b of [{}, { name: '' }, { name: 'x'.repeat(61) }, { name: { $ne: 1 } }, { name: 'ok', owner: 'x' }, { name: 'ok', description: 'x'.repeat(301) }]) expect((await u.call('post', '/api/v1/me/collections', b)).status, JSON.stringify(b)).toBe(400);
    const c = await u.call('post', '/api/v1/me/collections', { name: 'ok' });
    expect((await u.call('patch', `/api/v1/me/collections/${c.body.id}`, {})).status).toBe(400);
  });

  it('enforces collection and item limits', async () => {
    const ctx = makeCtx();
    const u = await signedIn(ctx, 'alice');
    for (let i = 0; i < LIMITS.collections; i++) await ctx.repos.collections.create({ userId: u.user.id, name: `c${i}`, description: null } as any);
    const r = await u.call('post', '/api/v1/me/collections', { name: 'one too many' });
    expect(r.status).toBe(409);
    expect(r.body.error.code).toBe('LIMIT_REACHED');

    const ctx2 = makeCtx();
    const v = await signedIn(ctx2, 'bob');
    const c = await v.call('post', '/api/v1/me/collections', { name: 'big' });
    for (let i = 0; i < LIMITS.itemsPerCollection; i++) {
      expect(await ctx2.repos.collections.addItem(c.body.id, v.user.id, { kind: 'TRACK', key: `track:${i}`, title: 't', subtitle: null, url: null, imageUrl: null }, LIMITS.itemsPerCollection)).toBe('ok');
    }
    const full = await v.call('post', `/api/v1/me/collections/${c.body.id}/items`, track(99999));
    expect(full.status).toBe(409);
    expect(full.body.error.code).toBe('LIMIT_REACHED');
  });

  it('is isolated between users on every operation', async () => {
    const ctx = makeCtx();
    const a = await signedIn(ctx, 'alice');
    const b = await signedIn(ctx, 'bob');
    const c = await a.call('post', '/api/v1/me/collections', { name: 'privée' });
    const id = c.body.id;
    const added = await a.call('post', `/api/v1/me/collections/${id}/items`, track(1));
    const itemId = (await a.call('get', `/api/v1/me/collections/${id}`)).body.items[0].id;
    expect(added.status).toBe(201);
    expect((await b.call('get', '/api/v1/me/collections')).body.items).toEqual([]);
    expect((await b.call('get', `/api/v1/me/collections/${id}`)).status).toBe(404);
    expect((await b.call('patch', `/api/v1/me/collections/${id}`, { name: 'pwned' })).status).toBe(404);
    expect((await b.call('post', `/api/v1/me/collections/${id}/items`, track(2))).status).toBe(404);
    expect((await b.call('delete', `/api/v1/me/collections/${id}/items/${itemId}`)).status).toBe(404);
    expect((await b.call('delete', `/api/v1/me/collections/${id}`)).status).toBe(404);
    const still = await a.call('get', `/api/v1/me/collections/${id}`);
    expect(still.body).toMatchObject({ name: 'privée' });
    expect(still.body.items.length).toBe(1);
  });
});

describe('preferences and profile', () => {
  it('reads, patches and validates preferences', async () => {
    const ctx = makeCtx();
    const u = await signedIn(ctx, 'alice');
    expect((await u.call('get', '/api/v1/me/preferences')).body).toEqual({ language: 'fr', historyEnabled: true, historyRetentionDays: 30 });
    expect((await u.call('patch', '/api/v1/me/preferences', { language: 'en' })).body).toMatchObject({ language: 'en', historyRetentionDays: 30 });
    for (const b of [{}, { language: 'de' }, { historyRetentionDays: 0 }, { historyRetentionDays: 366 }, { historyRetentionDays: 1.5 }, { historyEnabled: 'yes' }, { role: 'ADMIN' }]) expect((await u.call('patch', '/api/v1/me/preferences', b)).status, JSON.stringify(b)).toBe(400);
  });

  it('updates username/avatar but can never change role, e-mail or status', async () => {
    const ctx = makeCtx();
    const a = await signedIn(ctx, 'alice');
    await signedIn(ctx, 'bob');
    const r = await a.call('patch', '/api/v1/me/profile', { username: 'alice2', avatar: 'https://cdn.example.com/a.png' });
    expect(r.status).toBe(200);
    expect(r.body.user).toMatchObject({ username: 'alice2', avatar: 'https://cdn.example.com/a.png' });
    expect(JSON.stringify(r.body)).not.toMatch(/passwordHash|hash"/i);
    for (const b of [{ role: 'ADMIN' }, { email: 'x@y.com' }, { status: 'ACTIVE' }, { username: 'a' }, { username: 'bob' }, { avatar: 'http://insecure.example.com/a.png' }, { avatar: 'https://127.0.0.1/a.png' }, {}]) {
      const x = await a.call('patch', '/api/v1/me/profile', b);
      expect([400, 409], JSON.stringify(b)).toContain(x.status);
    }
    const stored = (await ctx.repos.users.findByEmail(a.email))!;
    expect(stored.role).toBe('USER');
    expect(stored.username).toBe('alice2');
    expect((await a.call('patch', '/api/v1/me/profile', { avatar: null })).body.user.avatar).toBeNull();
  });
});

describe('sessions', () => {
  it('lists devices, flags the current one, revokes others and a chosen one', async () => {
    const ctx = makeCtx();
    const u = await signedIn(ctx, 'alice');
    const s2 = await login(ctx, u.email);
    const s3 = await login(ctx, u.email);
    const list = await u.call('get', '/api/v1/me/sessions');
    expect(list.body.items.length).toBe(4); // OTP verification opened one, signedIn one, two more logins
    expect(list.body.items.filter((i: any) => i.current).length).toBe(1);
    expect(JSON.stringify(list.body)).not.toMatch(/tokenHash|mh_sid/);
    const other = list.body.items.find((i: any) => !i.current);
    expect((await u.call('delete', `/api/v1/me/sessions/${list.body.items.find((i: any) => i.current).id}`)).status).toBe(400);
    expect((await u.call('delete', `/api/v1/me/sessions/${other.id}`)).status).toBe(204);
    expect((await u.call('delete', `/api/v1/me/sessions/${other.id}`)).status).toBe(204); // idempotent
    const rv = await u.call('post', '/api/v1/me/sessions/revoke-others', {});
    expect(rv.body.revoked).toBe(2); // 4 sessions - current - the one already revoked
    expect((await u.call('get', '/api/v1/me/sessions')).body.items.length).toBe(1);
    // revoked sessions are really dead
    expect((await s2.agent.get('/api/v1/auth/me')).status).toBe(401);
    expect((await s3.agent.get('/api/v1/auth/me')).status).toBe(401);
    expect((await u.call('get', '/api/v1/auth/me')).status).toBe(200);
  });

  it("cannot revoke another user's session", async () => {
    const ctx = makeCtx();
    const a = await signedIn(ctx, 'alice');
    const b = await signedIn(ctx, 'bob');
    const bs = (await b.call('get', '/api/v1/me/sessions')).body.items[0];
    expect((await a.call('delete', `/api/v1/me/sessions/${bs.id}`)).status).toBe(404);
    expect((await b.call('get', '/api/v1/auth/me')).status).toBe(200);
  });
});

describe('account deletion erases personal data', () => {
  it('removes history, favourites, collections and sessions, and leaves other users untouched', async () => {
    const ctx = makeCtx();
    const a = await signedIn(ctx, 'alice');
    const b = await signedIn(ctx, 'bob');
    await a.call('post', '/api/v1/me/favorites', track(1));
    await b.call('post', '/api/v1/me/favorites', track(1));
    const c = await a.call('post', '/api/v1/me/collections', { name: 'x' });
    await ctx.repos.history.create({ userId: a.user.id, kind: 'SEARCH', tool: 'music', query: 'q', title: null, status: 'SUCCESS', createdAt: new Date(), expiresAt: new Date(Date.now() + 1e9) });
    expect((await a.call('delete', '/api/v1/auth/account', { password: 'wrong-password-123' })).status).toBeGreaterThanOrEqual(400);
    expect((await a.call('get', '/api/v1/me/favorites')).body.total).toBe(1);
    const del = await a.call('delete', '/api/v1/auth/account', { password: PASSWORD });
    expect(del.status).toBeLessThan(300);
    expect(await ctx.repos.users.findByEmail(a.email)).toBeNull();
    expect(await ctx.repos.favorites.count(a.user.id)).toBe(0);
    expect(await ctx.repos.collections.count(a.user.id)).toBe(0);
    expect((await ctx.repos.history.list({ userId: a.user.id, page: 1, pageSize: 10, now: new Date() })).total).toBe(0);
    expect((await a.agent.get('/api/v1/auth/me')).status).toBe(401);
    expect(c.status).toBe(201);
    expect((await b.call('get', '/api/v1/me/favorites')).body.total).toBe(1);
    expect(await ctx.repos.users.findByEmail(b.email)).not.toBeNull();
  });
});
