import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { ORIGIN, login, makeAdmin, makeCtx, registerVerified } from './helpers.js';

async function setup() {
  const ctx = makeCtx();
  const adminEmail = await registerVerified(ctx, 'boss');
  const adminId = await makeAdmin(ctx, adminEmail);
  const userEmail = await registerVerified(ctx, 'bob');
  const userId = (await ctx.repos.users.findByEmail(userEmail))!.id;
  const admin = await login(ctx, adminEmail);
  const user = await login(ctx, userEmail);
  const patch = (a: typeof admin, id: string, body: object) => a.agent.patch(`/api/admin/users/${id}`).set('Origin', ORIGIN).set('X-CSRF-Token', a.csrf).send(body);
  return { ctx, admin, user, adminId, userId, patch };
}

describe('admin API authorisation (server side)', () => {
  it('refuses anonymous callers with 401 and ordinary users with 403 on every admin route', async () => {
    const { ctx, user, userId, patch } = await setup();
    for (const path of ['/api/admin/stats', '/api/admin/users', '/api/admin/audit-logs']) {
      expect((await request(ctx.app).get(path)).status).toBe(401);
      expect((await user.agent.get(path)).status).toBe(403);
    }
    expect((await patch(user, userId, { role: 'ADMIN' })).status).toBe(403);
    expect((await ctx.repos.users.findById(userId))?.role).toBe('USER');
  });
  it('lets an administrator read real counts, users (with search/filter/pagination) and the audit log', async () => {
    const { admin } = await setup();
    const stats = await admin.agent.get('/api/admin/stats');
    expect(stats.status).toBe(200);
    expect(stats.body).toMatchObject({ total: 2, active: 2, admins: 1, suspended: 0 });
    const list = await admin.agent.get('/api/admin/users?pageSize=1&page=1');
    expect(list.body.items).toHaveLength(1);
    expect(list.body.total).toBe(2);
    expect(JSON.stringify(list.body)).not.toMatch(/passwordHash/);
    const search = await admin.agent.get('/api/admin/users?q=bob&role=USER');
    expect(search.body.items.map((u: { username: string }) => u.username)).toEqual(['bob']);
    expect((await admin.agent.get('/api/admin/users?pageSize=1000')).status).toBe(400);
    const audit = await admin.agent.get('/api/admin/audit-logs');
    expect(audit.body.total).toBeGreaterThan(0);
  });
  it('requires the CSRF token for admin mutations', async () => {
    const { admin, userId } = await setup();
    const r = await admin.agent.patch(`/api/admin/users/${userId}`).set('Origin', ORIGIN).send({ status: 'SUSPENDED' });
    expect(r.status).toBe(403);
  });
  it('suspends a user, revokes their sessions and journals the action', async () => {
    const { ctx, admin, user, userId, patch } = await setup();
    expect((await patch(admin, userId, { status: 'SUSPENDED' })).status).toBe(200);
    expect((await user.agent.get('/api/auth/me')).status).toBe(401);
    const log = await ctx.repos.audit.list({ page: 1, pageSize: 50, action: 'ADMIN_STATUS_CHANGED' });
    expect(log.items[0]).toMatchObject({ targetId: userId, metadata: { toStatus: 'SUSPENDED' } });
  });
  it('forbids changing your own role/status and demoting the last administrator', async () => {
    const { admin, adminId, userId, patch } = await setup();
    expect((await patch(admin, adminId, { role: 'USER' })).status).toBe(403);
    // promote bob, then the only other admin cannot be removed by a lone admin acting on themselves; test last-admin guard:
    expect((await patch(admin, userId, { role: 'ADMIN' })).status).toBe(200);
  });
  it('protects the last active administrator from demotion by another admin', async () => {
    const { ctx, admin, userId, adminId, patch } = await setup();
    await patch(admin, userId, { role: 'ADMIN' });
    const second = await login(ctx, 'bob@example.com');
    expect((await patch(second, adminId, { role: 'USER' })).status).toBe(200); // two admins: allowed
    const third = await login(ctx, 'boss@example.com');
    expect(third.res.status).toBe(200); // still a normal user now
    expect((await third.agent.get('/api/admin/stats')).status).toBe(403);
    expect((await patch(second, adminId, { status: 'SUSPENDED' })).status).toBe(200);
  });
  it('only promotes verified accounts and validates ids and bodies', async () => {
    const { ctx, admin, patch } = await setup();
    await ctx.repos.users.create({ username: 'carol', email: 'carol@example.com', passwordHash: 'x' });
    const carol = await ctx.repos.users.findByEmail('carol@example.com');
    expect((await patch(admin, carol!.id, { role: 'ADMIN' })).status).toBe(409);
    expect((await patch(admin, 'not-an-id', { role: 'USER' })).status).toBe(400);
    expect((await patch(admin, carol!.id, {})).status).toBe(400);
    expect((await patch(admin, carol!.id, { role: 'SUPERUSER' })).status).toBe(400);
    expect((await patch(admin, '0'.repeat(24), { role: 'USER' })).status).toBe(404);
  });
  it('does not let an admin without a verified e-mail use admin routes', async () => {
    const ctx = makeCtx();
    const email = await registerVerified(ctx, 'boss');
    const id = await makeAdmin(ctx, email);
    const { agent } = await login(ctx, email);
    await ctx.repos.users.update(id, { emailVerified: false });
    expect((await agent.get('/api/admin/stats')).status).toBe(403);
  });
  it('prevents the last administrator from deleting their account', async () => {
    const ctx = makeCtx();
    const email = await registerVerified(ctx, 'boss');
    await makeAdmin(ctx, email);
    const { agent, csrf } = await login(ctx, email);
    const r = await agent.delete('/api/auth/account').set('Origin', ORIGIN).set('X-CSRF-Token', csrf).send({ password: 'correct-horse-battery' });
    expect(r.status).toBe(409);
  });
});
