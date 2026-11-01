import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { ProviderError, type MediaProvider } from '../src/providers/types.js';
import { makeCtx, ORIGIN, PASSWORD, post, signedIn, signedInAdmin } from './helpers.js';

const REPORT = { kind: 'COPYRIGHT', targetUrl: 'https://www.facebook.com/watch?v=1', description: 'Cette vidéo viole mes droits.', contactEmail: 'owner@example.com' };

describe('reports (public form)', () => {
  it('accepts an anonymous report and returns only an id and status', async () => {
    const ctx = makeCtx();
    const r = await post(ctx, '/api/v1/reports', REPORT);
    expect(r.status).toBe(201);
    expect(r.body).toEqual({ id: expect.stringMatching(/^[a-f0-9]{24}$/), status: 'OPEN' });
    const stored = await ctx.repos.reports.findById(r.body.id);
    expect(stored).toMatchObject({ reporterId: null, kind: 'COPYRIGHT', contactEmail: 'owner@example.com' });
  });
  it('records the signed-in reporter, and then requires the CSRF token', async () => {
    const ctx = makeCtx();
    const u = await signedIn(ctx, 'alice');
    expect((await u.agent.post('/api/v1/reports').set('Origin', ORIGIN).send(REPORT)).status).toBe(403);
    const r = await u.call('post', '/api/v1/reports', { kind: 'ABUSE', description: 'Contenu abusif signalé.' });
    expect(r.status).toBe(201);
    expect((await ctx.repos.reports.findById(r.body.id))!.reporterId).toBe(u.user.id);
  });
  it('validates every field and refuses fields the client must not control', async () => {
    const big = { windowMs: 60_000, max: 1000 };
    const ctx = makeCtx({ limits: { general: big, login: big, register: big, reset: big, sensitive: big, otp: big, otpResend: big, reports: big } as any });
    const bad: object[] = [
      {}, { ...REPORT, kind: 'SPAM' }, { ...REPORT, description: 'court' }, { ...REPORT, description: 'x'.repeat(2001) },
      { ...REPORT, targetUrl: 'http://insecure.example.com/x' }, { ...REPORT, targetUrl: 'https://127.0.0.1/x' }, { ...REPORT, targetUrl: 'https://169.254.169.254/latest' },
      { ...REPORT, contactEmail: 'not-an-email' }, { ...REPORT, status: 'RESOLVED' }, { ...REPORT, reporterId: 'x' }, { ...REPORT, adminNote: 'x' },
      { ...REPORT, description: { $ne: '' } }, { ...REPORT, kind: { $ne: 'ABUSE' } },
    ];
    for (const b of bad) expect((await post(ctx, '/api/v1/reports', b)).status, JSON.stringify(b)).toBe(400);
    expect((await ctx.repos.reports.list({ page: 1, pageSize: 10 })).total).toBe(0);
  });
  it('is rate-limited', async () => {
    const big = { windowMs: 60_000, max: 1000 };
    const ctx = makeCtx({ limits: { general: big, login: big, register: big, reset: big, sensitive: big, otp: big, otpResend: big, reports: { windowMs: 60_000, max: 2 } } as any });
    const codes: number[] = [];
    for (let i = 0; i < 4; i++) codes.push((await post(ctx, '/api/v1/reports', REPORT)).status);
    expect(codes).toEqual([201, 201, 429, 429]);
  });
  it('rejects a foreign Origin', async () => {
    const ctx = makeCtx();
    expect((await request(ctx.app).post('/api/v1/reports').set('Origin', 'https://evil.example').send(REPORT)).status).toBe(403);
  });
});

describe('admin: reports management', () => {
  it('lists, filters, paginates and updates with an audit trail', async () => {
    const ctx = makeCtx();
    const admin = await signedInAdmin(ctx);
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) ids.push((await post(ctx, '/api/v1/reports', { ...REPORT, description: `Signalement numéro ${i} détaillé` })).body.id);
    const all = await admin.call('get', '/api/v1/admin/reports?pageSize=2');
    expect(all.status).toBe(200);
    expect(all.body).toMatchObject({ total: 3, page: 1, pageSize: 2 });
    expect(all.body.items.length).toBe(2);
    const upd = await admin.call('patch', `/api/v1/admin/reports/${ids[0]}`, { status: 'RESOLVED', adminNote: 'Retiré.' });
    expect(upd.status).toBe(200);
    expect(upd.body).toMatchObject({ status: 'RESOLVED', adminNote: 'Retiré.', handledBy: admin.user.id });
    expect((await admin.call('get', '/api/v1/admin/reports?status=OPEN')).body.total).toBe(2);
    expect((await admin.call('get', '/api/v1/admin/reports?status=RESOLVED')).body.total).toBe(1);
    expect((await ctx.repos.audit.list({ page: 1, pageSize: 10, action: 'ADMIN_REPORT_UPDATED' })).items.length).toBe(1);
    expect((await ctx.repos.reports.counts())).toEqual({ open: 2, inReview: 0, total: 3 });
  });
  it('validates and 404s correctly', async () => {
    const ctx = makeCtx();
    const admin = await signedInAdmin(ctx);
    const id = (await post(ctx, '/api/v1/reports', REPORT)).body.id;
    for (const b of [{}, { status: 'DONE' }, { adminNote: 'x'.repeat(1001) }, { status: 'OPEN', extra: 1 }, { status: { $ne: 'x' } }]) expect((await admin.call('patch', `/api/v1/admin/reports/${id}`, b)).status, JSON.stringify(b)).toBe(400);
    expect((await admin.call('patch', '/api/v1/admin/reports/bad-id', { status: 'OPEN' })).status).toBe(400);
    expect((await admin.call('patch', `/api/v1/admin/reports/${'0'.repeat(24)}`, { status: 'OPEN' })).status).toBe(404);
    for (const q of ['page=0', 'pageSize=101', 'status=X']) expect((await admin.call('get', `/api/v1/admin/reports?${q}`)).status, q).toBe(400);
  });
  it('deleting the reporter keeps the report but detaches the person', async () => {
    const ctx = makeCtx();
    const u = await signedIn(ctx, 'alice');
    const r = await u.call('post', '/api/v1/reports', REPORT);
    expect((await u.call('delete', '/api/v1/auth/account', { password: PASSWORD })).status).toBeLessThan(300);
    expect(await ctx.repos.reports.findById(r.body.id)).toMatchObject({ reporterId: null, status: 'OPEN' });
  });
});

describe('admin routes are admin-only', () => {
  it('401 anonymous, 403 for a normal user, on every admin route', async () => {
    const ctx = makeCtx();
    const user = await signedIn(ctx, 'alice');
    const id = '0'.repeat(24);
    const routes: [string, string, object?][] = [
      ['get', '/stats'], ['get', '/users'], ['patch', `/users/${id}`, { role: 'ADMIN' }], ['get', '/audit-logs'], ['get', '/api-stats'],
      ['get', '/integrations'], ['get', '/tools'], ['get', '/errors'], ['get', '/settings'], ['patch', '/settings', { ads: { enabled: true } }],
      ['get', '/reports'], ['patch', `/reports/${id}`, { status: 'OPEN' }],
    ];
    for (const [m, u, b] of routes) {
      const url = `/api/v1/admin${u}`;
      expect((await (request(ctx.app) as any)[m](url).set('Origin', ORIGIN).send(b ?? {})).status, `anon ${m} ${u}`).toBe(401);
      expect((await user.call(m as any, url, b)).status, `user ${m} ${u}`).toBe(403);
    }
  });
  it('a user cannot make themselves admin through the profile or by any request', async () => {
    const ctx = makeCtx();
    const u = await signedIn(ctx, 'alice');
    for (const [m, url, b] of [['patch', '/api/v1/me/profile', { role: 'ADMIN' }], ['patch', '/api/v1/me/preferences', { role: 'ADMIN' }], ['patch', `/api/v1/admin/users/${u.user.id}`, { role: 'ADMIN' }]] as const) await u.call(m, url, b);
    expect((await ctx.repos.users.findByEmail(u.email))!.role).toBe('USER');
  });
});

describe('admin: integrations, errors and secrets', () => {
  const SECRETS = { GOOGLE_CLIENT_ID: 'gid-123.apps.googleusercontent.com', GOOGLE_CLIENT_SECRET: 'GOCSPX-topsecret', GOOGLE_CALLBACK_URL: `${ORIGIN}/api/v1/auth/google/callback`, ANTHROPIC_API_KEY: 'sk-ant-VERYSECRET', AI_MODEL: 'some-model', RESEND_API_KEY: 're_VERYSECRET', EMAIL_FROM: 'Media Hub <no-reply@example.com>' };

  it('reports real configuration status as booleans and never leaks a secret', async () => {
    const ctx = makeCtx({ env: SECRETS });
    const admin = await signedInAdmin(ctx);
    const seen = [
      await admin.call('get', '/api/v1/admin/integrations'), await admin.call('get', '/api/v1/admin/tools'), await admin.call('get', '/api/v1/admin/settings'),
      await admin.call('get', '/api/v1/admin/stats'), await admin.call('get', '/api/v1/admin/errors'), await admin.call('get', '/api/v1/admin/audit-logs'),
      await request(ctx.app).get('/api/v1/settings/public'), await request(ctx.app).get('/api/v1/tools'), await request(ctx.app).get('/health'), await request(ctx.app).get('/api/v1/auth/google/status'),
    ];
    const blob = JSON.stringify(seen.map((r) => r.body));
    for (const secret of ['GOCSPX-topsecret', 'sk-ant-VERYSECRET', 're_VERYSECRET', 'x'.repeat(40), 'mongodb://', 'gid-123']) expect(blob).not.toContain(secret);
    for (const r of seen) expect(r.status).toBe(200);
    const i = seen[0]!.body;
    expect(i.database).toEqual({ status: 'up' });
    expect(i.email.provider).toBe('resend');
    expect(typeof i.email.configured).toBe('boolean');
    expect(i.google).toEqual({ configured: true });
    expect(i.ai).toEqual({ configured: true });
    expect(i.note).toMatch(/restart/);
  });

  it('says what is missing when nothing is configured', async () => {
    const ctx = makeCtx();
    const admin = await signedInAdmin(ctx);
    const r = await admin.call('get', '/api/v1/admin/integrations');
    expect(r.body.database).toEqual({ status: 'up' });
    expect(r.body.google).toEqual({ configured: false, missing: expect.stringContaining('GOOGLE_CLIENT_ID') });
    expect(r.body.ai).toEqual({ configured: false, missing: expect.stringContaining('ANTHROPIC_API_KEY') });
    expect(r.body.tools.find((t: any) => t.id === 'tiktok')).toMatchObject({ configured: false });
  });

  it('during a database outage the API answers 503 with Retry-After (no half-working state) and recovers', async () => {
    let up = true;
    const ctx = makeCtx({ deps: { checkDb: async () => up } });
    const admin = await signedInAdmin(ctx);
    up = false;
    const r = await admin.call('get', '/api/v1/admin/integrations');
    expect(r.status).toBe(503);
    expect(r.body.error.code).toBe('SERVICE_UNAVAILABLE');
    expect(r.headers['retry-after']).toBeTruthy();
    expect((await request(ctx.app).get('/health/ready')).status).toBe(503);
    expect((await request(ctx.app).get('/health/live')).status).toBe(200);
    up = true;
    expect((await admin.call('get', '/api/v1/admin/integrations')).status).toBe(200);
  });

  it('exposes real stats computed from the stored data', async () => {
    const ctx = makeCtx();
    const admin = await signedInAdmin(ctx);
    await signedIn(ctx, 'alice'); await signedIn(ctx, 'bob');
    const s = (await admin.call('get', '/api/v1/admin/stats')).body;
    expect(JSON.stringify(s)).toMatch(/3/); // 3 users exist
    await signedIn(ctx, 'carl');
    expect(JSON.stringify((await admin.call('get', '/api/v1/admin/stats')).body)).not.toBe(JSON.stringify(s));
  });

  it('records provider and server errors for the admin, scrubbed of URLs and internals', async () => {
    const boom: MediaProvider = { id: 'facebook', label: 'Facebook', hosts: ['facebook.com'], configured: true, analyze: async () => { throw new Error('mongodb://user:pw@host/db failed at https://internal.example/secret'); } };
    const slow: MediaProvider = { ...boom, analyze: async () => { throw new ProviderError(504, 'PROVIDER_TIMEOUT', 'see https://api.example.com/x?key=abc timed out'); } };
    for (const [provider, wantSource] of [[slow, 'provider'], [boom, 'http']] as const) {
      const ctx = makeCtx({ deps: { media: [provider] } });
      const admin = await signedInAdmin(ctx);
      await post(ctx, '/api/v1/tools/facebook/analyze', { url: 'https://www.facebook.com/watch?v=1' });
      const errs = await admin.call('get', '/api/v1/admin/errors');
      expect(errs.status).toBe(200);
      expect(errs.body).toMatchObject({ page: 1, pageSize: 20 });
      const mine = errs.body.items.filter((e: any) => e.source === wantSource);
      expect(mine.length, wantSource).toBeGreaterThanOrEqual(1);
      const blob = JSON.stringify(errs.body);
      expect(blob).not.toMatch(/mongodb:|internal\.example|api\.example\.com|key=abc|pw@/);
      expect((await admin.call('get', `/api/v1/admin/errors?source=${wantSource}`)).body.items.length).toBe(mine.length);
      expect((await admin.call('get', '/api/v1/admin/integrations')).body.errorsLast24h).toBeGreaterThanOrEqual(1);
    }
    const ctx = makeCtx();
    const admin = await signedInAdmin(ctx);
    for (const q of ['source=nope', 'page=0', 'pageSize=101']) expect((await admin.call('get', `/api/v1/admin/errors?${q}`)).status, q).toBe(400);
  });

  it('the 500 answer to the client carries a request id but no internals', async () => {
    const boom: MediaProvider = { id: 'facebook', label: 'Facebook', hosts: ['facebook.com'], configured: true, analyze: async () => { throw new Error('secret internal detail'); } };
    const ctx = makeCtx({ deps: { media: [boom] } });
    const r = await post(ctx, '/api/v1/tools/facebook/analyze', { url: 'https://www.facebook.com/watch?v=1' }).set('X-Request-Id', 'req-test-1');
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).not.toMatch(/secret internal detail|stack|at /);
    expect(r.body.error.requestId ?? r.body.requestId).toBeTruthy();
  });
});
