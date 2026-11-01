import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { ProviderError, type MediaProvider, type MusicProvider } from '../src/providers/types.js';
import { makeClock, makeCtx, ORIGIN, post, signedIn, signedInAdmin } from './helpers.js';

const LINK = 'https://www.facebook.com/watch?v=123';
const RESULT = { platform: 'facebook', title: 'Ma vidéo', thumbnail: 'https://cdn.example.com/t.jpg', author: null, downloads: [
  { label: 'HD', format: 'mp4', quality: 'HD', url: 'https://cdn.example.com/hd.mp4' },
  { label: 'SD', format: 'mp4', quality: 'SD', url: 'https://cdn.example.com/sd.mp4' },
] };
const fb = (over: Partial<MediaProvider> = {}): MediaProvider => ({ id: 'facebook', label: 'Facebook', hosts: ['facebook.com'], configured: true, analyze: async () => RESULT, ...over });
const tiktok: MediaProvider = { id: 'tiktok', label: 'TikTok', hosts: ['tiktok.com'], configured: false, notConfiguredReason: 'No TikTok integration has been provided yet.', analyze: async () => { throw new ProviderError(503, 'SERVICE_NOT_CONFIGURED', 'x'); } };
const music = (over: Partial<MusicProvider> = {}): MusicProvider => ({
  id: 'itunes', label: 'iTunes', configured: true,
  search: async (q) => ({ items: [{ id: 'track:1', type: q.type, title: 'T', artist: 'A', album: null, artwork: null, previewUrl: null, url: null, durationMs: null, releaseDate: null, genre: null }], page: q.page, pageSize: q.pageSize, hasMore: false }),
  ...over,
});
const setup = (media: MediaProvider[] = [fb(), tiktok], m: MusicProvider = music()) => {
  const clock = makeClock();
  const ctx = makeCtx({ now: clock.now, deps: { media, music: m } });
  return { ctx, clock };
};
const analyze = (ctx: ReturnType<typeof makeCtx>, url = LINK, tool = 'facebook') => post(ctx, `/api/v1/tools/${tool}/analyze`, { url });
const claim = (ctx: ReturnType<typeof makeCtx>, id: string) => post(ctx, `/api/v1/tools/jobs/${id}/claim`, {});
const enableAds = async (ctx: ReturnType<typeof makeCtx>, waitSeconds = 5) => {
  const admin = await signedInAdmin(ctx);
  const r = await admin.call('patch', '/api/v1/admin/settings', { ads: { enabled: true, waitSeconds } });
  expect(r.status).toBe(200);
  return admin;
};

describe('tool catalogue', () => {
  it('tells the truth about what is connected', async () => {
    const { ctx } = setup();
    const r = await request(ctx.app).get('/api/v1/tools');
    expect(r.status).toBe(200);
    const by = Object.fromEntries(r.body.items.map((i: any) => [i.id, i]));
    expect(by.facebook).toMatchObject({ enabled: true, configured: true, available: true });
    expect(by.tiktok).toMatchObject({ configured: false, available: false });
    expect(by.tiktok.reason).toMatch(/TikTok/);
    expect(by.music).toMatchObject({ kind: 'search', available: true });
    expect(JSON.stringify(r.body)).not.toMatch(/siputzx|api_key|secret/i);
  });
});

describe('analyze without ads (default: ads are OFF)', () => {
  it('returns metadata, no links, and a job that can be claimed immediately', async () => {
    const { ctx } = setup();
    const r = await analyze(ctx);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ platform: 'facebook', title: 'Ma vidéo', ads: { required: false, waitSeconds: 0 } });
    expect(r.body.formats).toEqual([{ label: 'HD', format: 'mp4', quality: 'HD' }, { label: 'SD', format: 'mp4', quality: 'SD' }]);
    expect(JSON.stringify(r.body)).not.toContain('cdn.example.com/hd.mp4');
    const c = await claim(ctx, r.body.jobId);
    expect(c.status).toBe(200);
    expect(c.body.downloads.map((d: any) => d.url)).toEqual(['https://cdn.example.com/hd.mp4', 'https://cdn.example.com/sd.mp4']);
  });
});

describe('server-side ad gate', () => {
  it('refuses early claims with 409 + retryAfter and releases links only after the wait', async () => {
    const { ctx, clock } = setup();
    await enableAds(ctx, 5);
    const a = await analyze(ctx);
    expect(a.body.ads).toEqual({ required: true, waitSeconds: 5, slot: null });
    expect(JSON.stringify(a.body)).not.toContain('cdn.example.com/hd.mp4');

    const early = await claim(ctx, a.body.jobId);
    expect(early.status).toBe(409);
    expect(early.body.error.code).toBe('AD_NOT_FINISHED');
    expect(early.body.error.meta?.retryAfter ?? early.body.meta?.retryAfter).toBe(5);
    expect(JSON.stringify(early.body)).not.toContain('cdn.example.com');

    clock.seconds(3);
    const mid = await claim(ctx, a.body.jobId);
    expect(mid.status).toBe(409);
    expect(JSON.stringify(mid.body)).not.toContain('cdn.example.com');

    clock.seconds(2);
    const ok = await claim(ctx, a.body.jobId);
    expect(ok.status).toBe(200);
    expect(ok.body.downloads.length).toBe(2);
  });

  it('a new analysis does not shorten the wait of another job, and the wait cannot be set by the client', async () => {
    const { ctx, clock } = setup();
    await enableAds(ctx, 10);
    const r = await post(ctx, '/api/v1/tools/facebook/analyze', { url: LINK, waitSeconds: 0 });
    expect(r.status).toBe(400); // strict schema: unknown field rejected
    const a = await analyze(ctx);
    clock.seconds(9);
    expect((await claim(ctx, a.body.jobId)).status).toBe(409);
  });

  it('expired, unknown and malformed jobs are 404 and leak nothing', async () => {
    const { ctx, clock } = setup();
    const a = await analyze(ctx);
    expect((await claim(ctx, 'nope')).status).toBe(404);
    expect((await claim(ctx, 'a'.repeat(24))).status).toBe(404);
    expect((await claim(ctx, '{"$ne":1}')).status).toBe(404);
    expect((await claim(ctx, 'f'.repeat(40))).status).toBe(404); // regression: valid hex but not an ObjectId must not reach the DB layer
    clock.advance(16 * 60_000);
    const gone = await claim(ctx, a.body.jobId);
    expect(gone.status).toBe(404);
    expect(JSON.stringify(gone.body)).not.toContain('cdn.example.com');
  });

  it('a job made by a signed-in user cannot be claimed by someone else or anonymously', async () => {
    const { ctx } = setup();
    const alice = await signedIn(ctx, 'alice');
    const bob = await signedIn(ctx, 'bob');
    const a = await alice.call('post', '/api/v1/tools/facebook/analyze', { url: LINK });
    expect(a.status).toBe(200);
    expect((await bob.call('post', `/api/v1/tools/jobs/${a.body.jobId}/claim`, {})).status).toBe(404);
    expect((await claim(ctx, a.body.jobId)).status).toBe(404);
    expect((await alice.call('post', `/api/v1/tools/jobs/${a.body.jobId}/claim`, {})).status).toBe(200);
  });

  it('public settings expose the ads configuration but admin changes require an admin', async () => {
    const { ctx } = setup();
    const pub = await request(ctx.app).get('/api/v1/settings/public');
    expect(pub.body.ads).toEqual({ enabled: false, waitSeconds: 5, homeSlotEnabled: false, slot: null });
    const user = await signedIn(ctx, 'alice');
    expect((await user.call('patch', '/api/v1/admin/settings', { ads: { enabled: true } })).status).toBe(403);
    expect((await request(ctx.app).patch('/api/v1/admin/settings').set('Origin', ORIGIN).send({ ads: { enabled: true } })).status).toBe(401);
    await enableAds(ctx, 7);
    const audit = await ctx.repos.audit.list({ page: 1, pageSize: 50, action: 'ADMIN_SETTINGS_CHANGED' });
    expect(audit.items.length).toBeGreaterThanOrEqual(1);
  });

  it('validates admin settings (bounds, unknown keys, empty patch)', async () => {
    const { ctx } = setup();
    const admin = await signedInAdmin(ctx);
    for (const body of [{ ads: { waitSeconds: 31 } }, { ads: { waitSeconds: -1 } }, { ads: { waitSeconds: 1.5 } }, { ads: { evil: true } }, { tools: { nope: true } }, {}, { extra: 1 }]) {
      expect((await admin.call('patch', '/api/v1/admin/settings', body)).status).toBe(400);
    }
  });
});

describe('analyze errors', () => {
  it('rejects unknown tools, bad links and wrong hosts before calling the provider', async () => {
    let calls = 0;
    const { ctx } = setup([fb({ analyze: async () => { calls++; return RESULT; } }), tiktok]);
    expect((await analyze(ctx, LINK, 'nope')).status).toBe(404);
    for (const bad of ['https://evil.example.com/x', 'http://facebook.com/x', 'https://facebook.com.evil.io/x', 'https://127.0.0.1/', 'javascript:alert(1)', 'not a url at all']) {
      const r = await analyze(ctx, bad);
      expect(r.status, bad).toBe(400);
      expect(r.body.error.code).toBe('INVALID_LINK');
    }
    expect(calls).toBe(0);
    expect((await post(ctx, '/api/v1/tools/facebook/analyze', {})).status).toBe(400);
    expect((await post(ctx, '/api/v1/tools/facebook/analyze', { url: { $ne: '' } })).status).toBe(400);
    expect((await post(ctx, '/api/v1/tools/facebook/analyze', { url: 'x'.repeat(3000) })).status).toBe(400);
  });

  it('an unconnected tool answers 503 SERVICE_NOT_CONFIGURED, never fake data', async () => {
    const { ctx } = setup();
    const r = await analyze(ctx, 'https://www.tiktok.com/@a/video/1', 'tiktok');
    expect(r.status).toBe(503);
    expect(r.body.error.code).toBe('SERVICE_NOT_CONFIGURED');
    expect(r.body.jobId).toBeUndefined();
  });

  it('a disabled tool answers 503 TOOL_DISABLED and reappears when re-enabled', async () => {
    const { ctx } = setup();
    const admin = await signedInAdmin(ctx);
    await admin.call('patch', '/api/v1/admin/settings', { tools: { facebook: false } });
    const off = await analyze(ctx);
    expect(off.status).toBe(503);
    expect(off.body.error.code).toBe('TOOL_DISABLED');
    const cat = await request(ctx.app).get('/api/v1/tools');
    expect(cat.body.items.find((i: any) => i.id === 'facebook')).toMatchObject({ enabled: false, available: false });
    await admin.call('patch', '/api/v1/admin/settings', { tools: { facebook: true } });
    expect((await analyze(ctx)).status).toBe(200);
  });

  it.each([
    [new ProviderError(504, 'PROVIDER_TIMEOUT', 'The service took too long to answer.'), 504],
    [new ProviderError(502, 'PROVIDER_BAD_RESPONSE', 'bad'), 502],
    [new ProviderError(422, 'NO_MEDIA', 'none'), 422],
  ])('propagates provider failure %#', async (err, status) => {
    const { ctx } = setup([fb({ analyze: async () => { throw err; } }), tiktok]);
    const r = await analyze(ctx);
    expect(r.status).toBe(status);
    expect(r.body.error.code).toBe(err.code);
    expect(r.body.jobId).toBeUndefined();
  });

  it('an unexpected provider exception becomes a clean 500 without internals', async () => {
    const { ctx } = setup([fb({ analyze: async () => { throw new Error('mongodb://user:pw@host secret stack'); } }), tiktok]);
    const r = await analyze(ctx);
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).not.toMatch(/mongodb|secret|stack/);
  });

  it('caps concurrent calls per provider and recovers (503 BUSY)', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const { ctx } = setup([fb({ analyze: async () => { await gate; return RESULT; } }), tiktok]);
    const inflight = Array.from({ length: 4 }, () => analyze(ctx).then((r) => r));
    await new Promise((r) => setTimeout(r, 100));
    const fifth = await analyze(ctx);
    expect(fifth.status).toBe(503);
    expect(fifth.body.error.code).toBe('BUSY');
    release();
    for (const r of await Promise.all(inflight)) expect(r.status).toBe(200);
    expect((await analyze(ctx)).status).toBe(200);
  });
});

describe('history recording for signed-in users', () => {
  it('records successful and failed operations (host only, never the full link), anonymous users nothing', async () => {
    let fail = false;
    const { ctx } = setup([fb({ analyze: async () => { if (fail) throw new ProviderError(502, 'PROVIDER_ERROR', 'x'); return RESULT; } }), tiktok]);
    const alice = await signedIn(ctx, 'alice');
    await alice.call('post', '/api/v1/tools/facebook/analyze', { url: LINK + '&secret=abc' });
    fail = true;
    await alice.call('post', '/api/v1/tools/facebook/analyze', { url: LINK });
    await analyze(ctx); // anonymous
    const h = await alice.call('get', '/api/v1/me/history');
    expect(h.status).toBe(200);
    const items = h.body.items;
    expect(items.length).toBe(2);
    expect(items.map((i: any) => i.status).sort()).toEqual(['FAILED', 'SUCCESS']);
    expect(JSON.stringify(items)).not.toMatch(/secret=abc|cdn\.example\.com/);
    expect(items.every((i: any) => i.query === 'www.facebook.com')).toBe(true);
  });

  it('respects the user preference to disable history', async () => {
    const { ctx } = setup();
    const alice = await signedIn(ctx, 'alice');
    const p = await alice.call('patch', '/api/v1/me/preferences', { historyEnabled: false });
    expect(p.status).toBe(200);
    await alice.call('post', '/api/v1/tools/facebook/analyze', { url: LINK });
    expect((await alice.call('get', '/api/v1/me/history')).body.items.length).toBe(0);
  });
});

describe('music search', () => {
  it('searches via GET and POST with validated, bounded parameters', async () => {
    const { ctx } = setup();
    const g = await request(ctx.app).get('/api/v1/tools/music/search').query({ q: 'daft punk', type: 'album', page: 2, pageSize: 5 });
    expect(g.status).toBe(200);
    expect(g.body).toMatchObject({ provider: 'itunes', page: 2, pageSize: 5, hasMore: false });
    expect(g.body.items[0].type).toBe('album');
    const p = await post(ctx, '/api/v1/tools/music/search', { q: 'x' });
    expect(p.status).toBe(200);
    expect(p.body).toMatchObject({ page: 1, pageSize: 10 });
    for (const q of [{}, { q: '' }, { q: 'a'.repeat(101) }, { q: 'x', type: 'video' }, { q: 'x', page: 0 }, { q: 'x', page: 21 }, { q: 'x', pageSize: 26 }, { q: ['a', 'b'] }, { 'q[$ne]': 'a' }]) {
      expect((await request(ctx.app).get('/api/v1/tools/music/search').query(q as any)).status, JSON.stringify(q)).toBe(400);
    }
  });

  it('is honest when no provider is connected or the tool is disabled', async () => {
    const none = setup([fb(), tiktok], music({ configured: false, notConfiguredReason: 'Music search is not connected.' }));
    const r = await request(none.ctx.app).get('/api/v1/tools/music/search').query({ q: 'x' });
    expect(r.status).toBe(503);
    expect(r.body.error.code).toBe('SERVICE_NOT_CONFIGURED');
    const { ctx } = setup();
    const admin = await signedInAdmin(ctx);
    await admin.call('patch', '/api/v1/admin/settings', { tools: { music: false } });
    expect((await request(ctx.app).get('/api/v1/tools/music/search').query({ q: 'x' })).body.error.code).toBe('TOOL_DISABLED');
  });

  it('maps provider failures and records search history only for page 1', async () => {
    const { ctx } = setup([fb(), tiktok], music({ search: async () => { throw new ProviderError(504, 'PROVIDER_TIMEOUT', 'slow'); } }));
    expect((await request(ctx.app).get('/api/v1/tools/music/search').query({ q: 'x' })).status).toBe(504);
    const ok = setup();
    const alice = await signedIn(ok.ctx, 'alice');
    await alice.call('get', '/api/v1/tools/music/search?q=hello');
    await alice.call('get', '/api/v1/tools/music/search?q=hello&page=2');
    const items = (await alice.call('get', '/api/v1/me/history')).body.items;
    expect(items.length).toBe(1);
    expect(items[0]).toMatchObject({ kind: 'SEARCH', tool: 'music', query: 'hello', status: 'SUCCESS' });
  });
});

describe('CSRF and rate limits on tools', () => {
  it('a signed-in session must send the CSRF token to analyze', async () => {
    const { ctx } = setup();
    const alice = await signedIn(ctx, 'alice');
    const r = await alice.agent.post('/api/v1/tools/facebook/analyze').set('Origin', ORIGIN).send({ url: LINK });
    expect(r.status).toBe(403);
  });
  it('rejects a foreign Origin', async () => {
    const { ctx } = setup();
    const r = await request(ctx.app).post('/api/v1/tools/facebook/analyze').set('Origin', 'https://evil.example').send({ url: LINK });
    expect(r.status).toBe(403);
  });
  it('rate-limits analyses and claims', async () => {
    const big = { windowMs: 60_000, max: 1000 };
    const ctx = makeCtx({ deps: { media: [fb(), tiktok], music: music() }, limits: { general: big, login: big, register: big, reset: big, sensitive: big, otp: big, otpResend: big, tools: { windowMs: 60_000, max: 3 }, claim: { windowMs: 60_000, max: 2 } } as any });
    const codes: number[] = [];
    for (let i = 0; i < 5; i++) codes.push((await analyze(ctx)).status);
    expect(codes).toEqual([200, 200, 200, 429, 429]);
    const c: number[] = [];
    for (let i = 0; i < 4; i++) c.push((await claim(ctx, 'a'.repeat(24))).status);
    expect(c).toEqual([404, 404, 429, 429]);
  });
});

describe('admin tools overview reflects real calls', () => {
  it('counts real successes and failures, with no secrets', async () => {
    let fail = false;
    const { ctx } = setup([fb({ analyze: async () => { if (fail) throw new ProviderError(502, 'PROVIDER_ERROR', 'x'); return RESULT; } }), tiktok]);
    const admin = await signedInAdmin(ctx);
    await analyze(ctx); await analyze(ctx); fail = true; await analyze(ctx);
    const r = await admin.call('get', '/api/v1/admin/tools');
    expect(r.status).toBe(200);
    const f = r.body.items.find((i: any) => i.id === 'facebook');
    expect(f.last24h).toEqual({ total: 3, failed: 1 });
    expect(f.live).toBeTruthy();
    const t = r.body.items.find((i: any) => i.id === 'tiktok');
    expect(t).toMatchObject({ configured: false, last24h: { total: 0, failed: 0 } });
    const user = await signedIn(ctx, 'alice');
    expect((await user.call('get', '/api/v1/admin/tools')).status).toBe(403);
    // provider 5xx errors are recorded for the admin error view
    const errs = await admin.call('get', '/api/v1/admin/errors');
    expect(errs.status).toBe(200);
    expect(JSON.stringify(errs.body)).not.toMatch(/https?:\/\//);
  });
});

describe('TOOLS_REQUIRE_LOGIN (accès réservé aux comptes)', () => {
  const gated = () => {
    const ctx = makeCtx({ env: { TOOLS_REQUIRE_LOGIN: true }, deps: { media: [fb(), tiktok], music: music() } });
    return ctx;
  };
  it('refuse les visiteurs sur analyze, claim et la recherche musicale, mais garde le catalogue public', async () => {
    const ctx = gated();
    expect((await analyze(ctx)).status).toBe(401);
    expect((await claim(ctx, 'a'.repeat(24))).status).toBe(401);
    expect((await request(ctx.app).get('/api/v1/tools/music/search?q=abba')).status).toBe(401);
    expect((await post(ctx, '/api/v1/tools/music/search', { q: 'abba' })).status).toBe(401);
    expect((await request(ctx.app).get('/api/v1/tools')).status).toBe(200);
  });
  it('un compte connecté peut analyser', async () => {
    const ctx = gated();
    const u = await signedIn(ctx, 'alice');
    const r = await u.call('post', '/api/v1/tools/facebook/analyze', { url: LINK });
    expect(r.status).toBe(200);
  });
  it('la valeur par défaut de la variable est true (production)', async () => {
    const { loadEnv } = await import('../src/config/env.js');
    const base = { NODE_ENV: 'test', MONGODB_URI: 'mongodb://localhost/x', SESSION_SECRET: 'x'.repeat(40), FRONTEND_URL: ORIGIN } as Record<string, string>;
    expect(loadEnv({ ...base }).TOOLS_REQUIRE_LOGIN).toBe(true);
    expect(loadEnv({ ...base, TOOLS_REQUIRE_LOGIN: 'false' }).TOOLS_REQUIRE_LOGIN).toBe(false);
  });
});

describe('Adsterra : réglages et emplacement publicitaire', () => {
  const KEY = '0123456789abcdef0123456789abcdef';
  const HOSTNAME = 'www.exemple-pub.com';
  const patch = (admin: any, ads: object) => admin.call('patch', '/api/v1/admin/settings', { ads });

  it('refuse un réseau Adsterra incomplet, une clé ou un domaine invalide', async () => {
    const { ctx } = setup(); const admin = await signedInAdmin(ctx, 'boss');
    expect((await patch(admin, { provider: 'adsterra' })).status).toBe(400);
    expect((await patch(admin, { provider: 'adsterra', bannerKey: KEY })).status).toBe(400);
    for (const bad of [{ bannerKey: 'xyz' }, { bannerKey: KEY + 'ff' }, { bannerHost: 'https://x.com/a' }, { bannerHost: '127.0.0.1' }, { bannerHost: 'localhost' }, { bannerHost: 'a.com/invoke.js' }, { bannerSize: '1x1' }, { provider: 'google' }, { script: '<script>' }]) {
      expect((await patch(admin, bad)).status, JSON.stringify(bad)).toBe(400);
    }
    expect((await patch(admin, { homeSlotEnabled: true })).status).toBe(400); // emplacement sans réseau
    expect((await admin.call('get', '/api/v1/admin/settings')).body.ads.provider).toBe('none');
  });

  it('accepte le nouveau format Adsterra (chemin de script sans invoke.js) et refuse les chemins dangereux', async () => {
    const { ctx } = setup(); const admin = await signedInAdmin(ctx, 'boss');
    for (const bad of ['../x', 'a//b', '/abs', 'a b', 'a"><script>', 'x?y=1']) expect((await patch(admin, { scriptPath: bad })).status, bad).toBe(400);
    expect((await patch(admin, { provider: 'adsterra', bannerKey: KEY, bannerHost: HOSTNAME, scriptPath: '22/41a030d6fde208eb9abd2e62d965bdaa', enabled: true })).status).toBe(200);
    const pub = await request(ctx.app).get('/api/v1/settings/public');
    expect(pub.body.ads.slot).toEqual({ provider: 'adsterra', key: KEY, host: HOSTNAME, width: 300, height: 250, path: '22/41a030d6fde208eb9abd2e62d965bdaa' });
  });

  it('expose l’emplacement (clé, domaine, taille) seulement quand tout est complet et activé', async () => {
    const { ctx } = setup(); const admin = await signedInAdmin(ctx, 'boss');
    expect((await patch(admin, { provider: 'adsterra', bannerKey: KEY.toUpperCase(), bannerHost: 'WWW.Exemple-Pub.com', bannerSize: '728x90' })).status).toBe(200);
    let pub = await request(ctx.app).get('/api/v1/settings/public');
    expect(pub.body.ads.slot).toBeNull(); // réseau configuré mais pubs éteintes
    await patch(admin, { enabled: true, homeSlotEnabled: true });
    pub = await request(ctx.app).get('/api/v1/settings/public');
    expect(pub.body.ads).toEqual({ enabled: true, waitSeconds: 5, homeSlotEnabled: true, slot: { provider: 'adsterra', key: KEY, host: HOSTNAME, width: 728, height: 90 } });
  });

  it('joint l’emplacement à la réponse d’analyse seulement quand une attente est imposée', async () => {
    const { ctx } = setup(); const admin = await signedInAdmin(ctx, 'boss');
    await patch(admin, { provider: 'adsterra', bannerKey: KEY, bannerHost: HOSTNAME, enabled: true, waitSeconds: 4 });
    const user = await signedIn(ctx, 'alice');
    const a = await user.call('post', '/api/v1/tools/facebook/analyze', { url: 'https://www.facebook.com/watch?v=1' });
    expect(a.body.ads).toEqual({ required: true, waitSeconds: 4, slot: { provider: 'adsterra', key: KEY, host: HOSTNAME, width: 300, height: 250 } });
    await patch(admin, { waitSeconds: 0 });
    const b = await user.call('post', '/api/v1/tools/facebook/analyze', { url: 'https://www.facebook.com/watch?v=2' });
    expect(b.body.ads).toEqual({ required: false, waitSeconds: 0, slot: null });
  });

  it('retire l’emplacement quand on repasse sur « aucun réseau »', async () => {
    const { ctx } = setup(); const admin = await signedInAdmin(ctx, 'boss');
    await patch(admin, { provider: 'adsterra', bannerKey: KEY, bannerHost: HOSTNAME, enabled: true });
    expect((await patch(admin, { provider: 'none', homeSlotEnabled: false })).status).toBe(200);
    expect((await request(ctx.app).get('/api/v1/settings/public')).body.ads.slot).toBeNull();
  });
});
      
