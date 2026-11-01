import { describe, expect, it } from 'vitest';
import { loadEnv } from '../src/config/env.js';
import { SafeFetchError, type SafeResponse } from '../src/net/safeFetch.js';
import type { SafeFn } from '../src/providers/facebook.js';
import { createInstagramProvider, createTikTokProvider, createWhiteShadowFacebookProvider, parseFacebookResult } from '../src/providers/whiteshadow.js';
import { ProviderError } from '../src/providers/types.js';

const TOKEN = 'tok_0123456789abcdef0123456789abcdef';
const base = { NODE_ENV: 'test', MONGODB_URI: 'mongodb://unused', SESSION_SECRET: 'x'.repeat(40), FRONTEND_URL: 'https://app.example.com' };
const env = loadEnv({ ...base, WHITESHADOW_API_TOKEN: TOKEN });
const resp = (body: unknown, status = 200): SafeResponse => {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return { status, finalUrl: 'https://x.example/', headers: new Headers(), body: new TextEncoder().encode(text), text: () => text, json: () => JSON.parse(text) };
};
const scripted = (h: (url: string) => SafeResponse | Promise<SafeResponse>) => { const calls: string[] = []; const fn: SafeFn = async (url) => { calls.push(url); return h(url); }; return { fn, calls }; };

const TT = { success: true, creator: 'WhiteShadow', result: { code: 0, msg: 'success', data: {
  title: ' Ma vidéo #cod ', cover: 'https://cdn.example.com/c.jpg', play: 'https://cdn.example.com/p.mp4', wmplay: 'https://cdn.example.com/wm.mp4', hdplay: 'https://cdn.example.com/hd.mp4',
  size: 3760047, hd_size: 6750144, music: 'https://cdn.example.com/m.mp3', author: { unique_id: 'lokiontt1', nickname: 'KB~LOKI' } } } };
const IG = { success: true, creator: 'WhiteShadow', input: 'x', result: [{ type: 'video', url: 'https://cdn.example.com/1.mp4' }, { type: 'video', url: 'https://cdn.example.com/2.mp4' }] };

describe('TikTok (WhiteShadow)', () => {
  const link = 'https://vt.tiktok.com/ZSgTjyuWP/';
  it('appelle /api/download/tiktok avec le lien encodé et le jeton, et ne propose pas la version filigranée', async () => {
    const s = scripted(() => resp(TT));
    const out = await createTikTokProvider(env, s.fn).analyze(link);
    const u = new URL(s.calls[0]!);
    expect(u.origin + u.pathname).toBe('https://whiteshadow-x-api.onrender.com/api/download/tiktok');
    expect(u.searchParams.get('url')).toBe(link);
    expect(u.searchParams.get('apitoken')).toBe(TOKEN);
    expect(out).toMatchObject({ platform: 'tiktok', title: 'Ma vidéo #cod', thumbnail: 'https://cdn.example.com/c.jpg', author: '@lokiontt1' });
    expect(out.downloads.map((d) => [d.quality, d.format, d.url])).toEqual([['HD', 'mp4', 'https://cdn.example.com/hd.mp4'], ['SD', 'mp4', 'https://cdn.example.com/p.mp4'], [null, 'mp3', 'https://cdn.example.com/m.mp3']]);
    expect(JSON.stringify(out)).not.toContain('wm.mp4');
  });
  it('refuse un lien d’un autre site sans appeler le service', async () => {
    const s = scripted(() => resp(TT));
    await expect(createTikTokProvider(env, s.fn).analyze('https://www.instagram.com/p/x')).rejects.toMatchObject({ status: 400, code: 'INVALID_LINK' });
    expect(s.calls).toHaveLength(0);
  });
  it('NO_MEDIA quand le service répond success=false, code≠0 ou aucune URL exploitable (http, pas d’URL)', async () => {
    for (const body of [{ success: false }, { ...TT, result: { ...TT.result, code: -1 } }, { ...TT, result: { code: 0, data: { play: 'http://insecure.example.com/x.mp4' } } }]) {
      await expect(createTikTokProvider(env, scripted(() => resp(body)).fn).analyze(link), JSON.stringify(body)).rejects.toMatchObject({ status: 422, code: 'NO_MEDIA' });
    }
  });
  it('réponse inattendue → 502 ; 5xx/429 → 502 ; 401/403 → SERVICE_NOT_CONFIGURED ; délai dépassé → 504', async () => {
    await expect(createTikTokProvider(env, scripted(() => resp({ hello: 1 })).fn).analyze(link)).rejects.toMatchObject({ status: 502, code: 'PROVIDER_BAD_RESPONSE' });
    await expect(createTikTokProvider(env, scripted(() => resp('<html>', 200)).fn).analyze(link)).rejects.toMatchObject({ code: 'PROVIDER_BAD_RESPONSE' });
    for (const st of [500, 503, 429]) await expect(createTikTokProvider(env, scripted(() => resp({}, st)).fn).analyze(link)).rejects.toMatchObject({ status: 502, code: 'PROVIDER_ERROR' });
    for (const st of [401, 403]) await expect(createTikTokProvider(env, scripted(() => resp({}, st)).fn).analyze(link)).rejects.toMatchObject({ status: 503, code: 'SERVICE_NOT_CONFIGURED' });
    const timeout: SafeFn = async () => { throw new SafeFetchError('TIMEOUT', 'x'); };
    await expect(createTikTokProvider(env, timeout).analyze(link)).rejects.toMatchObject({ status: 504, code: 'PROVIDER_TIMEOUT' });
  });
  it('le jeton n’apparaît dans aucune erreur', async () => {
    for (const fn of [async () => { throw new SafeFetchError('NETWORK', `failed ${TOKEN}`); }, async () => resp({}, 500)] as SafeFn[]) {
      const e = await createTikTokProvider(env, fn).analyze(link).catch((x) => x as ProviderError);
      expect(String((e as Error).message)).not.toContain(TOKEN);
    }
  });
  it('sans jeton : « non connecté », jamais de faux résultat', async () => {
    const p = createTikTokProvider(loadEnv(base));
    expect(p.configured).toBe(false);
    expect(p.notConfiguredReason).toContain('WHITESHADOW_API_TOKEN');
    await expect(p.analyze(link)).rejects.toMatchObject({ status: 503, code: 'SERVICE_NOT_CONFIGURED' });
  });
});

describe('Instagram (WhiteShadow)', () => {
  const link = 'https://www.instagram.com/p/DYXNVTNE04J/';
  it('appelle /api/download/ig et numérote plusieurs vidéos', async () => {
    const s = scripted(() => resp(IG));
    const out = await createInstagramProvider(env, s.fn).analyze(link);
    const u = new URL(s.calls[0]!);
    expect(u.pathname).toBe('/api/download/ig');
    expect(u.searchParams.get('url')).toBe(link);
    expect(u.searchParams.get('apitoken')).toBe(TOKEN);
    expect(out.platform).toBe('instagram');
    expect(out.downloads.map((d) => [d.label, d.format, d.url])).toEqual([['Vidéo 1', 'mp4', 'https://cdn.example.com/1.mp4'], ['Vidéo 2', 'mp4', 'https://cdn.example.com/2.mp4']]);
  });
  it('gère les images, retire les doublons et les URL non https', async () => {
    const body = { success: true, result: [{ type: 'image', url: 'https://cdn.example.com/a.jpg' }, { type: 'image', url: 'https://cdn.example.com/a.jpg' }, { type: 'video', url: 'https://cdn.example.com/v.mp4' }, { type: 'video', url: 'http://insecure.example.com/x.mp4' }] };
    const out = await createInstagramProvider(env, scripted(() => resp(body)).fn).analyze(link);
    expect(out.downloads.map((d) => [d.label, d.format])).toEqual([['Image', 'jpg'], ['Vidéo', 'mp4']]);
  });
  it('NO_MEDIA (liste vide, success=false), mauvais site, réponse inattendue', async () => {
    for (const body of [{ success: true, result: [] }, { success: false, result: [] }]) await expect(createInstagramProvider(env, scripted(() => resp(body)).fn).analyze(link)).rejects.toMatchObject({ status: 422, code: 'NO_MEDIA' });
    await expect(createInstagramProvider(env, scripted(() => resp(IG)).fn).analyze('https://vt.tiktok.com/x')).rejects.toMatchObject({ code: 'INVALID_LINK' });
    await expect(createInstagramProvider(env, scripted(() => resp({ result: 'x' })).fn).analyze(link)).rejects.toMatchObject({ code: 'PROVIDER_BAD_RESPONSE' });
  });
  it('sans jeton : non connecté', () => { expect(createInstagramProvider(loadEnv(base)).configured).toBe(false); });
});

describe('Facebook (WhiteShadow) — format de succès NON vérifié, analyse tolérante', () => {
  const link = 'https://www.facebook.com/watch/?v=123';
  it('forme d’erreur observée { Status:false, Code:400, Result:[] } → NO_MEDIA', async () => {
    await expect(createWhiteShadowFacebookProvider(env, scripted(() => resp({ creator: 'WhiteShadow', Status: false, Code: 400, Input: 'x', Result: [] })).fn).analyze(link)).rejects.toMatchObject({ status: 422, code: 'NO_MEDIA' });
  });
  it('appelle /api/download/fb avec le jeton', async () => {
    const s = scripted(() => resp({ Status: true, Result: [{ quality: 'hd', url: 'https://cdn.example.com/hd.mp4' }] }));
    const out = await createWhiteShadowFacebookProvider(env, s.fn).analyze(link);
    const u = new URL(s.calls[0]!);
    expect(u.pathname).toBe('/api/download/fb');
    expect(u.searchParams.get('apitoken')).toBe(TOKEN);
    expect(out.downloads[0]).toMatchObject({ label: 'Vidéo HD', quality: 'HD', format: 'mp4' });
  });
  it('accepte plusieurs variantes de forme et ignore les URL non https / doublons', () => {
    expect(parseFacebookResult({ Result: [{ resolution: 'SD', link: 'https://a.example/sd.mp4' }, { url: 'https://a.example/sd.mp4' }, { url: 'http://bad.example/x.mp4' }] }).downloads).toHaveLength(1);
    expect(parseFacebookResult({ result: { title: ' T ', hd: 'https://a.example/h.mp4', sd: 'https://a.example/s.mp4' } })).toMatchObject({ title: 'T', downloads: [{ quality: 'HD' }, { quality: 'SD' }] });
    expect(parseFacebookResult({ Result: ['https://a.example/x.mp4'] }).downloads).toHaveLength(1);
    expect(parseFacebookResult({ Result: 'nope' }).downloads).toHaveLength(0);
  });
  it('sans jeton : non connecté ; mauvais site refusé', async () => {
    expect(createWhiteShadowFacebookProvider(loadEnv(base)).configured).toBe(false);
    await expect(createWhiteShadowFacebookProvider(env, scripted(() => resp({})).fn).analyze('https://www.tiktok.com/x')).rejects.toMatchObject({ code: 'INVALID_LINK' });
  });
});
