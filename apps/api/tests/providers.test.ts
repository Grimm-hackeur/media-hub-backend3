import { describe, expect, it } from 'vitest';
import { loadEnv } from '../src/config/env.js';
import { SafeFetchError, type SafeResponse } from '../src/net/safeFetch.js';
import { createFacebookProvider, createUnconnectedProvider, type SafeFn } from '../src/providers/facebook.js';
import { createItunesProvider } from '../src/providers/music.js';
import { ProviderError } from '../src/providers/types.js';
import { createAnthropicProvider } from '../src/services/ai.service.js';
import { env } from './helpers.js';

const resp = (body: unknown, status = 200, finalUrl = 'https://x.example/'): SafeResponse => {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return { status, finalUrl, headers: new Headers(), body: new TextEncoder().encode(text), text: () => text, json: () => JSON.parse(text) };
};
/** Records every call and answers from a script. */
const scripted = (handler: (url: string, opts: any) => SafeResponse | Promise<SafeResponse>) => {
  const calls: { url: string; opts: any }[] = [];
  const fn: SafeFn = async (url, opts) => { calls.push({ url, opts }); return handler(url, opts); };
  return { fn, calls };
};

const FB_OK = { status: true, data: { title: 'Ma vidéo', thumbnail: 'https://cdn.example.com/t.jpg', data: [
  { resolution: 'SD', format: 'mp4', url: 'https://cdn.example.com/sd.mp4' },
  { resolution: 'HD', format: 'mp4', url: 'https://cdn.example.com/hd.mp4' },
  { resolution: 'HD', format: 'webm', url: 'https://cdn.example.com/hd.webm' },
  { resolution: 'SD', format: 'mp4', url: 'http://insecure.example.com/x.mp4' },
] } };

describe('Facebook provider (response shape from the supplied bot code)', () => {
  const link = 'https://www.facebook.com/watch?v=123';
  const handler = (apiBody: unknown, status = 200) => (url: string) => (url.includes('/api/d/facebook') ? resp(apiBody, status) : resp('', 200, url));

  it('calls the configured endpoint with the encoded link and returns HD first, mp4 https only', async () => {
    const s = scripted(handler(FB_OK));
    const out = await createFacebookProvider(env, s.fn).analyze(link);
    expect(out.title).toBe('Ma vidéo');
    expect(out.thumbnail).toBe('https://cdn.example.com/t.jpg');
    expect(out.downloads.map((d) => [d.quality, d.url])).toEqual([['HD', 'https://cdn.example.com/hd.mp4'], ['SD', 'https://cdn.example.com/sd.mp4']]);
    const api = s.calls.find((c) => c.url.includes('/api/d/facebook'))!;
    expect(api.url).toBe(`https://api.siputzx.my.id/api/d/facebook?url=${encodeURIComponent(link)}`);
    expect(api.opts.timeoutMs).toBeLessThanOrEqual(20_000);
    expect(api.opts.maxBytes).toBeLessThanOrEqual(1_000_000);
  });

  it('resolves short links first (redirects allowed, hosts pinned) and queries with the final URL', async () => {
    const final = 'https://www.facebook.com/reel/999';
    const s = scripted((url) => (url.includes('/api/d/facebook') ? resp(FB_OK) : resp('', 200, final)));
    await createFacebookProvider(env, s.fn).analyze('https://fb.watch/abc');
    const first = s.calls[0]!;
    expect(first.opts).toMatchObject({ allowedHosts: ['facebook.com', 'fb.watch', 'fb.me'], noBody: true });
    expect(first.opts.maxRedirects).toBeGreaterThan(0);
    expect(s.calls[1]!.url).toContain(encodeURIComponent(final));
  });

  it('falls back to the original link when resolution is slow, like the bot does', async () => {
    const s = scripted((url) => { if (url.includes('/api/d/facebook')) return resp(FB_OK); throw new SafeFetchError('TIMEOUT', 't'); });
    const out = await createFacebookProvider(env, s.fn).analyze(link);
    expect(out.downloads.length).toBe(2);
  });

  it('retries with the original link when the resolved one yields nothing', async () => {
    const final = 'https://www.facebook.com/reel/999';
    const s = scripted((url) => {
      if (!url.includes('/api/d/facebook')) return resp('', 200, final);
      return url.includes(encodeURIComponent(final)) ? resp({ status: false, data: { data: [] } }) : resp(FB_OK);
    });
    const out = await createFacebookProvider(env, s.fn).analyze('https://fb.me/xyz');
    expect(out.downloads.length).toBe(2);
    expect(s.calls.filter((c) => c.url.includes('/api/d/facebook')).length).toBe(2);
  });

  it('rejects links that are not Facebook before any network call', async () => {
    for (const bad of ['https://facebook.com.evil.io/x', 'https://evil.io/?u=facebook.com', 'http://facebook.com/x', 'https://127.0.0.1/', 'nonsense']) {
      const s = scripted(handler(FB_OK));
      await expect(createFacebookProvider(env, s.fn).analyze(bad)).rejects.toMatchObject({ code: 'INVALID_LINK', status: 400 });
      expect(s.calls.length).toBe(0);
    }
  });

  it('reports NO_MEDIA (422) when the provider finds nothing', async () => {
    for (const b of [{ status: false, data: { data: [] } }, { status: true, data: { data: [] } }, { status: true, data: { data: [{ resolution: 'HD', format: 'webm', url: 'https://c.example.com/a.webm' }] } }]) {
      await expect(createFacebookProvider(env, scripted(handler(b)).fn).analyze(link)).rejects.toMatchObject({ code: 'NO_MEDIA', status: 422 });
    }
  });

  it('maps an incorrect external response to PROVIDER_BAD_RESPONSE (502)', async () => {
    for (const b of [{ hello: 'world' }, '<html>nope</html>', { status: true, data: 'str' }]) {
      await expect(createFacebookProvider(env, scripted(handler(b)).fn).analyze(link)).rejects.toMatchObject({ code: 'PROVIDER_BAD_RESPONSE', status: 502 });
    }
  });

  it('maps provider errors, timeouts and oversize answers', async () => {
    await expect(createFacebookProvider(env, scripted(handler({}, 503)).fn).analyze(link)).rejects.toMatchObject({ code: 'PROVIDER_ERROR', status: 502 });
    await expect(createFacebookProvider(env, scripted(handler({}, 429)).fn).analyze(link)).rejects.toMatchObject({ code: 'PROVIDER_ERROR' });
    const t = (code: any) => scripted((url) => { if (url.includes('/api/d/facebook')) throw new SafeFetchError(code, 'x'); return resp('', 200, url); });
    await expect(createFacebookProvider(env, t('TIMEOUT').fn).analyze(link)).rejects.toMatchObject({ code: 'PROVIDER_TIMEOUT', status: 504 });
    await expect(createFacebookProvider(env, t('TOO_LARGE').fn).analyze(link)).rejects.toMatchObject({ code: 'PROVIDER_BAD_RESPONSE' });
    await expect(createFacebookProvider(env, t('NETWORK').fn).analyze(link)).rejects.toMatchObject({ code: 'PROVIDER_ERROR' });
  });

  it('honours SIPUTZX_BASE_URL and FACEBOOK_API_PATH', async () => {
    const e = loadEnv({ ...process.env, NODE_ENV: 'test', MONGODB_URI: 'x', SESSION_SECRET: 'x'.repeat(40), FRONTEND_URL: 'https://a.example.com', SIPUTZX_BASE_URL: 'https://api.other.example/', FACEBOOK_API_PATH: '/v2/fb' });
    const s = scripted(handler(FB_OK));
    const s2 = scripted((url) => (url.includes('/v2/fb') ? resp(FB_OK) : resp('', 200, url)));
    await createFacebookProvider(e, s2.fn).analyze(link);
    expect(s2.calls.some((c) => c.url.startsWith('https://api.other.example/v2/fb?url='))).toBe(true);
  });
});

describe('TikTok / Instagram placeholders', () => {
  it('say plainly that they are not connected and never return data', async () => {
    const p = createUnconnectedProvider('tiktok', 'TikTok', ['tiktok.com']);
    expect(p.configured).toBe(false);
    expect(p.notConfiguredReason).toMatch(/No TikTok integration has been provided/);
    await expect(p.analyze('https://tiktok.com/@a/video/1')).rejects.toMatchObject({ status: 503, code: 'SERVICE_NOT_CONFIGURED' });
  });
});

const ITUNES_SONGS = { resultCount: 2, results: [
  { wrapperType: 'track', kind: 'song', trackId: 111, artistName: 'Daft Punk', collectionName: 'Discovery', trackName: 'One More Time', artworkUrl100: 'https://is1-ssl.mzstatic.com/image/thumb/Music/x/100x100bb.jpg', previewUrl: 'https://audio-ssl.itunes.apple.com/p.m4a', trackViewUrl: 'https://music.apple.com/us/album/x?i=111', trackTimeMillis: 320000, releaseDate: '2001-03-12T08:00:00Z', primaryGenreName: 'Electronic' },
  { wrapperType: 'track', kind: 'song', trackId: 112, artistName: 'Daft Punk', trackName: 'Aerodynamic', previewUrl: 'http://insecure.example.com/p.m4a' },
  { wrapperType: 'track', kind: 'song', artistName: 'No id' },
] };

describe('iTunes music provider (documented Search API fields)', () => {
  it('builds the documented query and maps songs, dropping unsafe URLs and incomplete rows', async () => {
    const s = scripted(() => resp(ITUNES_SONGS));
    const out = await createItunesProvider(s.fn).search({ query: 'daft punk', type: 'song', page: 1, pageSize: 2 });
    const u = new URL(s.calls[0]!.url);
    expect(u.origin + u.pathname).toBe('https://itunes.apple.com/search');
    expect(Object.fromEntries(u.searchParams)).toEqual({ term: 'daft punk', media: 'music', entity: 'song', limit: '2', offset: '0' });
    expect(s.calls[0]!.opts.allowedHosts).toEqual(['itunes.apple.com']);
    expect(out.items.length).toBe(2);
    expect(out.items[0]).toMatchObject({ id: 'track:111', title: 'One More Time', artist: 'Daft Punk', album: 'Discovery', durationMs: 320000, genre: 'Electronic', previewUrl: 'https://audio-ssl.itunes.apple.com/p.m4a' });
    expect(out.items[0]!.artwork).toBe('https://is1-ssl.mzstatic.com/image/thumb/Music/x/600x600bb.jpg');
    expect(out.items[1]!.previewUrl).toBeNull();
    expect(out.hasMore).toBe(true);
  });

  it('paginates with offset and reports the end of results', async () => {
    const s = scripted(() => resp({ resultCount: 1, results: [ITUNES_SONGS.results[0]] }));
    const out = await createItunesProvider(s.fn).search({ query: 'x', type: 'song', page: 3, pageSize: 10 });
    expect(new URL(s.calls[0]!.url).searchParams.get('offset')).toBe('20');
    expect(out.hasMore).toBe(false);
  });

  it('maps albums and artists and never claims a download', async () => {
    const albums = scripted(() => resp({ results: [{ collectionId: 5, collectionName: 'Discovery', artistName: 'Daft Punk', collectionViewUrl: 'https://music.apple.com/a', artworkUrl100: 'https://is1-ssl.mzstatic.com/i/100x100bb.jpg' }] }));
    const a = await createItunesProvider(albums.fn).search({ query: 'x', type: 'album', page: 1, pageSize: 5 });
    expect(a.items[0]).toMatchObject({ id: 'album:5', type: 'album', title: 'Discovery', previewUrl: null });
    expect(new URL(albums.calls[0]!.url).searchParams.get('entity')).toBe('album');
    const artists = scripted(() => resp({ results: [{ artistId: 9, artistName: 'Daft Punk', artistLinkUrl: 'https://music.apple.com/ar', primaryGenreName: 'Dance' }] }));
    const r = await createItunesProvider(artists.fn).search({ query: 'x', type: 'artist', page: 1, pageSize: 5 });
    expect(r.items[0]).toMatchObject({ id: 'artist:9', title: 'Daft Punk' });
    expect(new URL(artists.calls[0]!.url).searchParams.get('entity')).toBe('musicArtist');
    expect(Object.keys(a.items[0]!)).not.toContain('downloadUrl');
  });

  it('maps upstream failures and malformed answers', async () => {
    await expect(createItunesProvider(scripted(() => resp({}, 503)).fn).search({ query: 'x', type: 'song', page: 1, pageSize: 5 })).rejects.toMatchObject({ code: 'PROVIDER_ERROR' });
    await expect(createItunesProvider(scripted(() => resp({ nope: 1 })).fn).search({ query: 'x', type: 'song', page: 1, pageSize: 5 })).rejects.toMatchObject({ code: 'PROVIDER_BAD_RESPONSE' });
    await expect(createItunesProvider(scripted(() => resp('<html>')).fn).search({ query: 'x', type: 'song', page: 1, pageSize: 5 })).rejects.toBeInstanceOf(ProviderError);
    const timeout: SafeFn = async () => { throw new SafeFetchError('TIMEOUT', 't'); };
    await expect(createItunesProvider(timeout).search({ query: 'x', type: 'song', page: 1, pageSize: 5 })).rejects.toMatchObject({ code: 'PROVIDER_TIMEOUT' });
  });
});

describe('Anthropic provider request shape', () => {
  it('sends the documented headers/body and returns the text blocks', async () => {
    const s = scripted(() => resp({ content: [{ type: 'text', text: 'Bonjour' }, { type: 'tool_use' }, { type: 'text', text: ' monde' }] }));
    const out = await createAnthropicProvider('sk-test-key', 'model-x', s.fn).complete({ system: 'sys', user: 'hi', maxTokens: 50 });
    expect(out).toBe('Bonjour monde');
    const c = s.calls[0]!;
    expect(c.url).toBe('https://api.anthropic.com/v1/messages');
    expect(c.opts).toMatchObject({ method: 'POST', allowedHosts: ['api.anthropic.com'] });
    expect(c.opts.headers['x-api-key']).toBe('sk-test-key');
    expect(c.opts.headers['anthropic-version']).toBe('2023-06-01');
    expect(JSON.parse(c.opts.body)).toEqual({ model: 'model-x', max_tokens: 50, system: 'sys', messages: [{ role: 'user', content: 'hi' }] });
  });
  it('maps empty answers, quota and errors without leaking the key', async () => {
    await expect(createAnthropicProvider('k', 'm', scripted(() => resp({ content: [] })).fn).complete({ system: '', user: 'x', maxTokens: 5 })).rejects.toMatchObject({ code: 'PROVIDER_BAD_RESPONSE' });
    await expect(createAnthropicProvider('k', 'm', scripted(() => resp({}, 429)).fn).complete({ system: '', user: 'x', maxTokens: 5 })).rejects.toMatchObject({ code: 'AI_BUSY', status: 503 });
    const e = await createAnthropicProvider('sk-secret', 'm', scripted(() => resp({ error: 'sk-secret' }, 401)).fn).complete({ system: '', user: 'x', maxTokens: 5 }).catch((x) => x);
    expect(e).toMatchObject({ code: 'PROVIDER_ERROR' });
    expect(e.message).not.toContain('sk-secret');
  });
});
