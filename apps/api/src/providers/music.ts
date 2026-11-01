import { z } from 'zod';
import type { Env } from '../config/env.js';
import { validateExternalUrl } from '../net/ipGuard.js';
import { safeFetch } from '../net/safeFetch.js';
import { mapFetchError, type SafeFn } from './facebook.js';
import { ProviderError, type MusicItem, type MusicProvider, type MusicType } from './types.js';

const schema = z.object({ resultCount: z.number().optional(), results: z.array(z.record(z.string(), z.unknown())) });
const httpsOrNull = (u: unknown): string | null => {
  if (typeof u !== 'string') return null;
  try { return validateExternalUrl(u).toString(); } catch { return null; }
};
const str = (v: unknown, max = 200): string | null => (typeof v === 'string' && v.length > 0 ? v.slice(0, max) : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const ENTITY: Record<MusicType, string> = { song: 'song', album: 'album', artist: 'musicArtist' };

/**
 * Apple's public Search API (https://developer.apple.com/library/archive/documentation/AudioVideo/Conceptual/iTuneSearchAPI/).
 * Metadata, artwork, 30-second previews and links to Apple Music only. It never provides full-length downloads.
 * NOT yet exercised against the live API from the build sandbox: tests use fixtures that follow its documented fields.
 */
export function createItunesProvider(safe: SafeFn = safeFetch): MusicProvider {
  return {
    id: 'itunes', label: 'Apple Music (aperçus)', configured: true,
    async search({ query, type, page, pageSize }) {
      const qs = new URLSearchParams({ term: query, media: 'music', entity: ENTITY[type], limit: String(pageSize), offset: String((page - 1) * pageSize) });
      try {
        const res = await safe(`https://itunes.apple.com/search?${qs}`, { allowedHosts: ['itunes.apple.com'], contentType: /json|javascript/i, maxBytes: 2_000_000, timeoutMs: 10_000, headers: { Accept: 'application/json' } });
        if (res.status === 429 || res.status >= 500) throw new ProviderError(502, 'PROVIDER_ERROR', 'The music service is temporarily unavailable.');
        if (res.status >= 400) throw new ProviderError(502, 'PROVIDER_ERROR', 'The music service refused the request.');
        const parsed = schema.safeParse(res.json());
        if (!parsed.success) throw new ProviderError(502, 'PROVIDER_BAD_RESPONSE', 'The music service returned an unexpected answer.');
        const items: MusicItem[] = [];
        for (const r of parsed.data.results.slice(0, pageSize)) {
          const art = httpsOrNull(r.artworkUrl100)?.replace(/\/\d+x\d+bb\./, '/600x600bb.') ?? null;
          if (type === 'song' && num(r.trackId) !== null) {
            items.push({ id: `track:${r.trackId}`, type, title: str(r.trackName) ?? 'Sans titre', artist: str(r.artistName), album: str(r.collectionName), artwork: art, previewUrl: httpsOrNull(r.previewUrl), url: httpsOrNull(r.trackViewUrl), durationMs: num(r.trackTimeMillis), releaseDate: str(r.releaseDate, 40), genre: str(r.primaryGenreName, 60) });
          } else if (type === 'album' && num(r.collectionId) !== null) {
            items.push({ id: `album:${r.collectionId}`, type, title: str(r.collectionName) ?? 'Sans titre', artist: str(r.artistName), album: null, artwork: art, previewUrl: null, url: httpsOrNull(r.collectionViewUrl), durationMs: null, releaseDate: str(r.releaseDate, 40), genre: str(r.primaryGenreName, 60) });
          } else if (type === 'artist' && num(r.artistId) !== null) {
            items.push({ id: `artist:${r.artistId}`, type, title: str(r.artistName) ?? 'Inconnu', artist: null, album: null, artwork: null, previewUrl: null, url: httpsOrNull(r.artistLinkUrl), durationMs: null, releaseDate: null, genre: str(r.primaryGenreName, 60) });
          }
        }
        return { items, page, pageSize, hasMore: parsed.data.results.length >= pageSize };
      } catch (e) { throw mapFetchError(e); }
    },
  };
}

export function createMusicProvider(env: Env, safe?: SafeFn): MusicProvider {
  if (env.MUSIC_PROVIDER === 'itunes') return createItunesProvider(safe);
  return {
    id: 'none', label: 'Recherche musicale', configured: false,
    notConfiguredReason: 'No music provider is configured (set MUSIC_PROVIDER).',
    async search() { throw new ProviderError(503, 'SERVICE_NOT_CONFIGURED', 'Music search is not connected.'); },
  };
}
