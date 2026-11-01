import { z } from 'zod';
import type { Env } from '../config/env.js';
import { validateExternalUrl } from '../net/ipGuard.js';
import { safeFetch } from '../net/safeFetch.js';
import { mapFetchError, createUnconnectedProvider, type SafeFn } from './facebook.js';
import { ProviderError, type MediaDownload, type MediaProvider, type MediaResult } from './types.js';

const httpsOrNull = (u: unknown): string | null => {
  if (typeof u !== 'string' || !u) return null;
  try { return validateExternalUrl(u).toString(); } catch { return null; }
};
const explicitFailure = (raw: unknown) => typeof raw === 'object' && raw !== null && ((raw as { success?: unknown }).success === false || (raw as { Status?: unknown }).Status === false);
const sizeLabel = (bytes: unknown) => (typeof bytes === 'number' && bytes > 0 ? ` · ${(bytes / 1_048_576).toLocaleString('fr-FR', { maximumFractionDigits: 1 })} Mo` : '');

const tiktokSchema = z.object({
  success: z.boolean(),
  result: z.object({
    code: z.number().optional(),
    data: z.object({
      title: z.string().optional(), cover: z.string().optional(), origin_cover: z.string().optional(),
      play: z.string().optional(), hdplay: z.string().optional(), music: z.string().optional(),
      size: z.number().optional(), hd_size: z.number().optional(),
      author: z.object({ unique_id: z.string().optional(), nickname: z.string().optional() }).passthrough().optional(),
    }).passthrough(),
  }).passthrough(),
}).passthrough();

const instagramSchema = z.object({
  success: z.boolean(),
  result: z.array(z.object({ type: z.string().optional(), url: z.string() }).passthrough()),
}).passthrough();

/** Appelle l'API WhiteShadow. Le jeton est dans l'URL (exigence de l'API) : jamais journalisé, jamais renvoyé, absent des messages d'erreur. */
function endpoint(env: Env, path: string, link: string): string {
  return `${env.WHITESHADOW_BASE_URL.replace(/\/$/, '')}${path}?url=${encodeURIComponent(link)}&apitoken=${encodeURIComponent(env.WHITESHADOW_API_TOKEN!)}`;
}
async function call(env: Env, safe: SafeFn, path: string, link: string): Promise<unknown> {
  const res = await safe(endpoint(env, path, link), { contentType: /json/i, maxBytes: 1_000_000, timeoutMs: 25_000, headers: { Accept: 'application/json', 'User-Agent': 'MediaHub/1.0' } });
  if (res.status === 401 || res.status === 403) throw new ProviderError(503, 'SERVICE_NOT_CONFIGURED', 'The download service refused our credentials.');
  if (res.status === 429) throw new ProviderError(502, 'PROVIDER_ERROR', 'The service is busy. Please retry shortly.');
  if (res.status >= 500) throw new ProviderError(502, 'PROVIDER_ERROR', 'The service is temporarily unavailable.');
  let body: unknown;
  try { body = res.json(); } catch { throw new ProviderError(502, 'PROVIDER_BAD_RESPONSE', 'The service returned an unexpected answer.'); }
  if (res.status >= 400) return null;
  return body;
}

export function createTikTokProvider(env: Env, safe: SafeFn = safeFetch): MediaProvider {
  const hosts = ['tiktok.com'];
  if (!env.WHITESHADOW_API_TOKEN) return createUnconnectedProvider('tiktok', 'TikTok', hosts, 'WHITESHADOW_API_TOKEN is not set.');
  return {
    id: 'tiktok', label: 'TikTok', hosts, configured: true,
    async analyze(link: string): Promise<MediaResult> {
      try {
        validateExternalUrl(link, { allowedHosts: hosts });
        const raw = await call(env, safe, '/api/download/tiktok', link);
        const parsed = tiktokSchema.safeParse(raw);
        if (raw === null || explicitFailure(raw) || (parsed.success && (!parsed.data.success || (parsed.data.result.code ?? 0) !== 0))) throw new ProviderError(422, 'NO_MEDIA', 'No downloadable video was found. It may be private, deleted or unsupported.');
        if (!parsed.success) throw new ProviderError(502, 'PROVIDER_BAD_RESPONSE', 'The service returned an unexpected answer.');
        const d = parsed.data.result.data;
        const downloads: MediaDownload[] = [];
        const hd = httpsOrNull(d.hdplay), sd = httpsOrNull(d.play), audio = httpsOrNull(d.music);
        if (hd) downloads.push({ label: `Vidéo HD${sizeLabel(d.hd_size)}`, format: 'mp4', quality: 'HD', url: hd });
        if (sd && sd !== hd) downloads.push({ label: `Vidéo standard${sizeLabel(d.size)}`, format: 'mp4', quality: 'SD', url: sd });
        if (audio) downloads.push({ label: 'Audio', format: 'mp3', quality: null, url: audio });
        if (downloads.length === 0) throw new ProviderError(422, 'NO_MEDIA', 'No downloadable video was found. It may be private, deleted or unsupported.');
        const who = d.author?.unique_id ? `@${d.author.unique_id}` : d.author?.nickname ?? null;
        return { platform: 'tiktok', title: (d.title ?? '').trim().slice(0, 200) || 'Vidéo TikTok', thumbnail: httpsOrNull(d.cover) ?? httpsOrNull(d.origin_cover), author: who, downloads };
      } catch (e) { throw mapFetchError(e); }
    },
  };
}

export function createInstagramProvider(env: Env, safe: SafeFn = safeFetch): MediaProvider {
  const hosts = ['instagram.com'];
  if (!env.WHITESHADOW_API_TOKEN) return createUnconnectedProvider('instagram', 'Instagram', hosts, 'WHITESHADOW_API_TOKEN is not set.');
  return {
    id: 'instagram', label: 'Instagram', hosts, configured: true,
    async analyze(link: string): Promise<MediaResult> {
      try {
        validateExternalUrl(link, { allowedHosts: hosts });
        const raw = await call(env, safe, '/api/download/ig', link);
        const parsed = instagramSchema.safeParse(raw);
        if (raw === null || explicitFailure(raw) || (parsed.success && !parsed.data.success)) throw new ProviderError(422, 'NO_MEDIA', 'No downloadable media was found. It may be private, deleted or unsupported.');
        if (!parsed.success) throw new ProviderError(502, 'PROVIDER_BAD_RESPONSE', 'The service returned an unexpected answer.');
        const seen = new Set<string>();
        const items: { kind: 'video' | 'image'; url: string }[] = [];
        for (const it of parsed.data.result.slice(0, 20)) {
          const url = httpsOrNull(it.url);
          if (!url || seen.has(url)) continue;
          seen.add(url);
          items.push({ kind: (it.type ?? 'video').toLowerCase() === 'image' ? 'image' : 'video', url });
        }
        const downloads: MediaDownload[] = items.map((it, i, all) => {
          const same = all.filter((x) => x.kind === it.kind);
          const n = same.indexOf(it) + 1;
          const noun = it.kind === 'video' ? 'Vidéo' : 'Image';
          return { label: same.length > 1 ? `${noun} ${n}` : noun, format: it.kind === 'video' ? 'mp4' : 'jpg', quality: null, url: it.url };
        });
        if (downloads.length === 0) throw new ProviderError(422, 'NO_MEDIA', 'No downloadable media was found. It may be private, deleted or unsupported.');
        return { platform: 'instagram', title: 'Publication Instagram', thumbnail: null, author: null, downloads };
      } catch (e) { throw mapFetchError(e); }
    },
  };
}

/**
 * Facebook via WhiteShadow (/api/download/fb). Seule la forme d'ERREUR a été observée : { Status:false, Code:400, Input, Result:[] }.
 * La forme d'un succès n'a pas pu être vérifiée : l'analyse est donc tolérante (Result tableau ou objet, clés url/link/download/hd/sd).
 * Tout ce qui n'est pas une URL https est ignoré ; sans lien exploitable → NO_MEDIA.
 */
const str = (v: unknown): string | undefined => (typeof v === 'string' && v.trim() ? v.trim() : undefined);
const rec = (v: unknown): Record<string, unknown> | null => (typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null);

export function parseFacebookResult(raw: unknown): { title: string | null; thumbnail: string | null; downloads: MediaDownload[] } {
  const root = rec(raw) ?? {};
  const result = root.Result ?? root.result ?? root.data;
  const resObj = rec(result);
  const candidates: unknown[] = Array.isArray(result) ? result : resObj ? (Array.isArray(resObj.data) ? resObj.data : Array.isArray(resObj.links) ? resObj.links : [resObj]) : [];
  const downloads: MediaDownload[] = [];
  const seen = new Set<string>();
  const add = (urlRaw: unknown, qualityRaw: unknown) => {
    const url = httpsOrNull(urlRaw);
    if (!url || seen.has(url)) return;
    seen.add(url);
    const q = str(qualityRaw)?.toUpperCase().slice(0, 12) ?? null;
    downloads.push({ label: q ? `Vidéo ${q}` : 'Vidéo', format: 'mp4', quality: q, url });
  };
  for (const c of candidates.slice(0, 20)) {
    if (typeof c === 'string') { add(c, null); continue; }
    const o = rec(c); if (!o) continue;
    const kind = str(o.type)?.toLowerCase();
    if (kind && /^(image|audio|photo)/.test(kind)) continue;
    add(o.url ?? o.link ?? o.download ?? o.src, o.quality ?? o.resolution ?? o.res ?? o.label);
    if (!(o.url ?? o.link ?? o.download ?? o.src)) { add(o.hd, 'HD'); add(o.sd, 'SD'); }
  }
  const t = str(root.Title) ?? str(root.title) ?? str(resObj?.title) ?? str(resObj?.Title);
  return { title: t ? t.slice(0, 200) : null, thumbnail: httpsOrNull(root.Thumbnail ?? root.thumbnail ?? resObj?.thumbnail ?? resObj?.thumb), downloads };
}

export function createWhiteShadowFacebookProvider(env: Env, safe: SafeFn = safeFetch): MediaProvider {
  const hosts = ['facebook.com', 'fb.watch', 'fb.me'];
  if (!env.WHITESHADOW_API_TOKEN) return createUnconnectedProvider('facebook', 'Facebook', hosts, 'WHITESHADOW_API_TOKEN is not set.');
  return {
    id: 'facebook', label: 'Facebook', hosts, configured: true,
    async analyze(link: string): Promise<MediaResult> {
      try {
        validateExternalUrl(link, { allowedHosts: hosts });
        const raw = await call(env, safe, '/api/download/fb', link);
        if (raw === null || explicitFailure(raw)) throw new ProviderError(422, 'NO_MEDIA', 'No downloadable video was found. It may be private, deleted or unsupported.');
        const p = parseFacebookResult(raw);
        if (p.downloads.length === 0) throw new ProviderError(422, 'NO_MEDIA', 'No downloadable video was found. It may be private, deleted or unsupported.');
        return { platform: 'facebook', title: p.title ?? 'Vidéo Facebook', thumbnail: p.thumbnail, author: null, downloads: p.downloads };
      } catch (e) { throw mapFetchError(e); }
    },
  };
}
