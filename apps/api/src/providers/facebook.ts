import { z } from 'zod';
import type { Env } from '../config/env.js';
import { SsrfError, validateExternalUrl } from '../net/ipGuard.js';
import { SafeFetchError, safeFetch, type SafeFetchOptions, type SafeResponse } from '../net/safeFetch.js';
import { ProviderError, type MediaDownload, type MediaProvider, type MediaResult, type MediaToolId } from './types.js';

export type SafeFn = (url: string, opts?: SafeFetchOptions) => Promise<SafeResponse>;

const responseSchema = z.object({
  status: z.boolean(),
  data: z.object({
    title: z.string().optional(),
    thumbnail: z.string().optional(),
    data: z.array(z.object({ resolution: z.string().optional(), format: z.string().optional(), url: z.string() }).passthrough()),
  }).passthrough(),
}).passthrough();

const httpsOrNull = (u: string | undefined): string | null => {
  if (!u) return null;
  try { return validateExternalUrl(u).toString(); } catch { return null; }
};

/** Maps a failed outbound call to a stable API error (no internal detail leaked). */
export function mapFetchError(e: unknown): ProviderError {
  if (e instanceof ProviderError) return e;
  if (e instanceof SsrfError) return new ProviderError(400, 'INVALID_LINK', 'This link cannot be used.');
  if (e instanceof SafeFetchError) {
    if (e.code === 'INVALID_URL' || e.code === 'BLOCKED_ADDRESS') return new ProviderError(400, 'INVALID_LINK', 'This link cannot be used.');
    if (e.code === 'TIMEOUT') return new ProviderError(504, 'PROVIDER_TIMEOUT', 'The service took too long to answer.');
    if (e.code === 'TOO_LARGE' || e.code === 'BAD_CONTENT_TYPE') return new ProviderError(502, 'PROVIDER_BAD_RESPONSE', 'The service returned an unexpected answer.');
    return new ProviderError(502, 'PROVIDER_ERROR', 'The service is unreachable.');
  }
  return new ProviderError(502, 'PROVIDER_ERROR', 'The service failed.');
}

/**
 * Facebook via the siputzx endpoint used in the supplied bot code:
 *   GET {base}/api/d/facebook?url=<link>  ->  { status, data: { title, data: [{ resolution: 'HD'|'SD', format: 'mp4', url }] } }
 * Short/share links are resolved first (redirects re-validated). NOT yet verified against the live service from the build sandbox
 * (outbound network was blocked there): the parser is exercised with fixtures that follow the response shape of the supplied code.
 */
export function createFacebookProvider(env: Env, safe: SafeFn = safeFetch): MediaProvider {
  const hosts = ['facebook.com', 'fb.watch', 'fb.me'];
  const endpoint = (target: string) => `${env.SIPUTZX_BASE_URL.replace(/\/$/, '')}${env.FACEBOOK_API_PATH}?url=${encodeURIComponent(target)}`;

  async function callApi(target: string): Promise<MediaResult | null> {
    const res = await safe(endpoint(target), { contentType: /json/i, maxBytes: 1_000_000, timeoutMs: 20_000, headers: { Accept: 'application/json', 'User-Agent': 'MediaHub/1.0' } });
    if (res.status >= 500 || res.status === 429) throw new ProviderError(502, 'PROVIDER_ERROR', 'The service is temporarily unavailable.');
    let parsed;
    try { parsed = responseSchema.safeParse(res.json()); } catch { throw new ProviderError(502, 'PROVIDER_BAD_RESPONSE', 'The service returned an unexpected answer.'); }
    if (res.status >= 400) return null;
    if (!parsed.success) throw new ProviderError(502, 'PROVIDER_BAD_RESPONSE', 'The service returned an unexpected answer.');
    if (!parsed.data.status) return null;
    const downloads: MediaDownload[] = [];
    for (const it of parsed.data.data.data.slice(0, 20)) {
      const url = httpsOrNull(it.url);
      const format = (it.format ?? 'mp4').toLowerCase();
      if (!url || format !== 'mp4') continue;
      const q = it.resolution?.toUpperCase() ?? null;
      downloads.push({ label: q ? `Vidéo ${q}` : 'Vidéo', format, quality: q, url });
    }
    downloads.sort((a, b) => (a.quality === 'HD' ? 0 : 1) - (b.quality === 'HD' ? 0 : 1));
    if (downloads.length === 0) return null;
    return { platform: 'facebook', title: parsed.data.data.title?.slice(0, 200) || 'Vidéo Facebook', thumbnail: httpsOrNull(parsed.data.data.thumbnail), author: null, downloads };
  }

  return {
    id: 'facebook', label: 'Facebook', hosts, configured: true,
    async analyze(link: string) {
      try {
        validateExternalUrl(link, { allowedHosts: hosts });
        let resolved = link;
        try {
          resolved = (await safe(link, { allowedHosts: hosts, maxRedirects: 5, noBody: true, timeoutMs: 10_000, headers: { 'User-Agent': 'Mozilla/5.0' } })).finalUrl;
        } catch (e) {
          if (e instanceof SafeFetchError && !['TIMEOUT', 'NETWORK'].includes(e.code)) throw e; // unusable link: stop. Slow/unreachable: try the original link
        }
        let result = await callApi(resolved).catch((e) => { if (resolved === link) throw e; return null; });
        if (!result && resolved !== link) result = await callApi(link);
        if (!result) throw new ProviderError(422, 'NO_MEDIA', 'No downloadable video was found. It may be private, deleted or unsupported.');
        return result;
      } catch (e) { throw mapFetchError(e); }
    },
  };
}

/** TikTok / Instagram: no endpoint or response format has been provided yet, so these report themselves as not connected. */
export function createUnconnectedProvider(id: MediaToolId, label: string, hosts: string[], reason?: string): MediaProvider {
  return {
    id, label, hosts, configured: false,
    notConfiguredReason: reason ?? `No ${label} integration has been provided yet (endpoint and response format required).`,
    async analyze() { throw new ProviderError(503, 'SERVICE_NOT_CONFIGURED', `${label} is not connected yet.`); },
  };
}
