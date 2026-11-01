import { z } from 'zod';
import type { Repos, UserRecord } from '../repositories/types.js';
import { Limiter } from '../net/safeFetch.js';
import { ProviderError, type MediaProvider, type MediaResult, type MediaToolId, type MusicProvider } from '../providers/types.js';
import type { ProviderHealth } from '../providers/health.js';
import { validateExternalUrl } from '../net/ipGuard.js';
import { coded, notFound } from '../utils/errors.js';
import { AppError } from '../utils/errors.js';
import { adSlot, type SettingsService } from './settings.service.js';
import type { MeService } from './me.service.js';

export const JOB_TTL_MS = 15 * 60_000;

export const analyzeSchema = z.object({ url: z.string().trim().min(8).max(2048) }).strict();
export const searchSchema = z.object({
  q: z.string().trim().min(1).max(100),
  type: z.enum(['song', 'album', 'artist']).default('song'),
  page: z.coerce.number().int().min(1).max(20).default(1),
  pageSize: z.coerce.number().int().min(1).max(25).default(10),
});

export interface ToolsDeps {
  repos: Repos; settings: SettingsService; me: MeService; health: ProviderHealth;
  media: MediaProvider[]; music: MusicProvider; now?: () => Date; maxConcurrent?: number;
}

const safeMessage = (e: unknown) => (e instanceof ProviderError ? e.message : 'Unexpected error').replace(/https?:\/\/\S+/g, '[url]').slice(0, 200);

export function createToolsService(deps: ToolsDeps) {
  const { repos, health } = deps;
  const now = deps.now ?? (() => new Date());
  const limiters = new Map<string, Limiter>();
  const limiterFor = (id: string) => { let l = limiters.get(id); if (!l) { l = new Limiter(deps.maxConcurrent ?? 4); limiters.set(id, l); } return l; };
  const byId = new Map(deps.media.map((p) => [p.id as string, p]));

  /** Runs a provider call with a concurrency cap, health metrics, usage counters and error tracking. */
  async function guarded<T>(toolId: string, userId: string | null, fn: () => Promise<T>): Promise<T> {
    const release = limiterFor(toolId).tryAcquire();
    if (!release) throw new AppError(503, 'BUSY', 'This tool is busy right now. Please try again in a moment.');
    const t0 = Date.now();
    try {
      const out = await fn();
      health.record(toolId, true, Date.now() - t0, null, now());
      await repos.toolEvents.create({ tool: toolId, ok: true, userId, at: now() }).catch(() => {});
      return out;
    } catch (e) {
      const code = e instanceof ProviderError ? e.code : 'INTERNAL';
      health.record(toolId, false, Date.now() - t0, code, now());
      await repos.toolEvents.create({ tool: toolId, ok: false, userId, code, at: now() }).catch(() => {});
      if (e instanceof ProviderError && e.status >= 500 && e.code !== 'SERVICE_NOT_CONFIGURED') {
        await repos.errors.create({ source: 'provider', code, route: toolId, message: safeMessage(e) }).catch(() => {});
      }
      if (e instanceof ProviderError) throw new AppError(e.status, e.code, e.message);
      throw e;
    } finally { release(); }
  }

  async function ensureAvailable(id: string, configured: boolean, reason: string | undefined) {
    const s = await deps.settings.get();
    if (!(s.tools as Record<string, boolean>)[id]) throw new AppError(503, 'TOOL_DISABLED', 'This tool is currently disabled.');
    if (!configured) throw new AppError(503, 'SERVICE_NOT_CONFIGURED', reason ?? 'This service is not connected yet.');
    return s;
  }

  return {
    /** Public catalogue: real availability, never a promise the server cannot keep. */
    async list() {
      const s = await deps.settings.get();
      const row = (id: string, label: string, kind: 'download' | 'search', configured: boolean, reason?: string) => {
        const enabled = (s.tools as Record<string, boolean>)[id] ?? false;
        return { id, label, kind, enabled, configured, available: enabled && configured, ...(reason && !configured ? { reason } : {}) };
      };
      return { items: [...deps.media.map((p) => row(p.id, p.label, 'download', p.configured, p.notConfiguredReason)), row('music', 'Musique', 'search', deps.music.configured, deps.music.notConfiguredReason)] };
    },

    async analyze(toolId: string, rawUrl: string, user: UserRecord | null) {
      const provider = byId.get(toolId);
      if (!provider) throw notFound('Unknown tool');
      const settings = await ensureAvailable(provider.id, provider.configured, provider.notConfiguredReason);
      let host: string;
      try { host = validateExternalUrl(rawUrl, { allowedHosts: provider.hosts }).hostname; }
      catch { throw new AppError(400, 'INVALID_LINK', `This is not a valid ${provider.label} link.`); }
      let result: MediaResult;
      try {
        result = await guarded(provider.id, user?.id ?? null, () => provider.analyze(rawUrl));
      } catch (e) {
        if (user) await deps.me.recordHistory(user, { kind: 'OPERATION', tool: provider.id, query: host, title: null, status: 'FAILED' });
        throw e;
      }
      const t = now();
      const wait = settings.ads.enabled ? settings.ads.waitSeconds : 0;
      const readyAt = new Date(t.getTime() + wait * 1000);
      const job = await repos.jobs.create({ tool: provider.id, userId: user?.id ?? null, result, readyAt, expiresAt: new Date(t.getTime() + JOB_TTL_MS + wait * 1000) });
      if (user) await deps.me.recordHistory(user, { kind: 'OPERATION', tool: provider.id, query: host, title: result.title, status: 'SUCCESS' });
      // The download links are NOT in this answer: they are released by claim() once the wait is over.
      return {
        jobId: job.id, platform: result.platform, title: result.title, thumbnail: result.thumbnail, author: result.author,
        formats: result.downloads.map((d) => ({ label: d.label, format: d.format, quality: d.quality })),
        ads: { required: wait > 0, waitSeconds: wait, slot: wait > 0 ? adSlot(settings.ads) : null }, readyAt: readyAt.toISOString(), expiresAt: job.expiresAt.toISOString(),
      };
    },

    /** Releases the download links, but only after the server-side wait (ad time) has fully elapsed. */
    async claim(jobId: string, user: UserRecord | null) {
      const job = /^[a-f0-9]{24}$/i.test(jobId) ? await repos.jobs.findById(jobId) : null;
      const t = now();
      if (!job || job.expiresAt <= t || (job.userId && job.userId !== user?.id)) throw notFound('This download has expired. Please analyse the link again.');
      if (job.readyAt > t) {
        throw coded(409, 'AD_NOT_FINISHED', 'Please wait for the end of the countdown.', { retryAfter: Math.max(1, Math.ceil((job.readyAt.getTime() - t.getTime()) / 1000)) });
      }
      const result = job.result as MediaResult;
      return { title: result.title, downloads: result.downloads, expiresAt: job.expiresAt.toISOString() };
    },

    async search(input: z.infer<typeof searchSchema>, user: UserRecord | null) {
      const { music } = deps;
      await ensureAvailable('music', music.configured, music.notConfiguredReason);
      let out;
      try { out = await guarded('music', user?.id ?? null, () => music.search({ query: input.q, type: input.type, page: input.page, pageSize: input.pageSize })); }
      catch (e) {
        if (user) await deps.me.recordHistory(user, { kind: 'SEARCH', tool: 'music', query: input.q, title: null, status: 'FAILED' });
        throw e;
      }
      if (user && input.page === 1) await deps.me.recordHistory(user, { kind: 'SEARCH', tool: 'music', query: input.q, title: null, status: 'SUCCESS' });
      return { provider: music.id, ...out };
    },

    /** Admin view: availability + real counters from actual calls. */
    async overview() {
      const s = await deps.settings.get();
      const since = (h: number) => new Date(now().getTime() - h * 3_600_000);
      const [d1, d7] = await Promise.all([repos.toolEvents.summary(since(24)), repos.toolEvents.summary(since(24 * 7))]);
      const pick = (rows: typeof d1, id: string) => { const r = rows.find((x) => x.tool === id); return { total: r?.total ?? 0, failed: r?.failed ?? 0 }; };
      const mk = (id: string, label: string, configured: boolean, reason?: string) => ({
        id, label, enabled: (s.tools as Record<string, boolean>)[id] ?? false, configured, ...(reason ? { reason } : {}),
        last24h: pick(d1, id), last7d: pick(d7, id), live: health.get(id),
      });
      return { items: [...deps.media.map((p) => mk(p.id, p.label, p.configured, p.notConfiguredReason)), mk('music', 'Musique', deps.music.configured, deps.music.notConfiguredReason)] };
    },
  };
}
export type ToolsService = ReturnType<typeof createToolsService>;
export type { MediaToolId };
