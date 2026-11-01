import { z } from 'zod';
import type { Repos } from '../repositories/types.js';
import { badRequest } from '../utils/errors.js';

const tools = z.object({ tiktok: z.boolean(), instagram: z.boolean(), facebook: z.boolean(), music: z.boolean() }).strict();
/** Formats de bannière Adsterra (largeur x hauteur) acceptés. */
export const BANNER_SIZES = ['300x250', '728x90', '468x60', '320x50', '160x600', '160x300'] as const;
const HOST = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/;
const ads = z.object({
  enabled: z.boolean(), waitSeconds: z.number().int().min(0).max(30), homeSlotEnabled: z.boolean(),
  /** Réseau publicitaire. `none` = décompte seul, sans bannière. */
  provider: z.enum(['none', 'adsterra']),
  /** Clé de la bannière Adsterra (32 caractères hexadécimaux). Identifiant public, pas un secret. */
  bannerKey: z.string().trim().toLowerCase().regex(/^[a-f0-9]{32}$/, 'Clé de bannière invalide (32 caractères hexadécimaux)').or(z.literal('')),
  /** Domaine qui sert invoke.js (celui du code Adsterra), sans https ni chemin. */
  bannerHost: z.string().trim().toLowerCase().regex(HOST, 'Domaine invalide (exemple : www.exemple.com)').or(z.literal('')),
  bannerSize: z.enum(BANNER_SIZES),
}).strict();
export const settingsShape = { tools, ads };
export type Settings = { tools: z.infer<typeof tools>; ads: z.infer<typeof ads> };

export const DEFAULT_SETTINGS: Settings = {
  tools: { tiktok: true, instagram: true, facebook: true, music: true },
  // Ads are OFF until an administrator turns them on.
  ads: { enabled: false, waitSeconds: 5, homeSlotEnabled: false, provider: 'none', bannerKey: '', bannerHost: '', bannerSize: '300x250' },
};

export const settingsPatchSchema = z.object({ tools: tools.partial().optional(), ads: ads.partial().optional() }).strict()
  .refine((v) => v.tools !== undefined || v.ads !== undefined, 'Nothing to update');

/** Un réseau choisi doit être complet : sinon la page afficherait un emplacement vide. */
function assertAdsConsistent(a: z.infer<typeof ads>) {
  if (a.provider === 'adsterra' && (!a.bannerKey || !a.bannerHost)) throw badRequest('Adsterra needs a banner key and a domain.', { bannerKey: a.bannerKey ? [] : ['Required'], bannerHost: a.bannerHost ? [] : ['Required'] });
  if (a.homeSlotEnabled && a.provider === 'none') throw badRequest('The home slot needs an ad provider.', { homeSlotEnabled: ['Choose a provider first'] });
}

export type AdSlot = { provider: 'adsterra'; key: string; host: string; width: number; height: number };
/** Emplacement publicitaire prêt à afficher, ou null (pas de réseau, ou configuration incomplète). */
export function adSlot(a: z.infer<typeof ads>): AdSlot | null {
  if (a.provider !== 'adsterra' || !a.bannerKey || !a.bannerHost) return null;
  const [w, h] = a.bannerSize.split('x').map(Number) as [number, number];
  return { provider: 'adsterra', key: a.bannerKey, host: a.bannerHost, width: w, height: h };
}

export function createSettingsService(repos: Repos, now: () => Date = () => new Date()) {
  let cache: { at: number; value: Settings } | null = null;
  const TTL = 5_000;

  async function load(): Promise<Settings> {
    const raw = await repos.settings.getAll();
    const t = tools.safeParse({ ...DEFAULT_SETTINGS.tools, ...(raw.tools as object | undefined) });
    const a = ads.safeParse({ ...DEFAULT_SETTINGS.ads, ...(raw.ads as object | undefined) });
    return { tools: t.success ? t.data : DEFAULT_SETTINGS.tools, ads: a.success ? a.data : DEFAULT_SETTINGS.ads };
  }
  return {
    async get(): Promise<Settings> {
      if (cache && now().getTime() - cache.at < TTL) return cache.value;
      const value = await load();
      cache = { at: now().getTime(), value };
      return value;
    },
    async update(actorId: string, patch: z.infer<typeof settingsPatchSchema>): Promise<Settings> {
      const cur = await load();
      const next: Settings = { tools: { ...cur.tools, ...patch.tools }, ads: { ...cur.ads, ...patch.ads } };
      if (patch.ads !== undefined) assertAdsConsistent(next.ads);
      const changed: string[] = [];
      for (const k of ['tools', 'ads'] as const) {
        if (patch[k] !== undefined) { await repos.settings.set(k, next[k], actorId); changed.push(k); }
      }
      await repos.audit.create({ actorId, action: 'ADMIN_SETTINGS_CHANGED', metadata: { keys: changed.join(',') } });
      cache = null;
      return next;
    },
    /** What the public front-end may know. */
    async publicView() {
      const s = await this.get();
      return { tools: s.tools, ads: { enabled: s.ads.enabled, waitSeconds: s.ads.waitSeconds, homeSlotEnabled: s.ads.homeSlotEnabled && s.ads.enabled, slot: s.ads.enabled ? adSlot(s.ads) : null } };
    },
  };
}
export type SettingsService = ReturnType<typeof createSettingsService>;
