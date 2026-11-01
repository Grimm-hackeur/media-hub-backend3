import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { HistoryRecord, ItemKind, Repos, SavedItem, UserRecord } from '../repositories/types.js';
import { validateExternalUrl } from '../net/ipGuard.js';
import { badRequest, conflict, DuplicateError, notFound } from '../utils/errors.js';
import { AppError } from '../utils/errors.js';
import { usernameSchema } from '../schemas/auth.js';

export const LIMITS = { favorites: 500, collections: 50, itemsPerCollection: 200 } as const;

const httpsUrl = z.string().max(2048).refine((u) => { try { validateExternalUrl(u); return true; } catch { return false; } }, 'Must be a public https URL');
export const savedItemSchema = z.object({
  kind: z.enum(['TRACK', 'ALBUM', 'LINK']),
  /** Provider id (tracks/albums). Ignored for LINK, where the URL itself is the identity. */
  externalId: z.string().regex(/^[A-Za-z0-9:_-]{1,64}$/).optional(),
  title: z.string().trim().min(1).max(200),
  subtitle: z.string().trim().max(200).nullish(),
  url: httpsUrl.nullish(),
  imageUrl: httpsUrl.nullish(),
}).strict().superRefine((v, ctx) => {
  if (v.kind === 'LINK' && !v.url) ctx.addIssue({ code: 'custom', path: ['url'], message: 'url is required for a link' });
  if (v.kind !== 'LINK' && !v.externalId) ctx.addIssue({ code: 'custom', path: ['externalId'], message: 'externalId is required' });
});
export type SavedItemInput = z.infer<typeof savedItemSchema>;

export const preferencesPatchSchema = z.object({
  language: z.enum(['fr', 'en']).optional(),
  historyEnabled: z.boolean().optional(),
  historyRetentionDays: z.number().int().min(1).max(365).optional(),
}).strict().refine((v) => Object.keys(v).length > 0, 'Nothing to update');
export const profilePatchSchema = z.object({ username: usernameSchema.optional(), avatar: httpsUrl.nullable().optional() }).strict()
  .refine((v) => Object.keys(v).length > 0, 'Nothing to update');
export const collectionInputSchema = z.object({ name: z.string().trim().min(1).max(60), description: z.string().trim().max(300).nullish() }).strict();
export const collectionPatchSchema = collectionInputSchema.partial().strict().refine((v) => Object.keys(v).length > 0, 'Nothing to update');
export const pageQuery = z.object({ page: z.coerce.number().int().min(1).default(1), pageSize: z.coerce.number().int().min(1).max(50).default(20) });
export const historyQuery = pageQuery.extend({ kind: z.enum(['SEARCH', 'OPERATION']).optional(), tool: z.string().trim().max(30).optional() });
export const favoritesQuery = pageQuery.extend({ kind: z.enum(['TRACK', 'ALBUM', 'LINK']).optional() });

const toSaved = (i: SavedItemInput): SavedItem => ({
  kind: i.kind as ItemKind,
  key: i.kind === 'LINK' ? createHash('sha256').update(i.url!).digest('hex').slice(0, 32) : i.externalId!,
  title: i.title, subtitle: i.subtitle ?? null, url: i.url ?? null, imageUrl: i.imageUrl ?? null,
});

export function createMeService(repos: Repos, now: () => Date = () => new Date()) {
  const audit = (actor: string, action: string, target?: string) => repos.audit.create({ actorId: actor, action, targetId: target ?? null });
  return {
    /** Stores a history entry, unless the user disabled history. Never throws (history must not break a tool). */
    async recordHistory(user: UserRecord, e: Pick<HistoryRecord, 'kind' | 'tool' | 'query' | 'title' | 'status'>) {
      if (!user.preferences.historyEnabled) return;
      const t = now();
      try {
        await repos.history.create({ userId: user.id, ...e, query: e.query?.slice(0, 200) ?? null, title: e.title?.slice(0, 200) ?? null, createdAt: t, expiresAt: new Date(t.getTime() + user.preferences.historyRetentionDays * 86_400_000) });
      } catch { /* best effort */ }
    },

    async updatePreferences(user: UserRecord, patch: z.infer<typeof preferencesPatchSchema>) {
      const u = await repos.users.update(user.id, { preferences: { ...user.preferences, ...patch } });
      return u!.preferences;
    },
    async updateProfile(user: UserRecord, patch: z.infer<typeof profilePatchSchema>) {
      try {
        const u = await repos.users.update(user.id, { ...(patch.username !== undefined ? { username: patch.username } : {}), ...(patch.avatar !== undefined ? { avatar: patch.avatar } : {}) });
        await audit(user.id, 'PROFILE_UPDATED', user.id);
        return u!;
      } catch (e) {
        if (e instanceof DuplicateError) throw conflict('This username is already taken');
        throw e;
      }
    },

    history: {
      list: (userId: string, q: z.infer<typeof historyQuery>) => repos.history.list({ userId, ...q, now: now() }),
      remove: async (userId: string, id: string) => { if (!(await repos.history.delete(id, userId))) throw notFound('Entry not found'); },
      clear: async (userId: string) => { const n = await repos.history.clear(userId); await audit(userId, 'HISTORY_CLEARED', userId); return n; },
    },

    favorites: {
      list: (userId: string, q: z.infer<typeof favoritesQuery>) => repos.favorites.list({ userId, ...q }),
      async add(userId: string, input: SavedItemInput) {
        if ((await repos.favorites.count(userId)) >= LIMITS.favorites) throw new AppError(409, 'LIMIT_REACHED', `You can keep up to ${LIMITS.favorites} favourites.`);
        try { return await repos.favorites.create({ userId, ...toSaved(input) }); }
        catch (e) { if (e instanceof DuplicateError) throw conflict('Already in your favourites'); throw e; }
      },
      remove: async (userId: string, id: string) => { if (!(await repos.favorites.delete(id, userId))) throw notFound('Favourite not found'); },
    },

    collections: {
      list: (userId: string) => repos.collections.list(userId),
      async create(userId: string, input: z.infer<typeof collectionInputSchema>) {
        if ((await repos.collections.count(userId)) >= LIMITS.collections) throw new AppError(409, 'LIMIT_REACHED', `You can create up to ${LIMITS.collections} collections.`);
        return repos.collections.create({ userId, name: input.name, description: input.description ?? null });
      },
      async get(userId: string, id: string) { const c = await repos.collections.findOwned(id, userId); if (!c) throw notFound('Collection not found'); return c; },
      async update(userId: string, id: string, patch: z.infer<typeof collectionPatchSchema>) {
        const c = await repos.collections.update(id, userId, { ...(patch.name !== undefined ? { name: patch.name } : {}), ...(patch.description !== undefined ? { description: patch.description ?? null } : {}) });
        if (!c) throw notFound('Collection not found');
        return c;
      },
      remove: async (userId: string, id: string) => { if (!(await repos.collections.delete(id, userId))) throw notFound('Collection not found'); },
      async addItem(userId: string, id: string, input: SavedItemInput) {
        const r = await repos.collections.addItem(id, userId, toSaved(input), LIMITS.itemsPerCollection);
        if (r === 'missing') throw notFound('Collection not found');
        if (r === 'duplicate') throw conflict('Already in this collection');
        if (r === 'full') throw new AppError(409, 'LIMIT_REACHED', `A collection holds up to ${LIMITS.itemsPerCollection} items.`);
        const c = await repos.collections.findOwned(id, userId);
        if (!c) throw notFound('Collection not found');
        return c;
      },
      async removeItem(userId: string, id: string, itemId: string) { if (!(await repos.collections.removeItem(id, userId, itemId))) throw notFound('Item not found'); },
    },

    sessions: {
      async list(userId: string, currentId: string) {
        const rows = await repos.sessions.listActive(userId, now());
        return rows.map((s) => ({ id: s.id, current: s.id === currentId, createdAt: s.createdAt.toISOString(), lastActivityAt: s.lastActivityAt.toISOString(), device: (s.userAgent ?? 'Unknown device').slice(0, 120) }));
      },
      async revoke(userId: string, id: string, currentId: string) {
        if (id === currentId) throw badRequest('Use logout to end the current session');
        if (!(await repos.sessions.revokeOwned(id, userId, now()))) throw notFound('Session not found');
        await audit(userId, 'SESSION_REVOKED', userId);
      },
      async revokeOthers(userId: string, currentId: string) { const n = await repos.sessions.revokeOthers(userId, currentId, now()); await audit(userId, 'SESSIONS_REVOKED_OTHERS', userId); return n; },
    },
  };
}
export type MeService = ReturnType<typeof createMeService>;
