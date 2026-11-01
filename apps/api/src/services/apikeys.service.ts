import type { ApiKeyRecord, Repos, UsageBucket } from '../repositories/types.js';
import { hashToken, randomToken } from '../utils/crypto.js';
import { conflict, forbidden, notFound } from '../utils/errors.js';

export const MAX_ACTIVE_KEYS = 5;
export const KEY_PREFIX = 'mh_live_';
const RANGES = { '24h': 24, '7d': 24 * 7, '30d': 24 * 30 } as const;
export type Range = keyof typeof RANGES;

const publicKey = (k: ApiKeyRecord) => ({
  id: k.id, name: k.name, prefix: k.prefix, createdAt: k.createdAt.toISOString(), lastUsedAt: k.lastUsedAt?.toISOString() ?? null,
  revokedAt: k.revokedAt?.toISOString() ?? null, requests: k.requests, errors: k.errors,
});

/** Hourly buckets for 24h, daily buckets for 7d/30d; always a gap-free series. */
function series(buckets: UsageBucket[], now: Date, range: Range) {
  const hours = RANGES[range];
  const step = range === '24h' ? 1 : 24;
  const endHour = Math.floor(now.getTime() / 3_600_000) * 3_600_000;
  const n = hours / step;
  const out = Array.from({ length: n }, (_, i) => ({ t: new Date(endHour - (hours - step * (i + 1)) * 3_600_000 - (step - 1) * 3_600_000).toISOString(), requests: 0, errors: 0 }));
  const startMs = Date.parse(out[0]!.t);
  for (const b of buckets) {
    const i = Math.floor((b.hour.getTime() - startMs) / (step * 3_600_000));
    if (i >= 0 && i < n) { out[i]!.requests += b.requests; out[i]!.errors += b.errors; }
  }
  return out;
}
const sinceFor = (now: Date, range: Range) => new Date(Math.floor(now.getTime() / 3_600_000) * 3_600_000 - (RANGES[range] - 1) * 3_600_000);

export function createApiKeyService(repos: Repos, secret: string, now: () => Date = () => new Date()) {
  const hash = (key: string) => hashToken(key, secret);
  return {
    async list(userId: string) { return (await repos.apiKeys.listByUser(userId)).map(publicKey); },

    /** The full key is returned exactly once, here. Only its keyed hash is stored. */
    async create(user: { id: string; emailVerified: boolean }, name: string) {
      if (!user.emailVerified) throw forbidden('Confirm your e-mail address before creating an API key');
      if ((await repos.apiKeys.countActive(user.id)) >= MAX_ACTIVE_KEYS) throw conflict(`Limit of ${MAX_ACTIVE_KEYS} active keys reached`);
      const secretPart = randomToken(32);
      const key = `${KEY_PREFIX}${secretPart}`;
      const rec = await repos.apiKeys.create({ userId: user.id, name, prefix: `${KEY_PREFIX}${secretPart.slice(0, 6)}`, keyHash: hash(key) });
      await repos.audit.create({ actorId: user.id, action: 'API_KEY_CREATED', targetId: rec.id });
      return { key, apiKey: publicKey(rec) };
    },

    async revoke(userId: string, id: string) {
      const rec = await repos.apiKeys.revoke(id, now(), userId);
      if (!rec) throw notFound('API key not found');
      await repos.audit.create({ actorId: userId, action: 'API_KEY_REVOKED', targetId: id });
      return publicKey(rec);
    },

    /** Resolves a presented key to its record + owner, or null. Never reveals why it failed. */
    async authenticate(presented: string) {
      if (!presented.startsWith(KEY_PREFIX) || presented.length > 120) return null;
      const rec = await repos.apiKeys.findByHash(hash(presented));
      if (!rec || rec.revokedAt) return null;
      const owner = await repos.users.findById(rec.userId);
      if (!owner || owner.status !== 'ACTIVE') return null;
      return { key: rec, owner };
    },
    async recordUse(key: ApiKeyRecord, ok: boolean) { await repos.apiKeys.recordUse(key.id, key.userId, now(), ok); },

    async userUsage(userId: string, range: Range) {
      const t = now();
      const [keys, buckets] = await Promise.all([repos.apiKeys.listByUser(userId), repos.apiKeys.usage({ since: sinceFor(t, range), userId })]);
      const perKey = new Map<string, { requests: number; errors: number }>();
      for (const b of buckets) { const c = perKey.get(b.keyId) ?? { requests: 0, errors: 0 }; c.requests += b.requests; c.errors += b.errors; perKey.set(b.keyId, c); }
      const requests = buckets.reduce((s, b) => s + b.requests, 0), errors = buckets.reduce((s, b) => s + b.errors, 0);
      return {
        range, generatedAt: t.toISOString(),
        totals: { requests, errors, activeKeys: keys.filter((k) => !k.revokedAt).length, maxKeys: MAX_ACTIVE_KEYS, errorRate: requests ? errors / requests : 0 },
        series: series(buckets, t, range),
        keys: keys.map((k) => ({ ...publicKey(k), periodRequests: perKey.get(k.id)?.requests ?? 0, periodErrors: perKey.get(k.id)?.errors ?? 0 })),
      };
    },

    async adminStats(range: Range) {
      const t = now();
      const [ks, buckets] = await Promise.all([repos.apiKeys.stats(t), repos.apiKeys.usage({ since: sinceFor(t, range) })]);
      const byUser = new Map<string, { requests: number; errors: number }>();
      for (const b of buckets) { const c = byUser.get(b.userId) ?? { requests: 0, errors: 0 }; c.requests += b.requests; c.errors += b.errors; byUser.set(b.userId, c); }
      const top = [...byUser.entries()].sort((a, b) => b[1].requests - a[1].requests).slice(0, 5);
      const topUsers = await Promise.all(top.map(async ([uid, c]) => ({ username: (await repos.users.findById(uid))?.username ?? 'compte supprimé', ...c })));
      const requests = buckets.reduce((s, b) => s + b.requests, 0), errors = buckets.reduce((s, b) => s + b.errors, 0);
      return { range, generatedAt: t.toISOString(), keys: ks, totals: { requests, errors, errorRate: requests ? errors / requests : 0, activeConsumers: byUser.size }, series: series(buckets, t, range), topUsers };
    },
  };
}
export type ApiKeyService = ReturnType<typeof createApiKeyService>;
