import { randomBytes } from 'node:crypto';
import { DuplicateError } from '../utils/errors.js';
import { normalizeUsername } from '../utils/normalize.js';
import { DEFAULT_PREFERENCES, type Page } from './types.js';
import type { CollectionItem, CollectionRecord, ErrorRecord, FavoriteRecord, HistoryRecord, JobRecord, ReportRecord, PendingRecord, ApiKeyRecord, AuditRecord, UsageBucket, Repos, SessionRecord, TokenKind, TokenRecord, UserRecord } from './types.js';

const id = () => randomBytes(12).toString('hex');

/** In-memory repositories used by the test-suite (no MongoDB needed). Same contract as the Mongo ones. */
export function createMemoryRepos() {
  const users = new Map<string, UserRecord>();
  const sessions = new Map<string, SessionRecord>();
  const tokens: Record<TokenKind, Map<string, TokenRecord>> = { EMAIL_VERIFICATION: new Map(), PASSWORD_RESET: new Map() };
  const identities = new Map<string, string>();
  const audit: AuditRecord[] = [];
  const keys = new Map<string, ApiKeyRecord>();
  const pending = new Map<string, PendingRecord>();
  const buckets = new Map<string, UsageBucket>();
  const history = new Map<string, HistoryRecord>();
  const favorites = new Map<string, FavoriteRecord>();
  const collections = new Map<string, CollectionRecord>();
  const jobs = new Map<string, JobRecord>();
  const reports = new Map<string, ReportRecord>();
  const settings = new Map<string, unknown>();
  const errorLog: ErrorRecord[] = [];
  const events: { tool: string; ok: boolean; userId: string | null; code: string | null; at: Date }[] = [];
  const paginate = <T>(all: T[], page: number, pageSize: number): Page<T> => ({ items: all.slice((page - 1) * pageSize, page * pageSize), total: all.length });

  const repos: Repos = {
    users: {
      async create(d) {
        for (const u of users.values()) {
          if (u.email === d.email) throw new DuplicateError('email');
          if (normalizeUsername(u.username) === normalizeUsername(d.username)) throw new DuplicateError('usernameLower');
        }
        const now = new Date();
        const u: UserRecord = { id: id(), ...d, role: 'USER', emailVerified: false, avatar: null, status: 'ACTIVE', createdAt: now, updatedAt: now, lastLoginAt: null, totp: null, preferences: { ...DEFAULT_PREFERENCES } };
        users.set(u.id, u);
        return { ...u };
      },
      async findById(i) { const u = users.get(i); return u ? { ...u } : null; },
      async findByEmail(e) { for (const u of users.values()) if (u.email === e) return { ...u }; return null; },
      async findByUsername(n) { for (const u of users.values()) if (normalizeUsername(u.username) === normalizeUsername(n)) return { ...u }; return null; },
      async update(i, patch) {
        const u = users.get(i);
        if (!u) return null;
        if (patch.username !== undefined) for (const o of users.values()) if (o.id !== i && normalizeUsername(o.username) === normalizeUsername(patch.username)) throw new DuplicateError('usernameLower');
        Object.assign(u, patch, { updatedAt: new Date() });
        return { ...u };
      },
      async list({ page, pageSize, q, role, status }) {
        let all = [...users.values()].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
        if (role) all = all.filter((u) => u.role === role);
        if (status) all = all.filter((u) => u.status === status);
        if (q) all = all.filter((u) => (u.email + ' ' + u.username).toLowerCase().includes(q.toLowerCase()));
        return { items: all.slice((page - 1) * pageSize, page * pageSize).map((u) => ({ ...u })), total: all.length };
      },
      async countAdmins() { return [...users.values()].filter((u) => u.role === 'ADMIN' && u.status === 'ACTIVE').length; },
      async stats(now) {
        const all = [...users.values()];
        const since = now.getTime() - 7 * 86400_000;
        return {
          total: all.filter((u) => u.status !== 'DELETED').length,
          active: all.filter((u) => u.status === 'ACTIVE').length,
          suspended: all.filter((u) => u.status === 'SUSPENDED').length,
          admins: all.filter((u) => u.role === 'ADMIN' && u.status === 'ACTIVE').length,
          createdLast7d: all.filter((u) => u.createdAt.getTime() >= since && u.status !== 'DELETED').length,
        };
      },
    },
    sessions: {
      async create(d) {
        const s: SessionRecord = { id: id(), revokedAt: null, ...d };
        sessions.set(s.id, s);
        return { ...s };
      },
      async findByTokenHash(h) { for (const s of sessions.values()) if (s.tokenHash === h) return { ...s }; return null; },
      async touch(i, at) { const s = sessions.get(i); if (s) s.lastActivityAt = at; },
      async revoke(i, at) { const s = sessions.get(i); if (s && !s.revokedAt) s.revokedAt = at; },
      async revokeAllForUser(uid, at) { for (const s of sessions.values()) if (s.userId === uid && !s.revokedAt) s.revokedAt = at; },
      async listActive(uid, now) { return [...sessions.values()].filter((s) => s.userId === uid && !s.revokedAt && s.expiresAt > now).sort((a, b) => b.lastActivityAt.getTime() - a.lastActivityAt.getTime()).map((s) => ({ ...s })); },
      async revokeOwned(i, uid, at) { const s = sessions.get(i); if (!s || s.userId !== uid) return false; s.revokedAt ??= at; return true; },
      async revokeOthers(uid, except, at) { let n = 0; for (const s of sessions.values()) if (s.userId === uid && s.id !== except && !s.revokedAt && s.expiresAt > at) { s.revokedAt = at; n++; } return n; },
    },
    tokens: {
      async create(kind, d) {
        const t: TokenRecord = { id: id(), usedAt: null, ...d };
        tokens[kind].set(t.id, t);
        return { ...t };
      },
      async findUsable(kind, h, now) {
        for (const t of tokens[kind].values()) if (t.tokenHash === h && !t.usedAt && t.expiresAt > now) return { ...t };
        return null;
      },
      async consume(kind, i, now) {
        const t = tokens[kind].get(i);
        if (!t || t.usedAt) return false;
        t.usedAt = now;
        return true;
      },
      async invalidateAllForUser(kind, uid, now) { for (const t of tokens[kind].values()) if (t.userId === uid && !t.usedAt) t.usedAt = now; },
    },
    identities: {
      async create(d) {
        const key = `${d.provider}:${d.providerUserId}`;
        if (identities.has(key)) throw new DuplicateError('providerUserId');
        for (const [k, v] of identities) if (v === d.userId && k.startsWith(`${d.provider}:`)) throw new DuplicateError('userId');
        identities.set(key, d.userId);
      },
      async findUserIdByProvider(p, pu) { return identities.get(`${p}:${pu}`) ?? null; },
      async deleteAllForUser(uid) { for (const [k, v] of identities) if (v === uid) identities.delete(k); },
      async deleteForUser(uid, provider) { let n = 0; for (const [k, v] of identities) if (v === uid && k.startsWith(`${provider}:`)) { identities.delete(k); n++; } return n > 0; },
      async hasProvider(uid, provider) { for (const [k, v] of identities) if (v === uid && k.startsWith(`${provider}:`)) return true; return false; },
    },
    audit: {
      async create(e) { audit.push({ id: id(), actorId: e.actorId, action: e.action, targetId: e.targetId ?? null, metadata: e.metadata ?? {}, timestamp: new Date() }); },
      async list({ page, pageSize, action }) {
        const all = audit.filter((a) => !action || a.action === action).sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
        return { items: all.slice((page - 1) * pageSize, page * pageSize), total: all.length };
      },
    },
    pending: {
      async upsert(d) {
        const old = pending.get(d.email);
        const rec: PendingRecord = { id: id(), createdAt: old?.createdAt ?? new Date(), ...d };
        pending.set(d.email, rec);
        return { ...rec };
      },
      async findByEmail(e) { const p = pending.get(e); return p ? { ...p } : null; },
      async recordFailure(i) { for (const p of pending.values()) if (p.id === i) { p.attemptsLeft = Math.max(0, p.attemptsLeft - 1); return p.attemptsLeft; } return 0; },
      async take(i) { for (const [k, p] of pending) if (p.id === i) { pending.delete(k); return true; } return false; },
      async deleteByEmail(e) { pending.delete(e); },
    },
    apiKeys: {
      async create(d) {
        const k: ApiKeyRecord = { id: id(), ...d, createdAt: new Date(), lastUsedAt: null, revokedAt: null, requests: 0, errors: 0 };
        keys.set(k.id, k);
        return { ...k };
      },
      async listByUser(uid) { return [...keys.values()].filter((k) => k.userId === uid).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()).map((k) => ({ ...k })); },
      async findByHash(h) { for (const k of keys.values()) if (k.keyHash === h) return { ...k }; return null; },
      async revoke(i, at, uid) {
        const k = keys.get(i);
        if (!k || (uid && k.userId !== uid)) return null;
        k.revokedAt ??= at;
        return { ...k };
      },
      async revokeAllForUser(uid, at) { for (const k of keys.values()) if (k.userId === uid) k.revokedAt ??= at; },
      async countActive(uid) { return [...keys.values()].filter((k) => k.userId === uid && !k.revokedAt).length; },
      async recordUse(kid, uid, at, ok) {
        const k = keys.get(kid); if (!k) return;
        k.requests += 1; if (!ok) k.errors += 1; k.lastUsedAt = at;
        const hour = new Date(Math.floor(at.getTime() / 3_600_000) * 3_600_000);
        const bk = `${kid}:${hour.getTime()}`;
        const b = buckets.get(bk) ?? { keyId: kid, userId: uid, hour, requests: 0, errors: 0 };
        b.requests += 1; if (!ok) b.errors += 1; buckets.set(bk, b);
      },
      async usage({ since, userId }) { return [...buckets.values()].filter((b) => b.hour >= since && (!userId || b.userId === userId)).map((b) => ({ ...b })); },
      async stats(now) {
        const all = [...keys.values()]; const week = now.getTime() - 7 * 86_400_000;
        const active = all.filter((k) => !k.revokedAt);
        return { total: all.length, active: active.length, revoked: all.length - active.length, createdLast7d: all.filter((k) => k.createdAt.getTime() >= week).length, owners: new Set(active.map((k) => k.userId)).size };
      },
    },
    history: {
      async create(d) { const r: HistoryRecord = { id: id(), ...d }; history.set(r.id, r); return { ...r }; },
      async list({ userId, page, pageSize, kind, tool, now }) {
        const all = [...history.values()].filter((h) => h.userId === userId && h.expiresAt > now && (!kind || h.kind === kind) && (!tool || h.tool === tool))
          .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
        return paginate(all.map((h) => ({ ...h })), page, pageSize);
      },
      async delete(i, uid) { const h = history.get(i); if (!h || h.userId !== uid) return false; history.delete(i); return true; },
      async clear(uid) { let n = 0; for (const [k, h] of history) if (h.userId === uid) { history.delete(k); n++; } return n; },
    },
    favorites: {
      async create(d) {
        for (const f of favorites.values()) if (f.userId === d.userId && f.kind === d.kind && f.key === d.key) throw new DuplicateError('key');
        const r: FavoriteRecord = { id: id(), createdAt: new Date(), ...d }; favorites.set(r.id, r); return { ...r };
      },
      async list({ userId, page, pageSize, kind }) {
        const all = [...favorites.values()].filter((f) => f.userId === userId && (!kind || f.kind === kind)).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
        return paginate(all.map((f) => ({ ...f })), page, pageSize);
      },
      async delete(i, uid) { const f = favorites.get(i); if (!f || f.userId !== uid) return false; favorites.delete(i); return true; },
      async count(uid) { return [...favorites.values()].filter((f) => f.userId === uid).length; },
      async deleteAllForUser(uid) { for (const [k, f] of favorites) if (f.userId === uid) favorites.delete(k); },
    },
    collections: {
      async create(d) { const now = new Date(); const c: CollectionRecord = { id: id(), ...d, items: [], createdAt: now, updatedAt: now }; collections.set(c.id, c); return structuredClone(c); },
      async list(uid) { return [...collections.values()].filter((c) => c.userId === uid).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()).map((c) => structuredClone(c)); },
      async findOwned(i, uid) { const c = collections.get(i); return c && c.userId === uid ? structuredClone(c) : null; },
      async update(i, uid, patch) {
        const c = collections.get(i); if (!c || c.userId !== uid) return null;
        if (patch.name !== undefined) c.name = patch.name;
        if (patch.description !== undefined) c.description = patch.description;
        c.updatedAt = new Date(); return structuredClone(c);
      },
      async delete(i, uid) { const c = collections.get(i); if (!c || c.userId !== uid) return false; collections.delete(i); return true; },
      async addItem(i, uid, item, max) {
        const c = collections.get(i); if (!c || c.userId !== uid) return 'missing';
        if (c.items.some((x) => x.kind === item.kind && x.key === item.key)) return 'duplicate';
        if (c.items.length >= max) return 'full';
        const it: CollectionItem = { id: id(), addedAt: new Date(), ...item }; c.items.push(it); c.updatedAt = new Date(); return 'ok';
      },
      async removeItem(i, uid, itemId) {
        const c = collections.get(i); if (!c || c.userId !== uid) return false;
        const n = c.items.length; c.items = c.items.filter((x) => x.id !== itemId); return c.items.length < n;
      },
      async count(uid) { return [...collections.values()].filter((c) => c.userId === uid).length; },
      async deleteAllForUser(uid) { for (const [k, c] of collections) if (c.userId === uid) collections.delete(k); },
    },
    jobs: {
      async create(d) { const j: JobRecord = { id: id(), createdAt: new Date(), ...d }; jobs.set(j.id, j); return { ...j }; },
      async findById(i) { const j = jobs.get(i); return j ? { ...j } : null; },
    },
    reports: {
      async create(d) { const now = new Date(); const r: ReportRecord = { id: id(), ...d, status: 'OPEN', adminNote: null, handledBy: null, createdAt: now, updatedAt: now }; reports.set(r.id, r); return { ...r }; },
      async list({ page, pageSize, status }) {
        const all = [...reports.values()].filter((r) => !status || r.status === status).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
        return paginate(all.map((r) => ({ ...r })), page, pageSize);
      },
      async findById(i) { const r = reports.get(i); return r ? { ...r } : null; },
      async update(i, patch) { const r = reports.get(i); if (!r) return null; Object.assign(r, patch, { updatedAt: new Date() }); return { ...r }; },
      async counts() { const all = [...reports.values()]; return { open: all.filter((r) => r.status === 'OPEN').length, inReview: all.filter((r) => r.status === 'IN_REVIEW').length, total: all.length }; },
      async detachReporter(uid) { for (const r of reports.values()) if (r.reporterId === uid) r.reporterId = null; },
    },
    settings: {
      async getAll() { return Object.fromEntries(settings); },
      async set(k, v) { settings.set(k, structuredClone(v)); },
    },
    errors: {
      async create(e) { errorLog.push({ id: id(), at: new Date(), source: e.source, code: e.code, route: e.route ?? null, message: e.message }); },
      async list({ page, pageSize, source }) {
        const all = errorLog.filter((e) => !source || e.source === source).sort((a, b) => b.at.getTime() - a.at.getTime());
        return paginate(all.map((e) => ({ ...e })), page, pageSize);
      },
      async countSince(since) { return errorLog.filter((e) => e.at >= since).length; },
    },
    toolEvents: {
      async create(e) { events.push({ tool: e.tool, ok: e.ok, userId: e.userId ?? null, code: e.code ?? null, at: e.at }); },
      async summary(since) {
        const m = new Map<string, { tool: string; total: number; failed: number }>();
        for (const e of events) if (e.at >= since) { const x = m.get(e.tool) ?? { tool: e.tool, total: 0, failed: 0 }; x.total++; if (!e.ok) x.failed++; m.set(e.tool, x); }
        return [...m.values()];
      },
      async countByUser(uid, prefix, since) { return events.filter((e) => e.userId === uid && e.tool.startsWith(prefix) && e.at >= since).length; },
    },
  };
  return { repos, _state: { pending, users, sessions, tokens, identities, audit, keys, buckets, history, favorites, collections, jobs, reports, settings, errorLog, events } };
}
