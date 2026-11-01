import type { HydratedDocument } from 'mongoose';
import {
  CollectionModel, ErrorLogModel, FavoriteModel, HistoryModel, ReportModel, SettingModel, ToolEventModel, ToolJobModel,
  PendingRegistrationModel, ApiKeyModel, ApiUsageModel, AuditLogModel, AuthIdentityModel, EmailVerificationTokenModel, PasswordResetTokenModel, SessionModel, UserModel,
} from '../models/index.js';
import { DuplicateError } from '../utils/errors.js';
import { normalizeUsername } from '../utils/normalize.js';
import { DEFAULT_PREFERENCES } from './types.js';
import type {
  CollectionRecord, ErrorRecord, FavoriteRecord, HistoryRecord, JobRecord, ReportRecord, SavedItem,
  PendingRecord, ApiKeyRecord, AuditRecord, Repos, SessionRecord, TokenKind, TokenRecord, UserRecord,
} from './types.js';

/** Strict 24-hex ObjectId check: anything else is simply "not found" (never a CastError, never a 500). */
const validId = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{24}$/i.test(v);
/** Values coming from users must be plain strings: an object such as {$ne:''} must never reach a query filter. */
const str = (v: unknown): string => { if (typeof v !== 'string') throw new TypeError('Expected a string'); return v; };

const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function isDuplicate(e: unknown): e is { code: number; keyPattern?: Record<string, number> } {
  return typeof e === 'object' && e !== null && (e as { code?: number }).code === 11000;
}
async function guard<T>(p: Promise<T>): Promise<T> {
  try {
    return await p;
  } catch (e) {
    if (isDuplicate(e)) throw new DuplicateError(Object.keys(e.keyPattern ?? {})[0] ?? 'unknown');
    throw e;
  }
}

const toKey = (d: HydratedDocument<any>): ApiKeyRecord => ({
  id: String(d._id), userId: String(d.userId), name: d.name, prefix: d.prefix, keyHash: d.keyHash,
  createdAt: d.createdAt, lastUsedAt: d.lastUsedAt ?? null, revokedAt: d.revokedAt ?? null, requests: d.requests ?? 0, errors: d.failures ?? 0,
});
const toPending = (d: HydratedDocument<any>): PendingRecord => ({
  id: String(d._id), email: d.email, username: d.username, passwordHash: d.passwordHash, codeHash: d.codeHash, codeExpiresAt: d.codeExpiresAt,
  attemptsLeft: d.attemptsLeft, resendCount: d.resendCount ?? 0, lastSentAt: d.lastSentAt, expiresAt: d.expiresAt, createdAt: d.createdAt,
});
const toUser = (d: HydratedDocument<any>): UserRecord => ({
  id: String(d._id), username: d.username, email: d.email, passwordHash: d.passwordHash ?? null,
  role: d.role, emailVerified: d.emailVerified, avatar: d.avatar ?? null, status: d.status,
  createdAt: d.createdAt, updatedAt: d.updatedAt, lastLoginAt: d.lastLoginAt ?? null,
  totp: d.totp ? { ...d.totp, lockedUntil: d.totp.lockedUntil ? new Date(d.totp.lockedUntil) : null } : null,
  preferences: { ...DEFAULT_PREFERENCES, ...(d.preferences?.toObject ? d.preferences.toObject() : d.preferences ?? {}) },
});
const toSession = (d: HydratedDocument<any>): SessionRecord => ({
  id: String(d._id), userId: String(d.userId), tokenHash: d.tokenHash, csrfToken: d.csrfToken,
  userAgent: d.userAgent ?? null, createdAt: d.createdAt, lastActivityAt: d.lastActivityAt,
  expiresAt: d.expiresAt, revokedAt: d.revokedAt ?? null,
});
const toToken = (d: HydratedDocument<any>): TokenRecord => ({
  id: String(d._id), userId: String(d.userId), tokenHash: d.tokenHash, expiresAt: d.expiresAt, usedAt: d.usedAt ?? null,
});
const toSaved = (d: any): SavedItem => ({ kind: d.kind, key: d.key, title: d.title, subtitle: d.subtitle ?? null, url: d.url ?? null, imageUrl: d.imageUrl ?? null });
const toHistory = (d: HydratedDocument<any>): HistoryRecord => ({
  id: String(d._id), userId: String(d.userId), kind: d.kind, tool: d.tool, query: d.query ?? null, title: d.title ?? null, status: d.status, createdAt: d.createdAt, expiresAt: d.expiresAt,
});
const toFavorite = (d: HydratedDocument<any>): FavoriteRecord => ({ id: String(d._id), userId: String(d.userId), ...toSaved(d), createdAt: d.createdAt });
const toCollection = (d: HydratedDocument<any>): CollectionRecord => ({
  id: String(d._id), userId: String(d.userId), name: d.name, description: d.description ?? null, createdAt: d.createdAt, updatedAt: d.updatedAt,
  items: (d.items ?? []).map((i: any) => ({ id: String(i._id), ...toSaved(i), addedAt: i.addedAt })),
});
const toJob = (d: HydratedDocument<any>): JobRecord => ({ id: String(d._id), tool: d.tool, userId: d.userId ? String(d.userId) : null, result: d.result, readyAt: d.readyAt, expiresAt: d.expiresAt, createdAt: d.createdAt });
const toReport = (d: HydratedDocument<any>): ReportRecord => ({
  id: String(d._id), reporterId: d.reporterId ? String(d.reporterId) : null, kind: d.kind, targetUrl: d.targetUrl ?? null, description: d.description, contactEmail: d.contactEmail ?? null,
  status: d.status, adminNote: d.adminNote ?? null, handledBy: d.handledBy ? String(d.handledBy) : null, createdAt: d.createdAt, updatedAt: d.updatedAt,
});
const tokenModel = (k: TokenKind) => (k === 'EMAIL_VERIFICATION' ? EmailVerificationTokenModel : PasswordResetTokenModel);

export function createMongoRepos(): Repos {
  return {
    users: {
      async create(data) {
        const d = await guard(UserModel.create({ ...data, usernameLower: normalizeUsername(data.username) }));
        return toUser(d);
      },
      async findById(id) { if (!validId(id)) return null; const d = await UserModel.findById(id); return d ? toUser(d) : null; },
      async findByEmail(email) { const d = await UserModel.findOne({ email: str(email) }); return d ? toUser(d) : null; },
      async findByUsername(name) { const d = await UserModel.findOne({ usernameLower: normalizeUsername(str(name)) }); return d ? toUser(d) : null; },
      async update(id, patch) {
        if (!validId(id)) return null;
        const set: Record<string, unknown> = { ...patch };
        if (patch.username) set.usernameLower = normalizeUsername(patch.username);
        const d = await guard(UserModel.findByIdAndUpdate(id, { $set: set }, { new: true }));
        return d ? toUser(d) : null;
      },
      async list({ page, pageSize, q, role, status }) {
        const filter: Record<string, unknown> = {};
        if (role) filter.role = role;
        if (status) filter.status = status;
        if (q) {
          const re = new RegExp(escapeRegex(q), 'i'); // escaped: no regex injection
          filter.$or = [{ email: re }, { username: re }];
        }
        const [docs, total] = await Promise.all([
          UserModel.find(filter).sort({ createdAt: -1 }).skip((page - 1) * pageSize).limit(pageSize),
          UserModel.countDocuments(filter),
        ]);
        return { items: docs.map(toUser), total };
      },
      countAdmins: () => UserModel.countDocuments({ role: 'ADMIN', status: 'ACTIVE' }),
      async stats(now) {
        const since = new Date(now.getTime() - 7 * 86400_000);
        const [total, active, suspended, admins, createdLast7d] = await Promise.all([
          UserModel.countDocuments({ status: { $ne: 'DELETED' } }),
          UserModel.countDocuments({ status: 'ACTIVE' }),
          UserModel.countDocuments({ status: 'SUSPENDED' }),
          UserModel.countDocuments({ role: 'ADMIN', status: 'ACTIVE' }),
          UserModel.countDocuments({ createdAt: { $gte: since }, status: { $ne: 'DELETED' } }),
        ]);
        return { total, active, suspended, admins, createdLast7d };
      },
    },
    sessions: {
      async create(data) { return toSession(await guard(SessionModel.create(data))); },
      async findByTokenHash(h) { const d = await SessionModel.findOne({ tokenHash: str(h) }); return d ? toSession(d) : null; },
      async touch(id, at) { if (!validId(id)) return; await SessionModel.updateOne({ _id: id }, { $set: { lastActivityAt: at } }); },
      async revoke(id, at) { if (!validId(id)) return; await SessionModel.updateOne({ _id: id, revokedAt: null }, { $set: { revokedAt: at } }); },
      async revokeAllForUser(userId, at) { await SessionModel.updateMany({ userId, revokedAt: null }, { $set: { revokedAt: at } }); },
      async listActive(userId, now) { return (await SessionModel.find({ userId, revokedAt: null, expiresAt: { $gt: now } }).sort({ lastActivityAt: -1 })).map(toSession); },
      async revokeOwned(id, userId, at) {
        if (!validId(id)) return false;
        const r = await SessionModel.updateOne({ _id: id, userId, revokedAt: null }, { $set: { revokedAt: at } });
        if (r.modifiedCount === 1) return true;
        return (await SessionModel.countDocuments({ _id: id, userId })) === 1; // already revoked counts as done
      },
      async revokeOthers(userId, exceptId, at) { return (await SessionModel.updateMany({ userId, _id: { $ne: exceptId }, revokedAt: null, expiresAt: { $gt: at } }, { $set: { revokedAt: at } })).modifiedCount; },
    },
    tokens: {
      async create(kind, data) { return toToken(await guard(tokenModel(kind).create(data))); },
      async findUsable(kind, tokenHash, now) {
        const d = await tokenModel(kind).findOne({ tokenHash: str(tokenHash), usedAt: null, expiresAt: { $gt: now } });
        return d ? toToken(d) : null;
      },
      async consume(kind, id, now) {
        if (!validId(id)) return false;
        const r = await tokenModel(kind).updateOne({ _id: id, usedAt: null }, { $set: { usedAt: now } });
        return r.modifiedCount === 1;
      },
      async invalidateAllForUser(kind, userId, now) {
        await tokenModel(kind).updateMany({ userId, usedAt: null }, { $set: { usedAt: now } });
      },
    },
    identities: {
      async create(data) { await guard(AuthIdentityModel.create(data)); },
      async findUserIdByProvider(provider, providerUserId) {
        const d = await AuthIdentityModel.findOne({ provider, providerUserId: str(providerUserId) });
        return d ? String(d.userId) : null;
      },
      async deleteAllForUser(userId) { await AuthIdentityModel.deleteMany({ userId }); },
      async deleteForUser(userId, provider) { return (await AuthIdentityModel.deleteOne({ userId, provider })).deletedCount === 1; },
      async hasProvider(userId, provider) { return (await AuthIdentityModel.countDocuments({ userId, provider })) > 0; },
    },
    audit: {
      async create(e) {
        await AuditLogModel.create({ actorId: e.actorId, action: e.action, targetId: e.targetId ?? null, metadata: e.metadata ?? {} });
      },
      async list({ page, pageSize, action }) {
        const filter = action ? { action } : {};
        const [docs, total] = await Promise.all([
          AuditLogModel.find(filter).sort({ timestamp: -1 }).skip((page - 1) * pageSize).limit(pageSize),
          AuditLogModel.countDocuments(filter),
        ]);
        const items: AuditRecord[] = docs.map((d) => ({
          id: String(d._id), actorId: d.actorId ? String(d.actorId) : null, action: d.action,
          targetId: d.targetId ? String(d.targetId) : null,
          metadata: (d.metadata ?? {}) as AuditRecord['metadata'], timestamp: d.timestamp,
        }));
        return { items, total };
      },
    },
    pending: {
      async upsert(d) {
        // findOneAndUpdate with upsert is atomic on the unique e-mail index; a new _id is not needed, the code hash changes.
        const doc = await PendingRegistrationModel.findOneAndUpdate({ email: d.email }, { $set: d }, { new: true, upsert: true, setDefaultsOnInsert: true });
        return toPending(doc!);
      },
      async findByEmail(email) { const d = await PendingRegistrationModel.findOne({ email: str(email) }); return d ? toPending(d) : null; }, // expiry is checked by the service (TTL purge is lazy)
      async recordFailure(id) {
        if (!validId(id)) return 0;
        const d = await PendingRegistrationModel.findOneAndUpdate({ _id: id, attemptsLeft: { $gt: 0 } }, { $inc: { attemptsLeft: -1 } }, { new: true });
        return d ? d.attemptsLeft : 0;
      },
      async take(id) { if (!validId(id)) return false; return (await PendingRegistrationModel.deleteOne({ _id: id })).deletedCount === 1; },
      async deleteByEmail(email) { await PendingRegistrationModel.deleteOne({ email }); },
    },
    apiKeys: {
      async create(d) { return toKey(await guard(ApiKeyModel.create(d))); },
      async listByUser(userId) { return (await ApiKeyModel.find({ userId }).sort({ createdAt: -1 })).map(toKey); },
      async findByHash(keyHash) { const d = await ApiKeyModel.findOne({ keyHash: str(keyHash) }); return d ? toKey(d) : null; },
      async revoke(id, at, userId) {
        if (!validId(id)) return null;
        const d = await ApiKeyModel.findOneAndUpdate({ _id: id, ...(userId ? { userId } : {}), revokedAt: null }, { $set: { revokedAt: at } }, { new: true })
          ?? await ApiKeyModel.findOne({ _id: id, ...(userId ? { userId } : {}) });
        return d ? toKey(d) : null;
      },
      async revokeAllForUser(userId, at) { await ApiKeyModel.updateMany({ userId, revokedAt: null }, { $set: { revokedAt: at } }); },
      async countActive(userId) { return ApiKeyModel.countDocuments({ userId, revokedAt: null }); },
      async recordUse(keyId, userId, at, ok) {
        const hour = new Date(Math.floor(at.getTime() / 3_600_000) * 3_600_000);
        await Promise.all([
          ApiKeyModel.updateOne({ _id: keyId }, { $inc: { requests: 1, failures: ok ? 0 : 1 }, $set: { lastUsedAt: at } }),
          ApiUsageModel.updateOne({ keyId, hour }, { $setOnInsert: { userId }, $inc: { requests: 1, failures: ok ? 0 : 1 } }, { upsert: true }),
        ]);
      },
      async usage({ since, userId }) {
        const docs = await ApiUsageModel.find({ hour: { $gte: since }, ...(userId ? { userId } : {}) });
        return docs.map((d) => ({ keyId: String(d.keyId), userId: String(d.userId), hour: d.hour, requests: d.requests ?? 0, errors: d.failures ?? 0 }));
      },
      async stats(now) {
        const week = new Date(now.getTime() - 7 * 86_400_000);
        const [total, active, createdLast7d, owners] = await Promise.all([
          ApiKeyModel.countDocuments({}), ApiKeyModel.countDocuments({ revokedAt: null }),
          ApiKeyModel.countDocuments({ createdAt: { $gte: week } }), ApiKeyModel.distinct('userId', { revokedAt: null }),
        ]);
        return { total, active, revoked: total - active, createdLast7d, owners: owners.length };
      },
    },
    history: {
      async create(d) { return toHistory(await HistoryModel.create(d)); },
      async list({ userId, page, pageSize, kind, tool, now }) {
        const filter = { userId, expiresAt: { $gt: now }, ...(kind ? { kind } : {}), ...(tool ? { tool } : {}) };
        const [docs, total] = await Promise.all([
          HistoryModel.find(filter).sort({ createdAt: -1 }).skip((page - 1) * pageSize).limit(pageSize), HistoryModel.countDocuments(filter),
        ]);
        return { items: docs.map(toHistory), total };
      },
      async delete(id, userId) { if (!validId(id)) return false; return (await HistoryModel.deleteOne({ _id: id, userId })).deletedCount === 1; },
      async clear(userId) { return (await HistoryModel.deleteMany({ userId })).deletedCount; },
    },
    favorites: {
      async create(d) { return toFavorite(await guard(FavoriteModel.create(d))); },
      async list({ userId, page, pageSize, kind }) {
        const filter = { userId, ...(kind ? { kind } : {}) };
        const [docs, total] = await Promise.all([
          FavoriteModel.find(filter).sort({ createdAt: -1 }).skip((page - 1) * pageSize).limit(pageSize), FavoriteModel.countDocuments(filter),
        ]);
        return { items: docs.map(toFavorite), total };
      },
      async delete(id, userId) { if (!validId(id)) return false; return (await FavoriteModel.deleteOne({ _id: id, userId })).deletedCount === 1; },
      async count(userId) { return FavoriteModel.countDocuments({ userId }); },
      async deleteAllForUser(userId) { await FavoriteModel.deleteMany({ userId }); },
    },
    collections: {
      async create(d) { return toCollection(await CollectionModel.create({ ...d, items: [] })); },
      async list(userId) { return (await CollectionModel.find({ userId }).sort({ createdAt: -1 })).map(toCollection); },
      async findOwned(id, userId) { if (!validId(id)) return null; const d = await CollectionModel.findOne({ _id: id, userId }); return d ? toCollection(d) : null; },
      async update(id, userId, patch) {
        if (!validId(id)) return null;
        const d = await CollectionModel.findOneAndUpdate({ _id: id, userId }, { $set: patch }, { new: true });
        return d ? toCollection(d) : null;
      },
      async delete(id, userId) { if (!validId(id)) return false; return (await CollectionModel.deleteOne({ _id: id, userId })).deletedCount === 1; },
      async addItem(id, userId, item, maxItems) {
        if (!validId(id)) return 'missing';
        // One atomic update: only if the collection is the user's, the item is absent (items.ref is "KIND:key") and the array has room.
        const ref = `${item.kind}:${item.key}`;
        const r = await CollectionModel.updateOne(
          { _id: id, userId, 'items.ref': { $ne: ref }, [`items.${maxItems - 1}`]: { $exists: false } },
          { $push: { items: { ...item, ref, addedAt: new Date() } }, $set: { updatedAt: new Date() } },
        );
        if (r.modifiedCount === 1) return 'ok';
        const c = await CollectionModel.findOne({ _id: id, userId });
        if (!c) return 'missing';
        if (c.items.some((x: any) => x.kind === item.kind && x.key === item.key)) return 'duplicate';
        return 'full';
      },
      async removeItem(id, userId, itemId) {
        if (!validId(id) || !validId(itemId)) return false;
        // Returns the document as it was BEFORE the pull, so "was the item really there?" does not depend on how the server counts modifications.
        const before = await CollectionModel.findOneAndUpdate({ _id: id, userId, 'items._id': itemId }, { $pull: { items: { _id: itemId } }, $set: { updatedAt: new Date() } }, { returnDocument: 'before' });
        return !!before && before.items.some((i: any) => String(i._id) === itemId);
      },
      async count(userId) { return CollectionModel.countDocuments({ userId }); },
      async deleteAllForUser(userId) { await CollectionModel.deleteMany({ userId }); },
    },
    jobs: {
      async create(d) { return toJob(await ToolJobModel.create(d)); },
      async findById(id) { if (!validId(id)) return null; const d = await ToolJobModel.findOne({ _id: id, expiresAt: { $gt: new Date() } }); return d ? toJob(d) : null; },
    },
    reports: {
      async create(d) { return toReport(await ReportModel.create(d)); },
      async list({ page, pageSize, status }) {
        const filter = status ? { status } : {};
        const [docs, total] = await Promise.all([
          ReportModel.find(filter).sort({ createdAt: -1 }).skip((page - 1) * pageSize).limit(pageSize), ReportModel.countDocuments(filter),
        ]);
        return { items: docs.map(toReport), total };
      },
      async findById(id) { if (!validId(id)) return null; const d = await ReportModel.findById(id); return d ? toReport(d) : null; },
      async update(id, patch) { if (!validId(id)) return null; const d = await ReportModel.findByIdAndUpdate(id, { $set: patch }, { new: true }); return d ? toReport(d) : null; },
      async counts() {
        const [open, inReview, total] = await Promise.all([ReportModel.countDocuments({ status: 'OPEN' }), ReportModel.countDocuments({ status: 'IN_REVIEW' }), ReportModel.countDocuments({})]);
        return { open, inReview, total };
      },
      async detachReporter(userId) { await ReportModel.updateMany({ reporterId: userId }, { $set: { reporterId: null } }); },
    },
    settings: {
      async getAll() { const docs = await SettingModel.find({}); return Object.fromEntries(docs.map((d) => [d.key, d.value])); },
      async set(key, value, by) { await SettingModel.updateOne({ key }, { $set: { value, updatedBy: by } }, { upsert: true }); },
    },
    errors: {
      async create(e) { await ErrorLogModel.create({ at: new Date(), source: e.source, code: e.code, route: e.route ?? null, message: e.message }); },
      async list({ page, pageSize, source }) {
        const filter = source ? { source } : {};
        const [docs, total] = await Promise.all([
          ErrorLogModel.find(filter).sort({ at: -1 }).skip((page - 1) * pageSize).limit(pageSize), ErrorLogModel.countDocuments(filter),
        ]);
        return { items: docs.map((d): ErrorRecord => ({ id: String(d._id), at: d.at, source: d.source as ErrorRecord['source'], code: d.code, route: d.route ?? null, message: d.message })), total };
      },
      async countSince(since) { return ErrorLogModel.countDocuments({ at: { $gte: since } }); },
    },
    toolEvents: {
      async create(e) { await ToolEventModel.create({ tool: e.tool, ok: e.ok, userId: e.userId ?? null, code: e.code ?? null, at: e.at }); },
      async summary(since) {
        const group = (match: Record<string, unknown>) => ToolEventModel.aggregate([{ $match: { at: { $gte: since }, ...match } }, { $group: { _id: '$tool', n: { $sum: 1 } } }]);
        const [all, bad] = await Promise.all([group({}), group({ ok: false })]);
        const failed = new Map(bad.map((r) => [String(r._id), r.n as number]));
        return all.map((r) => ({ tool: String(r._id), total: r.n as number, failed: failed.get(String(r._id)) ?? 0 }));
      },
      async countByUser(userId, prefix, since) { return ToolEventModel.countDocuments({ userId, tool: { $regex: `^${escapeRegex(prefix)}` }, at: { $gte: since } }); },
    },
  };
}
