/**
 * Integration tests of the Mongoose repositories against a real Mongo-protocol server.
 *
 * Skipped unless MONGO_TEST_URI is set (e.g. mongodb://127.0.0.1:27017). Each run uses a throw-away database
 * that is dropped at the end. Run with:  MONGO_TEST_URI=mongodb://127.0.0.1:27017 npm run test:mongo
 *
 * Set MONGO_TEST_FLAVOR=ferretdb when pointing at FerretDB: the tests that depend on real-MongoDB guarantees (atomic
 * concurrent updates, E11000 on update) are then reported as SKIPPED, never as passed.
 *
 * Honest scope: the build sandbox had no MongoDB, so this file was executed against FerretDB 1.24 (a Mongo-compatible
 * server on SQLite). Run it against MongoDB / Atlas yourself before going live. TTL *purging* is a server background
 * job and is not asserted here; only that the TTL indexes exist.
 */
import { randomBytes } from 'node:crypto';
import mongoose from 'mongoose';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import * as models from '../src/models/index.js';
import { createMongoRepos } from '../src/repositories/mongo.js';
import type { Repos } from '../src/repositories/types.js';
import { DuplicateError } from '../src/utils/errors.js';
import { env, fakeHasher, MailBox, ORIGIN, PASSWORD } from './helpers.js';

const URI = process.env.MONGO_TEST_URI;
const FERRET = process.env.MONGO_TEST_FLAVOR === 'ferretdb';
const sid = () => randomBytes(5).toString('hex');
const hex = () => randomBytes(12).toString('hex');
const future = (ms = 3_600_000) => new Date(Date.now() + ms);
const past = (ms = 3_600_000) => new Date(Date.now() - ms);

describe.skipIf(!URI)('Mongo repositories (integration)', () => {
  let repos: Repos;
  const dbName = `mh_test_${Date.now()}_${sid()}`;
  let ttlSupported = true;

  beforeAll(async () => {
    await mongoose.connect(URI!, { dbName, serverSelectionTimeoutMS: 5000 });
    for (const m of Object.values(models) as any[]) {
      if (!m || typeof m.init !== 'function' || !m.modelName) continue;
      try { await m.init(); } catch (e) {
        // FerretDB does not implement TTL indexes: build every other index so the uniqueness rules are still exercised.
        if (!/not implemented/i.test(String((e as Error).message))) throw e;
        ttlSupported = false;
        for (const [fields, opts] of m.schema.indexes()) { const { expireAfterSeconds: _t, ...rest } = opts; await m.collection.createIndex(fields, rest); }
      }
    }
    repos = createMongoRepos();
  }, 30_000);
  afterAll(async () => { try { await mongoose.connection.dropDatabase(); } finally { await mongoose.disconnect(); } });

  const newUser = async (name = `u${sid()}`) => repos.users.create({ username: name, email: `${name}@example.com`, passwordHash: 'h' });

  describe('indexes', () => {
    it('creates the unique and TTL indexes the design relies on', async () => {
      const idx = async (c: string) => (await mongoose.connection.collection(c).indexes()) as { key: Record<string, number>; unique?: boolean; expireAfterSeconds?: number }[];
      const names = (await mongoose.connection.db!.listCollections().toArray()).map((c) => c.name);
      const find = (n: string) => names.find((x) => x.toLowerCase().startsWith(n))!;
      const uniq = (i: { key: Record<string, number>; unique?: boolean }[]) => i.filter((x) => x.unique).map((x) => Object.keys(x.key).join('+'));
      expect(uniq(await idx(find('users')))).toEqual(expect.arrayContaining(['email', 'usernameLower']));
      expect(uniq(await idx(find('authidentities')))).toEqual(expect.arrayContaining(['provider+providerUserId', 'userId+provider']));
      expect(uniq(await idx(find('sessions')))).toContain('tokenHash');
      expect(uniq(await idx(find('favorites')))).toContain('userId+kind+key');
      expect(uniq(await idx(find('settings')))).toContain('key');
      // TTL indexes are declared in the schemas (always checked) and on the server only when it implements them.
      for (const [m, c] of [[models.SessionModel, 'sessions'], [models.HistoryModel, 'histories'], [models.ToolEventModel, 'toolevents'], [models.ErrorLogModel, 'errorlogs'], [models.ToolJobModel, 'tooljobs'], [models.AuditLogModel, 'auditlogs']] as const) {
        expect((m as any).schema.indexes().some(([, o]: any) => o.expireAfterSeconds !== undefined), `${c} schema`).toBe(true);
        if (ttlSupported) expect((await idx(find(c))).some((x) => x.expireAfterSeconds !== undefined), `${c} server`).toBe(true);
      }
    });
  });

  describe('users', () => {
    it('enforces unique e-mail and case-insensitive unique username, on create and on update', async () => {
      const a = await newUser('Alice' + sid());
      await expect(repos.users.create({ username: a.username.toUpperCase(), email: `x${sid()}@example.com`, passwordHash: null })).rejects.toBeInstanceOf(DuplicateError);
      await expect(repos.users.create({ username: `n${sid()}`, email: a.email, passwordHash: null })).rejects.toBeInstanceOf(DuplicateError);
      const b = await newUser();
      if (FERRET) await expect(repos.users.update(b.id, { username: a.username.toLowerCase() })).rejects.toThrow(); // FerretDB reports it as InternalError, not E11000
      else await expect(repos.users.update(b.id, { username: a.username.toLowerCase() })).rejects.toBeInstanceOf(DuplicateError);
      const renamed = await repos.users.update(b.id, { username: `Renamed${sid()}` });
      expect(renamed!.username).toMatch(/^Renamed/);
      expect((await repos.users.findByUsername(renamed!.username.toUpperCase()))!.id).toBe(b.id);
      expect(await repos.users.findByUsername(b.username)).toBeNull(); // old name freed
    });
    it('defaults, lookups, invalid ids, stats and admin count', async () => {
      const u = await newUser();
      expect(u).toMatchObject({ role: 'USER', status: 'ACTIVE', emailVerified: false, passwordHash: 'h', totp: null, preferences: { language: 'fr', historyEnabled: true, historyRetentionDays: 30 } });
      expect((await repos.users.findById(u.id))!.email).toBe(u.email);
      expect((await repos.users.findByEmail(u.email))!.id).toBe(u.id);
      expect(await repos.users.findById('not-an-id')).toBeNull();
      expect(await repos.users.findById(hex())).toBeNull();
      const before = await repos.users.stats(new Date());
      await repos.users.update(u.id, { role: 'ADMIN' });
      const after = await repos.users.stats(new Date());
      expect(after.admins).toBe(before.admins + 1);
      expect(after.total).toBe(before.total);
      expect(await repos.users.countAdmins()).toBe(after.admins);
      await repos.users.update(u.id, { role: 'USER' });
    });
    it('persists nested state (preferences, TOTP) and escapes regex characters in admin search', async () => {
      const u = await newUser();
      const upd = await repos.users.update(u.id, { preferences: { language: 'en', historyEnabled: false, historyRetentionDays: 7 }, totp: { secretEnc: 'enc', enabled: true, lastStep: 5, recoveryHashes: ['a', 'b'], fails: 1, lockedUntil: future() } });
      expect(upd!.preferences).toEqual({ language: 'en', historyEnabled: false, historyRetentionDays: 7 });
      expect(upd!.totp).toMatchObject({ enabled: true, lastStep: 5, recoveryHashes: ['a', 'b'], fails: 1 });
      expect((await repos.users.findById(u.id))!.totp!.lockedUntil).toBeInstanceOf(Date);
      expect((await repos.users.list({ page: 1, pageSize: 10, q: '.*' })).total).toBe(0);
      expect((await repos.users.list({ page: 1, pageSize: 10, q: '(' })).total).toBe(0);
      expect((await repos.users.list({ page: 1, pageSize: 10, q: u.username })).total).toBe(1);
    });
    it('does not let a query-operator object select a user', async () => {
      await newUser();
      for (const evil of [{ $ne: '' }, { $gt: '' }, { $regex: '.*' }]) {
        const r = await repos.users.findByEmail(evil as never).catch(() => null);
        expect(r).toBeNull();
      }
    });
    it('paginates and filters', async () => {
      const tag = sid();
      for (let i = 0; i < 3; i++) await newUser(`pg${tag}${i}`);
      const p1 = await repos.users.list({ page: 1, pageSize: 2, q: `pg${tag}` });
      const p2 = await repos.users.list({ page: 2, pageSize: 2, q: `pg${tag}` });
      expect([p1.total, p1.items.length, p2.items.length]).toEqual([3, 2, 1]);
      expect(p1.items[0]!.createdAt.getTime()).toBeGreaterThanOrEqual(p1.items[1]!.createdAt.getTime());
    });
  });

  describe('sessions', () => {
    it('lists only live sessions and scopes revocation to the owner', async () => {
      const a = await newUser(); const b = await newUser();
      const mk = (userId: string, over: object = {}) => repos.sessions.create({ userId, tokenHash: randomBytes(16).toString('hex'), csrfToken: 'c', userAgent: 'ua', createdAt: new Date(), lastActivityAt: new Date(), expiresAt: future(), ...over });
      const s1 = await mk(a.id); const s2 = await mk(a.id); await mk(a.id, { expiresAt: past() }); const sb = await mk(b.id);
      expect((await repos.sessions.findByTokenHash(s1.tokenHash))!.id).toBe(s1.id);
      expect(await repos.sessions.findByTokenHash('nope')).toBeNull();
      expect((await repos.sessions.listActive(a.id, new Date())).length).toBe(2);
      expect(await repos.sessions.revokeOwned(sb.id, a.id, new Date())).toBe(false);
      expect(await repos.sessions.revokeOwned(s2.id, a.id, new Date())).toBe(true);
      expect(await repos.sessions.revokeOwned(s2.id, a.id, new Date())).toBe(true); // idempotent
      expect(await repos.sessions.revokeOthers(a.id, s1.id, new Date())).toBe(0);
      const s3 = await mk(a.id);
      expect(await repos.sessions.revokeOthers(a.id, s1.id, new Date())).toBe(1);
      expect((await repos.sessions.listActive(a.id, new Date())).map((s) => s.id)).toEqual([s1.id]);
      await repos.sessions.revokeAllForUser(a.id, new Date());
      expect((await repos.sessions.listActive(a.id, new Date())).length).toBe(0);
      expect((await repos.sessions.findByTokenHash(sb.tokenHash))!.revokedAt).toBeNull();
      void s3;
    });
  });

  describe('single-use tokens and OTP (atomicity under concurrency)', () => {
    it('a reset/verification token can be consumed exactly once even when raced', async () => {
      const u = await newUser();
      const t = await repos.tokens.create('PASSWORD_RESET', { userId: u.id, tokenHash: hex(), expiresAt: future() });
      expect((await repos.tokens.findUsable('PASSWORD_RESET', t.tokenHash, new Date()))!.id).toBe(t.id);
      expect(await repos.tokens.findUsable('EMAIL_VERIFICATION', t.tokenHash, new Date())).toBeNull(); // kinds are separate
      if (FERRET) { expect(await repos.tokens.consume('PASSWORD_RESET', t.id, new Date())).toBe(true); expect(await repos.tokens.consume('PASSWORD_RESET', t.id, new Date())).toBe(false); }
      else { const results = await Promise.all(Array.from({ length: 12 }, () => repos.tokens.consume('PASSWORD_RESET', t.id, new Date()))); expect(results.filter(Boolean).length).toBe(1); }
      expect(await repos.tokens.findUsable('PASSWORD_RESET', t.tokenHash, new Date())).toBeNull();
      const expired = await repos.tokens.create('PASSWORD_RESET', { userId: u.id, tokenHash: hex(), expiresAt: past() });
      expect(await repos.tokens.findUsable('PASSWORD_RESET', expired.tokenHash, new Date())).toBeNull();
      const live = await repos.tokens.create('PASSWORD_RESET', { userId: u.id, tokenHash: hex(), expiresAt: future() });
      await repos.tokens.invalidateAllForUser('PASSWORD_RESET', u.id, new Date());
      expect(await repos.tokens.findUsable('PASSWORD_RESET', live.tokenHash, new Date())).toBeNull();
    });
    it('a pending registration has one live code, atomic attempt counting and a single winner on take', async () => {
      const email = `${sid()}@example.com`;
      const base = { email, username: `p${sid()}`, passwordHash: 'h', codeHash: 'c1', codeExpiresAt: future(), attemptsLeft: 5, resendCount: 0, lastSentAt: new Date(), expiresAt: future() };
      const a = await repos.pending.upsert(base);
      const b = await repos.pending.upsert({ ...base, codeHash: 'c2', resendCount: 1 });
      expect(b.id).toBe(a.id);
      expect((await repos.pending.findByEmail(email))).toMatchObject({ codeHash: 'c2', attemptsLeft: 5, resendCount: 1 });
      if (FERRET) {
        const lefts: number[] = []; for (let i = 0; i < 5; i++) lefts.push(await repos.pending.recordFailure(b.id));
        expect(lefts).toEqual([4, 3, 2, 1, 0]);
        expect(await repos.pending.recordFailure(b.id)).toBe(0);
        expect(await repos.pending.take(b.id)).toBe(true); expect(await repos.pending.take(b.id)).toBe(false);
      } else {
        const lefts = await Promise.all(Array.from({ length: 5 }, () => repos.pending.recordFailure(b.id)));
        expect([...lefts].sort()).toEqual([0, 1, 2, 3, 4]);
        const takes = await Promise.all(Array.from({ length: 8 }, () => repos.pending.take(b.id)));
        expect(takes.filter(Boolean).length).toBe(1);
      }
      expect(await repos.pending.findByEmail(email)).toBeNull();
      await repos.pending.upsert(base); await repos.pending.deleteByEmail(email);
      expect(await repos.pending.findByEmail(email)).toBeNull();
    });
  });

  describe('identities', () => {
    it('enforces one account per Google identity and one Google identity per account', async () => {
      const a = await newUser(); const b = await newUser(); const g = `g-${sid()}`;
      await repos.identities.create({ userId: a.id, provider: 'GOOGLE', providerUserId: g });
      await expect(repos.identities.create({ userId: b.id, provider: 'GOOGLE', providerUserId: g })).rejects.toBeInstanceOf(DuplicateError);
      await expect(repos.identities.create({ userId: a.id, provider: 'GOOGLE', providerUserId: `g-${sid()}` })).rejects.toBeInstanceOf(DuplicateError);
      expect(await repos.identities.findUserIdByProvider('GOOGLE', g)).toBe(a.id);
      expect(await repos.identities.hasProvider(a.id, 'GOOGLE')).toBe(true);
      expect(await repos.identities.deleteForUser(b.id, 'GOOGLE')).toBe(false);
      expect(await repos.identities.deleteForUser(a.id, 'GOOGLE')).toBe(true);
      expect(await repos.identities.findUserIdByProvider('GOOGLE', g)).toBeNull();
      await repos.identities.create({ userId: a.id, provider: 'GOOGLE', providerUserId: g });
      await repos.identities.deleteAllForUser(a.id);
      expect(await repos.identities.hasProvider(a.id, 'GOOGLE')).toBe(false);
    });
  });

  describe('history', () => {
    it('lists newest first with filters, hides expired entries, isolates users', async () => {
      const a = await newUser(); const b = await newUser();
      const mk = (userId: string, over: object = {}) => repos.history.create({ userId, kind: 'SEARCH', tool: 'music', query: 'q', title: null, status: 'SUCCESS', createdAt: new Date(), expiresAt: future(), ...over });
      const h1 = await mk(a.id, { createdAt: past(3000), query: 'old' });
      await mk(a.id, { createdAt: past(2000), kind: 'OPERATION', tool: 'facebook', query: 'mid' });
      await mk(a.id, { createdAt: past(1000), query: 'new' });
      await mk(a.id, { expiresAt: past(), query: 'expired' });
      await mk(b.id, { query: 'other' });
      const all = await repos.history.list({ userId: a.id, page: 1, pageSize: 10, now: new Date() });
      expect(all.items.map((i) => i.query)).toEqual(['new', 'mid', 'old']);
      expect(all.total).toBe(3);
      expect((await repos.history.list({ userId: a.id, page: 1, pageSize: 10, kind: 'OPERATION', now: new Date() })).items.length).toBe(1);
      expect((await repos.history.list({ userId: a.id, page: 1, pageSize: 10, tool: 'music', now: new Date() })).total).toBe(2);
      expect((await repos.history.list({ userId: a.id, page: 2, pageSize: 2, now: new Date() })).items.map((i) => i.query)).toEqual(['old']);
      expect(await repos.history.delete(h1.id, b.id)).toBe(false);
      expect(await repos.history.delete(h1.id, a.id)).toBe(true);
      expect(await repos.history.delete('bad-id', a.id)).toBe(false);
      expect(await repos.history.clear(a.id)).toBe(3); // includes the expired row still physically present
      expect((await repos.history.list({ userId: b.id, page: 1, pageSize: 10, now: new Date() })).total).toBe(1);
    });
  });

  describe('favourites', () => {
    it('deduplicates per user, scopes deletion, counts and cascades', async () => {
      const a = await newUser(); const b = await newUser();
      const item = { kind: 'TRACK' as const, key: 'track:1', title: 'T', subtitle: null, url: null, imageUrl: null };
      const f = await repos.favorites.create({ ...item, userId: a.id });
      await expect(repos.favorites.create({ ...item, userId: a.id })).rejects.toBeInstanceOf(DuplicateError);
      await repos.favorites.create({ ...item, userId: b.id });
      await repos.favorites.create({ ...item, key: 'track:2', kind: 'ALBUM', userId: a.id });
      expect(await repos.favorites.count(a.id)).toBe(2);
      const l = await repos.favorites.list({ userId: a.id, page: 1, pageSize: 10 });
      expect([l.total, l.items.length]).toEqual([2, 2]);
      expect((await repos.favorites.list({ userId: a.id, page: 1, pageSize: 10, kind: 'ALBUM' })).total).toBe(1);
      expect(await repos.favorites.delete(f.id, b.id)).toBe(false);
      expect(await repos.favorites.delete(f.id, a.id)).toBe(true);
      await repos.favorites.deleteAllForUser(a.id);
      expect(await repos.favorites.count(a.id)).toBe(0);
      expect(await repos.favorites.count(b.id)).toBe(1);
    });
  });

  describe('collections', () => {
    const it1 = (n: number): import('../src/repositories/types.js').SavedItem => ({ kind: 'TRACK', key: `track:${n}`, title: `T${n}`, subtitle: null, url: null, imageUrl: null });
    it('CRUD is owner-scoped', async () => {
      const a = await newUser(); const b = await newUser();
      const c = await repos.collections.create({ userId: a.id, name: 'Mix', description: null });
      expect(c.items).toEqual([]);
      expect((await repos.collections.findOwned(c.id, b.id))).toBeNull();
      expect(await repos.collections.findOwned('bad', a.id)).toBeNull();
      expect((await repos.collections.update(c.id, a.id, { name: 'Mix 2', description: 'd' }))).toMatchObject({ name: 'Mix 2', description: 'd' });
      expect(await repos.collections.update(c.id, b.id, { name: 'pwn' })).toBeNull();
      expect(await repos.collections.count(a.id)).toBe(1);
      expect(await repos.collections.delete(c.id, b.id)).toBe(false);
      expect(await repos.collections.delete(c.id, a.id)).toBe(true);
    });
    it('addItem: ok / duplicate / missing / not-yours / full', async () => {
      const a = await newUser(); const b = await newUser();
      const c = await repos.collections.create({ userId: a.id, name: 'x', description: null });
      expect(await repos.collections.addItem(c.id, a.id, it1(1), 3)).toBe('ok');
      expect(await repos.collections.addItem(c.id, a.id, it1(1), 3)).toBe('duplicate');
      expect(await repos.collections.addItem(c.id, b.id, it1(2), 3)).toBe('missing');
      expect(await repos.collections.addItem(hex(), a.id, it1(2), 3)).toBe('missing');
      expect(await repos.collections.addItem(c.id, a.id, it1(2), 3)).toBe('ok');
      expect(await repos.collections.addItem(c.id, a.id, it1(3), 3)).toBe('ok');
      expect(await repos.collections.addItem(c.id, a.id, it1(4), 3)).toBe('full');
      const got = (await repos.collections.findOwned(c.id, a.id))!;
      expect(got.items.map((i) => i.key)).toEqual(['track:1', 'track:2', 'track:3']);
      expect(got.items.every((i) => /^[a-f0-9]{24}$/.test(i.id))).toBe(true);
      await repos.collections.deleteAllForUser(a.id);
      expect(await repos.collections.count(a.id)).toBe(0);
    });
    it('removeItem is owner-scoped and reports whether the item was really there', async (ctx) => {
      if (FERRET) ctx.skip(); // FerretDB 1.24 silently ignores $pull with a condition, so this cannot be verified on it
      const a = await newUser(); const b = await newUser();
      const c = await repos.collections.create({ userId: a.id, name: 'x', description: null });
      for (const n of [1, 2, 3]) await repos.collections.addItem(c.id, a.id, it1(n), 3);
      const got = (await repos.collections.findOwned(c.id, a.id))!;
      expect(await repos.collections.removeItem(c.id, b.id, got.items[0]!.id)).toBe(false);
      expect(await repos.collections.removeItem(c.id, a.id, got.items[0]!.id)).toBe(true);
      expect(await repos.collections.removeItem(c.id, a.id, got.items[0]!.id)).toBe(false);
      expect((await repos.collections.findOwned(c.id, a.id))!.items.length).toBe(2);
      expect(await repos.collections.addItem(c.id, a.id, it1(4), 3)).toBe('ok'); // room again
    });
    it('the item limit and de-duplication hold under concurrent requests', async (ctx) => {
      if (FERRET) ctx.skip(); // needs MongoDB's single-document atomicity; FerretDB/SQLite does not provide it
      const a = await newUser();
      const c = await repos.collections.create({ userId: a.id, name: 'race', description: null });
      const adds = await Promise.all(Array.from({ length: 12 }, (_, i) => repos.collections.addItem(c.id, a.id, it1(100 + i), 5)));
      expect(adds.filter((r) => r === 'ok').length).toBe(5);
      expect(adds.filter((r) => r === 'full').length).toBe(7);
      expect((await repos.collections.findOwned(c.id, a.id))!.items.length).toBe(5);
      const d = await repos.collections.create({ userId: a.id, name: 'dup', description: null });
      const dups = await Promise.all(Array.from({ length: 8 }, () => repos.collections.addItem(d.id, a.id, it1(7), 50)));
      expect(dups.filter((r) => r === 'ok').length).toBe(1);
      expect(dups.filter((r) => r === 'duplicate').length).toBe(7);
      expect((await repos.collections.findOwned(d.id, a.id))!.items.length).toBe(1);
    });
  });

  describe('jobs, reports, settings', () => {
    it('stores and reads ad-gate jobs (invalid ids are just not found)', async () => {
      const j = await repos.jobs.create({ tool: 'facebook', userId: null, result: { title: 'x', downloads: [{ url: 'https://c.example.com/a.mp4' }] }, readyAt: future(5000), expiresAt: future() });
      const back = (await repos.jobs.findById(j.id))!;
      expect(back.tool).toBe('facebook'); expect(back.userId).toBeNull();
      expect((back.result as any).downloads[0].url).toBe('https://c.example.com/a.mp4');
      expect(back.readyAt.getTime()).toBeGreaterThan(Date.now());
      expect(await repos.jobs.findById('zzz')).toBeNull();
      expect(await repos.jobs.findById(hex())).toBeNull();
    });
    it('reports: create, filter, count, update, detach reporter', async () => {
      const u = await newUser();
      const r = await repos.reports.create({ reporterId: u.id, kind: 'ABUSE', targetUrl: null, description: 'desc desc desc', contactEmail: null });
      expect(r).toMatchObject({ status: 'OPEN', handledBy: null, adminNote: null });
      const before = await repos.reports.counts();
      const r2 = await repos.reports.create({ reporterId: null, kind: 'OTHER', targetUrl: 'https://a.example.com', description: 'desc desc desc', contactEmail: 'a@b.co' });
      expect((await repos.reports.counts()).total).toBe(before.total + 1);
      const upd = await repos.reports.update(r.id, { status: 'IN_REVIEW', adminNote: 'n', handledBy: u.id });
      expect(upd).toMatchObject({ status: 'IN_REVIEW', adminNote: 'n', handledBy: u.id });
      expect(await repos.reports.update(hex(), { status: 'RESOLVED' })).toBeNull();
      expect((await repos.reports.counts()).inReview).toBeGreaterThanOrEqual(1);
      expect((await repos.reports.list({ page: 1, pageSize: 50, status: 'IN_REVIEW' })).items.some((x) => x.id === r.id)).toBe(true);
      await repos.reports.detachReporter(u.id);
      expect((await repos.reports.findById(r.id))!.reporterId).toBeNull();
      expect((await repos.reports.findById(r2.id))!.id).toBe(r2.id);
    });
    it('settings upsert and read back', async () => {
      await repos.settings.set('ads', { enabled: true, waitSeconds: 7 }, null);
      await repos.settings.set('ads', { enabled: false, waitSeconds: 3 }, null);
      await repos.settings.set('tools', { music: false }, null);
      const all = await repos.settings.getAll();
      expect(all.ads).toEqual({ enabled: false, waitSeconds: 3 });
      expect(all.tools).toEqual({ music: false });
    });
  });

  describe('audit, errors, tool events, API keys', () => {
    it('audit log lists newest first and filters by action', async () => {
      const act = `TEST_${sid()}`;
      await repos.audit.create({ actorId: null, action: act, metadata: { n: 1 } });
      await repos.audit.create({ actorId: null, action: act, metadata: { n: 2 } });
      await repos.audit.create({ actorId: null, action: 'OTHER' });
      const l = await repos.audit.list({ page: 1, pageSize: 10, action: act });
      expect(l.total).toBe(2);
      expect(l.items.map((i) => i.metadata.n)).toEqual([2, 1]);
    });
    it('error log: list, filter, countSince', async () => {
      const route = `r-${sid()}`;
      await repos.errors.create({ source: 'provider', code: 'X', route, message: 'm' });
      await repos.errors.create({ source: 'http', code: 'Y', message: 'm2' });
      expect((await repos.errors.list({ page: 1, pageSize: 100, source: 'provider' })).items.some((e) => e.route === route)).toBe(true);
      expect(await repos.errors.countSince(past(60_000))).toBeGreaterThanOrEqual(2);
      expect(await repos.errors.countSince(future())).toBe(0);
    });
    it('tool events aggregate per tool and count per user with an escaped prefix', async () => {
      const u = await newUser(); const tag = `t${sid()}`;
      for (const ok of [true, true, false]) await repos.toolEvents.create({ tool: tag, ok, userId: u.id, at: new Date() });
      await repos.toolEvents.create({ tool: tag, ok: true, userId: u.id, at: past(10 * 86_400_000) });
      const s = (await repos.toolEvents.summary(past(86_400_000))).find((x) => x.tool === tag)!;
      expect(s).toMatchObject({ total: 3, failed: 1 });
      await repos.toolEvents.create({ tool: 'ai:titles', ok: true, userId: u.id, at: new Date() });
      await repos.toolEvents.create({ tool: 'ai:hashtags', ok: false, userId: u.id, at: new Date() });
      expect(await repos.toolEvents.countByUser(u.id, 'ai:', past(86_400_000))).toBe(2);
      expect(await repos.toolEvents.countByUser(u.id, '.*', past(86_400_000))).toBe(0);
      expect(await repos.toolEvents.countByUser((await newUser()).id, 'ai:', past(86_400_000))).toBe(0);
    });
    it('API keys: create, lookup, usage buckets, revoke (owner-scoped), stats', async () => {
      const a = await newUser(); const b = await newUser();
      const k = await repos.apiKeys.create({ userId: a.id, name: 'k', prefix: `mh_live_${sid()}`, keyHash: hex() });
      expect((await repos.apiKeys.findByHash(k.keyHash))!.id).toBe(k.id);
      expect(await repos.apiKeys.countActive(a.id)).toBe(1);
      await repos.apiKeys.recordUse(k.id, a.id, new Date(), true);
      await repos.apiKeys.recordUse(k.id, a.id, new Date(), false);
      await repos.apiKeys.recordUse(k.id, a.id, new Date(), true);
      const back = (await repos.apiKeys.listByUser(a.id))[0]!;
      expect([back.requests, back.errors]).toEqual([3, 1]);
      expect(back.lastUsedAt).toBeInstanceOf(Date);
      const usage = await repos.apiKeys.usage({ since: past(86_400_000), userId: a.id });
      expect(usage.reduce((n, x) => n + x.requests, 0)).toBe(3);
      expect(usage.reduce((n, x) => n + x.errors, 0)).toBe(1);
      expect(await repos.apiKeys.revoke(k.id, new Date(), b.id)).toBeNull();
      expect((await repos.apiKeys.revoke(k.id, new Date(), a.id))!.revokedAt).toBeInstanceOf(Date);
      expect(await repos.apiKeys.countActive(a.id)).toBe(0);
      expect((await repos.apiKeys.stats(new Date())).revoked).toBeGreaterThanOrEqual(1);
    });
  });

  describe('full HTTP flow on the Mongo repositories (data survives an "application restart")', () => {
    const build = (mail: MailBox) => createApp({ env, repos: createMongoRepos(), hasher: fakeHasher, email: mail, limits: { general: { windowMs: 60_000, max: 5000 }, login: { windowMs: 60_000, max: 5000 }, register: { windowMs: 60_000, max: 5000 }, reset: { windowMs: 60_000, max: 5000 }, sensitive: { windowMs: 60_000, max: 5000 }, otp: { windowMs: 60_000, max: 5000 }, otpResend: { windowMs: 60_000, max: 5000 } } });
    it('register → OTP → session → favourites/collections/history → restart → still signed in → delete account erases everything', async () => {
      const mail = new MailBox();
      const app1 = build(mail);
      const email = `flow${sid()}@example.com`;
      const O = (r: request.Test) => r.set('Origin', ORIGIN);
      const reg = await O(request(app1).post('/api/v1/auth/register')).send({ username: `flow${sid()}`, email, password: PASSWORD, acceptTerms: true });
      expect(reg.status).toBeLessThan(300);
      expect(await (await import('../src/repositories/mongo.js')).createMongoRepos().users.findByEmail(email)).toBeNull(); // no account before the code
      const ver = await O(request(app1).post('/api/v1/auth/verify-otp')).send({ email, code: mail.otpFrom(email) });
      expect(ver.status).toBeLessThan(300);
      const agent1 = request.agent(app1);
      const login = await O(agent1.post('/api/v1/auth/login')).send({ email, password: PASSWORD });
      expect(login.status).toBe(200);
      const csrf = login.body.csrfToken as string;
      const call = (ag: ReturnType<typeof request.agent>, m: 'get' | 'post' | 'delete' | 'patch', url: string, body?: object) => { const r = O((ag as any)[m](url)); if (m !== 'get') r.set('X-CSRF-Token', csrf); return body ? r.send(body) : r; };

      expect((await call(agent1, 'post', '/api/v1/me/favorites', { kind: 'TRACK', externalId: 'track:1', title: 'Titre' })).status).toBe(201);
      expect((await call(agent1, 'post', '/api/v1/me/favorites', { kind: 'TRACK', externalId: 'track:1', title: 'Titre' })).status).toBe(409);
      const col = await call(agent1, 'post', '/api/v1/me/collections', { name: 'Mix' });
      expect(col.status).toBe(201);
      expect((await call(agent1, 'post', `/api/v1/me/collections/${col.body.id}/items`, { kind: 'TRACK', externalId: 'track:2', title: 'B' })).status).toBe(201);
      expect((await call(agent1, 'post', `/api/v1/me/collections/${col.body.id}/items`, { kind: 'TRACK', externalId: 'track:2', title: 'B' })).status).toBe(409);
      await call(agent1, 'patch', '/api/v1/me/preferences', { historyRetentionDays: 5 });

      // "restart": a brand-new app instance, brand-new repos, same database; the old cookie must still work
      const app2 = build(new MailBox());
      const cookie = (login.headers['set-cookie'] as unknown as string[]).find((c) => c.startsWith('mh_sid='))!.split(';')[0]!;
      const me = await request(app2).get('/api/v1/auth/me').set('Cookie', cookie);
      expect(me.status).toBe(200);
      expect(me.body.user.email).toBe(email);
      const favs = await request(app2).get('/api/v1/me/favorites').set('Cookie', cookie);
      expect(favs.body.total).toBe(1);
      const cols = await request(app2).get(`/api/v1/me/collections/${col.body.id}`).set('Cookie', cookie);
      expect(cols.body.items.length).toBe(1);
      expect((await request(app2).get('/api/v1/me/preferences').set('Cookie', cookie)).body.historyRetentionDays).toBe(5);
      expect(JSON.stringify(me.body)).not.toMatch(/passwordHash|tokenHash/);

      // logout kills the session in the database
      const out = await O(request(app2).post('/api/v1/auth/logout').set('Cookie', cookie)).set('X-CSRF-Token', csrf);
      expect(out.status).toBeLessThan(300);
      expect((await request(app2).get('/api/v1/auth/me').set('Cookie', cookie)).status).toBe(401);

      // delete the account: everything personal is gone
      const agent3 = request.agent(app2);
      const l3 = await O(agent3.post('/api/v1/auth/login')).send({ email, password: PASSWORD });
      const csrf3 = l3.body.csrfToken as string;
      const del = await O(agent3.delete('/api/v1/auth/account')).set('X-CSRF-Token', csrf3).send({ password: PASSWORD });
      expect(del.status).toBeLessThan(300);
      const repos2 = createMongoRepos();
      expect(await repos2.users.findByEmail(email)).toBeNull();
      expect(await repos2.favorites.count(col.body.userId ?? '0'.repeat(24))).toBe(0);
      expect((await mongoose.connection.collection('collections').countDocuments({ _id: new mongoose.Types.ObjectId(col.body.id) }))).toBe(0);
      expect((await mongoose.connection.collection('favorites').countDocuments({ title: 'Titre', userId: { $exists: true } }))).toBe(0);
    });

    it('operator-injection attempts are rejected at the HTTP layer and never match a stored account', async () => {
      const mail = new MailBox(); const app = build(mail);
      const email = `inj${sid()}@example.com`;
      const O = (r: request.Test) => r.set('Origin', ORIGIN);
      await O(request(app).post('/api/v1/auth/register')).send({ username: `inj${sid()}`, email, password: PASSWORD, acceptTerms: true });
      await O(request(app).post('/api/v1/auth/verify-otp')).send({ email, code: mail.otpFrom(email) });
      for (const body of [{ email: { $ne: null }, password: { $ne: null } }, { email: { $gt: '' }, password: PASSWORD }, { email, password: { $ne: '' } }, { 'email.$ne': 'x', password: 'y' }, { email: { $regex: '.*' }, password: PASSWORD }]) {
        const r = await O(request(app).post('/api/v1/auth/login')).send(body);
        expect(r.status, JSON.stringify(body)).toBeGreaterThanOrEqual(400);
        expect(r.status).toBeLessThan(500);
        expect(r.headers['set-cookie']).toBeUndefined();
      }
    });
  });
});
