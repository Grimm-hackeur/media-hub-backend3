export type Role = 'USER' | 'ADMIN';
export type UserStatus = 'ACTIVE' | 'SUSPENDED' | 'DELETED';
export type Provider = 'GOOGLE' | 'EMAIL';
export type TokenKind = 'EMAIL_VERIFICATION' | 'PASSWORD_RESET';

export interface TotpState {
  secretEnc: string; // AES-256-GCM, never the raw secret
  enabled: boolean;
  lastStep: number; // anti-replay: a time step can be used once
  recoveryHashes: string[];
  fails: number;
  lockedUntil: Date | null;
}
export interface Preferences {
  language: 'fr' | 'en';
  /** When false nothing is written to the user's history. */
  historyEnabled: boolean;
  /** Entries are deleted automatically after this many days (applies to entries written afterwards). */
  historyRetentionDays: number;
}
export const DEFAULT_PREFERENCES: Preferences = { language: 'fr', historyEnabled: true, historyRetentionDays: 30 };
export interface UserRecord {
  id: string;
  username: string;
  email: string;
  passwordHash: string | null;
  role: Role;
  emailVerified: boolean;
  avatar: string | null;
  status: UserStatus;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | null;
  totp: TotpState | null;
  preferences: Preferences;
}
export interface SessionRecord {
  id: string;
  userId: string;
  tokenHash: string;
  csrfToken: string;
  userAgent: string | null;
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
}
export interface TokenRecord {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  usedAt: Date | null;
}
export interface AuditRecord {
  id: string;
  actorId: string | null;
  action: string;
  targetId: string | null;
  metadata: Record<string, string | number | boolean | null>;
  timestamp: Date;
}
export interface PendingRecord {
  id: string;
  email: string;
  username: string;
  passwordHash: string;
  codeHash: string;
  codeExpiresAt: Date;
  attemptsLeft: number;
  resendCount: number;
  lastSentAt: Date;
  expiresAt: Date; // the whole pending registration is purged after this date
  createdAt: Date;
}
export interface PendingRepo {
  /** Creates or replaces the pending registration for this e-mail (old code becomes invalid). */
  upsert(d: Omit<PendingRecord, 'id' | 'createdAt'>): Promise<PendingRecord>;
  findByEmail(email: string): Promise<PendingRecord | null>;
  /** Atomically decrements the attempts of the CURRENT code; returns what is left. */
  recordFailure(id: string): Promise<number>;
  /** Atomically deletes; false if it was already taken (concurrent verification). */
  take(id: string): Promise<boolean>;
  deleteByEmail(email: string): Promise<void>;
}
export interface Page<T> {
  items: T[];
  total: number;
}

export interface UserRepo {
  create(data: { username: string; email: string; passwordHash: string | null }): Promise<UserRecord>;
  findById(id: string): Promise<UserRecord | null>;
  findByEmail(email: string): Promise<UserRecord | null>;
  findByUsername(username: string): Promise<UserRecord | null>; // case-insensitive, exact
  update(id: string, patch: Partial<Omit<UserRecord, 'id' | 'createdAt' | 'updatedAt'>>): Promise<UserRecord | null>;
  list(q: { page: number; pageSize: number; q?: string; role?: Role; status?: UserStatus }): Promise<Page<UserRecord>>;
  countAdmins(): Promise<number>;
  stats(now: Date): Promise<{ total: number; active: number; suspended: number; admins: number; createdLast7d: number }>;
}
export interface SessionRepo {
  create(data: Omit<SessionRecord, 'id' | 'revokedAt'>): Promise<SessionRecord>;
  findByTokenHash(tokenHash: string): Promise<SessionRecord | null>;
  touch(id: string, at: Date): Promise<void>;
  revoke(id: string, at: Date): Promise<void>;
  revokeAllForUser(userId: string, at: Date): Promise<void>;
  listActive(userId: string, now: Date): Promise<SessionRecord[]>;
  /** Revokes only if the session belongs to userId. */
  revokeOwned(id: string, userId: string, at: Date): Promise<boolean>;
  revokeOthers(userId: string, exceptId: string, at: Date): Promise<number>;
}
export interface TokenRepo {
  create(kind: TokenKind, data: { userId: string; tokenHash: string; expiresAt: Date }): Promise<TokenRecord>;
  findUsable(kind: TokenKind, tokenHash: string, now: Date): Promise<TokenRecord | null>;
  /** Atomically marks the token as used. Returns false if it was already used. */
  consume(kind: TokenKind, id: string, now: Date): Promise<boolean>;
  invalidateAllForUser(kind: TokenKind, userId: string, now: Date): Promise<void>;
}
export interface IdentityRepo {
  create(data: { userId: string; provider: Provider; providerUserId: string }): Promise<void>;
  findUserIdByProvider(provider: Provider, providerUserId: string): Promise<string | null>;
  deleteAllForUser(userId: string): Promise<void>;
  /** Returns false if the user had no identity for this provider. */
  deleteForUser(userId: string, provider: Provider): Promise<boolean>;
  hasProvider(userId: string, provider: Provider): Promise<boolean>;
}
export interface AuditRepo {
  create(e: { actorId: string | null; action: string; targetId?: string | null; metadata?: AuditRecord['metadata'] }): Promise<void>;
  list(q: { page: number; pageSize: number; action?: string }): Promise<Page<AuditRecord>>;
}
export interface ApiKeyRecord {
  id: string;
  userId: string;
  name: string;
  /** Non-secret display prefix, e.g. "mh_live_AbCd1234". */
  prefix: string;
  keyHash: string;
  createdAt: Date;
  lastUsedAt: Date | null;
  revokedAt: Date | null;
  requests: number;
  errors: number;
}
export interface UsageBucket { keyId: string; userId: string; hour: Date; requests: number; errors: number }
export interface ApiKeyRepo {
  create(d: { userId: string; name: string; prefix: string; keyHash: string }): Promise<ApiKeyRecord>;
  listByUser(userId: string): Promise<ApiKeyRecord[]>;
  findByHash(keyHash: string): Promise<ApiKeyRecord | null>;
  /** Revokes only if the key belongs to userId (when given). Returns the key, or null if absent. */
  revoke(id: string, at: Date, userId?: string): Promise<ApiKeyRecord | null>;
  revokeAllForUser(userId: string, at: Date): Promise<void>;
  countActive(userId: string): Promise<number>;
  recordUse(keyId: string, userId: string, at: Date, ok: boolean): Promise<void>;
  usage(q: { since: Date; userId?: string }): Promise<UsageBucket[]>;
  stats(now: Date): Promise<{ total: number; active: number; revoked: number; createdLast7d: number; owners: number }>;
}
export type ItemKind = 'TRACK' | 'ALBUM' | 'LINK';
export interface SavedItem {
  kind: ItemKind;
  /** Stable de-duplication key (provider id, or hash of the URL). */
  key: string;
  title: string;
  subtitle: string | null;
  url: string | null;
  imageUrl: string | null;
}
export interface HistoryRecord {
  id: string; userId: string; kind: 'SEARCH' | 'OPERATION'; tool: string;
  /** Search text (music) or the host of the analysed link. Full URLs are deliberately NOT stored. */
  query: string | null; title: string | null; status: 'SUCCESS' | 'FAILED'; createdAt: Date; expiresAt: Date;
}
export interface HistoryRepo {
  create(d: Omit<HistoryRecord, 'id'>): Promise<HistoryRecord>;
  list(q: { userId: string; page: number; pageSize: number; kind?: HistoryRecord['kind']; tool?: string; now: Date }): Promise<Page<HistoryRecord>>;
  delete(id: string, userId: string): Promise<boolean>;
  clear(userId: string): Promise<number>;
}
export interface FavoriteRecord extends SavedItem { id: string; userId: string; createdAt: Date }
export interface FavoriteRepo {
  /** Throws DuplicateError('key') when the user already saved this item. */
  create(d: SavedItem & { userId: string }): Promise<FavoriteRecord>;
  list(q: { userId: string; page: number; pageSize: number; kind?: ItemKind }): Promise<Page<FavoriteRecord>>;
  delete(id: string, userId: string): Promise<boolean>;
  count(userId: string): Promise<number>;
  deleteAllForUser(userId: string): Promise<void>;
}
export interface CollectionItem extends SavedItem { id: string; addedAt: Date }
export interface CollectionRecord { id: string; userId: string; name: string; description: string | null; items: CollectionItem[]; createdAt: Date; updatedAt: Date }
export interface CollectionRepo {
  create(d: { userId: string; name: string; description: string | null }): Promise<CollectionRecord>;
  list(userId: string): Promise<CollectionRecord[]>;
  findOwned(id: string, userId: string): Promise<CollectionRecord | null>;
  update(id: string, userId: string, patch: { name?: string; description?: string | null }): Promise<CollectionRecord | null>;
  delete(id: string, userId: string): Promise<boolean>;
  addItem(id: string, userId: string, item: SavedItem, maxItems: number): Promise<'ok' | 'full' | 'duplicate' | 'missing'>;
  removeItem(id: string, userId: string, itemId: string): Promise<boolean>;
  count(userId: string): Promise<number>;
  deleteAllForUser(userId: string): Promise<void>;
}
export interface JobRecord { id: string; tool: string; userId: string | null; result: unknown; readyAt: Date; expiresAt: Date; createdAt: Date }
export interface JobRepo {
  create(d: { tool: string; userId: string | null; result: unknown; readyAt: Date; expiresAt: Date }): Promise<JobRecord>;
  findById(id: string): Promise<JobRecord | null>;
}
export type ReportKind = 'COPYRIGHT' | 'ABUSE' | 'ILLEGAL' | 'OTHER';
export type ReportStatus = 'OPEN' | 'IN_REVIEW' | 'RESOLVED' | 'REJECTED';
export interface ReportRecord {
  id: string; reporterId: string | null; kind: ReportKind; targetUrl: string | null; description: string; contactEmail: string | null;
  status: ReportStatus; adminNote: string | null; handledBy: string | null; createdAt: Date; updatedAt: Date;
}
export interface ReportRepo {
  create(d: Pick<ReportRecord, 'reporterId' | 'kind' | 'targetUrl' | 'description' | 'contactEmail'>): Promise<ReportRecord>;
  list(q: { page: number; pageSize: number; status?: ReportStatus }): Promise<Page<ReportRecord>>;
  findById(id: string): Promise<ReportRecord | null>;
  update(id: string, patch: { status?: ReportStatus; adminNote?: string | null; handledBy?: string | null }): Promise<ReportRecord | null>;
  counts(): Promise<{ open: number; inReview: number; total: number }>;
  /** Detaches reports from a deleted account (the report itself is kept). */
  detachReporter(userId: string): Promise<void>;
}
export interface SettingRepo {
  getAll(): Promise<Record<string, unknown>>;
  set(key: string, value: unknown, by: string | null): Promise<void>;
}
export interface ErrorRecord { id: string; at: Date; source: 'http' | 'provider' | 'process'; code: string; route: string | null; message: string }
export interface ErrorRepo {
  create(e: { source: ErrorRecord['source']; code: string; route?: string | null; message: string }): Promise<void>;
  list(q: { page: number; pageSize: number; source?: ErrorRecord['source'] }): Promise<Page<ErrorRecord>>;
  countSince(since: Date): Promise<number>;
}
export interface ToolEventRepo {
  create(e: { tool: string; ok: boolean; userId?: string | null; code?: string | null; at: Date }): Promise<void>;
  summary(since: Date): Promise<{ tool: string; total: number; failed: number }[]>;
  countByUser(userId: string, toolPrefix: string, since: Date): Promise<number>;
}
export interface Repos {
  users: UserRepo;
  sessions: SessionRepo;
  tokens: TokenRepo;
  identities: IdentityRepo;
  audit: AuditRepo;
  apiKeys: ApiKeyRepo;
  pending: PendingRepo;
  history: HistoryRepo;
  favorites: FavoriteRepo;
  collections: CollectionRepo;
  jobs: JobRepo;
  reports: ReportRepo;
  settings: SettingRepo;
  errors: ErrorRepo;
  toolEvents: ToolEventRepo;
}
