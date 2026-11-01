import { Schema, model, type InferSchemaType } from 'mongoose';

const userSchema = new Schema(
  {
    username: { type: String, required: true, trim: true, minlength: 3, maxlength: 30 },
    // Lower-cased copy: gives case-insensitive uniqueness without collations.
    usernameLower: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
    passwordHash: { type: String, default: null }, // null for Google-only accounts
    role: { type: String, enum: ['USER', 'ADMIN'], default: 'USER', required: true },
    emailVerified: { type: Boolean, default: false },
    avatar: { type: String, default: null, maxlength: 500 },
    status: { type: String, enum: ['ACTIVE', 'SUSPENDED', 'DELETED'], default: 'ACTIVE', required: true },
    lastLoginAt: { type: Date, default: null },
    totp: { type: Schema.Types.Mixed, default: null }, // { secretEnc, enabled, lastStep, recoveryHashes, fails, lockedUntil }
    preferences: {
      language: { type: String, enum: ['fr', 'en'], default: 'fr' },
      historyEnabled: { type: Boolean, default: true },
      historyRetentionDays: { type: Number, min: 1, max: 365, default: 30 },
    },
  },
  { timestamps: true },
);
userSchema.index({ createdAt: -1 });
userSchema.index({ role: 1, status: 1 });

const authIdentitySchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    provider: { type: String, enum: ['GOOGLE', 'EMAIL'], required: true },
    providerUserId: { type: String, required: true }, // Google `sub`, or the normalised email for EMAIL
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
// A Google identity can belong to one user only, and a user has at most one identity per provider.
authIdentitySchema.index({ provider: 1, providerUserId: 1 }, { unique: true });
authIdentitySchema.index({ userId: 1, provider: 1 }, { unique: true });

const sessionSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    tokenHash: { type: String, required: true, unique: true }, // never the raw token
    csrfToken: { type: String, required: true },
    userAgent: { type: String, default: null, maxlength: 200 },
    lastActivityAt: { type: Date, required: true },
    expiresAt: { type: Date, required: true },
    revokedAt: { type: Date, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // MongoDB removes expired sessions

const tokenFields = {
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  tokenHash: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true },
  usedAt: { type: Date, default: null },
};
const verificationSchema = new Schema(tokenFields, { timestamps: { createdAt: true, updatedAt: false } });
const resetSchema = new Schema(tokenFields, { timestamps: { createdAt: true, updatedAt: false } });
// Keep used/expired tokens for 7 days after expiry (support/audit), then purge.
verificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 7 * 24 * 3600 });
resetSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 7 * 24 * 3600 });

const auditSchema = new Schema({
  actorId: { type: Schema.Types.ObjectId, default: null },
  action: { type: String, required: true, maxlength: 60 },
  targetId: { type: Schema.Types.ObjectId, default: null },
  metadata: { type: Schema.Types.Mixed, default: {} }, // non-sensitive, flat, validated in the service
  timestamp: { type: Date, default: () => new Date(), required: true },
});
auditSchema.index({ timestamp: -1 });
auditSchema.index({ action: 1, timestamp: -1 });
// Security logs are kept 365 days. Adjust to your retention policy.
auditSchema.index({ timestamp: 1 }, { expireAfterSeconds: 365 * 24 * 3600 });

const apiKeySchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    name: { type: String, required: true, trim: true, maxlength: 60 },
    prefix: { type: String, required: true, maxlength: 24 },
    keyHash: { type: String, required: true, unique: true }, // HMAC-SHA256 of the full key; the key itself is never stored
    lastUsedAt: { type: Date, default: null },
    revokedAt: { type: Date, default: null },
    requests: { type: Number, default: 0 },
    failures: { type: Number, default: 0 },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
apiKeySchema.index({ userId: 1, revokedAt: 1 });

const apiUsageSchema = new Schema({
  keyId: { type: Schema.Types.ObjectId, required: true },
  userId: { type: Schema.Types.ObjectId, required: true },
  hour: { type: Date, required: true },
  requests: { type: Number, default: 0 },
  failures: { type: Number, default: 0 },
});
apiUsageSchema.index({ keyId: 1, hour: 1 }, { unique: true });
apiUsageSchema.index({ userId: 1, hour: 1 });
apiUsageSchema.index({ hour: 1 }, { expireAfterSeconds: 35 * 24 * 3600 }); // hourly counters kept 35 days

export const ApiKeyModel = model('ApiKey', apiKeySchema);
export const ApiUsageModel = model('ApiUsage', apiUsageSchema);
const pendingSchema = new Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
    username: { type: String, required: true, maxlength: 30 },
    passwordHash: { type: String, required: true },
    codeHash: { type: String, required: true }, // HMAC of the 4-digit code; the code itself is never stored
    codeExpiresAt: { type: Date, required: true },
    attemptsLeft: { type: Number, required: true },
    resendCount: { type: Number, default: 0 },
    lastSentAt: { type: Date, required: true },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
pendingSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // unverified registrations are purged automatically

export const PendingRegistrationModel = model('PendingRegistration', pendingSchema);
export const UserModel = model('User', userSchema);
export const AuthIdentityModel = model('AuthIdentity', authIdentitySchema);
export const SessionModel = model('Session', sessionSchema);
export const EmailVerificationTokenModel = model('EmailVerificationToken', verificationSchema);
export const PasswordResetTokenModel = model('PasswordResetToken', resetSchema);
export const AuditLogModel = model('AuditLog', auditSchema);
export type UserDoc = InferSchemaType<typeof userSchema>;

const historySchema = new Schema({
  userId: { type: Schema.Types.ObjectId, required: true },
  kind: { type: String, enum: ['SEARCH', 'OPERATION'], required: true },
  tool: { type: String, required: true, maxlength: 30 },
  query: { type: String, default: null, maxlength: 200 },
  title: { type: String, default: null, maxlength: 200 },
  status: { type: String, enum: ['SUCCESS', 'FAILED'], required: true },
  createdAt: { type: Date, required: true },
  expiresAt: { type: Date, required: true },
});
historySchema.index({ userId: 1, createdAt: -1 });
historySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // retention: MongoDB deletes entries at their expiry date

const savedItemFields = {
  kind: { type: String, enum: ['TRACK', 'ALBUM', 'LINK'], required: true },
  key: { type: String, required: true, maxlength: 128 },
  title: { type: String, required: true, maxlength: 200 },
  subtitle: { type: String, default: null, maxlength: 200 },
  url: { type: String, default: null, maxlength: 2048 },
  imageUrl: { type: String, default: null, maxlength: 2048 },
};
const favoriteSchema = new Schema({ userId: { type: Schema.Types.ObjectId, required: true }, ...savedItemFields }, { timestamps: { createdAt: true, updatedAt: false } });
favoriteSchema.index({ userId: 1, kind: 1, key: 1 }, { unique: true });
favoriteSchema.index({ userId: 1, createdAt: -1 });

const collectionSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, required: true, index: true },
    name: { type: String, required: true, trim: true, maxlength: 60 },
    description: { type: String, default: null, maxlength: 300 },
    items: [new Schema({ ...savedItemFields, ref: { type: String, required: true, maxlength: 80 }, addedAt: { type: Date, required: true } })],
  },
  { timestamps: true },
);

const jobSchema = new Schema({
  tool: { type: String, required: true },
  userId: { type: Schema.Types.ObjectId, default: null },
  result: { type: Schema.Types.Mixed, required: true },
  readyAt: { type: Date, required: true },
  expiresAt: { type: Date, required: true },
}, { timestamps: { createdAt: true, updatedAt: false } });
jobSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const reportSchema = new Schema(
  {
    reporterId: { type: Schema.Types.ObjectId, default: null },
    kind: { type: String, enum: ['COPYRIGHT', 'ABUSE', 'ILLEGAL', 'OTHER'], required: true },
    targetUrl: { type: String, default: null, maxlength: 2048 },
    description: { type: String, required: true, maxlength: 2000 },
    contactEmail: { type: String, default: null, maxlength: 254 },
    status: { type: String, enum: ['OPEN', 'IN_REVIEW', 'RESOLVED', 'REJECTED'], default: 'OPEN' },
    adminNote: { type: String, default: null, maxlength: 1000 },
    handledBy: { type: Schema.Types.ObjectId, default: null },
  },
  { timestamps: true },
);
reportSchema.index({ status: 1, createdAt: -1 });

const settingSchema = new Schema({
  key: { type: String, required: true, unique: true, maxlength: 60 },
  value: { type: Schema.Types.Mixed, required: true },
  updatedBy: { type: Schema.Types.ObjectId, default: null },
}, { timestamps: { createdAt: false, updatedAt: true } });

const errorLogSchema = new Schema({
  at: { type: Date, required: true },
  source: { type: String, enum: ['http', 'provider', 'process'], required: true },
  code: { type: String, required: true, maxlength: 60 },
  route: { type: String, default: null, maxlength: 120 },
  message: { type: String, required: true, maxlength: 300 },
});
errorLogSchema.index({ at: -1 });
errorLogSchema.index({ at: 1 }, { expireAfterSeconds: 30 * 24 * 3600 }); // error log kept 30 days

const toolEventSchema = new Schema({
  tool: { type: String, required: true, maxlength: 40 },
  ok: { type: Boolean, required: true },
  userId: { type: Schema.Types.ObjectId, default: null },
  code: { type: String, default: null, maxlength: 60 },
  at: { type: Date, required: true },
});
toolEventSchema.index({ at: -1 });
toolEventSchema.index({ userId: 1, tool: 1, at: -1 });
toolEventSchema.index({ at: 1 }, { expireAfterSeconds: 90 * 24 * 3600 }); // usage counters kept 90 days

export const HistoryModel = model('History', historySchema);
export const FavoriteModel = model('Favorite', favoriteSchema);
export const CollectionModel = model('Collection', collectionSchema);
export const ToolJobModel = model('ToolJob', jobSchema);
export const ReportModel = model('Report', reportSchema);
export const SettingModel = model('Setting', settingSchema);
export const ErrorLogModel = model('ErrorLog', errorLogSchema);
export const ToolEventModel = model('ToolEvent', toolEventSchema);
