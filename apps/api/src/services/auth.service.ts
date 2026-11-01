import type { Env } from '../config/env.js';
import type { Repos, UserRecord } from '../repositories/types.js';
import { badRequest, coded, conflict, DuplicateError, forbidden, unauthorized } from '../utils/errors.js';
import { hashToken, randomToken, safeEqual } from '../utils/crypto.js';
import { randomInt } from 'node:crypto';
import { decryptSecret, encryptSecret, generateSecret, otpauthUri, stepOf, verifyTotp } from '../utils/totp.js';
import { normalizeUsername } from '../utils/normalize.js';
import { accountExistsEmail, otpEmail, passwordChangedEmail, resetEmail, verificationEmail, type EmailProvider } from './email.js';
import type { PasswordHasher } from './password.js';

export const SESSION_TTL_MS = 14 * 24 * 3600_000;
export const VERIFY_TTL_MS = 24 * 3600_000;
export const RESET_TTL_MS = 30 * 60_000;
export const OTP_TTL_MS = 10 * 60_000;
export const OTP_ATTEMPTS = 5;
export const OTP_RESEND_WAIT_S = 60;
export const OTP_MAX_SENDS = 5; // per pending registration (initial send + 4 resends)
export const PENDING_TTL_MS = 60 * 60_000;
export const CHALLENGE_TTL_MS = 5 * 60_000;
export const TOTP_MAX_FAILS = 5;
export const TOTP_LOCK_MS = 15 * 60_000;
const TOUCH_EVERY_MS = 5 * 60_000;

export interface PublicUser {
  id: string; username: string; email: string; role: 'USER' | 'ADMIN'; emailVerified: boolean;
  avatar: string | null; createdAt: string; lastLoginAt: string | null; twoFactorEnabled: boolean;
  hasPassword: boolean; preferences: UserRecord['preferences'];
}
export const toPublicUser = (u: UserRecord): PublicUser => ({
  id: u.id, username: u.username, email: u.email, role: u.role, emailVerified: u.emailVerified, avatar: u.avatar,
  createdAt: u.createdAt.toISOString(), lastLoginAt: u.lastLoginAt?.toISOString() ?? null, twoFactorEnabled: !!u.totp?.enabled,
  hasPassword: u.passwordHash !== null, preferences: u.preferences,
});

export interface AuthDeps {
  repos: Repos; hasher: PasswordHasher; email: EmailProvider; env: Env; now?: () => Date;
  onEmailError?: (e: unknown) => void;
}

export function createAuthService(deps: AuthDeps) {
  const { repos, hasher, email, env } = deps;
  const now = deps.now ?? (() => new Date());
  const sign = (t: string) => hashToken(t, env.SESSION_SECRET);
  // Pre-computed hash so that unknown accounts cost the same time as wrong passwords (anti user-enumeration timing).
  let dummyHash: Promise<string> | null = null;
  const getDummy = () => (dummyHash ??= hasher.hash('dummy-password-for-timing-equalisation'));

  async function safeSend(mail: Parameters<EmailProvider['send']>[0]) {
    try { await email.send(mail); } catch (e) { deps.onEmailError?.(e); }
  }
  async function issueVerification(user: UserRecord) {
    await repos.tokens.invalidateAllForUser('EMAIL_VERIFICATION', user.id, now());
    const token = randomToken();
    await repos.tokens.create('EMAIL_VERIFICATION', { userId: user.id, tokenHash: sign(token), expiresAt: new Date(now().getTime() + VERIFY_TTL_MS) });
    await safeSend(verificationEmail(user.email, user.username, `${env.FRONTEND_URL.replace(/\/$/, '')}/verify-email?token=${token}`));
  }
  const audit = (actorId: string | null, action: string, targetId?: string | null, metadata?: Record<string, string | number | boolean | null>) =>
    repos.audit.create({ actorId, action, targetId: targetId ?? null, metadata });

  async function startSession(user: UserRecord, userAgent: string | null) {
      const token = randomToken();
      const csrfToken = randomToken(24);
      const t = now();
      await repos.sessions.create({
        userId: user.id, tokenHash: sign(token), csrfToken, userAgent: userAgent?.slice(0, 200) ?? null,
        createdAt: t, lastActivityAt: t, expiresAt: new Date(t.getTime() + SESSION_TTL_MS),
      });
      const updated = (await repos.users.update(user.id, { lastLoginAt: t })) ?? user;
      await audit(user.id, 'LOGIN', user.id);
      return { token, csrfToken, user: updated };
  }

  // Stateless login challenge: userId.expiry.signature (HMAC). Proves the password step succeeded in the last 5 minutes.
  const makeChallenge = (userId: string) => { const body = `${userId}.${now().getTime() + CHALLENGE_TTL_MS}`; return `${body}.${sign(`ch:${body}`)}`; };
  const readChallenge = (c: string): string | null => {
    const parts = c.split('.'); if (parts.length !== 3) return null;
    const [uid, exp, sig] = parts as [string, string, string];
    if (!safeEqual(sig, sign(`ch:${uid}.${exp}`)) || Number(exp) <= now().getTime()) return null;
    return uid;
  };
  /** TOTP (single use per time step) or recovery code (single use). Locks after repeated failures. */
  async function checkSecondFactor(user: UserRecord, code: string, action: string) {
    const st = user.totp!; const t = now();
    if (st.lockedUntil && st.lockedUntil > t) throw coded(429, 'TWO_FACTOR_LOCKED', 'Too many attempts. Try again later.', { retryAfter: Math.ceil((st.lockedUntil.getTime() - t.getTime()) / 1000) });
    const clean = code.trim().toLowerCase();
    const step = verifyTotp(decryptSecret(st.secretEnc, env.SESSION_SECRET), clean, t);
    if (step !== null && step > st.lastStep) { await repos.users.update(user.id, { totp: { ...st, lastStep: step, fails: 0, lockedUntil: null } }); return; }
    const h = sign(`rc:${clean}`);
    if (st.recoveryHashes.includes(h)) {
      await repos.users.update(user.id, { totp: { ...st, recoveryHashes: st.recoveryHashes.filter((x) => x !== h), fails: 0, lockedUntil: null } });
      await audit(user.id, 'RECOVERY_CODE_USED', user.id);
      return;
    }
    const fails = st.fails + 1;
    await repos.users.update(user.id, { totp: { ...st, fails: fails >= TOTP_MAX_FAILS ? 0 : fails, lockedUntil: fails >= TOTP_MAX_FAILS ? new Date(t.getTime() + TOTP_LOCK_MS) : st.lockedUntil } });
    await audit(user.id, `${action}_FAILED`, user.id);
    throw unauthorized('Invalid verification code');
  }
  const getPending = async (e: string) => { const p = await repos.pending.findByEmail(e); return p && p.expiresAt > now() ? p : null; };
  const otpHash = (emailAddr: string, code: string) => sign(`otp:${emailAddr}:${code}`);
  async function issueOtp(d: { email: string; username: string; passwordHash: string; resendCount: number }) {
    const t = now();
    const code = String(randomInt(0, 10_000)).padStart(4, '0');
    await repos.pending.upsert({ ...d, codeHash: otpHash(d.email, code), codeExpiresAt: new Date(t.getTime() + OTP_TTL_MS), attemptsLeft: OTP_ATTEMPTS, lastSentAt: t, expiresAt: new Date(t.getTime() + PENDING_TTL_MS) });
    await safeSend(otpEmail(d.email, d.username, code));
  }

  return {
    /**
     * Starts a registration. Nothing is created in `users` yet: only a pending record holding the Argon2id hash and the HMAC of a
     * 4-digit code. The outcome is identical whether or not the address already has an account (the owner gets an informative e-mail).
     */
    async register(input: { username: string; email: string; password: string }): Promise<{ retryAfter: number }> {
      const passwordHash = await hasher.hash(input.password); // always paid, so timing does not reveal existing accounts
      const existing = await repos.users.findByEmail(input.email);
      if (existing) {
        await audit(null, 'REGISTER_DUPLICATE_EMAIL');
        if (existing.status !== 'DELETED') await safeSend(accountExistsEmail(existing.email, `${env.FRONTEND_URL.replace(/\/$/, '')}/connexion`));
        return { retryAfter: OTP_RESEND_WAIT_S };
      }
      // Username already used by a real account: the person must choose another one (usernames are public anyway).
      const taken = await repos.users.findByUsername(input.username);
      if (taken) throw conflict('This username is already taken');

      const prev = await getPending(input.email);
      const t = now();
      if (prev) {
        const wait = OTP_RESEND_WAIT_S - Math.floor((t.getTime() - prev.lastSentAt.getTime()) / 1000);
        if (wait > 0) return { retryAfter: wait }; // cooldown: do not mail again, do not reset anything
        if (prev.resendCount + 1 >= OTP_MAX_SENDS) throw coded(429, 'RATE_LIMITED', 'Too many codes requested. Try again later.', { retryAfter: 3600 });
      }
      await issueOtp({ email: input.email, username: input.username, passwordHash, resendCount: prev ? prev.resendCount + 1 : 0 });
      await audit(null, 'REGISTER_PENDING');
      return { retryAfter: OTP_RESEND_WAIT_S };
    },

    /** Checks the code server-side; only a valid code creates the account and the session. */
    async verifyOtp(input: { email: string; code: string; userAgent: string | null }) {
      const t = now();
      const pending = await getPending(input.email);
      const invalid = () => coded(400, 'OTP_INVALID', 'Incorrect code.');
      if (!pending) throw invalid(); // same answer as a wrong code: no hint about which addresses are pending
      if (pending.attemptsLeft <= 0) throw coded(429, 'OTP_LOCKED', 'Too many attempts. Request a new code.');
      if (pending.codeExpiresAt <= t) throw coded(400, 'OTP_EXPIRED', 'This code has expired.');
      if (!safeEqual(otpHash(pending.email, input.code), pending.codeHash)) {
        const left = await repos.pending.recordFailure(pending.id);
        await audit(null, 'OTP_FAILED');
        if (left <= 0) throw coded(429, 'OTP_LOCKED', 'Too many attempts. Request a new code.');
        throw coded(400, 'OTP_INVALID', 'Incorrect code.', { attemptsLeft: left });
      }
      if (!(await repos.pending.take(pending.id))) throw invalid(); // a concurrent request already consumed this code
      let user: UserRecord;
      try {
        user = await repos.users.create({ username: pending.username, email: pending.email, passwordHash: pending.passwordHash });
      } catch (e) {
        if (e instanceof DuplicateError && e.field.startsWith('username')) throw conflict('This username is already taken. Please register again.');
        if (e instanceof DuplicateError) throw invalid();
        throw e;
      }
      user = (await repos.users.update(user.id, { emailVerified: true })) ?? user;
      await repos.identities.create({ userId: user.id, provider: 'EMAIL', providerUserId: user.email });
      await audit(user.id, 'REGISTER', user.id);
      await audit(user.id, 'EMAIL_VERIFIED', user.id);
      return startSession(user, input.userAgent);
    },

    /** New code (the previous one stops working). Generic answer when nothing is pending. */
    async resendOtp(emailAddr: string): Promise<{ retryAfter: number }> {
      const prev = await getPending(emailAddr);
      if (!prev) return { retryAfter: OTP_RESEND_WAIT_S };
      const t = now();
      const wait = OTP_RESEND_WAIT_S - Math.floor((t.getTime() - prev.lastSentAt.getTime()) / 1000);
      if (wait > 0) throw coded(429, 'RATE_LIMITED', 'Please wait before requesting another code.', { retryAfter: wait });
      if (prev.resendCount + 1 >= OTP_MAX_SENDS) throw coded(429, 'RATE_LIMITED', 'Too many codes requested. Try again later.', { retryAfter: 3600 });
      await issueOtp({ email: prev.email, username: prev.username, passwordHash: prev.passwordHash, resendCount: prev.resendCount + 1 });
      await audit(null, 'OTP_RESENT');
      return { retryAfter: OTP_RESEND_WAIT_S };
    },

    async verifyEmail(token: string): Promise<void> {
      const rec = await repos.tokens.findUsable('EMAIL_VERIFICATION', sign(token), now());
      if (!rec || !(await repos.tokens.consume('EMAIL_VERIFICATION', rec.id, now()))) throw badRequest('Invalid or expired link');
      await repos.users.update(rec.userId, { emailVerified: true });
      await audit(rec.userId, 'EMAIL_VERIFIED', rec.userId);
    },

    async resendVerification(userId: string): Promise<void> {
      const user = await repos.users.findById(userId);
      if (user && !user.emailVerified && user.status === 'ACTIVE') await issueVerification(user);
    },

    async login(input: { email: string; password: string; userAgent: string | null }) {
      const user = await repos.users.findByEmail(input.email);
      const hash = user?.passwordHash ?? (await getDummy());
      const ok = await hasher.verify(hash, input.password);
      if (!user || !user.passwordHash || !ok || user.status === 'DELETED') {
        await audit(user?.id ?? null, 'LOGIN_FAILED');
        throw unauthorized('Invalid email or password');
      }
      if (user.status === 'SUSPENDED') {
        await audit(user.id, 'LOGIN_BLOCKED_SUSPENDED', user.id);
        throw forbidden('This account is suspended');
      }
      if (user.totp?.enabled) return { twoFactorRequired: true as const, challenge: makeChallenge(user.id) };
      return { twoFactorRequired: false as const, ...(await startSession(user, input.userAgent)) };
    },

    /** Second login step: a valid challenge (issued after the password was verified) + a TOTP code or a recovery code. */
    async loginTwoFactor(input: { challenge: string; code: string; userAgent: string | null }) {
      const uid = readChallenge(input.challenge);
      const user = uid ? await repos.users.findById(uid) : null;
      if (!user || user.status !== 'ACTIVE' || !user.totp?.enabled) throw unauthorized('Invalid or expired verification');
      await checkSecondFactor(user, input.code, 'LOGIN_2FA');
      return startSession(user, input.userAgent);
    },

    /** Session for an identity already verified by an external provider (Google). Honours the account's own 2FA. */
    async loginExternal(user: UserRecord, userAgent: string | null) {
      if (user.status !== 'ACTIVE') throw forbidden('This account is not available');
      if (user.totp?.enabled) return { twoFactorRequired: true as const, challenge: makeChallenge(user.id) };
      return { twoFactorRequired: false as const, ...(await startSession(user, userAgent)) };
    },

    /** Account created from a verified Google identity. The e-mail is verified by Google, so no OTP is requested. */
    async registerExternal(input: { username: string; email: string; avatar: string | null; provider: 'GOOGLE'; providerUserId: string }) {
      const user = await repos.users.create({ username: input.username, email: input.email, passwordHash: null });
      const updated = (await repos.users.update(user.id, { emailVerified: true, avatar: input.avatar })) ?? user;
      await repos.identities.create({ userId: user.id, provider: input.provider, providerUserId: input.providerUserId });
      await audit(user.id, 'REGISTER_GOOGLE', user.id);
      return updated;
    },

    async twoFactorSetup(user: UserRecord) {
      if (user.totp?.enabled) throw conflict('Two-factor authentication is already enabled');
      const secret = generateSecret();
      await repos.users.update(user.id, { totp: { secretEnc: encryptSecret(secret, env.SESSION_SECRET), enabled: false, lastStep: 0, recoveryHashes: [], fails: 0, lockedUntil: null } });
      return { secret, otpauthUri: otpauthUri(secret, user.email) };
    },

    /** Activates 2FA once a code from the authenticator app proves it was configured. Returns the recovery codes ONCE. */
    async twoFactorEnable(user: UserRecord, code: string) {
      const st = user.totp;
      if (!st || st.enabled) throw badRequest('Start the setup first');
      const step = verifyTotp(decryptSecret(st.secretEnc, env.SESSION_SECRET), code, now());
      if (step === null) throw badRequest('Incorrect code');
      const recovery = Array.from({ length: 8 }, () => `${randomToken(4).slice(0, 5)}-${randomToken(4).slice(0, 5)}`.toLowerCase());
      await repos.users.update(user.id, { totp: { ...st, enabled: true, lastStep: step, recoveryHashes: recovery.map((c) => sign(`rc:${c}`)), fails: 0, lockedUntil: null } });
      await audit(user.id, 'TWO_FACTOR_ENABLED', user.id);
      return { recoveryCodes: recovery };
    },

    async twoFactorDisable(user: UserRecord, password: string, code: string) {
      if (!user.totp?.enabled) throw badRequest('Two-factor authentication is not enabled');
      if (!user.passwordHash || !(await hasher.verify(user.passwordHash, password))) throw forbidden('Password confirmation failed');
      await checkSecondFactor(user, code, 'DISABLE_2FA');
      await repos.users.update(user.id, { totp: null });
      await audit(user.id, 'TWO_FACTOR_DISABLED', user.id);
    },

    /** Resolves a raw cookie token to a live session + active user, or null. */
    async authenticate(rawToken: string) {
      const session = await repos.sessions.findByTokenHash(sign(rawToken));
      const t = now();
      if (!session || session.revokedAt || session.expiresAt <= t) return null;
      const user = await repos.users.findById(session.userId);
      if (!user || user.status !== 'ACTIVE') return null;
      if (t.getTime() - session.lastActivityAt.getTime() > TOUCH_EVERY_MS) await repos.sessions.touch(session.id, t);
      return { session, user };
    },

    async logout(sessionId: string, userId: string) {
      await repos.sessions.revoke(sessionId, now());
      await audit(userId, 'LOGOUT', userId);
    },

    /** Generic outcome: never reveals whether the account exists. */
    async requestPasswordReset(emailAddr: string): Promise<void> {
      const user = await repos.users.findByEmail(emailAddr);
      if (!user || user.status !== 'ACTIVE') return;
      await repos.tokens.invalidateAllForUser('PASSWORD_RESET', user.id, now());
      const token = randomToken();
      await repos.tokens.create('PASSWORD_RESET', { userId: user.id, tokenHash: sign(token), expiresAt: new Date(now().getTime() + RESET_TTL_MS) });
      await audit(user.id, 'PASSWORD_RESET_REQUESTED', user.id);
      await safeSend(resetEmail(user.email, user.username, `${env.FRONTEND_URL.replace(/\/$/, '')}/reset-password?token=${token}`));
    },

    async resetPassword(token: string, newPassword: string): Promise<void> {
      const rec = await repos.tokens.findUsable('PASSWORD_RESET', sign(token), now());
      if (!rec || !(await repos.tokens.consume('PASSWORD_RESET', rec.id, now()))) throw badRequest('Invalid or expired link');
      const user = await repos.users.findById(rec.userId);
      if (!user || user.status !== 'ACTIVE') throw badRequest('Invalid or expired link');
      const passwordHash = await hasher.hash(newPassword);
      // Owning the mailbox proves the address, so the email becomes verified too.
      await repos.users.update(user.id, { passwordHash, emailVerified: true });
      await repos.sessions.revokeAllForUser(user.id, now());
      await repos.tokens.invalidateAllForUser('PASSWORD_RESET', user.id, now());
      await audit(user.id, 'PASSWORD_RESET_DONE', user.id);
      await safeSend(passwordChangedEmail(user.email, user.username));
    },

    /** Re-authenticates with the password, then anonymises the account and removes everything linked to it. */
    async deleteAccount(userId: string, proof: { password?: string; confirmEmail?: string }): Promise<void> {
      const user = await repos.users.findById(userId);
      if (!user) throw unauthorized();
      if (user.passwordHash) {
        if (!proof.password || !(await hasher.verify(user.passwordHash, proof.password))) throw forbidden('Password confirmation failed');
      } else if (!proof.confirmEmail || proof.confirmEmail.trim().toLowerCase() !== user.email) {
        throw forbidden('Confirmation failed'); // accounts without a password (Google) confirm by typing their e-mail address
      }
      if (user.role === 'ADMIN' && (await repos.users.countAdmins()) <= 1) throw conflict('The last administrator cannot delete their account');
      await repos.sessions.revokeAllForUser(user.id, now());
      await repos.apiKeys.revokeAllForUser(user.id, now());
      await repos.tokens.invalidateAllForUser('EMAIL_VERIFICATION', user.id, now());
      await repos.tokens.invalidateAllForUser('PASSWORD_RESET', user.id, now());
      await repos.identities.deleteAllForUser(user.id);
      // Personal data: history, favourites and collections are erased; reports are kept but detached from the account.
      await repos.history.clear(user.id);
      await repos.favorites.deleteAllForUser(user.id);
      await repos.collections.deleteAllForUser(user.id);
      await repos.reports.detachReporter(user.id);
      await repos.users.update(user.id, {
        status: 'DELETED', passwordHash: null, avatar: null, emailVerified: false, role: 'USER', totp: null,
        email: `deleted-${user.id}@deleted.invalid`, username: `deleted-${user.id}`,
      });
      // Audit entries keep only the opaque id (no personal data) for the retention period.
      await audit(user.id, 'ACCOUNT_DELETED', user.id);
    },
  };
}
export type AuthService = ReturnType<typeof createAuthService>;
export { normalizeUsername };
