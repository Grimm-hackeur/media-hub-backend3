import { rateLimit, ipKeyGenerator, type Options } from 'express-rate-limit';
import type { Request } from 'express';

export interface LimitConfig { windowMs: number; max: number }
export interface Limits { general: LimitConfig; login: LimitConfig; register: LimitConfig; reset: LimitConfig; sensitive: LimitConfig; otp: LimitConfig; otpResend: LimitConfig; tools?: LimitConfig; claim?: LimitConfig; reports?: LimitConfig; oauth?: LimitConfig; ai?: LimitConfig }
export const defaultLimits: Limits = {
  general: { windowMs: 15 * 60_000, max: 300 },
  login: { windowMs: 15 * 60_000, max: 10 },
  register: { windowMs: 60 * 60_000, max: 5 },
  reset: { windowMs: 60 * 60_000, max: 5 },
  sensitive: { windowMs: 15 * 60_000, max: 10 },
  otp: { windowMs: 15 * 60_000, max: 20 },
  otpResend: { windowMs: 60 * 60_000, max: 10 },
  tools: { windowMs: 15 * 60_000, max: 40 },
  claim: { windowMs: 15 * 60_000, max: 80 },
  reports: { windowMs: 60 * 60_000, max: 5 },
  oauth: { windowMs: 15 * 60_000, max: 30 },
  ai: { windowMs: 15 * 60_000, max: 30 },
};

const base = (c: LimitConfig): Partial<Options> => ({
  windowMs: c.windowMs, limit: c.max, standardHeaders: 'draft-7', legacyHeaders: false,
  handler: (_req, res) => {
    res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many attempts. Please try again later.' } });
  },
});
const ip = (req: Request) => ipKeyGenerator(req.ip ?? '0.0.0.0');
const emailKey = (req: Request) => {
  const e = (req.body as { email?: unknown } | undefined)?.email;
  return typeof e === 'string' ? e.trim().toLowerCase().slice(0, 254) : '';
};

// NOTE: counters live in the memory of one API instance (fine for a single Render instance).
// Use a shared store (Redis / Mongo) before scaling horizontally.
export const makeLimiters = (l: Limits) => ({
  tools: rateLimit({ ...base(l.tools ?? defaultLimits.tools!), keyGenerator: (r) => `u:${r.auth?.user.id ?? ip(r)}` }),
  claim: rateLimit({ ...base(l.claim ?? defaultLimits.claim!), keyGenerator: ip }),
  reports: rateLimit({ ...base(l.reports ?? defaultLimits.reports!), keyGenerator: ip }),
  oauth: rateLimit({ ...base(l.oauth ?? defaultLimits.oauth!), keyGenerator: ip }),
  ai: rateLimit({ ...base(l.ai ?? defaultLimits.ai!), keyGenerator: (r) => `u:${r.auth?.user.id ?? ip(r)}` }),
  general: rateLimit({ ...base(l.general), keyGenerator: ip }),
  loginByIp: rateLimit({ ...base(l.login), keyGenerator: ip }),
  loginByEmail: rateLimit({ ...base(l.login), keyGenerator: (r) => `e:${emailKey(r)}|${ip(r)}` }),
  register: rateLimit({ ...base(l.register), keyGenerator: ip }),
  registerByEmail: rateLimit({ ...base(l.register), keyGenerator: (r) => `e:${emailKey(r)}` }),
  otpByIp: rateLimit({ ...base(l.otp), keyGenerator: ip }),
  otpByEmail: rateLimit({ ...base(l.otp), keyGenerator: (r) => `e:${emailKey(r)}` }),
  otpResendByIp: rateLimit({ ...base(l.otpResend), keyGenerator: ip }),
  otpResendByEmail: rateLimit({ ...base(l.otpResend), keyGenerator: (r) => `e:${emailKey(r)}` }),
  reset: rateLimit({ ...base(l.reset), keyGenerator: ip }),
  resetByEmail: rateLimit({ ...base(l.reset), keyGenerator: (r) => `e:${emailKey(r)}` }),
  sensitive: rateLimit({ ...base(l.sensitive), keyGenerator: (r) => `u:${r.auth?.user.id ?? ip(r)}` }),
});
