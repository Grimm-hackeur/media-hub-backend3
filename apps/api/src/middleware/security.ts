import type { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import type { Env } from '../config/env.js';
import { allowedOrigins } from '../config/env.js';
import { AppError, forbidden, unauthorized } from '../utils/errors.js';
import { safeEqual } from '../utils/crypto.js';
import type { AuthService } from '../services/auth.service.js';

export const cookieName = (env: Env) => (env.NODE_ENV === 'production' ? '__Host-mh_sid' : 'mh_sid');

export const securityHeaders = () =>
  helmet({
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    crossOriginResourcePolicy: { policy: 'same-site' },
    referrerPolicy: { policy: 'no-referrer' },
  });

/** CORS only for the configured front-end origin; credentials allowed for that origin only. */
export const corsPolicy = (env: Env) =>
  cors({
    origin: (origin, cb) => cb(null, origin !== undefined && allowedOrigins(env).includes(origin)),
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'X-Request-Id'],
    maxAge: 600,
  });

const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Login-CSRF / cross-site request defence: state-changing requests must come from the front-end origin and be JSON. */
export const requireTrustedOrigin = (env: Env) => (req: Request, _res: Response, next: NextFunction) => {
  if (SAFE.has(req.method)) return next();
  const origin = req.get('origin');
  if (!origin || !allowedOrigins(env).includes(origin)) return next(forbidden('Untrusted origin'));
  if (req.body !== undefined && !req.is('application/json')) return next(forbidden('JSON body required'));
  next();
};

export const loadSession = (env: Env, auth: AuthService) => async (req: Request, _res: Response, next: NextFunction) => {
  try {
    const raw = req.cookies?.[cookieName(env)];
    if (typeof raw === 'string' && raw.length > 0 && raw.length < 200) req.auth = (await auth.authenticate(raw)) ?? undefined;
    next();
  } catch (e) {
    next(e);
  }
};

export const requireAuth = (req: Request, _res: Response, next: NextFunction) =>
  req.auth ? next() : next(unauthorized());

/** Synchroniser token bound to the session; required on every authenticated state-changing request. */
export const requireCsrf = (req: Request, _res: Response, next: NextFunction) => {
  if (SAFE.has(req.method)) return next();
  const sent = req.get('x-csrf-token');
  if (!req.auth || !sent || !safeEqual(sent, req.auth.session.csrfToken)) return next(forbidden('Invalid CSRF token'));
  next();
};

/** Server-side authorisation. Admin routes also require a verified e-mail. */
export const requireRole = (role: 'ADMIN', opts: { require2fa?: boolean } = {}) => (req: Request, _res: Response, next: NextFunction) => {
  if (!req.auth) return next(unauthorized());
  if (req.auth.user.role !== role || !req.auth.user.emailVerified) return next(forbidden());
  if (opts.require2fa && !req.auth.user.totp?.enabled) return next(new AppError(403, 'TWO_FACTOR_REQUIRED', 'Two-factor authentication must be enabled for administrators'));
  next();
};
