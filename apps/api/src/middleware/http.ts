import { randomBytes } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import type { Logger } from 'pino';
import { badRequest, forbidden } from '../utils/errors.js';
import { safeEqual } from '../utils/crypto.js';

/** Gives each request an id (returned in X-Request-Id and in 500 answers) so a user report can be matched to a log line. */
export const requestId = () => (_req: Request, res: Response, next: NextFunction) => {
  const id = randomBytes(8).toString('hex');
  res.locals.reqId = id;
  res.setHeader('X-Request-Id', id);
  next();
};

/** One structured line per request. Only method, path WITHOUT query string, status and duration: never headers, cookies or bodies. */
export const requestLog = (log: Logger) => (req: Request, res: Response, next: NextFunction) => {
  const t0 = process.hrtime.bigint();
  res.on('finish', () => {
    const ms = Number((process.hrtime.bigint() - t0) / 1_000_000n);
    log.info({ reqId: res.locals.reqId, method: req.method, path: req.originalUrl.split('?')[0], status: res.statusCode, ms }, 'request');
  });
  next();
};

const MAX_DEPTH = 6;
function hasOperatorKey(v: unknown, depth = 0): boolean {
  if (depth > MAX_DEPTH) return true; // absurdly deep: reject
  if (Array.isArray(v)) return v.some((x) => hasOperatorKey(x, depth + 1));
  if (v && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      if (k.startsWith('$') || k.includes('.') || k === '__proto__' || k === 'constructor' || k === 'prototype') return true;
      if (hasOperatorKey(x, depth + 1)) return true;
    }
  }
  return false;
}
/** NoSQL-injection / prototype-pollution guard: no MongoDB operator ($...), dotted or prototype keys in bodies or query strings. */
export const rejectOperatorKeys = () => (req: Request, _res: Response, next: NextFunction) => {
  if (hasOperatorKey(req.body) || hasOperatorKey(req.query)) return next(badRequest('Invalid request'));
  next();
};

/** When a session cookie is present the request acts on behalf of that user, so it must carry the CSRF token. Anonymous requests pass. */
export const csrfIfSession = (req: Request, _res: Response, next: NextFunction) => {
  if (!req.auth || ['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const sent = req.get('x-csrf-token');
  if (!sent || !safeEqual(sent, req.auth.session.csrfToken)) return next(forbidden('Invalid CSRF token'));
  next();
};

export const requireVerified = (req: Request, _res: Response, next: NextFunction) => {
  if (!req.auth) return next(forbidden());
  if (!req.auth.user.emailVerified) return next(Object.assign(forbidden('Please confirm your e-mail address first'), {}));
  next();
};
