import type { ErrorRequestHandler, RequestHandler } from 'express';
import type { Logger } from 'pino';
import { ZodError } from 'zod';
import { AppError } from '../utils/errors.js';

export const notFoundHandler: RequestHandler = (_req, res) => {
  res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Not found' } });
};

/** Strips anything that could carry a secret or a URL out of a message before it is stored. */
export const scrub = (m: string) => m.replace(/\b[a-z][a-z0-9+.-]*:\/\/\S+/gi, '[url]').slice(0, 280);

export const errorHandler = (log: Logger, onServerError?: (e: { code: string; route: string; message: string }) => void): ErrorRequestHandler => (err, req, res, _next) => {
  if (err instanceof ZodError) {
    const details: Record<string, string[]> = {};
    for (const i of err.issues) (details[i.path.join('.') || '_'] ??= []).push(i.message);
    res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'Invalid input', details } });
    return;
  }
  if (err instanceof AppError) {
    res.status(err.status).json({ error: { code: err.code, message: err.message, ...(err.details ? { details: err.details } : {}), ...(err.meta ? { meta: err.meta } : {}) } });
    return;
  }
  const status = (err as { status?: number }).status;
  if (status === 400 || status === 413) { // malformed / oversized JSON from body-parser
    res.status(status).json({ error: { code: 'BAD_REQUEST', message: 'Invalid request body' } });
    return;
  }
  log.error({ reqId: res.locals.reqId, err: { name: (err as Error).name, message: scrub((err as Error).message ?? '') } }, 'unhandled error');
  try { onServerError?.({ code: 'INTERNAL_ERROR', route: `${req.method} ${req.baseUrl}${req.route?.path ?? ''}`.slice(0, 120), message: scrub(`${(err as Error).name}: ${(err as Error).message ?? ''}`) }); } catch { /* tracking must never fail a request */ }
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Something went wrong', ...(res.locals.reqId ? { requestId: res.locals.reqId } : {}) } });
};
