import { Router, type NextFunction, type Request, type Response } from 'express';
import { requireAuth, requireCsrf } from '../middleware/security.js';
import { createKeySchema, objectIdParam, usageQuery } from '../schemas/auth.js';
import type { ApiKeyService } from '../services/apikeys.service.js';
import { unauthorized } from '../utils/errors.js';

/** Dashboard routes (session cookie + CSRF): manage your own keys and read your own usage. */
export function keysRouter(keys: ApiKeyService) {
  const r = Router();
  r.use(requireAuth, requireCsrf);
  r.get('/', async (req, res) => { res.json({ items: await keys.list(req.auth!.user.id) }); });
  r.get('/usage', async (req, res) => { res.json(await keys.userUsage(req.auth!.user.id, usageQuery.parse(req.query).range)); });
  r.post('/', async (req, res) => {
    const { name } = createKeySchema.parse(req.body);
    res.setHeader('Cache-Control', 'no-store');
    res.status(201).json(await keys.create(req.auth!.user, name));
  });
  r.delete('/:id', async (req, res) => { res.json(await keys.revoke(req.auth!.user.id, objectIdParam.parse(req.params).id)); });
  return r;
}

const WINDOW = 60_000, LIMIT = 60;
/** Public API (X-API-Key header). Counts every authenticated call; 60 requests/minute/key (single instance, in-memory). */
export function publicApiRouter(keys: ApiKeyService, now: () => Date = () => new Date()) {
  const r = Router();
  const hits = new Map<string, { n: number; reset: number }>();
  const guard = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const presented = req.get('x-api-key');
      const found = presented ? await keys.authenticate(presented) : null;
      if (!found) return next(unauthorized('Invalid or missing API key'));
      const t = now().getTime();
      const h = hits.get(found.key.id);
      const c = !h || h.reset <= t ? { n: 0, reset: t + WINDOW } : h;
      c.n += 1; hits.set(found.key.id, c);
      if (c.n > LIMIT) {
        await keys.recordUse(found.key, false);
        res.setHeader('Retry-After', String(Math.ceil((c.reset - t) / 1000)));
        res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many requests' } });
        return;
      }
      res.locals.apiKey = found.key;
      next();
    } catch (e) { next(e); }
  };
  // Only the public API paths require a key; every other /api/v1 path belongs to the web application routes.
  r.get('/status', guard, async (_req, res) => {
    await keys.recordUse(res.locals.apiKey, true);
    res.json({ status: 'ok', time: now().toISOString() });
  });
  return r;
}
