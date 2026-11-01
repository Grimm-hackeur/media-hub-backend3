import { Router } from 'express';
import type { makeLimiters } from '../middleware/rateLimit.js';
import { csrfIfSession, requireVerified } from '../middleware/http.js';
import { requireAuth, requireCsrf } from '../middleware/security.js';
import { aiInputSchema, type AiFeature, type AiService, AI_FEATURES } from '../services/ai.service.js';
import { createReportSchema, type ReportsService } from '../services/reports.service.js';
import type { SettingsService } from '../services/settings.service.js';
import { notFound } from '../utils/errors.js';

export function reportsRouter(reports: ReportsService, lim: ReturnType<typeof makeLimiters>) {
  const r = Router();
  r.post('/', csrfIfSession, lim.reports, async (req, res) => {
    res.status(201).json(await reports.create(req.auth?.user ?? null, createReportSchema.parse(req.body)));
  });
  return r;
}

/** What the public front-end needs: which tools are on and the ad timing. Nothing sensitive. */
export function settingsRouter(settings: SettingsService) {
  const r = Router();
  r.get('/public', async (_req, res) => { res.setHeader('Cache-Control', 'no-cache'); res.json(await settings.publicView()); });
  return r;
}

export function aiRouter(ai: AiService, lim: ReturnType<typeof makeLimiters>) {
  const r = Router();
  r.use(requireAuth, requireVerified, requireCsrf);
  r.get('/capabilities', (_req, res) => { res.json(ai.capabilities()); });
  r.post('/:feature', lim.ai, async (req, res) => {
    const f = String(req.params.feature);
    if (!Object.hasOwn(AI_FEATURES, f)) throw notFound('Unknown AI feature');
    res.json(await ai.run(f as AiFeature, req.auth!.user, aiInputSchema.parse(req.body)));
  });
  return r;
}
