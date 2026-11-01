import { Router, type Response } from 'express';
import type { Env } from '../config/env.js';
import type { makeLimiters } from '../middleware/rateLimit.js';
import { cookieName, requireAuth, requireCsrf } from '../middleware/security.js';
import { AppError } from '../utils/errors.js';
import { SESSION_TTL_MS } from '../services/auth.service.js';
import { FLOW_TTL_MS, type GoogleService } from '../services/google.service.js';

export function googleRouter(env: Env, google: GoogleService, lim: ReturnType<typeof makeLimiters>) {
  const r = Router();
  const secure = env.NODE_ENV === 'production';
  const flowName = secure ? '__Host-mh_oauth' : 'mh_oauth';
  const base = { httpOnly: true, secure, sameSite: 'lax' as const, path: '/' };
  const needConfigured = () => { if (!google.configured) throw new AppError(503, 'SERVICE_NOT_CONFIGURED', 'Google sign-in is not configured on this server.'); };
  const setFlow = (res: Response, cookie: string) => res.cookie(flowName, cookie, { ...base, maxAge: FLOW_TTL_MS });

  r.get('/status', (_req, res) => { res.json({ configured: google.configured }); });

  r.get('/start', lim.oauth, (_req, res) => {
    needConfigured();
    const { url, cookie } = google.startLogin();
    setFlow(res, cookie);
    res.setHeader('Cache-Control', 'no-store');
    res.redirect(302, url);
  });

  // Linking is a POST with session + CSRF, so a third-party page cannot make a victim attach an attacker's Google account.
  r.post('/link', requireAuth, requireCsrf, lim.oauth, (req, res) => {
    needConfigured();
    const { url, cookie } = google.startLink(req.auth!.user);
    setFlow(res, cookie);
    res.setHeader('Cache-Control', 'no-store');
    res.json({ url });
  });

  r.delete('/', requireAuth, requireCsrf, lim.oauth, async (req, res) => {
    if (!(await google.unlink(req.auth!.user))) throw new AppError(409, 'CONFLICT', 'Set a password before removing Google sign-in, or no Google account is linked.');
    res.status(204).end();
  });

  r.get('/callback', lim.oauth, async (req, res) => {
    needConfigured();
    const out = await google.callback(req.query, req.cookies?.[flowName], req.auth?.user ?? null, req.get('user-agent') ?? null);
    res.clearCookie(flowName, base);
    res.setHeader('Cache-Control', 'no-store');
    if (out.kind === 'session') res.cookie(cookieName(env), out.token, { ...base, maxAge: SESSION_TTL_MS });
    res.redirect(302, out.redirect);
  });
  return r;
}
