import cookieParser from 'cookie-parser';
import express, { Router, type Express } from 'express';
import pino, { type Logger } from 'pino';
import type { Env } from './config/env.js';
import { errorHandler, notFoundHandler } from './middleware/errors.js';
import { rejectOperatorKeys, requestId, requestLog } from './middleware/http.js';
import { defaultLimits, makeLimiters, type Limits } from './middleware/rateLimit.js';
import { corsPolicy, loadSession, requireTrustedOrigin, securityHeaders } from './middleware/security.js';
import { createFacebookProvider } from './providers/facebook.js';
import { createInstagramProvider, createTikTokProvider, createWhiteShadowFacebookProvider } from './providers/whiteshadow.js';
import { ProviderHealth } from './providers/health.js';
import { createMusicProvider } from './providers/music.js';
import type { MediaProvider, MusicProvider } from './providers/types.js';
import type { Repos } from './repositories/types.js';
import { adminRouter } from './routes/admin.js';
import { authRouter } from './routes/auth.js';
import { googleRouter } from './routes/google.js';
import { healthRouter } from './routes/health.js';
import { keysRouter, publicApiRouter } from './routes/keys.js';
import { meRouter } from './routes/me.js';
import { aiRouter, reportsRouter, settingsRouter } from './routes/misc.js';
import { toolsRouter } from './routes/tools.js';
import { createAdminService } from './services/admin.service.js';
import { createAiService, type AiProvider } from './services/ai.service.js';
import { createApiKeyService } from './services/apikeys.service.js';
import { createAuthService } from './services/auth.service.js';
import type { EmailProvider } from './services/email.js';
import { createGoogleClient, createGoogleService, type GoogleClient } from './services/google.service.js';
import { createMeService } from './services/me.service.js';
import { createOpsService } from './services/ops.service.js';
import type { PasswordHasher } from './services/password.js';
import { createReportsService } from './services/reports.service.js';
import { createSettingsService } from './services/settings.service.js';
import { createToolsService } from './services/tools.service.js';

export interface AppDeps {
  env: Env; repos: Repos; hasher: PasswordHasher; email: EmailProvider;
  logger?: Logger; limits?: Limits; checkDb?: () => Promise<boolean>; isShuttingDown?: () => boolean; now?: () => Date;
  /** Overridable in tests; by default built from the environment. */
  media?: MediaProvider[]; music?: MusicProvider; google?: GoogleClient; aiProvider?: AiProvider;
}

export function createApp(deps: AppDeps): Express {
  const { env } = deps;
  const logger = deps.logger ?? pino({ level: env.LOG_LEVEL, redact: ['req.headers.cookie', 'req.headers.authorization', 'password', '*.password', 'token', '*.token'] });
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', env.TRUST_PROXY);

  const auth = createAuthService({ repos: deps.repos, hasher: deps.hasher, email: deps.email, env, now: deps.now, onEmailError: (e) => logger.error({ msg: (e as Error).message }, 'email send failed') });
  const admin = createAdminService(deps.repos, deps.now);
  const keys = createApiKeyService(deps.repos, env.SESSION_SECRET, deps.now);
  const settings = createSettingsService(deps.repos, deps.now);
  const me = createMeService(deps.repos, deps.now);
  const health = new ProviderHealth();
  const media = deps.media ?? [createTikTokProvider(env), createInstagramProvider(env), env.WHITESHADOW_API_TOKEN ? createWhiteShadowFacebookProvider(env) : createFacebookProvider(env)];
  const music = deps.music ?? createMusicProvider(env);
  const tools = createToolsService({ repos: deps.repos, settings, me, health, media, music, now: deps.now });
  const google = createGoogleService({ repos: deps.repos, auth, client: deps.google ?? createGoogleClient(env), env, now: deps.now });
  const ai = createAiService({ env, repos: deps.repos, provider: deps.aiProvider, now: deps.now });
  const reports = createReportsService(deps.repos);
  const ops = createOpsService({ env, repos: deps.repos, email: deps.email, google, ai, tools, checkDb: deps.checkDb, now: deps.now });
  const lim = makeLimiters(deps.limits ?? defaultLimits);

  app.use(requestId());
  app.use(securityHeaders());
  app.use(corsPolicy(env));
  app.use(requestLog(logger));

  // Health endpoints (platform probes and external monitors): no secrets, no heavy work. /api/health kept for older clients.
  const hr = healthRouter({ checkDb: deps.checkDb, isShuttingDown: deps.isShuttingDown });
  app.use(['/health', '/api/health', '/api/v1/health'], hr);

  // The application needs MongoDB: while it is unreachable (or the process is stopping) no normal API traffic is accepted.
  app.use(['/api', '/api/v1'], async (_req, res, next) => {
    if (deps.isShuttingDown?.()) { res.status(503).json({ error: { code: 'SERVICE_UNAVAILABLE', message: 'The service is restarting. Please retry shortly.' } }); return; }
    if (deps.checkDb && !(await deps.checkDb().catch(() => false))) { res.setHeader('Retry-After', '5'); res.status(503).json({ error: { code: 'SERVICE_UNAVAILABLE', message: 'The service is temporarily unavailable.' } }); return; }
    next();
  });
  app.use(['/api', '/api/v1'], lim.general);
  app.use('/api', express.json({ limit: '10kb' }));
  app.use('/api', rejectOperatorKeys());
  app.use('/api/v1', publicApiRouter(keys, deps.now)); // X-API-Key routes (GET /api/v1/status)

  // The web application API. Canonical prefix /api/v1; /api is kept as an alias so existing clients keep working.
  const web = Router();
  web.use(cookieParser());
  web.use(requireTrustedOrigin(env));
  web.use(loadSession(env, auth));
  web.use('/auth/google', googleRouter(env, google, lim));
  web.use('/auth', authRouter(env, auth, lim));
  web.use('/keys', keysRouter(keys));
  web.use('/me', meRouter(me));
  web.use('/tools', toolsRouter(tools, lim, env.TOOLS_REQUIRE_LOGIN));
  web.use('/reports', reportsRouter(reports, lim));
  web.use('/settings', settingsRouter(settings));
  web.use('/ai', aiRouter(ai, lim));
  web.use('/admin', adminRouter(admin, keys, { settings, reports, ops, tools }, env.REQUIRE_ADMIN_2FA));
  app.use(['/api/v1', '/api'], web);

  app.use(notFoundHandler);
  app.use(errorHandler(logger, (e) => { void deps.repos.errors.create({ source: 'http', code: e.code, route: e.route, message: e.message }).catch(() => {}); }));
  return app;
}
