import { Router } from 'express';

export interface HealthDeps { checkDb?: () => Promise<boolean>; isShuttingDown?: () => boolean; startedAt?: number }

/**
 * /health/live  : the process is up. No dependency, no database query (safe for frequent platform probes).
 * /health/ready : able to serve traffic = database reachable and not shutting down.
 * /health       : short non-sensitive summary. Never exposes environment variables, hosts, versions of dependencies or secrets.
 */
export function healthRouter(deps: HealthDeps) {
  const r = Router();
  const started = deps.startedAt ?? Date.now();
  const dbUp = async () => (deps.checkDb ? await deps.checkDb().catch(() => false) : true);
  r.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
  r.get('/live', (_req, res) => { res.json({ status: 'alive' }); });
  r.get('/ready', async (_req, res) => {
    if (deps.isShuttingDown?.()) { res.status(503).json({ status: 'shutting_down' }); return; }
    const ok = await dbUp();
    res.status(ok ? 200 : 503).json({ status: ok ? 'ready' : 'unavailable' });
  });
  r.get('/', async (_req, res) => {
    const stopping = deps.isShuttingDown?.() ?? false;
    const ok = await dbUp();
    const healthy = ok && !stopping;
    res.status(healthy ? 200 : 503).json({
      status: healthy ? 'ok' : 'degraded', service: 'media-hub-api', uptimeSeconds: Math.round((Date.now() - started) / 1000),
      database: ok ? 'up' : 'down', shuttingDown: stopping, time: new Date().toISOString(),
    });
  });
  return r;
}
