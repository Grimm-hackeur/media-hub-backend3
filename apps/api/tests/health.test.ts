import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import { makeCtx, env } from './helpers.js';

describe('health endpoints', () => {
  it('/health/live answers without touching the database', async () => {
    const checkDb = vi.fn(async () => { throw new Error('db must not be queried'); });
    const { app } = makeCtx({ deps: { checkDb } });
    const res = await request(app).get('/health/live');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'alive' });
    expect(checkDb).not.toHaveBeenCalled();
  });

  it('/health/ready is 200 when MongoDB is reachable', async () => {
    const { app } = makeCtx({ deps: { checkDb: async () => true } });
    const res = await request(app).get('/health/ready');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ready');
  });

  it('/health/ready is 503 when MongoDB is unavailable (false or throwing)', async () => {
    for (const checkDb of [async () => false, async () => { throw new Error('boom'); }]) {
      const { app } = makeCtx({ deps: { checkDb } });
      const res = await request(app).get('/health/ready');
      expect(res.status).toBe(503);
      expect(res.body.status).toBe('unavailable');
    }
  });

  it('/health/ready turns 503 while the process is shutting down, /health/live stays 200', async () => {
    let stopping = false;
    const { app } = makeCtx({ deps: { checkDb: async () => true, isShuttingDown: () => stopping } });
    expect((await request(app).get('/health/ready')).status).toBe(200);
    stopping = true;
    expect((await request(app).get('/health/ready')).status).toBe(503);
    expect((await request(app).get('/health/live')).status).toBe(200);
  });

  it('/health gives a non-sensitive summary', async () => {
    const { app } = makeCtx({ deps: { checkDb: async () => true } });
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(Object.keys(res.body).sort()).toEqual(['database', 'service', 'shuttingDown', 'status', 'time', 'uptimeSeconds']);
    const text = JSON.stringify(res.body);
    for (const secret of [env.SESSION_SECRET, env.MONGODB_URI, 'MONGODB', 'SESSION_SECRET', 'process']) expect(text).not.toContain(secret);
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('/health is 503 (degraded) when the database is down', async () => {
    const { app } = makeCtx({ deps: { checkDb: async () => false } });
    const res = await request(app).get('/health');
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ status: 'degraded', database: 'down' });
  });

  it('legacy /api/health and the versioned /api/v1/health still work', async () => {
    const { app } = makeCtx({ deps: { checkDb: async () => true } });
    expect((await request(app).get('/api/health')).status).toBe(200);
    expect((await request(app).get('/api/v1/health/live')).status).toBe(200);
  });

  it('refuses normal API traffic while MongoDB is unavailable, but keeps health probes answering', async () => {
    const { app } = makeCtx({ deps: { checkDb: async () => false } });
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('SERVICE_UNAVAILABLE');
    expect(res.headers['retry-after']).toBeDefined();
    expect((await request(app).get('/health/live')).status).toBe(200);
  });

  it('refuses API traffic while shutting down', async () => {
    const { app } = makeCtx({ deps: { checkDb: async () => true, isShuttingDown: () => true } });
    expect((await request(app).get('/api/settings/public')).status).toBe(503);
  });

  it('sends a request id on every answer', async () => {
    const { app } = makeCtx();
    const res = await request(app).get('/health/live');
    expect(res.headers['x-request-id']).toMatch(/^[a-f0-9]{16}$/);
  });
});
