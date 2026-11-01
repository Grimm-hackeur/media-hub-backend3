#!/usr/bin/env node
/**
 * Availability probe for an external monitor (UptimeRobot, Better Stack, cron...).
 *   node scripts/healthcheck.mjs https://your-api.onrender.com [/health/live] [timeoutMs]
 * Exit code 0 = healthy, 1 = unhealthy/unreachable. Prints one line. Makes ONE request: it never loops.
 * /health/live does not touch MongoDB; use /health/ready only if you want the database checked too.
 */
const [base, path = '/health/live', timeout = '10000'] = process.argv.slice(2);
if (!base) { console.error('usage: healthcheck.mjs <base-url> [path] [timeoutMs]'); process.exit(2); }
const t0 = Date.now();
try {
  const res = await fetch(new URL(path, base), { signal: AbortSignal.timeout(Number(timeout)), headers: { 'user-agent': 'media-hub-healthcheck' } });
  const ms = Date.now() - t0;
  console.log(`${res.ok ? 'OK' : 'FAIL'} ${res.status} ${path} ${ms}ms`);
  process.exit(res.ok ? 0 : 1);
} catch (e) {
  console.log(`FAIL unreachable ${path} ${Date.now() - t0}ms (${e?.name ?? 'error'})`);
  process.exit(1);
}
