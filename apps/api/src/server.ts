import mongoose from 'mongoose';
import pino from 'pino';
import { createApp } from './app.js';
import { loadEnv } from './config/env.js';
import { createMongoRepos } from './repositories/mongo.js';
import { createEmailProvider } from './services/email.js';
import { argon2idHasher } from './services/password.js';

let env: ReturnType<typeof loadEnv>;
try {
  env = loadEnv();
} catch (e) {
  // Clear, actionable message; values are never printed.
  console.error(`${(e as Error).message}\n\nCopy apps/api/.env.example to .env (local) or set these variables in your host (Render > Environment).`);
  process.exit(1);
}
const logger = pino({ level: env.LOG_LEVEL, redact: ['req.headers.cookie', 'password', '*.password', 'token', '*.token', 'code'] });
let shuttingDown = false;

async function main() {
  mongoose.set('strictQuery', true);
  mongoose.connection.on('disconnected', () => logger.warn('MongoDB disconnected'));
  mongoose.connection.on('reconnected', () => logger.info('MongoDB reconnected'));
  mongoose.connection.on('error', (e) => logger.error({ msg: String((e as Error).message).split('\n')[0] }, 'MongoDB error')); // URI is never logged
  try {
    await mongoose.connect(env.MONGODB_URI, { serverSelectionTimeoutMS: 10_000, maxPoolSize: 10 });
  } catch (e) {
    logger.fatal({ msg: (e as Error).message.split('\n')[0] }, 'MongoDB connection failed');
    process.exit(1);
  }
  await mongoose.syncIndexes();
  const email = createEmailProvider(env, () => logger.warn('E-mail provider not configured: message not sent'));
  const app = createApp({
    env, repos: createMongoRepos(), hasher: argon2idHasher, email, logger,
    checkDb: async () => mongoose.connection.readyState === 1, isShuttingDown: () => shuttingDown,
  });
  // 0.0.0.0 so the platform proxy can reach the process (Render sets PORT).
  const server = app.listen(env.PORT, '0.0.0.0', () => logger.info({ port: env.PORT }, 'API listening'));
  server.keepAliveTimeout = 65_000; // above typical proxy idle timeouts, avoids sporadic 502
  server.headersTimeout = 66_000;

  const stop = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true; // /health/ready now answers 503, new API traffic is refused
    logger.info({ signal }, 'shutting down');
    const force = setTimeout(() => { logger.error('forced exit after timeout'); process.exit(1); }, 10_000);
    force.unref();
    server.close(() => { mongoose.disconnect().catch(() => {}).finally(() => process.exit(0)); });
    server.closeIdleConnections();
  };
  process.on('SIGTERM', () => stop('SIGTERM'));
  process.on('SIGINT', () => stop('SIGINT'));
}
process.on('unhandledRejection', (r) => { logger.fatal({ msg: String((r as Error)?.message ?? r).slice(0, 200) }, 'unhandled rejection'); process.exit(1); });
process.on('uncaughtException', (e) => { logger.fatal({ msg: e.message.slice(0, 200) }, 'uncaught exception'); process.exit(1); });
main().catch((e) => { logger.fatal({ msg: (e as Error).message }, 'fatal'); process.exit(1); });
