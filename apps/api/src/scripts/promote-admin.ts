/**
 * Creates the first administrator by promoting an EXISTING, verified account.
 * Runs only where MONGODB_URI is available (your machine / Render shell). No default credentials exist.
 * Usage:  npm run admin:promote -w apps/api -- you@example.com
 */
import mongoose from 'mongoose';
import { createMongoRepos } from '../repositories/mongo.js';
import { normalizeEmail } from '../utils/normalize.js';

async function main() {
  const raw = process.argv[2];
  const uri = process.env.MONGODB_URI;
  if (!raw || !uri) throw new Error('Usage: MONGODB_URI=... npm run admin:promote -- <email>');
  await mongoose.connect(uri, { serverSelectionTimeoutMS: 10_000 });
  const repos = createMongoRepos();
  const user = await repos.users.findByEmail(normalizeEmail(raw));
  if (!user || user.status !== 'ACTIVE') throw new Error('No active account with this e-mail. Register it first.');
  if (!user.emailVerified) throw new Error('Verify the e-mail address first (click the confirmation link).');
  if (user.role === 'ADMIN') { console.log('Already an administrator.'); return; }
  await repos.users.update(user.id, { role: 'ADMIN' });
  await repos.audit.create({ actorId: null, action: 'ADMIN_PROMOTED_CLI', targetId: user.id, metadata: {} });
  console.log(`Account ${user.id} is now ADMIN.`);
}
main().catch((e) => { console.error(e.message); process.exitCode = 1; }).finally(() => mongoose.disconnect());
