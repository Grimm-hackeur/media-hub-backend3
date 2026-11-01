import type { Env } from '../config/env.js';
import type { ErrorRecord, Repos } from '../repositories/types.js';
import type { EmailProvider } from './email.js';
import type { GoogleService } from './google.service.js';
import type { AiService } from './ai.service.js';
import type { ToolsService } from './tools.service.js';

/** Read-only operational views for administrators. Booleans and counters only: never keys, URIs or other secrets. */
export function createOpsService(deps: { env: Env; repos: Repos; email: EmailProvider; google: GoogleService; ai: AiService; tools: ToolsService; checkDb?: () => Promise<boolean>; now?: () => Date }) {
  const now = deps.now ?? (() => new Date());
  return {
    async integrations() {
      const db = deps.checkDb ? await deps.checkDb().catch(() => false) : true;
      const since = new Date(now().getTime() - 24 * 3_600_000);
      return {
        generatedAt: now().toISOString(),
        database: { status: db ? 'up' : 'down' },
        email: { provider: deps.env.EMAIL_PROVIDER === 'brevo' || (deps.env.EMAIL_PROVIDER === 'auto' && !!deps.env.BREVO_API_KEY) ? 'brevo' : 'resend', configured: deps.email.configured, ...(deps.email.configured ? {} : { missing: deps.env.EMAIL_PROVIDER === 'brevo' || (deps.env.EMAIL_PROVIDER === 'auto' && !!deps.env.BREVO_API_KEY) ? 'BREVO_API_KEY and a valid EMAIL_FROM' : 'RESEND_API_KEY and EMAIL_FROM (or BREVO_API_KEY)' }) },
        google: { configured: deps.google.configured, ...(deps.google.configured ? {} : { missing: 'GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL' }) },
        ai: { configured: deps.ai.configured, ...(deps.ai.configured ? {} : { missing: 'ANTHROPIC_API_KEY and AI_MODEL' }) },
        tools: (await deps.tools.overview()).items,
        errorsLast24h: await deps.repos.errors.countSince(since),
        note: 'Live counters reset when the server restarts or wakes up.',
      };
    },
    errors: (q: { page: number; pageSize: number; source?: ErrorRecord['source'] }) => deps.repos.errors.list(q),
  };
}
export type OpsService = ReturnType<typeof createOpsService>;
