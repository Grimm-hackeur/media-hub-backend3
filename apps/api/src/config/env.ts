import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  MONGODB_URI: z.string().min(1, 'MONGODB_URI is required'),
  SESSION_SECRET: z.string().min(32, 'SESSION_SECRET must be at least 32 characters'),
  FRONTEND_URL: z.string().url(),
  /** Extra allowed browser origins, comma separated (e.g. a preview domain). FRONTEND_URL is always allowed. */
  FRONTEND_ORIGINS: z.string().optional(),
  API_BASE_URL: z.string().url().optional(),
  RESEND_API_KEY: z.string().optional(),
  /** Legacy name, still accepted. */
  EMAIL_PROVIDER_API_KEY: z.string().optional(),
  EMAIL_FROM: z.string().optional(),
  /** Fournisseur d'e-mails : "auto" (Brevo si BREVO_API_KEY, sinon Resend), "brevo" ou "resend". */
  EMAIL_PROVIDER: z.enum(['auto', 'brevo', 'resend']).default('auto'),
  /** Brevo (API HTTP, sans domaine : une adresse d'expéditeur vérifiée suffit). */
  BREVO_API_KEY: z.string().optional(),
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GOOGLE_CALLBACK_URL: z.string().url().optional(),
  /** Media providers. Facebook follows the code you supplied. TikTok/Instagram stay disabled until their endpoint and response format are provided. */
  SIPUTZX_BASE_URL: z.string().url().default('https://api.siputzx.my.id'),
  FACEBOOK_API_PATH: z.string().startsWith('/').default('/api/d/facebook'),
  /** TikTok et Instagram via l'API WhiteShadow. Le jeton est un SECRET : uniquement dans les variables d'environnement du serveur. */
  WHITESHADOW_BASE_URL: z.string().url().default('https://whiteshadow-x-api.onrender.com'),
  WHITESHADOW_API_TOKEN: z.string().min(16).optional(),
  /** Music metadata provider: "itunes" (public Apple Search API, no key) or "none". */
  MUSIC_PROVIDER: z.enum(['itunes', 'none']).default('itunes'),
  /** Optional AI features (server-side only). Both are required to enable them. Usage is billed by the provider. */
  ANTHROPIC_API_KEY: z.string().optional(),
  AI_MODEL: z.string().optional(),
  AI_DAILY_LIMIT: z.coerce.number().int().min(1).max(1000).default(20),
  /** When true, administrators must have two-factor authentication enabled to use /api/admin. */
  /** When true (default) the download tools need a signed-in user; anonymous visitors get 401. */
  TOOLS_REQUIRE_LOGIN: z.enum(['true', 'false']).default('true').transform((v) => v === 'true'),
  REQUIRE_ADMIN_2FA: z.enum(['true', 'false']).default('false').transform((v) => v === 'true'),
  TRUST_PROXY: z.coerce.number().int().min(0).default(1),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
});

export type Env = z.infer<typeof schema>;

/** Validates environment variables once, at startup. Never logs values. */
export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = schema.safeParse(source);
  if (!parsed.success) {
    const names = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n  ');
    throw new Error(`Invalid environment configuration:\n  ${names}`);
  }
  return parsed.data;
}

export function allowedOrigin(env: Env): string {
  return new URL(env.FRONTEND_URL).origin;
}

/** Exact list of browser origins allowed by CORS and by the CSRF origin check. */
export function allowedOrigins(env: Env): string[] {
  const extra = (env.FRONTEND_ORIGINS ?? '').split(',').map((o) => o.trim()).filter(Boolean).map((o) => new URL(o).origin);
  return [...new Set([allowedOrigin(env), ...extra])];
}
