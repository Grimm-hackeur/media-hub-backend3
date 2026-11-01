import { z } from 'zod';
import type { Env } from '../config/env.js';
import { safeFetch } from '../net/safeFetch.js';
import { mapFetchError, type SafeFn } from '../providers/facebook.js';
import { ProviderError } from '../providers/types.js';
import type { Repos, UserRecord } from '../repositories/types.js';
import { AppError, coded } from '../utils/errors.js';

export const AI_FEATURES = {
  titles: 'Suggestions de titres',
  description: 'Description',
  hashtags: 'Hashtags',
  translate: 'Traduction de sous-titres',
  summarize: 'Résumé',
} as const;
export type AiFeature = keyof typeof AI_FEATURES;
export const UNAVAILABLE_FEATURES = [{ id: 'transcribe', label: 'Transcription audio', reason: 'No transcription provider is integrated.' }];

export const aiInputSchema = z.object({
  text: z.string().trim().min(1).max(8000),
  language: z.string().trim().min(2).max(40).optional(),
}).strict();

export interface AiProvider { readonly id: string; complete(p: { system: string; user: string; maxTokens: number }): Promise<string> }

const anthropicResponse = z.object({ content: z.array(z.object({ type: z.string(), text: z.string().optional() }).passthrough()) }).passthrough();

/** Anthropic Messages API (server-side only; the key never reaches the browser). NOT exercised against the live API in the build sandbox. */
export function createAnthropicProvider(apiKey: string, model: string, safe: SafeFn = safeFetch): AiProvider {
  return {
    id: 'anthropic',
    async complete({ system, user, maxTokens }) {
      try {
        const res = await safe('https://api.anthropic.com/v1/messages', {
          method: 'POST', allowedHosts: ['api.anthropic.com'], timeoutMs: 30_000, maxBytes: 200_000, contentType: /json/i,
          headers: { 'content-type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
          body: JSON.stringify({ model, max_tokens: maxTokens, system, messages: [{ role: 'user', content: user }] }),
        });
        if (res.status === 429) throw new ProviderError(503, 'AI_BUSY', 'The AI service is busy. Please try again later.');
        if (res.status >= 400) throw new ProviderError(502, 'PROVIDER_ERROR', 'The AI service refused the request.');
        const parsed = anthropicResponse.safeParse(res.json());
        const text = parsed.success ? parsed.data.content.filter((c) => c.type === 'text').map((c) => c.text ?? '').join('').trim() : '';
        if (!text) throw new ProviderError(502, 'PROVIDER_BAD_RESPONSE', 'The AI service returned an empty answer.');
        return text;
      } catch (e) { throw mapFetchError(e); }
    },
  };
}

const PROMPTS: Record<AiFeature, (lang?: string) => { system: string; maxTokens: number }> = {
  titles: (l) => ({ system: `You write short, accurate video titles. Reply with exactly 5 numbered title suggestions${l ? ` in ${l}` : ' in the language of the input'}. No preamble.`, maxTokens: 400 }),
  description: (l) => ({ system: `You write a clear description (max 120 words)${l ? ` in ${l}` : ' in the language of the input'} from the given content. Reply with the description only.`, maxTokens: 400 }),
  hashtags: () => ({ system: 'You suggest 10 relevant hashtags for the given content. Reply with the hashtags only, separated by spaces.', maxTokens: 200 }),
  translate: (l) => ({ system: `You translate subtitles into ${l ?? 'English'}. Keep the line structure and any timestamps unchanged. Reply with the translation only.`, maxTokens: 3000 }),
  summarize: (l) => ({ system: `You summarise the given text in at most 8 bullet points${l ? ` in ${l}` : ' in the language of the input'}. Reply with the bullet points only.`, maxTokens: 700 }),
};

export function createAiService(deps: { env: Env; repos: Repos; provider?: AiProvider; now?: () => Date }) {
  const now = deps.now ?? (() => new Date());
  const provider = deps.provider ?? (deps.env.ANTHROPIC_API_KEY && deps.env.AI_MODEL ? createAnthropicProvider(deps.env.ANTHROPIC_API_KEY, deps.env.AI_MODEL) : undefined);
  return {
    configured: !!provider,
    capabilities() {
      return {
        configured: !!provider, dailyLimit: deps.env.AI_DAILY_LIMIT,
        features: Object.entries(AI_FEATURES).map(([id, label]) => ({ id, label, available: !!provider, ...(provider ? {} : { reason: 'Set ANTHROPIC_API_KEY and AI_MODEL on the server.' }) })),
        unavailable: UNAVAILABLE_FEATURES,
      };
    },
    async run(feature: AiFeature, user: UserRecord, input: z.infer<typeof aiInputSchema>) {
      if (!provider) throw new AppError(503, 'SERVICE_NOT_CONFIGURED', 'AI features are not connected on this server.');
      const since = new Date(now().getTime() - 24 * 3_600_000);
      const used = await deps.repos.toolEvents.countByUser(user.id, 'ai:', since);
      if (used >= deps.env.AI_DAILY_LIMIT) throw coded(429, 'AI_QUOTA', 'Daily AI limit reached. Try again tomorrow.', { retryAfter: 3600 });
      const p = PROMPTS[feature](input.language);
      try {
        const result = await provider.complete({ system: p.system, user: input.text, maxTokens: p.maxTokens });
        await deps.repos.toolEvents.create({ tool: `ai:${feature}`, ok: true, userId: user.id, at: now() });
        return { feature, result };
      } catch (e) {
        await deps.repos.toolEvents.create({ tool: `ai:${feature}`, ok: false, userId: user.id, code: e instanceof ProviderError ? e.code : 'INTERNAL', at: now() }).catch(() => {});
        if (e instanceof ProviderError) throw new AppError(e.status, e.code, e.message);
        throw e;
      }
    },
  };
}
export type AiService = ReturnType<typeof createAiService>;
