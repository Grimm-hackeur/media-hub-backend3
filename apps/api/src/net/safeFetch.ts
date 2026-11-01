import { Agent, fetch as undiciFetch } from 'undici';
import { guardedLookup, resolvePublic, SsrfError, validateExternalUrl, type UrlRules } from './ipGuard.js';

export type SafeFetchErrorCode =
  | 'INVALID_URL' | 'BLOCKED_ADDRESS' | 'TIMEOUT' | 'TOO_LARGE' | 'TOO_MANY_REDIRECTS' | 'BAD_CONTENT_TYPE' | 'NETWORK';
export class SafeFetchError extends Error {
  constructor(public readonly code: SafeFetchErrorCode, message: string) { super(message); }
}

export interface SafeFetchOptions extends UrlRules {
  method?: 'GET' | 'HEAD' | 'POST';
  /** JSON body (POST only). */
  body?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
  /** Regex the response Content-Type must match (e.g. /json/). */
  contentType?: RegExp;
  /** Read no body at all (used to resolve short links to their final URL). */
  noBody?: boolean;
  /** Injected in tests. Defaults to undici with an Agent whose connect step validates the destination IP. */
  fetchImpl?: (url: string, init: { method: string; headers: Record<string, string>; body?: string; redirect: 'manual'; signal: AbortSignal }) => Promise<Response>;
  /** Injected in tests. Defaults to a DNS lookup that rejects private/loopback/link-local addresses. */
  resolve?: (host: string) => Promise<string[]>;
}
export interface SafeResponse { status: number; finalUrl: string; headers: Headers; body: Uint8Array; text(): string; json(): unknown }

let agent: Agent | undefined;
const defaultFetch: NonNullable<SafeFetchOptions['fetchImpl']> = (url, init) => {
  agent ??= new Agent({ connect: { lookup: guardedLookup as never }, headersTimeout: 15_000, bodyTimeout: 15_000 });
  return undiciFetch(url, { ...init, dispatcher: agent }) as unknown as Promise<Response>;
};

/** Rejects as soon as the signal aborts, even if the underlying stream never settles (stalled body). */
function raceAbort<T>(p: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener('abort', onAbort, { once: true });
    p.then((v) => { signal.removeEventListener('abort', onAbort); resolve(v); }, (e) => { signal.removeEventListener('abort', onAbort); reject(e); });
  });
}

async function readCapped(res: Response, max: number, signal: AbortSignal): Promise<Uint8Array> {
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > max) { await res.body?.cancel().catch(() => {}); throw new SafeFetchError('TOO_LARGE', 'Response too large'); }
  if (!res.body) return new Uint8Array();
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    let chunk: ReadableStreamReadResult<Uint8Array>;
    try { chunk = await raceAbort(reader.read(), signal); } catch (e) { reader.cancel().catch(() => {}); throw e; }
    const { done, value } = chunk;
    if (done) break;
    total += value.byteLength;
    if (total > max) { await reader.cancel().catch(() => {}); throw new SafeFetchError('TOO_LARGE', 'Response too large'); }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.byteLength; }
  return out;
}

/**
 * The only way the server fetches a URL that a user (or a configuration) can influence.
 * https only, no credentials/ports/IP literals, every resolved address must be public, redirects are followed manually and
 * re-validated at each hop, hard timeout, hard size cap, optional host allow-list and content-type check.
 */
export async function safeFetch(rawUrl: string, opts: SafeFetchOptions = {}): Promise<SafeResponse> {
  const { timeoutMs = 15_000, maxBytes = 1_000_000, maxRedirects = 0 } = opts;
  const doFetch = opts.fetchImpl ?? defaultFetch;
  const resolve = opts.resolve ?? resolvePublic;
  const signal = AbortSignal.timeout(timeoutMs);
  let current = rawUrl;
  try {
    for (let hop = 0; ; hop++) {
      const u = validateExternalUrl(current, { allowedHosts: opts.allowedHosts });
      await resolve(u.hostname);
      const res = await doFetch(u.toString(), { method: opts.method ?? 'GET', headers: { Accept: '*/*', ...opts.headers }, ...(opts.body !== undefined && (opts.method ?? 'GET') === 'POST' ? { body: opts.body } : {}), redirect: 'manual', signal });
      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        await res.body?.cancel().catch(() => {});
        if (hop >= maxRedirects) throw new SafeFetchError('TOO_MANY_REDIRECTS', 'Too many redirects');
        current = new URL(res.headers.get('location')!, u).toString();
        continue;
      }
      if (opts.contentType && !opts.contentType.test(res.headers.get('content-type') ?? '')) {
        await res.body?.cancel().catch(() => {});
        throw new SafeFetchError('BAD_CONTENT_TYPE', 'Unexpected content type');
      }
      let body: Uint8Array = new Uint8Array();
      if (opts.noBody) await res.body?.cancel().catch(() => {});
      else body = await readCapped(res, maxBytes, signal);
      return {
        status: res.status, finalUrl: u.toString(), headers: res.headers, body,
        text: () => new TextDecoder().decode(body),
        json: () => JSON.parse(new TextDecoder().decode(body)) as unknown,
      };
    }
  } catch (e) {
    if (e instanceof SafeFetchError) throw e;
    if (e instanceof SsrfError) throw new SafeFetchError(e.code, e.message);
    const name = (e as Error)?.name;
    if (name === 'TimeoutError' || name === 'AbortError' || signal.aborted) throw new SafeFetchError('TIMEOUT', 'The remote service did not answer in time');
    const cause = (e as { cause?: unknown })?.cause;
    if (cause instanceof SsrfError) throw new SafeFetchError(cause.code, cause.message);
    throw new SafeFetchError('NETWORK', 'Network error while contacting the remote service');
  }
}

/** Small counting semaphore: bounds concurrent outbound calls per provider. */
export class Limiter {
  private active = 0;
  constructor(private readonly max: number) {}
  tryAcquire(): (() => void) | null {
    if (this.active >= this.max) return null;
    this.active++;
    let done = false;
    return () => { if (!done) { done = true; this.active--; } };
  }
  get inFlight() { return this.active; }
}
