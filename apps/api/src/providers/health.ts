export interface ProviderStats {
  calls: number; failures: number; lastOkAt: string | null; lastErrorAt: string | null; lastErrorCode: string | null; avgMs: number | null;
}
/** Live counters since the process started (real calls only; nothing is simulated). Reset on restart / Render sleep. */
export class ProviderHealth {
  private s = new Map<string, { calls: number; failures: number; ok: Date | null; err: Date | null; code: string | null; ms: number }>();
  record(id: string, ok: boolean, ms: number, code: string | null, at: Date) {
    const x = this.s.get(id) ?? { calls: 0, failures: 0, ok: null, err: null, code: null, ms: 0 };
    x.calls++; x.ms += ms;
    if (ok) x.ok = at; else { x.failures++; x.err = at; x.code = code; }
    this.s.set(id, x);
  }
  get(id: string): ProviderStats {
    const x = this.s.get(id);
    if (!x) return { calls: 0, failures: 0, lastOkAt: null, lastErrorAt: null, lastErrorCode: null, avgMs: null };
    return { calls: x.calls, failures: x.failures, lastOkAt: x.ok?.toISOString() ?? null, lastErrorAt: x.err?.toISOString() ?? null, lastErrorCode: x.code, avgMs: Math.round(x.ms / x.calls) };
  }
}
