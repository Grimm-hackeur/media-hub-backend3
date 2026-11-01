import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it } from 'vitest';
import { guardedLookup, isPublicAddress, SsrfError, validateExternalUrl } from '../src/net/ipGuard.js';
import { Limiter, safeFetch, SafeFetchError, type SafeFetchOptions } from '../src/net/safeFetch.js';

describe('isPublicAddress', () => {
  it.each([
    '127.0.0.1', '127.255.255.254', '10.0.0.1', '10.255.255.255', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1',
    '0.0.0.0', '224.0.0.1', '255.255.255.255', '198.18.0.1', '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1', '::ffff:127.0.0.1', '::ffff:10.1.2.3',
    '::ffff:7f00:1', '64:ff9b::7f00:1', '2002:7f00:1::1', 'not-an-ip', '',
  ])('blocks %s', (ip) => { expect(isPublicAddress(ip)).toBe(false); });
  it.each(['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.15.0.1', '172.32.0.1', '2606:4700:4700::1111', '2001:4860:4860::8888', '::ffff:8.8.8.8'])('allows %s', (ip) => {
    expect(isPublicAddress(ip)).toBe(true);
  });
});

describe('validateExternalUrl', () => {
  it.each([
    'http://example.com/x', 'ftp://example.com/x', 'file:///etc/passwd', 'javascript:alert(1)', 'https://user:pw@example.com/', 'https://example.com:8443/',
    'https://127.0.0.1/', 'https://[::1]/', 'https://localhost/', 'https://printer.local/', 'https://db.internal/', 'https://169.254.169.254/latest/meta-data',
    'https://2130706433/', 'https://0x7f.0.0.1/', 'https://intranet/', '', 'not a url', `https://example.com/${'a'.repeat(2100)}`,
  ])('rejects %s', (u) => { expect(() => validateExternalUrl(u)).toThrow(SsrfError); });

  it('accepts ordinary public https URLs and enforces host allow-lists exactly', () => {
    expect(validateExternalUrl('https://www.facebook.com/watch?v=1', { allowedHosts: ['facebook.com'] }).hostname).toBe('www.facebook.com');
    expect(() => validateExternalUrl('https://facebook.com.evil.io/', { allowedHosts: ['facebook.com'] })).toThrow(/does not belong/);
    expect(() => validateExternalUrl('https://notfacebook.com/', { allowedHosts: ['facebook.com'] })).toThrow(/does not belong/);
    expect(() => validateExternalUrl('https://evil.io/?u=facebook.com', { allowedHosts: ['facebook.com'] })).toThrow(/does not belong/);
  });
});

describe('guardedLookup (connect-time DNS check)', () => {
  it('refuses a name that resolves to loopback', async () => {
    const err = await new Promise<unknown>((resolve) => guardedLookup('localhost', {}, (e) => resolve(e)));
    expect(err).toBeInstanceOf(SsrfError);
  });
});

const ok = (body: BodyInit, init: ResponseInit = {}) => new Response(body, { status: 200, headers: { 'content-type': 'application/json' }, ...init });
const publicResolve = async () => ['93.184.216.34'];
const run = (url: string, opts: SafeFetchOptions) => safeFetch(url, { resolve: publicResolve, ...opts });

describe('safeFetch', () => {
  it('returns the body, status and final url', async () => {
    const r = await run('https://example.com/a', { fetchImpl: async () => ok('{"a":1}') });
    expect(r.status).toBe(200);
    expect(r.json()).toEqual({ a: 1 });
    expect(r.finalUrl).toBe('https://example.com/a');
  });

  it('never lets fetch follow redirects itself and sends the validated URL', async () => {
    let seen: { url: string; redirect?: string } | null = null;
    await run('https://example.com/a', { fetchImpl: async (url, init) => { seen = { url, redirect: init.redirect }; return ok('{}'); } });
    expect(seen).toEqual({ url: 'https://example.com/a', redirect: 'manual' });
  });

  it('rejects a destination whose DNS answer is private, before any request is made', async () => {
    let called = false;
    await expect(safeFetch('https://example.com/', { resolve: async () => { throw new SsrfError('BLOCKED_ADDRESS', 'x'); }, fetchImpl: async () => { called = true; return ok('{}'); } }))
      .rejects.toMatchObject({ code: 'BLOCKED_ADDRESS' });
    expect(called).toBe(false);
  });

  it('rejects private IP literals and non-https URLs without resolving', async () => {
    await expect(safeFetch('https://10.0.0.5/', {})).rejects.toMatchObject({ code: 'INVALID_URL' });
    await expect(safeFetch('http://example.com/', {})).rejects.toMatchObject({ code: 'INVALID_URL' });
  });

  it('enforces the size cap on a streamed body (no Content-Length)', async () => {
    const big = new ReadableStream({ start(c) { for (let i = 0; i < 50; i++) c.enqueue(new Uint8Array(1000)); c.close(); } });
    await expect(run('https://example.com/', { maxBytes: 5000, fetchImpl: async () => new Response(big, { headers: { 'content-type': 'application/json' } }) })).rejects.toMatchObject({ code: 'TOO_LARGE' });
  });

  it('enforces the size cap from Content-Length without reading the body', async () => {
    await expect(run('https://example.com/', { maxBytes: 100, fetchImpl: async () => ok('{}', { headers: { 'content-type': 'application/json', 'content-length': '999999' } }) })).rejects.toMatchObject({ code: 'TOO_LARGE' });
  });

  it('times out slow remotes', async () => {
    const hang: SafeFetchOptions['fetchImpl'] = (_u, init) => new Promise((_res, rej) => { init.signal.addEventListener('abort', () => rej(init.signal.reason)); });
    const t0 = Date.now();
    await expect(run('https://example.com/', { timeoutMs: 80, fetchImpl: hang })).rejects.toMatchObject({ code: 'TIMEOUT' });
    expect(Date.now() - t0).toBeLessThan(1500);
  });

  it('times out a body that stalls after the headers', async () => {
    const stall = new ReadableStream({ start() { /* never enqueues */ } });
    const impl: SafeFetchOptions['fetchImpl'] = async () => new Response(stall, { headers: { 'content-type': 'application/json' } });
    const t0 = Date.now();
    await expect(run('https://example.com/', { timeoutMs: 80, fetchImpl: impl })).rejects.toMatchObject({ code: 'TIMEOUT' });
    expect(Date.now() - t0).toBeLessThan(1500);
  });

  it('follows redirects manually, re-validating every hop', async () => {
    const hops: string[] = [];
    const impl: SafeFetchOptions['fetchImpl'] = async (url) => {
      hops.push(url);
      return url.endsWith('/start') ? new Response(null, { status: 302, headers: { location: '/next' } }) : ok('{}');
    };
    const r = await run('https://example.com/start', { maxRedirects: 3, fetchImpl: impl });
    expect(hops).toEqual(['https://example.com/start', 'https://example.com/next']);
    expect(r.finalUrl).toBe('https://example.com/next');
  });

  it('blocks a redirect to a private address, a non-https scheme, or another host outside the allow-list', async () => {
    const redirectTo = (loc: string): SafeFetchOptions['fetchImpl'] => async () => new Response(null, { status: 302, headers: { location: loc } });
    await expect(run('https://example.com/', { maxRedirects: 3, fetchImpl: redirectTo('https://169.254.169.254/latest') })).rejects.toMatchObject({ code: 'INVALID_URL' });
    await expect(run('https://example.com/', { maxRedirects: 3, fetchImpl: redirectTo('http://example.com/') })).rejects.toMatchObject({ code: 'INVALID_URL' });
    await expect(run('https://facebook.com/', { allowedHosts: ['facebook.com'], maxRedirects: 3, fetchImpl: redirectTo('https://evil.example.net/') })).rejects.toMatchObject({ code: 'INVALID_URL' });
    // a hostname that resolves to a private address on the second hop
    let n = 0;
    const resolve = async () => { if (++n > 1) throw new SsrfError('BLOCKED_ADDRESS', 'x'); return ['93.184.216.34']; };
    await expect(safeFetch('https://example.com/', { resolve, maxRedirects: 3, fetchImpl: redirectTo('https://internal-looking.example.org/') })).rejects.toMatchObject({ code: 'BLOCKED_ADDRESS' });
  });

  it('refuses redirects by default and caps redirect chains', async () => {
    const loop: SafeFetchOptions['fetchImpl'] = async () => new Response(null, { status: 302, headers: { location: 'https://example.com/again' } });
    await expect(run('https://example.com/', { fetchImpl: loop })).rejects.toMatchObject({ code: 'TOO_MANY_REDIRECTS' });
    await expect(run('https://example.com/', { maxRedirects: 3, fetchImpl: loop })).rejects.toMatchObject({ code: 'TOO_MANY_REDIRECTS' });
  });

  it('checks the content type', async () => {
    await expect(run('https://example.com/', { contentType: /json/, fetchImpl: async () => ok('<html>', { headers: { 'content-type': 'text/html' } }) })).rejects.toMatchObject({ code: 'BAD_CONTENT_TYPE' });
  });

  it('maps network failures to NETWORK without leaking details', async () => {
    const err = await run('https://example.com/', { fetchImpl: async () => { throw new Error('ECONNREFUSED 10.1.2.3:443 secret'); } }).catch((e) => e);
    expect(err).toMatchObject({ code: 'NETWORK' });
    expect(err.message).not.toMatch(/10\.1|secret/);
  });

  it('sends a POST body only for POST', async () => {
    const seen: { m: string; b?: string }[] = [];
    const impl: SafeFetchOptions['fetchImpl'] = async (_u, init) => { seen.push({ m: init.method, b: init.body }); return ok('{}'); };
    await run('https://example.com/', { method: 'POST', body: '{"x":1}', fetchImpl: impl });
    await run('https://example.com/', { method: 'GET', body: '{"x":1}', fetchImpl: impl });
    expect(seen).toEqual([{ m: 'POST', b: '{"x":1}' }, { m: 'GET', b: undefined }]);
  });

  it('with the real network stack, a server on loopback is unreachable (blocked at validation, not by luck)', async () => {
    const server = createServer((_q, res) => { res.end('secret'); });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;
    try {
      await expect(safeFetch(`https://127.0.0.1:${port}/`, {})).rejects.toMatchObject({ code: 'INVALID_URL' });
      await expect(safeFetch(`https://localhost/`, {})).rejects.toMatchObject({ code: 'INVALID_URL' });
    } finally { server.close(); }
  });
});

describe('Limiter', () => {
  it('bounds concurrency and releases once', () => {
    const l = new Limiter(2);
    const a = l.tryAcquire()!, b = l.tryAcquire()!;
    expect(l.tryAcquire()).toBeNull();
    a(); a();
    expect(l.inFlight).toBe(1);
    expect(l.tryAcquire()).not.toBeNull();
    b();
  });
});
