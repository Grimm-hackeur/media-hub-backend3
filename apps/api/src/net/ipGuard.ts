import { BlockList, isIP } from 'node:net';
import dns from 'node:dns';

export class SsrfError extends Error {
  constructor(public readonly code: 'INVALID_URL' | 'BLOCKED_ADDRESS', message: string) {
    super(message);
  }
}

const blocked = new BlockList();
const v4: [string, number][] = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];
for (const [a, p] of v4) blocked.addSubnet(a, p, 'ipv4');
const v6: [string, number][] = [
  ['::', 128], ['::1', 128], ['64:ff9b::', 96], ['100::', 64], ['2001::', 32], ['2001:db8::', 32],
  ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8],
];
for (const [a, p] of v6) blocked.addSubnet(a, p, 'ipv6');

/** Unwraps IPv4-mapped IPv6 (::ffff:10.0.0.1) so it is judged as the IPv4 address it really is. */
function unmap(ip: string): string {
  const m = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (m) return m[1]!;
  const h = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip);
  if (h) {
    const hi = parseInt(h[1]!, 16), lo = parseInt(h[2]!, 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return ip;
}

export function isPublicAddress(ip: string): boolean {
  const u = unmap(ip);
  const fam = isIP(u);
  if (fam === 0) return false;
  return !blocked.check(u, fam === 4 ? 'ipv4' : 'ipv6');
}

export function assertPublicAddress(ip: string): void {
  if (!isPublicAddress(ip)) throw new SsrfError('BLOCKED_ADDRESS', 'Destination address is not allowed');
}

/** DNS lookup used at CONNECT time, so the address that is validated is the one the socket uses (DNS-rebinding safe). */
export function guardedLookup(
  hostname: string,
  options: dns.LookupOptions,
  cb: (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void,
): void {
  dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return cb(err, '', 0);
    const list = addrs as dns.LookupAddress[];
    try {
      if (list.length === 0) throw new SsrfError('BLOCKED_ADDRESS', 'No address');
      for (const a of list) assertPublicAddress(a.address);
    } catch (e) {
      return cb(e as NodeJS.ErrnoException, '', 0);
    }
    if (options.all) return cb(null, list);
    cb(null, list[0]!.address, list[0]!.family);
  });
}

export async function resolvePublic(hostname: string): Promise<string[]> {
  const addrs = await dns.promises.lookup(hostname, { all: true });
  if (addrs.length === 0) throw new SsrfError('BLOCKED_ADDRESS', 'No address');
  for (const a of addrs) assertPublicAddress(a.address);
  return addrs.map((a) => a.address);
}

export interface UrlRules { allowedHosts?: string[] }

/** Strict validation of a user-supplied URL before any outbound request. */
export function validateExternalUrl(raw: string, rules: UrlRules = {}): URL {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) throw new SsrfError('INVALID_URL', 'Invalid URL');
  let u: URL;
  try { u = new URL(raw.trim()); } catch { throw new SsrfError('INVALID_URL', 'Invalid URL'); }
  if (u.protocol !== 'https:') throw new SsrfError('INVALID_URL', 'Only https links are accepted');
  if (u.username || u.password) throw new SsrfError('INVALID_URL', 'Credentials in URL are not allowed');
  if (u.port && u.port !== '443') throw new SsrfError('INVALID_URL', 'Custom ports are not allowed');
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (host.length > 253 || !host.includes('.') || isIP(host.replace(/^\[|\]$/g, '')) !== 0 || host.startsWith('[')) {
    throw new SsrfError('INVALID_URL', 'Invalid host');
  }
  if (/(^|\.)(localhost|local|internal|lan|intranet|home|corp)$/.test(host)) throw new SsrfError('INVALID_URL', 'Invalid host');
  if (rules.allowedHosts && !rules.allowedHosts.some((h) => host === h || host.endsWith(`.${h}`))) {
    throw new SsrfError('INVALID_URL', 'This link does not belong to the selected service');
  }
  return u;
}
