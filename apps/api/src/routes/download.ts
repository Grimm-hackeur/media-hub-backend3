import { Readable } from 'node:stream';
import type { Request, Response } from 'express';
import { openStream, SafeFetchError, type StreamOpener } from '../net/safeFetch.js';
import { AppError } from '../utils/errors.js';

export const MAX_DOWNLOAD_BYTES = 300 * 1024 * 1024;
const TYPES: Record<string, string> = { mp4: 'video/mp4', mp3: 'audio/mpeg', jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp' };

/** Safe download name: letters, digits, spaces and a few separators only; never a path. */
export function fileName(title: string, format: string): string {
  const ext = /^[a-z0-9]{2,5}$/i.test(format) ? format.toLowerCase() : 'bin';
  const base = title.normalize('NFKC').replace(/[^\p{L}\p{N} ._-]+/gu, ' ').replace(/\s+/g, ' ').trim().replace(/^\.+/, '').slice(0, 80).trim() || 'media-hub';
  return `${base}.${ext}`;
}
export function contentDisposition(name: string): string {
  const ascii = name.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)}`;
}

/** Streams the remote file to the visitor as an attachment, so the browser saves it instead of opening a player. */
export async function streamDownload(res: Response, req: Request, f: { title: string; file: { url: string; format: string } }, open: StreamOpener = openStream): Promise<void> {
  let up;
  try { up = await open(f.file.url); }
  catch (e) {
    if (e instanceof SafeFetchError && e.code === 'TIMEOUT') throw new AppError(504, 'PROVIDER_TIMEOUT', 'The file server took too long to answer.');
    throw new AppError(502, 'PROVIDER_ERROR', 'The file could not be fetched.');
  }
  if (up.status !== 200 || !up.body) { up.abort(); throw new AppError(502, 'PROVIDER_ERROR', 'The file is no longer available. Please analyse the link again.'); }
  const declared = Number(up.headers.get('content-length') ?? '0');
  if (declared > MAX_DOWNLOAD_BYTES) { up.abort(); throw new AppError(413, 'FILE_TOO_LARGE', 'This file is too large to download here.'); }

  res.status(200);
  res.setHeader('Content-Type', TYPES[f.file.format.toLowerCase()] ?? 'application/octet-stream');
  res.setHeader('Content-Disposition', contentDisposition(fileName(f.title, f.file.format)));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  if (declared > 0) res.setHeader('Content-Length', String(declared));

  const src = Readable.fromWeb(up.body as never);
  let sent = 0;
  src.on('data', (c: Buffer) => { sent += c.length; if (sent > MAX_DOWNLOAD_BYTES) { src.destroy(); res.destroy(); } });
  src.on('error', () => { up.abort(); res.destroy(); });
  res.on('close', () => { up.abort(); src.destroy(); });
  await new Promise<void>((resolve) => { res.on('finish', resolve); res.on('close', resolve); src.pipe(res); });
    }
                       
