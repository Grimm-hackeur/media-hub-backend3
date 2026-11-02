import { Router } from 'express';
import type { makeLimiters } from '../middleware/rateLimit.js';
import { csrfIfSession } from '../middleware/http.js';
import { requireAuth } from '../middleware/security.js';
import type { StreamOpener } from '../net/safeFetch.js';
import { streamDownload } from './download.js';
import { analyzeSchema, searchSchema, type ToolsService } from '../services/tools.service.js';

/** Tools. With `requireLogin` (default) every route except the public catalogue needs a session; otherwise anonymous visitors are allowed (rate-limited). A signed-in user additionally gets history, and must send the CSRF token. */
export function toolsRouter(tools: ToolsService, lim: ReturnType<typeof makeLimiters>, requireLogin = false, opener?: StreamOpener) {
  const r = Router();
  const gate = requireLogin ? [requireAuth] : [];
  r.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
  r.get('/', async (_req, res) => { res.json(await tools.list()); });

  r.get('/music/search', ...gate, lim.tools, async (req, res) => { res.json(await tools.search(searchSchema.parse(req.query), req.auth?.user ?? null)); });
  r.post('/music/search', ...gate, csrfIfSession, lim.tools, async (req, res) => { res.json(await tools.search(searchSchema.parse(req.body), req.auth?.user ?? null)); });

  /** Releases the links once the server-side wait (ad time) is over. */
  r.post('/jobs/:jobId/claim', ...gate, csrfIfSession, lim.claim, async (req, res) => { res.json(await tools.claim(String(req.params.jobId), req.auth?.user ?? null)); });

  /** Direct download: the file is streamed through the server as an attachment (same wait/owner rules as claim). */
  r.get('/jobs/:jobId/file/:index', ...gate, lim.claim, async (req, res) => {
    const index = /^\d{1,2}$/.test(String(req.params.index)) ? Number(req.params.index) : -1;
    const f = await tools.fileFor(String(req.params.jobId), index, req.auth?.user ?? null);
    await streamDownload(res, req, f, opener);
  });

  r.post('/:id/analyze', ...gate, csrfIfSession, lim.tools, async (req, res) => {
    res.json(await tools.analyze(String(req.params.id), analyzeSchema.parse(req.body).url, req.auth?.user ?? null));
  });
  return r;
                                                    }
