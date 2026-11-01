import { Router } from 'express';
import { requireAuth, requireCsrf } from '../middleware/security.js';
import { requireVerified } from '../middleware/http.js';
import { objectIdParam } from '../schemas/auth.js';
import { toPublicUser } from '../services/auth.service.js';
import {
  collectionInputSchema, collectionPatchSchema, favoritesQuery, historyQuery, preferencesPatchSchema, profilePatchSchema, savedItemSchema,
  type MeService,
} from '../services/me.service.js';
import { z } from 'zod';

const itemParams = z.object({ id: z.string().regex(/^[a-f0-9]{24}$/i), itemId: z.string().regex(/^[a-f0-9]{24}$/i) });
/** Public shape of a stored record: the owner id is internal and never leaves the server. */
const dto = <T extends { userId?: unknown }>(x: T): Omit<T, 'userId'> => { const { userId: _u, ...rest } = x; return rest; };
const paged = <T extends { userId?: unknown }>(p: { items: T[]; total: number }, q: { page: number; pageSize: number }) => ({ items: p.items.map(dto), total: p.total, page: q.page, pageSize: q.pageSize });

/** Everything here is scoped to the signed-in user: every repository call takes the user id from the SESSION, never from the request. */
export function meRouter(me: MeService) {
  const r = Router();
  r.use(requireAuth, requireVerified, requireCsrf);

  r.patch('/profile', async (req, res) => { res.json({ user: toPublicUser(await me.updateProfile(req.auth!.user, profilePatchSchema.parse(req.body))) }); });
  r.get('/preferences', (req, res) => { res.json(req.auth!.user.preferences); });
  r.patch('/preferences', async (req, res) => { res.json(await me.updatePreferences(req.auth!.user, preferencesPatchSchema.parse(req.body))); });

  r.get('/history', async (req, res) => { const q = historyQuery.parse(req.query); res.json(paged(await me.history.list(req.auth!.user.id, q), q)); });
  r.delete('/history', async (req, res) => { res.json({ deleted: await me.history.clear(req.auth!.user.id) }); });
  r.delete('/history/:id', async (req, res) => { await me.history.remove(req.auth!.user.id, objectIdParam.parse(req.params).id); res.status(204).end(); });

  r.get('/favorites', async (req, res) => { const q = favoritesQuery.parse(req.query); res.json(paged(await me.favorites.list(req.auth!.user.id, q), q)); });
  r.post('/favorites', async (req, res) => { res.status(201).json(dto(await me.favorites.add(req.auth!.user.id, savedItemSchema.parse(req.body)))); });
  r.delete('/favorites/:id', async (req, res) => { await me.favorites.remove(req.auth!.user.id, objectIdParam.parse(req.params).id); res.status(204).end(); });

  r.get('/collections', async (req, res) => { res.json({ items: (await me.collections.list(req.auth!.user.id)).map(dto) }); });
  r.post('/collections', async (req, res) => { res.status(201).json(dto(await me.collections.create(req.auth!.user.id, collectionInputSchema.parse(req.body)))); });
  r.get('/collections/:id', async (req, res) => { res.json(dto(await me.collections.get(req.auth!.user.id, objectIdParam.parse(req.params).id))); });
  r.patch('/collections/:id', async (req, res) => { res.json(dto(await me.collections.update(req.auth!.user.id, objectIdParam.parse(req.params).id, collectionPatchSchema.parse(req.body)))); });
  r.delete('/collections/:id', async (req, res) => { await me.collections.remove(req.auth!.user.id, objectIdParam.parse(req.params).id); res.status(204).end(); });
  r.post('/collections/:id/items', async (req, res) => { res.status(201).json(dto(await me.collections.addItem(req.auth!.user.id, objectIdParam.parse(req.params).id, savedItemSchema.parse(req.body)))); });
  r.delete('/collections/:id/items/:itemId', async (req, res) => { const p = itemParams.parse(req.params); await me.collections.removeItem(req.auth!.user.id, p.id, p.itemId); res.status(204).end(); });

  r.get('/sessions', async (req, res) => { res.json({ items: await me.sessions.list(req.auth!.user.id, req.auth!.session.id) }); });
  r.post('/sessions/revoke-others', async (req, res) => { res.json({ revoked: await me.sessions.revokeOthers(req.auth!.user.id, req.auth!.session.id) }); });
  r.delete('/sessions/:id', async (req, res) => { await me.sessions.revoke(req.auth!.user.id, objectIdParam.parse(req.params).id, req.auth!.session.id); res.status(204).end(); });
  return r;
}
