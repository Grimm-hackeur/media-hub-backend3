import type { Repos, Role, UserStatus } from '../repositories/types.js';
import { conflict, forbidden, notFound } from '../utils/errors.js';
import { toPublicUser } from './auth.service.js';

export function createAdminService(repos: Repos, now: () => Date = () => new Date()) {
  return {
    async stats() {
      return repos.users.stats(now());
    },
    async listUsers(q: { page: number; pageSize: number; q?: string; role?: Role; status?: UserStatus }) {
      const { items, total } = await repos.users.list(q);
      return { items: items.map((u) => ({ ...toPublicUser(u), status: u.status })), total, page: q.page, pageSize: q.pageSize };
    },
    async updateUser(actorId: string, targetId: string, patch: { role?: Role; status?: 'ACTIVE' | 'SUSPENDED' }) {
      if (actorId === targetId) throw forbidden('You cannot change your own role or status');
      const target = await repos.users.findById(targetId);
      if (!target || target.status === 'DELETED') throw notFound('User not found');
      const demotes = (patch.role === 'USER' && target.role === 'ADMIN') || (patch.status === 'SUSPENDED' && target.role === 'ADMIN');
      if (demotes && (await repos.users.countAdmins()) <= 1) throw conflict('At least one active administrator is required');
      if (patch.role === 'ADMIN' && !target.emailVerified) throw conflict('Only verified accounts can become administrators');
      const updated = await repos.users.update(targetId, patch);
      if (!updated) throw notFound('User not found');
      if (patch.status === 'SUSPENDED') await repos.sessions.revokeAllForUser(targetId, now());
      await repos.audit.create({
        actorId, action: patch.role ? 'ADMIN_ROLE_CHANGED' : 'ADMIN_STATUS_CHANGED', targetId,
        metadata: { ...(patch.role ? { from: target.role, to: patch.role } : {}), ...(patch.status ? { fromStatus: target.status, toStatus: patch.status } : {}) },
      });
      return { ...toPublicUser(updated), status: updated.status };
    },
    async listAudit(q: { page: number; pageSize: number; action?: string }) {
      const r = await repos.audit.list(q);
      return {
        items: r.items.map((a) => ({ id: a.id, actorId: a.actorId, action: a.action, targetId: a.targetId, metadata: a.metadata, timestamp: a.timestamp.toISOString() })),
        total: r.total, page: q.page, pageSize: q.pageSize,
      };
    },
  };
}
export type AdminService = ReturnType<typeof createAdminService>;
