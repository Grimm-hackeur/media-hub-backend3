import { Router } from 'express';
import { requireAuth, requireCsrf, requireRole } from '../middleware/security.js';
import { adminAuditQuery, adminListUsersQuery, adminUpdateUserSchema, objectIdParam } from '../schemas/auth.js';
import type { AdminService } from '../services/admin.service.js';
import type { ApiKeyService } from '../services/apikeys.service.js';
import { usageQuery } from '../schemas/auth.js';
import { adminReportsQuery, updateReportSchema, type ReportsService } from '../services/reports.service.js';
import { settingsPatchSchema, type SettingsService } from '../services/settings.service.js';
import type { OpsService } from '../services/ops.service.js';
import type { ToolsService } from '../services/tools.service.js';
import { z } from 'zod';

const errorsQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  source: z.enum(['http', 'provider', 'process']).optional(),
});
export interface AdminExtras { settings: SettingsService; reports: ReportsService; ops: OpsService; tools: ToolsService }

export function adminRouter(admin: AdminService, keys: ApiKeyService, x: AdminExtras, require2fa = false) {
  const r = Router();
  r.use(requireAuth, requireRole('ADMIN', { require2fa }), requireCsrf);
  r.get('/stats', async (_req, res) => { res.json(await admin.stats()); });
  r.get('/users', async (req, res) => { res.json(await admin.listUsers(adminListUsersQuery.parse(req.query))); });
  r.patch('/users/:id', async (req, res) => {
    const { id } = objectIdParam.parse(req.params);
    res.json(await admin.updateUser(req.auth!.user.id, id, adminUpdateUserSchema.parse(req.body)));
  });
  r.get('/audit-logs', async (req, res) => { res.json(await admin.listAudit(adminAuditQuery.parse(req.query))); });
  r.get('/api-stats', async (req, res) => { res.json(await keys.adminStats(usageQuery.parse(req.query).range)); });

  r.get('/integrations', async (_req, res) => { res.json(await x.ops.integrations()); });
  r.get('/tools', async (_req, res) => { res.json(await x.tools.overview()); });
  r.get('/errors', async (req, res) => { const q = errorsQuery.parse(req.query); res.json({ ...(await x.ops.errors(q)), page: q.page, pageSize: q.pageSize }); });
  r.get('/settings', async (_req, res) => { res.json(await x.settings.get()); });
  r.patch('/settings', async (req, res) => { res.json(await x.settings.update(req.auth!.user.id, settingsPatchSchema.parse(req.body))); });
  r.get('/reports', async (req, res) => { const q = adminReportsQuery.parse(req.query); res.json({ ...(await x.reports.list(q)), page: q.page, pageSize: q.pageSize }); });
  r.patch('/reports/:id', async (req, res) => { res.json(await x.reports.update(req.auth!.user.id, objectIdParam.parse(req.params).id, updateReportSchema.parse(req.body))); });
  return r;
}
