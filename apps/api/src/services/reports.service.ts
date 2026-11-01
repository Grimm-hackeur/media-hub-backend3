import { z } from 'zod';
import type { ReportRecord, ReportStatus, Repos, UserRecord } from '../repositories/types.js';
import { validateExternalUrl } from '../net/ipGuard.js';
import { emailSchema } from '../schemas/auth.js';
import { notFound } from '../utils/errors.js';

export const createReportSchema = z.object({
  kind: z.enum(['COPYRIGHT', 'ABUSE', 'ILLEGAL', 'OTHER']),
  targetUrl: z.string().max(2048).refine((u) => { try { validateExternalUrl(u); return true; } catch { return false; } }, 'Must be a public https URL').nullish(),
  description: z.string().trim().min(10).max(2000),
  contactEmail: emailSchema.nullish(),
}).strict();
export const adminReportsQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  status: z.enum(['OPEN', 'IN_REVIEW', 'RESOLVED', 'REJECTED']).optional(),
});
export const updateReportSchema = z.object({
  status: z.enum(['OPEN', 'IN_REVIEW', 'RESOLVED', 'REJECTED']).optional(),
  adminNote: z.string().trim().max(1000).nullable().optional(),
}).strict().refine((v) => v.status !== undefined || v.adminNote !== undefined, 'Nothing to update');

export function createReportsService(repos: Repos) {
  return {
    /** Anyone may report; the reporter (if signed in) is recorded so an administrator can follow up. */
    async create(reporter: UserRecord | null, input: z.infer<typeof createReportSchema>) {
      const r = await repos.reports.create({ reporterId: reporter?.id ?? null, kind: input.kind, targetUrl: input.targetUrl ?? null, description: input.description, contactEmail: input.contactEmail ?? null });
      await repos.audit.create({ actorId: reporter?.id ?? null, action: 'REPORT_CREATED', targetId: r.id, metadata: { kind: input.kind } });
      return { id: r.id, status: r.status };
    },
    list: (q: z.infer<typeof adminReportsQuery>) => repos.reports.list(q),
    async update(actorId: string, id: string, patch: z.infer<typeof updateReportSchema>): Promise<ReportRecord> {
      const upd: { status?: ReportStatus; adminNote?: string | null; handledBy?: string | null } = { handledBy: actorId };
      if (patch.status !== undefined) upd.status = patch.status;
      if (patch.adminNote !== undefined) upd.adminNote = patch.adminNote;
      const r = await repos.reports.update(id, upd);
      if (!r) throw notFound('Report not found');
      await repos.audit.create({ actorId, action: 'ADMIN_REPORT_UPDATED', targetId: id, metadata: { status: r.status } });
      return r;
    },
    counts: () => repos.reports.counts(),
  };
}
export type ReportsService = ReturnType<typeof createReportsService>;
