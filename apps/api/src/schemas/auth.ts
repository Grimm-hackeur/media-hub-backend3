import { z } from 'zod';
import { normalizeEmail } from '../utils/normalize.js';

export const emailSchema = z
  .string()
  .max(254)
  .transform(normalizeEmail)
  .pipe(z.string().email('Invalid email address'));

export const passwordSchema = z
  .string()
  .min(10, 'Password must be at least 10 characters')
  .max(128, 'Password must be at most 128 characters');

export const usernameSchema = z
  .string()
  .trim()
  .min(3)
  .max(30)
  .regex(/^[\p{L}\p{N}_.-]+$/u, 'Letters, digits, dot, dash and underscore only');

export const registerSchema = z
  .object({
    username: usernameSchema,
    email: emailSchema,
    password: passwordSchema,
    acceptTerms: z.literal(true, { error: 'You must accept the terms' }),
  })
  .strict();

export const loginSchema = z.object({ email: emailSchema, password: z.string().min(1).max(128) }).strict();
export const tokenSchema = z.object({ token: z.string().min(20).max(200) }).strict();
export const forgotSchema = z.object({ email: emailSchema }).strict();
export const resetSchema = z.object({ token: z.string().min(20).max(200), password: passwordSchema }).strict();
export const deleteAccountSchema = z.object({ password: z.string().min(1).max(128).optional(), confirmEmail: z.string().max(254).optional() }).strict()
  .refine((v) => v.password !== undefined || v.confirmEmail !== undefined, 'Confirmation required');

export const adminListUsersQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  q: z.string().trim().max(100).optional(),
  role: z.enum(['USER', 'ADMIN']).optional(),
  status: z.enum(['ACTIVE', 'SUSPENDED', 'DELETED']).optional(),
});
export const adminUpdateUserSchema = z
  .object({ role: z.enum(['USER', 'ADMIN']).optional(), status: z.enum(['ACTIVE', 'SUSPENDED']).optional() })
  .strict()
  .refine((v) => v.role !== undefined || v.status !== undefined, 'Nothing to update');
export const adminAuditQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  action: z.string().trim().max(60).optional(),
});
export const objectIdParam = z.object({ id: z.string().regex(/^[a-f0-9]{24}$/i, 'Invalid id') });

export const createKeySchema = z.object({ name: z.string().trim().min(1).max(60) }).strict();
export const usageQuery = z.object({ range: z.enum(['24h', '7d', '30d']).default('24h') });

export const verifyOtpSchema = z.object({ email: emailSchema, code: z.string().regex(/^\d{4}$/, 'Code must be 4 digits') }).strict();
export const resendOtpSchema = z.object({ email: emailSchema }).strict();

export const login2faSchema = z.object({ challenge: z.string().min(10).max(200), code: z.string().trim().min(6).max(16) }).strict();
export const enable2faSchema = z.object({ code: z.string().regex(/^\d{6}$/, 'Code must be 6 digits') }).strict();
export const disable2faSchema = z.object({ password: z.string().min(1).max(128), code: z.string().trim().min(6).max(16) }).strict();
