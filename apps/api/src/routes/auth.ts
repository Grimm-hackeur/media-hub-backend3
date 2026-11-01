import { Router, type Response } from 'express';
import type { Env } from '../config/env.js';
import type { makeLimiters } from '../middleware/rateLimit.js';
import { cookieName, requireAuth, requireCsrf } from '../middleware/security.js';
import { deleteAccountSchema, forgotSchema, loginSchema, registerSchema, resetSchema, tokenSchema, resendOtpSchema, verifyOtpSchema, login2faSchema, enable2faSchema, disable2faSchema } from '../schemas/auth.js';
import { SESSION_TTL_MS, toPublicUser, type AuthService } from '../services/auth.service.js';

export function authRouter(env: Env, auth: AuthService, lim: ReturnType<typeof makeLimiters>) {
  const r = Router();
  const cookieOpts = { httpOnly: true, secure: env.NODE_ENV === 'production', sameSite: 'lax' as const, path: '/' };
  const clear = (res: Response) => res.clearCookie(cookieName(env), cookieOpts);

  r.post('/register', lim.register, lim.registerByEmail, async (req, res) => {
    const body = registerSchema.parse(req.body);
    const { retryAfter } = await auth.register(body);
    res.status(202).json({ status: 'pending', retryAfter });
  });

  r.post('/verify-otp', lim.otpByIp, lim.otpByEmail, async (req, res) => {
    const body = verifyOtpSchema.parse(req.body);
    const { token, csrfToken, user } = await auth.verifyOtp({ ...body, userAgent: req.get('user-agent') ?? null });
    res.cookie(cookieName(env), token, { ...cookieOpts, maxAge: SESSION_TTL_MS });
    res.json({ user: toPublicUser(user), csrfToken });
  });

  r.post('/resend-otp', lim.otpResendByIp, lim.otpResendByEmail, async (req, res) => {
    res.json(await auth.resendOtp(resendOtpSchema.parse(req.body).email));
  });

  r.post('/login', lim.loginByIp, lim.loginByEmail, async (req, res) => {
    const body = loginSchema.parse(req.body);
    const r = await auth.login({ ...body, userAgent: req.get('user-agent') ?? null });
    if (r.twoFactorRequired) { res.json({ twoFactorRequired: true, challenge: r.challenge }); return; }
    res.cookie(cookieName(env), r.token, { ...cookieOpts, maxAge: SESSION_TTL_MS });
    res.json({ user: toPublicUser(r.user), csrfToken: r.csrfToken });
  });

  r.post('/login/2fa', lim.loginByIp, lim.otpByIp, async (req, res) => {
    const body = login2faSchema.parse(req.body);
    const { token, csrfToken, user } = await auth.loginTwoFactor({ ...body, userAgent: req.get('user-agent') ?? null });
    res.cookie(cookieName(env), token, { ...cookieOpts, maxAge: SESSION_TTL_MS });
    res.json({ user: toPublicUser(user), csrfToken });
  });

  r.post('/2fa/setup', requireAuth, requireCsrf, lim.sensitive, async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json(await auth.twoFactorSetup(req.auth!.user));
  });
  r.post('/2fa/enable', requireAuth, requireCsrf, lim.sensitive, async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json(await auth.twoFactorEnable(req.auth!.user, enable2faSchema.parse(req.body).code));
  });
  r.post('/2fa/disable', requireAuth, requireCsrf, lim.sensitive, async (req, res) => {
    const b = disable2faSchema.parse(req.body);
    await auth.twoFactorDisable(req.auth!.user, b.password, b.code);
    res.status(204).end();
  });

  r.get('/me', requireAuth, (req, res) => {
    res.json({ user: toPublicUser(req.auth!.user), csrfToken: req.auth!.session.csrfToken });
  });

  r.post('/logout', requireAuth, requireCsrf, async (req, res) => {
    await auth.logout(req.auth!.session.id, req.auth!.user.id);
    clear(res);
    res.status(204).end();
  });

  r.post('/verify-email', lim.sensitive, async (req, res) => {
    await auth.verifyEmail(tokenSchema.parse(req.body).token);
    res.json({ message: 'E-mail address confirmed.' });
  });

  r.post('/resend-verification', requireAuth, requireCsrf, lim.sensitive, async (req, res) => {
    await auth.resendVerification(req.auth!.user.id);
    res.status(202).json({ message: 'If the address is not yet confirmed, a new e-mail has been sent.' });
  });

  r.post('/forgot-password', lim.reset, lim.resetByEmail, async (req, res) => {
    await auth.requestPasswordReset(forgotSchema.parse(req.body).email);
    res.status(202).json({ message: 'If an account exists for this address, a reset e-mail has been sent.' });
  });

  r.post('/reset-password', lim.reset, async (req, res) => {
    const b = resetSchema.parse(req.body);
    await auth.resetPassword(b.token, b.password);
    res.json({ message: 'Password updated. Please sign in again.' });
  });

  r.delete('/account', requireAuth, requireCsrf, lim.sensitive, async (req, res) => {
    await auth.deleteAccount(req.auth!.user.id, deleteAccountSchema.parse(req.body));
    clear(res);
    res.status(204).end();
  });
  return r;
}
