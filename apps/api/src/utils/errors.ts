export class AppError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details?: Record<string, string[]>,
    public readonly meta?: Record<string, number>,
  ) {
    super(message);
  }
}
export const badRequest = (message = 'Invalid request', details?: Record<string, string[]>) =>
  new AppError(400, 'BAD_REQUEST', message, details);
export const unauthorized = (message = 'Authentication required') => new AppError(401, 'UNAUTHORIZED', message);
export const forbidden = (message = 'Forbidden') => new AppError(403, 'FORBIDDEN', message);
export const notFound = (message = 'Not found') => new AppError(404, 'NOT_FOUND', message);
export const conflict = (message = 'Conflict') => new AppError(409, 'CONFLICT', message);

/** Thrown by repositories when a unique index is violated. */
export class DuplicateError extends Error {
  constructor(public readonly field: string) {
    super(`Duplicate value for ${field}`);
  }
}

/** Errors the front-end acts on (OTP flow): machine-readable code + numeric meta (attemptsLeft, retryAfter). */
export const coded = (status: number, code: string, message: string, meta?: Record<string, number>) =>
  new AppError(status, code, message, undefined, meta);
