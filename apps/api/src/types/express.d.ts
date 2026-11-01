import type { SessionRecord, UserRecord } from '../repositories/types.js';
declare global {
  namespace Express {
    interface Request {
      auth?: { user: UserRecord; session: SessionRecord };
    }
  }
}
export {};
