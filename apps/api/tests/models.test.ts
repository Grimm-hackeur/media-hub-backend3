import { describe, expect, it } from 'vitest';
import { AuditLogModel, AuthIdentityModel, SessionModel, UserModel } from '../src/models/index.js';

// These tests need no database: they check schema validation and declared indexes only.
// Behaviour against a real MongoDB (unique-index enforcement, TTL purge) is NOT covered here.
describe('Mongoose schemas (no DB)', () => {
  it('validates enums and required fields on User', async () => {
    await expect(new UserModel({ username: 'ab', usernameLower: 'ab', email: 'a@b.co', role: 'ROOT' }).validate()).rejects.toThrow(/role/);
    await expect(new UserModel({ username: 'alice', usernameLower: 'alice', email: 'a@b.co' }).validate()).resolves.toBeUndefined();
    expect(new UserModel({ username: 'alice', usernameLower: 'alice', email: 'a@b.co' }).role).toBe('USER');
  });
  const uniques = (m: { schema: { indexes(): [Record<string, unknown>, Record<string, unknown>][] } }) =>
    m.schema.indexes().filter(([, o]) => o.unique).map(([k]) => Object.keys(k).join('+'));
  it('declares the unique indexes the security model relies on', () => {
    expect(UserModel.schema.path('email').options.unique).toBe(true);
    expect(UserModel.schema.path('usernameLower').options.unique).toBe(true);
    expect(uniques(AuthIdentityModel as never)).toEqual(expect.arrayContaining(['provider+providerUserId', 'userId+provider']));
    expect(SessionModel.schema.path('tokenHash').options.unique).toBe(true);
  });
  it('declares TTL indexes for sessions and audit logs', () => {
    const ttl = (m: { schema: { indexes(): [Record<string, unknown>, Record<string, unknown>][] } }) =>
      m.schema.indexes().filter(([, o]) => o.expireAfterSeconds !== undefined).length;
    expect(ttl(SessionModel as never)).toBe(1);
    expect(ttl(AuditLogModel as never)).toBe(1);
  });
});
