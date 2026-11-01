import argon2 from 'argon2';

export interface PasswordHasher {
  hash(password: string): Promise<string>;
  verify(hash: string, password: string): Promise<boolean>;
}

/** Argon2id with the OWASP minimum profile (19 MiB, t=2, p=1): safe on small Render instances. */
export const argon2idHasher: PasswordHasher = {
  hash: (password) => argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 }),
  async verify(hash, password) {
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  },
};
