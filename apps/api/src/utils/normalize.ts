/** Single place where emails are normalised: trimmed, NFKC, lowercase. */
export const normalizeEmail = (email: string): string => email.normalize('NFKC').trim().toLowerCase();
export const normalizeUsername = (u: string): string => u.normalize('NFKC').trim().toLowerCase();
