import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadEnv } from '../src/config/env.js';
import { BrevoEmailProvider, DisabledEmailProvider, ResendEmailProvider, createEmailProvider, parseSender } from '../src/services/email.js';

const base = { NODE_ENV: 'test', MONGODB_URI: 'mongodb://unused', SESSION_SECRET: 'x'.repeat(40), FRONTEND_URL: 'https://app.example.com' };
const env = (o: Record<string, string> = {}) => loadEnv({ ...base, ...o });
const MAIL = { to: 'alice@example.com', subject: 'Code', text: 'Votre code : 1234', html: '<p>1234</p>' };
afterEach(() => vi.unstubAllGlobals());

describe('parseSender', () => {
  it('lit « Nom <adresse> », une adresse seule et refuse le reste', () => {
    expect(parseSender('Media Hub <No-Reply@Exemple.com>')).toEqual({ name: 'Media Hub', email: 'no-reply@exemple.com' });
    expect(parseSender('"Media Hub" <a@b.co>')).toEqual({ name: 'Media Hub', email: 'a@b.co' });
    expect(parseSender('moi@gmail.com')).toEqual({ email: 'moi@gmail.com' });
    for (const bad of ['', 'sans arobase', 'Nom <pas-une-adresse>', '<a@b.co> extra']) expect(parseSender(bad), bad).toBeNull();
  });
});

describe('choix du fournisseur', () => {
  it('Brevo dès que BREVO_API_KEY est présente (mode auto)', () => {
    expect(createEmailProvider(env({ BREVO_API_KEY: 'k', EMAIL_FROM: 'Media Hub <moi@gmail.com>' }))).toBeInstanceOf(BrevoEmailProvider);
  });
  it('Resend quand seule sa clé est présente', () => {
    expect(createEmailProvider(env({ RESEND_API_KEY: 'k', EMAIL_FROM: 'Media Hub <no-reply@x.com>' }))).toBeInstanceOf(ResendEmailProvider);
  });
  it('désactivé (et honnête) si une valeur manque ou si l’expéditeur est invalide', () => {
    expect(createEmailProvider(env())).toBeInstanceOf(DisabledEmailProvider);
    expect(createEmailProvider(env({ BREVO_API_KEY: 'k' }))).toBeInstanceOf(DisabledEmailProvider);
    expect(createEmailProvider(env({ BREVO_API_KEY: 'k', EMAIL_FROM: 'pas une adresse' }))).toBeInstanceOf(DisabledEmailProvider);
    expect(createEmailProvider(env({ EMAIL_PROVIDER: 'brevo', RESEND_API_KEY: 'k', EMAIL_FROM: 'a@b.co' }))).toBeInstanceOf(DisabledEmailProvider);
  });
});

describe('Brevo', () => {
  it('envoie la bonne requête HTTP (clé en en-tête, expéditeur, destinataire, texte et HTML)', async () => {
    const f = vi.fn(async () => new Response('{"messageId":"x"}', { status: 201 })); vi.stubGlobal('fetch', f);
    await new BrevoEmailProvider('secret-key', { name: 'Media Hub', email: 'moi@gmail.com' }).send(MAIL);
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://api.brevo.com/v3/smtp/email');
    expect((init.headers as Record<string, string>)['api-key']).toBe('secret-key');
    expect(JSON.parse(String(init.body))).toEqual({ sender: { name: 'Media Hub', email: 'moi@gmail.com' }, to: [{ email: 'alice@example.com' }], subject: 'Code', textContent: 'Votre code : 1234', htmlContent: '<p>1234</p>' });
    expect(String(init.body)).not.toContain('secret-key');
  });
  it('lève une erreur sans fuite de la clé quand Brevo refuse', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"message":"Sender not valid"}', { status: 400 })));
    const p = new BrevoEmailProvider('secret-key', { email: 'moi@gmail.com' });
    await expect(p.send(MAIL)).rejects.toThrow('Email provider responded with HTTP 400');
    await expect(p.send(MAIL)).rejects.not.toThrow(/secret-key/);
  });
});
