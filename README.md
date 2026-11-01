# Media Hub

Monorepo : `apps/api` (Express 5 + TypeScript + MongoDB/Mongoose) et `apps/web` (React + Vite + Tailwind).
**Cette livraison = le backend complet.** Le frontend est à brancher séparément (contrat : `docs/API.md`).
État exact (ce qui est testé / non testé) : `PROJECT_STATUS.md`.

## Prérequis
Node.js ≥ 20 (testé sur 22), npm ≥ 10, un cluster MongoDB Atlas.

## Commandes
```bash
npm install
cp .env.example apps/api/.env          # puis remplir (jamais commité)
npm run api:typecheck                  # TypeScript strict
npm run api:test                       # suite vitest (dépôts en mémoire, sans base)
npm run api:build                      # -> apps/api/dist
npm run api:dev                        # dev (MONGODB_URI valide requis) : node --env-file=apps/api/.env …
npm run healthcheck -w apps/api -- https://votre-api.onrender.com /health/live
# Tests d'intégration des dépôts Mongo (nécessitent une base de test, base temporaire supprimée à la fin) :
MONGO_TEST_URI=mongodb://127.0.0.1:27017 npm run test:mongo -w apps/api
```

## Architecture (apps/api/src)
`config/` (env validé par Zod) · `routes/` (HTTP fin) · `services/` (règles métier) · `repositories/` (interfaces + `mongo.ts` + `memory.ts` pour les tests) · `models/` (Mongoose, index uniques/TTL) · `providers/` (Facebook, TikTok/Instagram via WhiteShadow (jeton `WHITESHADOW_API_TOKEN`), musique iTunes) · `net/` (anti-SSRF, `safeFetch`) · `middleware/` (sécurité, CSRF, limites de débit, erreurs, journaux) · `schemas/` (Zod).
Ajouter un fournisseur : implémenter `MediaProvider` (`providers/types.ts`) et l'ajouter à la liste dans `app.ts` ; aucune autre couche ne change.

## API
Préfixe canonique **`/api/v1`** (l'alias `/api` reste actif). Tableau complet des routes, permissions, formats et codes d'erreur : **`docs/API.md`**.
Santé (à la racine, pas de préfixe) : `GET /health`, `/health/live`, `/health/ready`.

## Sécurité (implémentée et testée)
- Mots de passe **Argon2id**. Sessions opaques 256 bits **hachées** (HMAC) en base, 14 jours, révocables ; cookie `HttpOnly`, `SameSite=Lax`, `Secure` + `__Host-` en production.
- **CSRF** : jeton lié à la session (`X-CSRF-Token`) + contrôle strict de `Origin` ; **CORS** sur liste d'origines exactes.
- E-mail : code **OTP à 4 chiffres** haché, 10 min, 5 essais, renvoi après 60 s, limites par IP et par adresse ; le compte n'existe qu'**après** code valide.
- **Google OAuth** : code + PKCE + `state` + `nonce`, jeton vérifié côté serveur (signature RS256 via JWKS, émetteur, audience, expiration, nonce, e-mail vérifié). **Aucune liaison automatique par e-mail** : on lie depuis un compte connecté (POST + CSRF).
- **2FA TOTP** pour les admins (optionnelle, exigible via `REQUIRE_ADMIN_2FA`).
- **Anti-SSRF** : https seul, port 443, pas d'IP littérale ni d'adresse privée/loopback/link-local/métadonnées cloud, vérification au moment de la connexion (anti DNS-rebinding), redirections revalidées une à une, délai, taille et type de contenu bornés, listes d'hôtes exactes.
- Helmet, limites de débit, validation Zod stricte (champs inconnus refusés), rejet des clés `$…`/`__proto__` (injection NoSQL), erreurs centralisées sans fuite (identifiant de requête renvoyé), journaux Pino masquant secrets/cookies, journal d'audit.
- Isolation stricte des données entre utilisateurs (historique, favoris, collections, sessions).

## Publicité avant téléchargement (barrière côté serveur)
`POST /tools/:id/analyze` renvoie le titre et les formats **sans lien**, plus `jobId`, `ads.required`, `ads.waitSeconds`, `readyAt`.
Le frontend affiche la publicité pendant `waitSeconds`, puis appelle `POST /tools/jobs/:jobId/claim` : avant la fin du délai la réponse est **409 `AD_NOT_FINISHED`** (avec `meta.retryAfter`) et ne contient aucun lien. Contourner l'interface ne sert donc à rien. Désactivée par défaut ; l'admin règle `ads.enabled`, `ads.waitSeconds` (0–30), `ads.homeSlotEnabled` via `PATCH /admin/settings`. **Le choix du réseau publicitaire et l'affichage de la pub restent à faire côté frontend.**

## Premier administrateur
Aucun compte admin par défaut. S'inscrire normalement (code OTP), puis sur une machine qui possède `MONGODB_URI` :
```bash
MONGODB_URI=... npm run admin:promote -w apps/api -- vous@exemple.com
```
Le compte doit être actif et vérifié. Activer ensuite la 2FA (`/auth/2fa/setup`) puis mettre `REQUIRE_ADMIN_2FA=true`.

## Déploiement
### MongoDB Atlas
1. Créer un cluster, puis un **utilisateur de base dédié** : rôle `readWrite` sur la seule base `media-hub`.
2. Network Access : autoriser les IP sortantes de Render (page « Outbound IPs ») plutôt que `0.0.0.0/0` si possible.
3. Mettre la chaîne dans `MONGODB_URI` (Render uniquement). Les index (uniques, TTL) sont synchronisés au démarrage.

### Render (backend)
Web Service — Build : `npm install && npm run api:build` (Render fixe `NODE_ENV=production`, qui fait **sauter les `devDependencies`** : c'est pourquoi `typescript` et les `@types/*` nécessaires à la compilation sont dans `dependencies` de `apps/api/package.json`) — Start : `node apps/api/dist/server.js` — Health Check Path : `/health/live`.
Variables : voir `.env.example` (obligatoires : `MONGODB_URI`, `SESSION_SECRET`, `FRONTEND_URL` ; `NODE_ENV=production`, `TRUST_PROXY=1`). Les limites de débit sont en mémoire : **une seule instance**. L'arrêt (SIGTERM) est propre : `/health/ready` passe en 503 puis le serveur se ferme.

### Vercel (frontend) — même origine
`apps/web/vercel.json` réécrit `/api/*` vers Render (remplacer l'URL). Le navigateur ne voit qu'un site : cookie premier-partie `SameSite=Lax` (un cookie `SameSite=None` entre `*.vercel.app` et `*.onrender.com` serait bloqué par Safari/mobile). `FRONTEND_URL` = origine publique du frontend. Non testé en déploiement réel.

### Resend
**Sans domaine (recommandé si le DNS n'est pas à vous)** : compte Brevo, `Senders` → ajouter et vérifier une adresse (lien reçu par e-mail), créer une clé API v3, puis `BREVO_API_KEY` et `EMAIL_FROM="Media Hub <adresse vérifiée>"`. L'API HTTP fonctionne sur Render gratuit (SMTP y est bloqué).
**Avec Resend** : créer un compte, **vérifier le domaine d'envoi** (DNS SPF/DKIM), créer une clé API, renseigner `RESEND_API_KEY` et `EMAIL_FROM` (adresse sur ce domaine). Sans cela, aucun code OTP n'est envoyé. Le fournisseur est derrière une interface (`services/email.ts`) et peut être remplacé.

### Google Cloud Console
APIs & Services → Identifiants → ID client OAuth « Application Web ». **Origines JavaScript autorisées** : l'origine du frontend. **URI de redirection autorisées** : exactement `https://VOTRE-FRONT/api/v1/auth/google/callback` (identique à `GOOGLE_CALLBACK_URL`, au caractère près). Écran de consentement : portées `openid email profile`.

## Surveillance et « ping »
- `GET /health/live` : le processus répond (sans toucher à MongoDB). `GET /health/ready` : prêt **et** MongoDB joignable, sinon 503 ; réponses minimales, sans détail interne.
- Monitoring externe (UptimeRobot ou équivalent) : *Add New Monitor* → type HTTP(s) → URL `https://VOTRE-API.onrender.com/health/live` → intervalle au choix → alertes e-mail. Vérification manuelle : `npm run healthcheck -w apps/api -- <url>` (une requête, code de sortie 0/1).
- **Pas de ping automatique interne** (boucle d'auto-appel) : volontairement non implémenté. Sur l'offre gratuite de Render, le service **s'endort après ~15 min d'inactivité** et le premier appel est lent (réveil) ; un moniteur sert à être **alerté**, pas à empêcher cet endormissement. Pour un service toujours actif : offre payante.

## Fichiers et traitement de médias
Aucun upload ni traitement de fichier (conversion, compression, découpage) n'est implémenté : ce n'est pas défini assez précisément dans ce qui m'a été fourni, et Render gratuit n'a ni disque persistant ni CPU adaptés. Si ajoutés plus tard : worker séparé + stockage objet (S3/R2), URLs signées, limites strictes.
