# Contrat d'API — Media Hub (pour le frontend)

Base : `/api/v1` (alias `/api`). Santé : `/health`, `/health/live`, `/health/ready` (sans préfixe).
Tout est JSON. Les requêtes avec corps : `Content-Type: application/json`, 10 ko max.

## Conventions
- **Cookie de session** `mh_sid` (`__Host-mh_sid` en prod) : `HttpOnly`, posé par le serveur ; le frontend n'y touche pas. Appeler avec `credentials: 'include'` si l'origine diffère (en déploiement même origine via Vercel, c'est automatique).
- **CSRF** : après `login`/`verify-otp`/`GET /auth/me`, la réponse contient `csrfToken`. Toute requête **non-GET** d'un utilisateur connecté doit envoyer `X-CSRF-Token: <csrfToken>`, sinon 403. L'en-tête `Origin` doit être une origine autorisée (le navigateur l'envoie seul).
- **Erreurs** : `{ "error": { "code": "…", "message": "…", "details"?: […], "meta"?: { "retryAfter"?: n, "attemptsLeft"?: n } } }`. Un 500 ajoute `requestId` (à donner au support). Codes HTTP : 400 validation/lien invalide · 401 non connecté · 403 interdit/CSRF · 404 introuvable · 409 conflit/limite · 422 aucun média · 429 trop de requêtes · 502/504 fournisseur · 503 service indisponible/non configuré/BD down (avec `Retry-After`).
- **Pagination** : `?page=1&pageSize=20` (max 50, admin 100) → `{ items, total, page, pageSize }`.
- Les champs inconnus dans un corps sont **refusés** (400).

## Authentification
| Méthode | Route | Corps | Accès / réponse |
|---|---|---|---|
| POST | `/auth/register` | `{username,email,password,acceptTerms:true}` | public. Envoie un code à 4 chiffres. Réponse identique si l'e-mail existe. **Aucun compte avant le code.** |
| POST | `/auth/verify-otp` | `{email,code}` | public. Crée le compte + la session → `{user,csrfToken}`. Erreurs `OTP_*` avec `meta.attemptsLeft` |
| POST | `/auth/resend-otp` | `{email}` | public, ≥ 60 s entre deux envois (`meta.retryAfter`) |
| POST | `/auth/login` | `{email,password}` | public → `{user,csrfToken}` ou `{twoFactorRequired:true,challenge}` |
| POST | `/auth/login/2fa` | `{challenge,code}` | public (code TOTP 6 chiffres ou de récupération) |
| GET | `/auth/me` | — | session → `{user,csrfToken}` |
| POST | `/auth/logout` | — | session + CSRF |
| POST | `/auth/forgot-password` · `/auth/reset-password` | `{email}` · `{token,password}` | public, réponse générique |
| POST | `/auth/verify-email` · `/auth/resend-verification` | `{token}` · — | liens e-mail |
| POST | `/auth/2fa/setup` · `/2fa/enable` · `/2fa/disable` | — · `{code}` · `{password,code}` | session + CSRF |
| DELETE | `/auth/account` | `{password}` (ou `{confirmEmail}` si pas de mot de passe) | session + CSRF. Efface historique, favoris, collections, sessions |
| GET | `/auth/google/status` | — | `{configured}` |
| GET | `/auth/google/start` | — | **navigation** (redirige vers Google) |
| GET | `/auth/google/callback` | — | appelé par Google ; redirige vers `FRONTEND_URL/?login=google` (ou `/connexion?error=<code>`, `/compte?linked=google`) |
| POST | `/auth/google/link` | — | session + CSRF → `{url}` à ouvrir |
| DELETE | `/auth/google` | — | session + CSRF ; 409 si ce serait le seul moyen de connexion |

`user` : `{id,username,email,role,emailVerified,avatar,createdAt,lastLoginAt,twoFactorEnabled,hasPassword,preferences}`.
Codes d'erreur de redirection Google : `google_denied, google_invalid_state, google_session_expired, google_failed, google_email_unverified, google_email_conflict` (un compte e-mail existe : se connecter puis lier), `google_in_use, google_link_session, account_suspended`.

## Outils (publics, limités ; la session est facultative)
| Méthode | Route | Notes |
|---|---|---|
| GET | `/tools` | `{items:[{id,label,kind:'download'|'search',enabled,configured,available,reason?}]}` — **à utiliser pour griser un outil non disponible** |
| POST | `/tools/:id/analyze` | `id` ∈ `facebook`,`tiktok`,`instagram`. Corps `{url}`. → `{jobId,platform,title,thumbnail,author,formats:[{label,format,quality}],ads:{required,waitSeconds,slot},readyAt,expiresAt}` — **sans lien**. `slot` = emplacement Adsterra `{provider,key,host,width,height}` ou `null` |
| POST | `/tools/jobs/:jobId/claim` | → `{title,downloads:[{label,format,quality,url}],expiresAt}`. Avant `readyAt` : **409 `AD_NOT_FINISHED`**, `meta.retryAfter`. Job valable 15 min, lié à l'utilisateur s'il était connecté |
| GET/POST | `/tools/music/search` | `?q=&type=song|album|artist&page=&pageSize=` → `{provider,items:[{id,type,title,artist,album,artwork,previewUrl,url,durationMs,releaseDate,genre}],page,pageSize,hasMore}`. **Extraits d'écoute uniquement, pas de téléchargement** |

Erreurs outils : `INVALID_LINK` 400 · `TOOL_DISABLED` 503 · `SERVICE_NOT_CONFIGURED` 503 (si `WHITESHADOW_API_TOKEN` est absent, ou refusé par le service) · `NO_MEDIA` 422 · `PROVIDER_TIMEOUT` 504 · `PROVIDER_BAD_RESPONSE`/`PROVIDER_ERROR` 502 · `BUSY` 503.
`GET /settings/public` → `{tools:{…},ads:{enabled,waitSeconds,homeSlotEnabled,slot}}` (`slot` = `{provider:'adsterra',key,host,width,height}` ou `null` ; `homeSlotEnabled` n'est vrai que si les pubs sont actives).

## Espace personnel `/me/*` (session vérifiée + CSRF pour les non-GET)
`PATCH /me/profile {username?,avatar?}` · `GET|PATCH /me/preferences {language:'fr'|'en',historyEnabled,historyRetentionDays 1–365}` ·
`GET /me/history?kind=SEARCH|OPERATION&tool=` · `DELETE /me/history` → `{deleted}` · `DELETE /me/history/:id` (204) ·
`GET|POST /me/favorites` (POST `{kind:'TRACK'|'ALBUM'|'LINK',externalId?,title,subtitle?,url?,imageUrl?}` → 201 ; doublon 409 ; max 500) · `DELETE /me/favorites/:id` ·
`GET|POST /me/collections {name,description?}` · `GET|PATCH|DELETE /me/collections/:id` · `POST /me/collections/:id/items` (même corps que favori ; max 200) · `DELETE /me/collections/:id/items/:itemId` (max 50 collections) ·
`GET /me/sessions` · `DELETE /me/sessions/:id` · `POST /me/sessions/revoke-others`.
L'historique ne stocke que l'**hôte** du lien analysé (jamais l'URL complète) et expire selon la préférence.

## Autres
- `POST /reports` `{kind:'COPYRIGHT'|'ABUSE'|'ILLEGAL'|'OTHER',targetUrl?,description(10–2000),contactEmail?}` → 201 `{id,status}` (public, 5/h).
- **IA** (connecté) : `GET /ai/capabilities`, `POST /ai/:feature` avec `feature` ∈ `titles,description,hashtags,translate,summarize`, corps `{text(≤8000),language?}` → `{feature,result}` ; quota par utilisateur (`AI_QUOTA` 429). `transcribe` **n'existe pas**.
- **Clés API développeur** : `GET|POST /keys`, `DELETE /keys/:id`, `GET /keys/usage?range=24h|7d|30d` ; `GET /status` avec `X-API-Key`.

## Administration `/admin/*` (rôle ADMIN, + 2FA si `REQUIRE_ADMIN_2FA`, + CSRF)
`GET /stats` · `GET /users?q=&role=&status=` · `PATCH /users/:id {role?,status?}` (jamais soi-même ; dernier admin protégé) · `GET /audit-logs?action=` · `GET /api-stats` ·
`GET /integrations` (état réel : base, e-mail, Google, IA, outils, erreurs 24 h — **jamais de secret**) · `GET /tools` (compteurs réels 24 h/7 j) · `GET /errors?source=http|provider|process` · `GET|PATCH /settings {tools?:{facebook,tiktok,instagram,music},ads?:{enabled,waitSeconds(0-30),homeSlotEnabled,provider:'none'|'adsterra',bannerKey(32 hex),bannerHost(domaine),bannerSize('300x250'|'728x90'|'468x60'|'320x50'|'160x600'|'160x300')}}` — `adsterra` exige clé + domaine, l'emplacement d'accueil exige un réseau (400 sinon` · `GET /reports?status=` · `PATCH /reports/:id {status?,adminNote?}`.
Les compteurs « live » des outils se remettent à zéro au redémarrage/réveil du serveur.

## Santé
`GET /health/live` → 200 `{status:'alive'}` · `GET /health/ready` → 200 `{status:'ready'}` si MongoDB joignable, sinon 503 `{status:'unavailable'}` (ou `shutting_down`) · `GET /health` → `{status:'ok'|'degraded',service,uptimeSeconds,…}` minimal. Pendant une panne de base, toutes les autres routes répondent 503 `SERVICE_UNAVAILABLE` + `Retry-After`.
