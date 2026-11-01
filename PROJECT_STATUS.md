# PROJECT_STATUS — Media Hub (backend)

Mis à jour : 2026-10-22. Langue : français. Admin principal unique : Zephyr.

## Livré (backend complet)
Auth e-mail + OTP 4 chiffres · Google OAuth (code+PKCE+state+nonce, vérification JWKS) · sessions/CSRF/CORS · 2FA TOTP admin · clés API développeur · historique / favoris / collections / sessions / préférences (isolation par utilisateur, rétention) · outils média avec **barrière publicitaire côté serveur** · recherche musicale (iTunes, extraits seulement) · IA côté serveur avec quotas · signalements · administration (stats, utilisateurs, rôles, suspension, audit, intégrations, erreurs, réglages, signalements) · anti-SSRF · santé `/health[/live|/ready]` + script de vérification · arrêt propre · `vercel.json` · docs (`README.md`, `docs/API.md`, `.env.example`).

## Vérifications réellement exécutées
| Vérification | Résultat |
|---|---|
| `tsc --noEmit` (API et web) | OK |
| `npm run api:build`, build web | OK |
| Tests API (vitest, dépôts en mémoire) | **287 réussis**, 0 échec (15 fichiers) |
| Tests web | 19 réussis |
| `npm audit --omit=dev` | 0 vulnérabilité |
| Intégration dépôts Mongoose | **23 réussis, 2 ignorés** — exécutée sur **FerretDB 1.24 (SQLite)**, PAS sur MongoDB |
| `.env.example` chargé par Node + `loadEnv` | OK |

Domaines couverts : santé (dont MongoDB indisponible → 503 + `Retry-After`), sécurité HTTP/CORS/CSRF/injection d'opérateurs, SSRF (IP privées, rebinding, redirections, timeouts, taille, corps bloqué), fournisseurs (Facebook, iTunes, Anthropic : formes de requête/réponse, erreurs, timeouts), barrière pub (409 avant délai, aucun lien dans les réponses), `/me` (isolation, limites, rétention, suppression de compte), Google (vraies signatures RS256 : alg `none`, confusion HS256, issuer, audience, expiration, nonce ; flux complet), signalements/admin (autorisations 401/403, aucun secret dans les sorties), IA (quota, erreurs), OTP, 2FA, clés API.

## Défauts trouvés et corrigés pendant les tests
Lien invalide côté fournisseur renvoyé en 502 au lieu de 400 · identifiant de job « hex mais pas ObjectId » → 500 sur Mongo · dépôts Mongo levant `CastError` sur identifiant invalide · lookups acceptant un objet `{$ne:''}` au niveau dépôt · `removeItem` annonçant un succès sur élément absent · `revokeOthers` comptant des sessions expirées · unicité du pseudo non contrôlée à la modification (dépôt mémoire) · `userId` interne exposé dans les réponses favoris/collections · pagination incomplète.

## Publicités (Adsterra)
Réglages admin : réseau (`none`/`adsterra`), clé de bannière (32 hex), domaine du script, format. Validation stricte (domaine sans chemin ni IP, clé hexadécimale, réseau complet obligatoire). Le serveur impose toujours l'attente ; l'emplacement est joint à la réponse d'analyse (`ads.slot`) et à `/settings/public`. Aucune garantie que la bannière s'affiche : dépend du compte Adsterra (site validé) et du navigateur de l'utilisateur (bloqueurs).

## E-mails
Deux fournisseurs HTTP derrière `EmailProvider` : Brevo (sans domaine) et Resend (domaine vérifié). Choix par `EMAIL_PROVIDER` (`auto` : Brevo si `BREVO_API_KEY`). Testé avec des réponses simulées, jamais contre les vrais services.

## NON vérifié (à ne pas tenir pour acquis)
1. **Aucun test sur un vrai MongoDB / Atlas.** À faire : `MONGO_TEST_URI=<base de test> npm run test:mongo -w apps/api` (sans `MONGO_TEST_FLAVOR`). Trois choses ne sont vérifiées nulle part pour l'instant : atomicité sous concurrence (consommation unique des jetons/OTP, limite d'éléments d'une collection, doublons), `$pull` (`removeItem`) et code `E11000` sur un `update`. FerretDB ne les supporte pas : ces tests sont **ignorés** (skipped), pas réussis. La **purge TTL** n'est vérifiée nulle part (seule la déclaration des index l'est).
2. **Aucun appel réel** à siputzx (Facebook), iTunes, Google, Resend, Anthropic : le bac à sable n'a pas accès à ces hôtes. Les adaptateurs sont testés avec des réponses simulées reprenant le format documenté/fourni. **Aucune garantie que ces services répondent aujourd'hui comme prévu.**
3. **Facebook : branché sur WhiteShadow aussi (`/api/download/fb`) quand le jeton est présent, mais seul le format d'ERREUR a été observé ; l'analyse du succès est tolérante et NON vérifiée.**
3b. **TikTok et Instagram : branchés sur l'API WhiteShadow** (`WHITESHADOW_API_TOKEN` dans Render). Testés avec des réponses simulées ; **aucun appel réel depuis l'application déployée n'a été vérifié**. Sans jeton : 503 `SERVICE_NOT_CONFIGURED`. La version TikTok avec filigrane n'est jamais proposée.
4. Résultat 2FA admin via Google (redirection avec `challenge`) : code écrit, **non testé**.
5. Déploiement réel Render/Vercel/Atlas, réécriture Vercel et cookies en production : non testés.
6. Pas d'OpenAPI/Swagger (le contrat est dans `docs/API.md`), pas d'e2e navigateur ni de CI.
7. Pas de traitement/upload de fichiers (non défini dans ce que j'ai reçu).
8. Le brief joint est **tronqué** (il s'arrête à la section 13 dans la dernière version reçue) : si des exigences existent après (tests, livraison, protections), elles n'ont pas pu être prises en compte.

## Reste à faire (hors backend)
Frontend : branchement des endpoints, affichage de la pub pendant `waitSeconds`, emplacement pub d'accueil, pages légales, PWA, choix du réseau publicitaire. Informations à fournir : domaine d'envoi Resend, identifiants Google, informations légales.
