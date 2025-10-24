# E2E Test Plan — Mini IAM Lab (Azure-First)

**But**
Valider de bout en bout l’authentification OIDC+PKCE+MFA, le RBAC UI, la SCIM API, la révocation immédiate (leaver), la rotation de secrets prod-like, et les garde-fous Nginx/TLS, sans fuite de secrets.

---

## 0) Métadonnées

* **Portée** : Nginx (TLS/headers) · Flask (UI/SCIM) · Keycloak · Azure Key Vault (prod-like)
* **Périmètres exclus** : perf lourde, HA multi-nœuds, DRP
* **Environnements** :

  * `local-demo` (DEMO_MODE=true, KV désactivé)
  * `prod-like` (DEMO_MODE=false, Key Vault activé)
* **Personas de test** :

| User  | Rôles                     | Attendu UI                 |
| ----- | ------------------------- | -------------------------- |
| alice | analyst                   | Vue snapshot uniquement    |
| carol | manager                   | Vue snapshot uniquement    |
| joe   | iam-operator, realm-admin | Formulaires JML + snapshot |
| admin | master admin              | Accès total                |

---

## 1) Pré-requis & Données

* Stack démarrée et saine (UI, SCIM, Keycloak, Nginx, health OK)
* Comptes démo actifs (alice, carol, joe, admin)
* Compte service `automation-cli` (SCIM)
* Certificat TLS self-signed accepté localement
* **Artefacts à collecter** : captures écran clés, HAR réseau, extraits logs d’audit avant/après leaver, en-têtes HTTP, (prod-like) extrait Activity Log Key Vault

---

## 2) Campagne “Smoke” (golden path)

* [ ] **Smoke-01** — Page d’accueil → redirection login → login **alice**

  * Étapes : ouvrir `/`, login, accéder `/admin`
  * Attendu :

    * [ ] `/admin` = 200 (vue restreinte)
    * [ ] Cookies `Secure`, `HttpOnly`, `SameSite=Lax`
    * [ ] Aucune erreur HTTP 4xx/5xx non attendue

---

## 3) OIDC + PKCE + MFA (navigateur)

* [ ] **OIDC-01** — Premier login **alice** avec MFA (TOTP)

  * Étapes : login → config TOTP → valider 2FA
  * Attendu :

    * [ ] Flux PKCE réussi (pas d’`invalid_grant`)
    * [ ] Session unique (pas de double `Set-Cookie`)
* [ ] **OIDC-02** — Relogin **alice** (MFA déjà configuré)

  * Attendu :

    * [ ] Pas de required action TOTP
    * [ ] Accès direct à `/admin`
* [ ] **OIDC-03** — Erreurs JWT visibles côté app

  * Étapes : tenter accès avec token expiré / audience invalide
  * Attendu :

    * [ ] 401/403 propres (pas de stacktrace en réponse)

---

## 4) RBAC UI (personas)

* [ ] **RBAC-01** — **alice** (analyst)

  * Attendu :

    * [ ] Onglets/boutons JML **absents**
* [ ] **RBAC-02** — **carol** (manager)

  * Attendu :

    * [ ] JML **absent**, snapshot visible
* [ ] **RBAC-03** — **joe** (iam-operator + realm-admin)

  * Attendu :

    * [ ] JML **présent et fonctionnel** (pas de 403)

---

## 5) SCIM 2.0 — CRUD + pagination + erreurs RFC

* [ ] **SCIM-01** — Create user (POST `/Users`)

  * Attendu :

    * [ ] 201 + `id`, schéma conforme
* [ ] **SCIM-02** — Read (GET `/Users/{id}`) & Filter (GET `/Users?filter=...`)

  * Attendu :

    * [ ] 200, résultat correct · pagination `startIndex/count` respectée
* [ ] **SCIM-03** — Update idempotent (PUT `/Users/{id}`)

  * Attendu :

    * [ ] 200/204, pas de duplication/effet de bord
* [ ] **SCIM-04** — Soft delete (DELETE `/Users/{id}`)

  * Attendu :

    * [ ] Désactivation enregistrée (sans suppression irréversible)
* [ ] **SCIM-05** — Erreurs RFC

  * Étapes : envoyer attribut interdit (`password`) / schéma invalide
  * Attendu :

    * [ ] `schemas` d’erreur + `status` + `detail` + `scimType` conformes

---

## 6) “Leaver” — révocation immédiate

* [ ] **LEAVER-01** — `active=false` coupe toutes les sessions

  * Étapes :

    1. Connecter **user A**, noter cookie/session
    2. SCIM PUT `/Users/{id}` → `active=false`
    3. Rejouer `/admin` avec l’ancien cookie/token
    4. Vérifier sessions via Admin API
  * Attendu :

    * [ ] `/admin` = 401/403 **immédiat**
    * [ ] Admin API : **0 session** pour user A
    * [ ] Événements d’audit correctement enregistrés

---

## 7) Rotation orchestrée (prod-like)

> À exécuter en environnement `prod-like` (Key Vault actif)

* [ ] **ROT-01** — Rotation secret service (Keycloak → KV → restart)

  * Étapes :

    1. Déclencher rotation orchestrée
    2. Tester l’**ancien** secret : échec auth
    3. Tester le **nouveau** secret : succès
    4. Vérifier `/health` après restart
  * Attendu :

    * [ ] Ancien secret **KO**, nouveau **OK**
    * [ ] Health `/health` = 200
    * [ ] **Aucun secret** en stdout/stderr CI
* [ ] **ROT-02** — Idempotence (rotation 2x)

  * Attendu :

    * [ ] Valeurs différentes à chaque rotation
    * [ ] Pas de dérive de config (stack saine)

---

## 8) Nginx / HTTPS / Headers

* [ ] **NGX-01** — HTTP → HTTPS

  * Attendu :

    * [ ] `http://…` renvoie 301 vers `https://…`
* [ ] **NGX-02** — Headers sécurité

  * Attendu (sur `/` et `/health`) :

    * [ ] `Strict-Transport-Security: max-age ≥ 31536000; includeSubDomains`
    * [ ] `Content-Security-Policy: default-src 'self' …`
    * [ ] `X-Frame-Options: DENY`
    * [ ] `X-Content-Type-Options: nosniff`
    * [ ] `Referrer-Policy: strict-origin-when-cross-origin`
* [ ] **NGX-03** — TLS min

  * Attendu :

    * [ ] TLS 1.0/1.1 refusés ; 1.2/1.3 OK

---

## 9) Confidentialité des secrets (boîte noire)

* [ ] **SECRETS-01** — Aucune fuite côté client

  * Étapes : appeler `/`, `/admin`, `/scim/v2/ServiceProviderConfig`, `/health`
  * Attendu :

    * [ ] Corps + en-têtes **sans** noms/valeurs de secrets
    * [ ] Pas de `Server` / `X-Powered-By` verbeux
* [ ] **SECRETS-02** — Aucune fuite côté logs

  * Attendu :

    * [ ] stdout/stderr sans secret ni token sensibles
    * [ ] Logs d’audit ne contiennent pas de secret (HMAC uniquement)

---

## 10) Mode DOGFOOD (UI → SCIM HTTP)

* [ ] **DOGFOOD-01** — UI consomme SCIM en HTTP interne

  * Étapes : activer `DOGFOOD_SCIM`, créer user via formulaire Joiner
  * Attendu :

    * [ ] Appel SCIM 201 vu en logs
    * [ ] Résultat identique à un POST SCIM direct
    * [ ] Surcharge de latence raisonnable (surcoût constant et faible)

---

## 11) Prod-like Azure (si activé)

* [ ] **AZ-KV-01** — Utilisation réelle de Key Vault

  * Attendu :

    * [ ] Secrets chargés depuis KV (pas depuis `.env`)
    * [ ] **Activity Log** : événements `SecretGet/SecretNewVersionCreated`
* [ ] **AZ-MI-01** — Managed Identity (quand implémenté)

  * Attendu :

    * [ ] `DefaultAzureCredential` choisit MI, accès KV OK, aucun secret d’auth

---

## 12) Résilience & redémarrage doux

* [ ] **RES-01** — Redémarrage Flask pendant session

  * Attendu :

    * [ ] Reprise de session si cookie valide
    * [ ] `/health` 200, pas d’exceptions au restart

---

## 13) Négatifs maîtrisés (erreurs propres)

* [ ] **NEG-01** — Token expiré / aud invalide / alg none

  * Attendu :

    * [ ] 401/403 propres, aucun 500
* [ ] **NEG-02** — SCIM sans Bearer / scope insuffisant

  * Attendu :

    * [ ] 401/403 RFC-compliant, texte d’erreur non verbeux

---

## 14) Acceptation & Sortie

**Gates obligatoires (pass/fail)**

* [ ] OIDC : PKCE + MFA OK, erreurs JWT propres
* [ ] RBAC : visibilité UI conforme aux rôles
* [ ] SCIM : CRUD + erreurs RFC + **leaver immédiat**
* [ ] Secrets : **zéro fuite** (client & logs)
* [ ] Nginx : HTTP→HTTPS, HSTS/CSP/XFO/XCTO/Referrer-Policy présents
* [ ] Rotation : ancien secret KO / nouveau OK / `/health`=200
* [ ] (Prod-like) KV utilisé réellement, Activity Log présent

**Temps cible** : < 10 minutes en local · < 15 minutes en CI
**Flakiness** : 0 test instable autorisé

---

## 15) Rapports & Artefacts

* [x] Captures d’écran (login, TOTP, JML, headers)
* [ ] HAR réseau (flux PKCE + MFA)
* [ ] Extraits logs d’audit (avant/après leaver) + vérification HMAC
* [ ] Dump en-têtes HTTP `/` & `/health`
* [ ] (Prod-like) Export Activity Log KV (filtré sur secrets)

---

## 16) Suivi des écarts

* [ ] Tous les écarts ouverts documentés avec : ID, sévérité, owner, ETA
* [ ] Re-test ciblé après correctifs
* [ ] Mise à jour du tableau de **couverture sécurité** dans le README

---

> ✅ Ce plan sert de checklist E2E officielle. Marquez chaque cas “pass/fail” lors de la campagne et attachez les artefacts au rapport de test.
