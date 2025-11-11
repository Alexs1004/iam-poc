# TODO — Backlog **Complet v3** (Azure & Multi‑IdP)

> Mode d’emploi rapide
> 
> - 1 tâche = **1 branche** = **1 PR**.
> - Utilise **Claude 4.5 Sonnet** pour produire un **patch unified diff + message de commit** (*diff‑only*).
> - Utilise **GitHub Copilot Chat** pour les micro-ajustements dans un fichier.
> - Chaque tâche inclut un **Prompt (Claude)** prêt à coller, et des **Critères de validation** mesurables.
> 
> **Contraintes à ajouter à la fin de CHAQUE prompt Claude**
> 
> ```
> Sortie attendue : UN SEUL patch unified diff (peut créer/modifier des fichiers) + un court message de commit. Aucune explication.
> Ne modifier que les fichiers listés/nécessaires.
> Aucun secret/token en clair.
> Inclure les tests quand mentionnés.
> 
> ```
> 

---

## 🔵 Phase Z — Azure‑first & Multi‑IdP (priorité démo Vaud)

> But : prouver l’intégration Microsoft Entra sans casser Keycloak, et pouvoir choisir l’IdP via variable d’environnement (override démo par query param).
> 

### Z1 — Entra ➜ SCIM provisioning (Enterprise App) + token statique optionnel

**Branche** : `entra/scim-provisioning`

**Prompt (Claude)**

```
Objectif: Créer la doc pas-à-pas Entra SCIM et ajouter (option) un token SCIM statique côté API.
Travaux:
- docs/ENTRA_SCIM_HOWTO.md : Enterprise App non‑galerie → Provisioning (Automatic) → SCIM endpoint & secret token; mappings: userPrincipalName→userName, objectId→externalId, mail→emails[work].value; "Provision now"; captures placeholders (docs/images/entra_provisioning_*.png).
- app/scim_api.py : middleware d'auth optionnel acceptant un Bearer statique si env SCIM_STATIC_TOKEN est défini (sinon comportement actuel OAuth2 inchangé).
- .env.example : SCIM_STATIC_TOKEN=demo-scim-token
- tests/test_scim_token.py : 401 si mauvais/absent ; 200 si bon token.
Critères: Provision now crée/disable un user (visible côté app) ; tests scim_token OK.
Sortie attendue : patch diff + message de commit.

```

**Validation**

- Entra **Provision now** ➜ user créé/disable ; logs d’audit présents.
- `pytest -k scim_token -q` ✅.

---

### Z2 — Conditional Access (MFA) : garde‑fou applicatif optionnel

**Branche** : `entra/conditional-access-mfa`

**Prompt (Claude)**

```
Objectif: Documenter une stratégie MFA ciblée (groupe demo-admins) côté Entra et ajouter un garde-fou /admin : si REQUIRE_MFA=true, vérifier 'amr' contient 'mfa' dans l'ID token, sinon 403. Fallback permissif si 'amr' absent.
Fichiers: app/flask_app.py (decorator/guard /admin), docs/SECOPS.md (section Conditional Access), tests/test_mfa_guard.py (tokens factices).
Critères: tests passent; doc avec captures placeholders.
Sortie: patch diff + message.

```

**Validation**

- `pytest -k mfa_guard -q` ✅.
- README ➜ lien vers docs/SECOPS.md.

---

### Z3 — **Multi‑IdP toggle** par env + override démo `?provider=`

**Branche** : `auth/multi-idp-toggle`

**Prompt (Claude)**

```
Objectif: Permettre de choisir l'IdP via OIDC_PROVIDER=keycloak|entra, avec override GET /login?provider=entra|keycloak (stockage en session) pour la démo. Enregistrer les 2 providers avec Authlib; normaliser les claims vers un RBAC interne unique (Keycloak: realm_access.roles/groups; Entra: roles). Ajouter tests: défaut via env, override via query, normalisation des rôles, logout provider-spécifique.
Fichiers: app/flask_app.py (ou app/oidc.py), tests/test_oidc_provider_toggle.py, README.md (section "Choisir l'IdP").
Variables: OIDC_PROVIDER, KC_ISSUER, KC_CLIENT_ID, KC_CLIENT_SECRET?, ENTRA_ISSUER, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET?
Critères: tests OK; README documente env & sécurité (désactiver override en prod).
Sortie: patch diff + message.

```

**Validation**

- `pytest -k oidc_provider_toggle -q` ✅.
- `/login?provider=entra` bascule sur Entra; Keycloak continue de marcher.

---

### Z4 — Entra **App Registration + App Roles** (OIDC Entra en parallèle)

**Branche** : `entra/app-registration-roles`

**Prompt (Claude)**

```
Objectif: Documenter la création de l'App Registration (ID tokens, App Roles 'admin','viewer') et mapper 'roles' (Entra) vers le RBAC applicatif (/admin). Adapter normalize_claims si nécessaire. Tester accès /admin: admin=200, viewer=403.
Fichiers: docs/ENTRA_OIDC_APPREG.md, app/flask_app.py (normalize_claims), tests/test_roles_entra.py.
Critères: test roles_entra OK; doc claire avec captures placeholders.
Sortie: patch diff + message.

```

**Validation**

- `pytest -k roles_entra -q` ✅.
- Démo : `/admin` accessible avec rôle `admin`.

---

### Z5 — Mise à jour README (démo Azure/Keycloak + sécurité)

**Branche** : `docs/readme-multi-idp`

**Prompt (Claude)**

```
Objectif: Ajouter en haut du README une section "Démo Multi-IdP" (comment basculer d'un IdP à l'autre), avertissement: override ?provider seulement en demo. Lier ENTRA_SCIM_HOWTO.md et ENTRA_OIDC_APPREG.md.
Fichiers: README.md
Critères: section visible, liens corrects.
Sortie: patch diff + message.

```

**Validation**

- README à jour et lisible pour recruteur.

---

## 🟩 Phase A — Socle sécurité & exécution (compléments)

### A1 — Désactiver TLS 1.0/1.1 explicitement & durcissement Nginx

**Branche** : `nginx/tls-hardening`

**Prompt (Claude)**

```
Objectif: Forcer ssl_protocols TLSv1.2 TLSv1.3 et ajouter ssl_prefer_server_ciphers on; conserver HSTS/CSP/nosniff/XFO existants. Ajouter rate limit 10r/s burst 20 si manquant.
Fichiers: nginx/conf.d/security.conf (ou nginx.conf).
Critères: curl -kI https://localhost/health => headers + protocole >= TLSv1.2 (openssl s_client).
Sortie: diff + message.

```

**Validation**

- `openssl s_client -tls1_1 -connect localhost:443` doit **échouer**.

### A2 — Tests d’en‑têtes sécurité

**Branche** : `test/headers`

**Prompt (Claude)**

```
Objectif: Créer tests/test_headers.py qui vérifie HSTS, CSP, X-Frame-Options, X-Content-Type-Options sur /health (https, self-signed accepté).
Fichiers: tests/test_headers.py.
Critères: make pytest passe; supprimer un header doit faire échouer le test.
Sortie: diff + message.

```

**Validation**

- `make pytest` ✅.

---

## 🟧 Phase B — CI/CD & supply chain

### B1 — Pipeline CI de base

**Branche** : `ci/base`

**Prompt (Claude)**

```
Objectif: Créer .github/workflows/ci.yml (checkout, Python 3.12, pip install -r requirements.txt, pytest, upload artefact de rapport).
Fichiers: .github/workflows/ci.yml.
Critères: workflow "ci" tourne sur push/PR; artefact visible.
Sortie: diff + message.

```

**Validation**

- Action verte; artefact listé.

### B2 — Scanners: gitleaks, Syft (SBOM), Trivy (FS & image)

**Branche** : `ci/scans`

**Prompt (Claude)**

```
Objectif: Étendre ci.yml: installer gitleaks/syft/trivy; exécuter gitleaks detect --redact; syft -> sbom.spdx.json (artefact); trivy fs (HIGH/CRIT exit 1); docker build mini-iam:ci + trivy image (HIGH/CRIT exit 1).
Fichiers: .github/workflows/ci.yml.
Critères: CI échoue si vulnérabilité HIGH/CRIT ou secret; SBOM artefact présent.
Sortie: diff + message.

```

**Validation**

- SBOM présent; échec attendu si CVE injectée.

### B3 — Docker **non‑root**

**Branche** : `feat/docker-nonroot`

**Prompt (Claude)**

```
Objectif: Modifier Dockerfile pour USER 65532:65532, exposer 8000, CMD gunicorn; ne rien casser côté compose.
Fichiers: Dockerfile.
Critères: stack démarre; uid/gid != 0 dans le conteneur.
Sortie: diff + message.

```

**Validation**

- `docker exec` → `id` ≠ root.

### B4 — CI: login Azure (OIDC) + Terraform validate

**Branche** : `ci/oidc-azure-terraform`

**Prompt (Claude)**

```
Objectif: Ajouter azure/login@v2 (secrets AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID) puis terraform fmt/init/validate dans infra/ (sans échouer si le dossier est absent).
Fichiers: .github/workflows/ci.yml.
Critères: logs Azure login OK; terraform validate OK.
Sortie: diff + message.

```

**Validation**

- Logs OIDC OK ; validate passe.

### B5 — Publier l’image sur GHCR (optionnel ++)

**Branche** : `ci/ghcr-publish`

**Prompt (Claude)**

```
Objectif: Étendre ci.yml pour builder et pousser l'image sur GHCR: ghcr.io/<org>/mini-iam:<git-sha> en utilisant GITHUB_TOKEN.
Fichiers: .github/workflows/ci.yml.
Critères: image poussée; tag récupérable.
Sortie: diff + message.

```

**Validation**

- Image visible sur GHCR.

### B6 — Badge CI dans README

**Branche** : `docs/ci-badge`

**Prompt (Claude)**

```
Objectif: Ajouter un badge du workflow 'ci' en haut du README.
Fichiers: README.md.
Critères: badge visible et pointe vers le bon workflow.
Sortie: diff + message.

```

**Validation**

- Badge présent.

---

## 🟦 Phase C — Infra Azure minimale (Terraform)

### C1 — Providers & variables (squelette)

**Branche** : `infra/skeleton`

**Prompt (Claude)**

```
Objectif: Créer infra/providers.tf (azurerm ~>3), variables.tf (prefix, location, rg_name, tenant_id, subnet_id), outputs.tf (placeholders), main.tf (placeholder).
Critères: terraform -chdir=infra init/validate OK.
Sortie: diff + message.

```

**Validation**

- Init/validate ✅.

### C2 — Resource Group + Log Analytics

**Branche** : `infra/log-analytics`

**Prompt (Claude)**

```
Objectif: Ajouter infra/log_analytics.tf : RG + LAW (rétention 30j), output law_id.
Critères: terraform plan montre RG + LAW.
Sortie: diff + message.

```

**Validation**

- Plan OK.

### C3 — VNet + Subnet pour Private Endpoint

**Branche** : `infra/network-pe`

**Prompt (Claude)**

```
Objectif: Créer VNet et subnet dédiés aux Private Endpoints (adresse RFC1918), outputs nécessaires.
Fichiers: infra/network.tf.
Critères: plan montre VNet + subnet.
Sortie: diff + message.

```

**Validation**

- Plan OK.

### C4 — Key Vault **privé** (PE) + sécurité

**Branche** : `infra/keyvault-pe`

**Prompt (Claude)**

```
Objectif: Créer Key Vault avec public_network_access=false, soft delete + purge protection, Private Endpoint sur le subnet créé; Private DNS si besoin.
Fichiers: infra/keyvault.tf.
Critères: plan affiche KV privé + PE.
Sortie: diff + message.

```

**Validation**

- Plan OK.

### C5 — App Service Linux + Managed Identity + app settings

**Branche** : `infra/appservice-mi`

**Prompt (Claude)**

```
Objectif: Créer App Service Plan Linux (B1) + Web App (TLS>=1.2, http2, always_on), identité managée (system), app_settings: WEBSITES_PORT=8000, KEY_VAULT_URL, AZURE_USE_KEYVAULT=true, DEMO_MODE=false. Donner Get/List Secrets à l'identité sur KV.
Fichiers: infra/appservice.tf.
Critères: plan montre ASP/WebApp + access policy KV.
Sortie: diff + message.

```

**Validation**

- Plan OK ; settings visibles.

### C6 — Diagnostics ➜ Log Analytics

**Branche** : `infra/diagnostics`

**Prompt (Claude)**

```
Objectif: Configurer azurerm_monitor_diagnostic_setting pour envoyer les logs App Service (HTTPLogs, ConsoleLogs) vers LAW.
Fichiers: infra/diagnostics.tf.
Critères: plan montre la ressource de diagnostic.
Sortie: diff + message.

```

**Validation**

- Plan OK.

### C7 — README_infra

**Branche** : `docs/infra-readme`

**Prompt (Claude)**

```
Objectif: Ajouter infra/README_infra.md avec prérequis (az login), variables, commandes init/plan/apply/destroy, exemples -var.
Critères: doc copiable claire.
Sortie: diff + message.

```

**Validation**

- Doc lisible.

---

## 🟪 Phase D — Observabilité & détection

### D1 — Logs JSON (sans secrets)

**Branche** : `feat/logs-json`

**Prompt (Claude)**

```
Objectif: Standardiser les logs Flask/Gunicorn en JSON (Timestamp, Level, Message, User) et s'assurer qu'aucun token/secret n'est loggé. Adapter la config logger.
Fichiers: app/logging.py (nouveau), app/flask_app.py (import), config gunicorn si besoin.
Critères: docker compose logs => JSON; grep 'token' ne remonte pas de secrets.
Sortie: diff + message.

```

**Validation**

- Logs JSON ; pas de secrets.

### D2 — KQL + doc SecOps

**Branche** : `docs/secops`

**Prompt (Claude)**

```
Objectif: Créer docs/SECOPS.md avec 3 KQL: (1) spike 401, (2) création user hors-heures, (3) rotation de secret; lier sentinel/*.json (placeholders).
Fichiers: docs/SECOPS.md.
Critères: KQL parsables; doc claire.
Sortie: diff + message.

```

**Validation**

- Doc OK.

### D3 — Sentinel rules (placeholders JSON)

**Branche** : `sentinel/rules`

**Prompt (Claude)**

```
Objectif: Ajouter sentinel/rule-401-spike.json et sentinel/rule-offhours-usercreate.json avec displayName, query (KQL), severity, suppressionDuration; référencer depuis docs/SECOPS.md.
Critères: JSON valides (lint JSON).
Sortie: diff + message.

```

**Validation**

- JSON valides.

### D4 — Action Group (doc) & test d’alerte

**Branche** : `docs/alerts`

**Prompt (Claude)**

```
Objectif: Étendre docs/SECOPS.md avec un pas-à-pas pour créer un Action Group (email/Teams/webhook) et un test de déclenchement (simuler spike 401). Ajouter captures placeholders.
Fichiers: docs/SECOPS.md.
Critères: doc claire; alerte testable.
Sortie: diff + message.

```

**Validation**

- Alerte reçue lors d’un test.

---

## 🟥 Phase E — Gouvernance & conformité (Suisse)

### E1 — Azure Policy (deny) baselines

**Branche** : `policy/baseline`

**Prompt (Claude)**

```
Objectif: Ajouter policy/https_only.json, policy/keyvault_private_endpoint.json, policy/allowed_locations.json (+ README d'assignation rapide).
Critères: JSON valides; README explique l’assignation et l’effet attendu.
Sortie: diff + message.

```

**Validation**

- Assignation possible; au moins 1 deny testé.

### E2 — COMPLIANCE_CH.md (LPD/FINMA)

**Branche** : `docs/compliance-ch`

**Prompt (Claude)**

```
Objectif: Créer docs/COMPLIANCE_CH.md (½ page) : tableau Exigence→Contrôle (LPD: transparence/sécurité; FINMA Outsourcing: droit d’audit; résidence; rétention logs; plan d’EXIT) avec liens vers composants du repo.
Critères: document concis, non-jargon, liens internes valides.
Sortie: diff + message.

```

**Validation**

- Doc lisible pour un manager suisse.

---

## 🟨 Phase F — Performance & résilience

### F1 — k6 + cible Make

**Branche** : `perf/k6`

**Prompt (Claude)**

```
Objectif: Créer k6/login.js (GET /health; option /admin léger), vus=25, duration=2m. Ajouter target make perf.
Critères: make perf génère un rapport local.
Sortie: diff + message.

```

**Validation**

- Rapport k6 produit.

### F2 — SLO & KPI dans README

**Branche** : `docs/perf-kpi`

**Prompt (Claude)**

```
Objectif: Créer docs/PERF.md avec SLO: p95 /admin < 300ms, error < 1%. Ajouter une section KPI en haut du README pointant vers PERF.md.
Critères: README affiche KPI; PERF.md présent.
Sortie: diff + message.

```

**Validation**

- KPI visibles ; doc perf présente.

### F3 — Chaos light & runbook Keycloak indispo

**Branche** : `ops/chaos-keycloak`

**Prompt (Claude)**

```
Objectif: Ajouter un runbook docs/RUNBOOK_KEYCLOAK_DOWN.md et un petit script de test qui stoppe le conteneur Keycloak, observe le comportement app et restaure. Documenter métriques d'erreur/retour à la normale.
Critères: doc claire; script fonctionne localement.
Sortie: diff + message.

```

**Validation**

- Runbook testé.

### F4 — Backup/restore (App config & KV)

**Branche** : `ops/backup-restore`

**Prompt (Claude)**

```
Objectif: Documenter (et/ou scripter) backup/restore d’App Service config et Key Vault secrets (sans exposer les valeurs). Ajouter docs/BACKUP_RESTORE.md avec pas-à-pas.
Critères: doc testée.
Sortie: diff + message.

```

**Validation**

- Doc claire.

---

## 🧩 Phase G — Améliorations optionnelles

### G1 — Révoquer automatiquement l’ancien secret après rotation

**Branche** : `sec/rotate-revoke-old`

**Prompt (Claude)**

```
Objectif: Étendre scripts/rotate_secret.sh pour révoquer l'ancien secret une fois la rotation validée (health OK). Ajouter flag --no-revoke pour rétro-compat. Test: l'ancien secret échoue à s'authentifier.
Fichiers: scripts/rotate_secret.sh, tests/test_rotation_revoke.py.
Critères: test passe; logs clairs.
Sortie: diff + message.

```

**Validation**

- `pytest -k rotation_revoke -q` ✅.

### G2 — Webhooks d’audit avec queue & retry

**Branche** : `audit/webhooks-queue`

**Prompt (Claude)**

```
Objectif: Implémenter un sink d'audit en file d'attente (in-memory + JSONL durable) avec retry exponentiel vers AUDIT_WEBHOOK_URL, auth par bearer AUDIT_WEBHOOK_TOKEN. Tests de résilience.
Fichiers: app/audit_sink.py, intégration dans app/flask_app.py, tests/test_audit_webhook.py, docs/SECOPS.md (section Webhooks).
Critères: test passe (échec réseau puis succès), pas de secrets dans logs.
Sortie: diff + message.

```

**Validation**

- Tests ✅ ; doc mise à jour.

### G3 — OPA/Conftest pour Terraform (policy‑as‑code)

**Branche** : `policy/opa-conftest`

**Prompt (Claude)**

```
Objectif: Ajouter des règles Conftest pour refuser: Key Vault public, TLS<1.2, locations hors Switzerland*. Intégrer à CI en étape "policy check".
Fichiers: policy/opa/*.rego, .github/workflows/ci.yml.
Critères: CI échoue si règle violée.
Sortie: diff + message.

```

**Validation**

- CI fail si non conforme.

### G4 — Images distroless + Sigstore (supply chain)

**Branche** : `supplychain/distroless-sigstore`

**Prompt (Claude)**

```
Objectif: Adapter Dockerfile vers base distroless si possible et signer l'image via cosign (signature keyless en CI). Doc rapide d'utilisation.
Fichiers: Dockerfile, .github/workflows/ci.yml, docs/SUPPLY_CHAIN.md.
Critères: build OK; signature cosign visible.
Sortie: diff + message.

```

**Validation**

- Signature vérifiable.

### G5 — Nginx: rate limits affinés & CORS whitelist stricte

**Branche** : `nginx/rate-cors`

**Prompt (Claude)**

```
Objectif: Ajuster rate limiting (zones, burst) et whitelist CORS à localhost uniquement; tests de prévol (OPTIONS) si nécessaire.
Fichiers: nginx/conf.d/security.conf, tests/test_cors.py.
Critères: preflight autorisé pour origin autorisés, refusé sinon.
Sortie: diff + message.

```

**Validation**

- Tests CORS ✅.

---

## 🧾 Annexes

- **PR template** : `.github/PULL_REQUEST_TEMPLATE.md` (déjà fournie)
- **Patch applier** : `bin/apply-patch.sh` (déjà fourni)
- **Exécution patch** :
    
    ```bash
    # depuis un fichier
    bin/apply-patch.sh -f patch.diff --push
    # macOS: depuis le presse‑papiers
    pbpaste | bin/apply-patch.sh --push
    
    ```