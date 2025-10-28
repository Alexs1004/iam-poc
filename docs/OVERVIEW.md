# Overview — Mini IAM Lab

## Pourquoi ce PoC existe
- **Objectif** : démontrer une stack IAM "Azure-first" prête pour un environnement entreprise.
- **Public cible** : recruteurs cloud security, architectes IAM, DevSecOps.
- **Contexte** : gestion Joiner/Mover/Leaver (JML), API SCIM 2.0, audit inviolable, secrets hors dépôt.

## Ce qu'il faut retenir
| Domaine | Points clés |
|---------|-------------|
| **Identité** | Keycloak pour la démo, migration planifiée vers Microsoft Entra ID. |
| **Applications** | Flask (admin UI + SCIM API) derrière Nginx avec TLS auto-généré. |
| **Sécurité** | OAuth2 + PKCE, MFA TOTP obligatoire, audit HMAC-SHA256, secrets via `/run/secrets`. |
| **Azure** | Azure Key Vault via `DefaultAzureCredential`, roadmap Managed Identity & Monitor. |

## Flux essentiels
1. **Joiner/Mover/Leaver** : scripts automatisés + interface admin → provisioning SCIM → audit signé.
2. **SCIM API** : endpoints `/scim/v2/*` servant de façade standardisée vers Keycloak.
3. **Secrets** : mode démo auto-généré, mode production connecté à Azure Key Vault.
4. **Audit** : chaque opération critique appose une signature HMAC (détection de tampering).

## Architecture (vue logique)
```
┌──────────────┐     HTTPS      ┌──────────────┐     OAuth Admin API     ┌──────────────┐
│  Client IAM  │ ─────────────▶ │    Nginx     │ ───────────────────────▶ │   Keycloak   │
│ (UI / SCIM)  │                │ TLS + CSP    │                         │  Realm demo  │
└──────────────┘                └──────┬───────┘                         └──────┬───────┘
                                       │                                      │
                                       │HTTP                                  │
                                       ▼                                      ▼
                                ┌──────────────┐                      ┌──────────────┐
                                │   Flask      │                      │ Azure Key    │
                                │ (admin+SCIM) │◀── Docker secrets ───│   Vault      │
                                └──────┬───────┘                      └──────────────┘
                                       │
                                       ▼
                                ┌──────────────┐
                                │ Audit JSONL  │
                                │  HMAC signé  │
                                └──────────────┘
```

## Où continuer
- Déploiement détaillé : [Setup Guide](SETUP_GUIDE.md)
- Contrôles de sécurité : [Security Design](SECURITY_DESIGN.md)
- Stratégie de tests : [Test Strategy](TEST_STRATEGY.md)
- Détails API : [API Reference](API_REFERENCE.md)
- Vision produit : [Roadmap](ROADMAP.md)
