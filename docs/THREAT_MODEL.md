# Threat Model – IAM PoC (Swiss Enterprise)

## 1. Contexte

- IAM applicatif pour recrutement (Suisse romande), orienté Azure-first.
- Acteurs : candidats, recruteurs, automatisation SCIM, identités techniques.
- Normes : RFC 7644, FINMA Circ. 08/21, nLPD, ISO 27001, OWASP API.

## 2. Vue Système

```
Clients → Nginx (TLS) → Flask (SCIM/Admin) → Keycloak → Azure Key Vault
```

Principaux actifs : secrets dans Key Vault, comptes Keycloak, audit logs, données personnelles (nLPD).

## 3. STRIDE Résumé

| Catégorie | Risque | Exemple | Mitigation |
|-----------|--------|---------|------------|
| **Spoofing** | Tokens usurpés | Attaquant obtient bearer token | OAuth strict, rotation secrets, `DefaultAzureCredential` + managed identity. |
| **Tampering** | Altération SCIM payload | Injection dans PATCH | Validation stricte (`schemas`, `active` boolean), JSON schema, audit HMAC. |
| **Repudiation** | Nie l’opération | SCIM delete contesté | Logs HMAC-SHA256 + horodatage UTC + rétention immuable. |
| **Information Disclosure** | Secrets exposés | `.env` livré en prod | Secrets uniquement dans Key Vault + `/run/secrets` (chmod 400). |
| **Denial of Service** | Flood SCIM | Burst requêtes `filter` | Rate-limit au proxy, limiter `count`, WAF (Azure App Gateway). |
| **Elevation of Privilege** | Service account abusé | Token automation-cli réutilisé | Rôles Keycloak limités, rotation orchestrée, IP allow-list. |

## 4. MITRE ATT&CK (sélection)

| Technique | ID | Impact | Contremesure |
|-----------|----|--------|--------------|
| Credential Dumping | T1552.001 | Exfiltration secrets | Key Vault + RBAC → pas de secrets dans FS. |
| Valid Accounts | T1078 | Tokens automation-cli | Rotation + surveillance logs Keycloak (`events`). |
| Exposed Admin Interface | T1190 | Attaque /admin | OIDC + MFA TOTP, CSP stricte, CSRF enforcement. |
| API Abuse | T1190/T1499 | Brute force SCIM | Rate limiting (nginx), audit HMAC + détection anomalie. |

## 5. RFC 7644 Risks

- **Filter injection** : expressions complexes ⇒ restreint à `eq`.
- **Bulk** : désactivé (`bulk.supported=false`) pour éviter DoS.
- **Patch** : opérations limitées (`replace`) et cibles restreintes.
- **Attribute over-posting** : validation stricte (schemas whitelists).
- **Access tokens** : distribution par service account unique (rotation journalière recommandée).

## 6. Mitigations Clés

1. **OAuth obligatoire** (Bearer) – refuser toute requête sans `Authorization`.
2. **TLS 1.2+** (HSTS 31536000, disable TLS 1.0/1.1).
3. **Audit non répudiable** – HMAC + stockage immuable (Azure Storage).
4. **Key Vault** – Soft delete + purge protection + RBAC minimal.
5. **Secrets rotation** – `make rotate-secret`, pipeline automatisé.
6. **Monitoring** – Azure Monitor + AAD sign-in logs + Key Vault diagnostics.
7. **Data minimisation** – champs SCIM limités (respect nLPD art. 5).

## 7. Conformité & Références

- **FINMA RS 08/21** : ch. 9 (sécurité des systèmes, journaux), ch. 12 (externalisation).
- **nLPD** : art. 8-12 (licéité, sécurité).
- **ISO 27001/27002** : A.9 (contrôle accès), A.12 (exploitation).
- **OWASP API Security Top 10 (2023)** : API1 (Broken Auth), API3 (Excessive Data), API5 (Broken Function Level Auth).

## 8. Actions Ouvertes

- [ ] Intégrer Managed Identity (supprimer `az login` manuel).
- [ ] Activer WAF (Azure App Gateway) + rate limiting.
- [ ] Intégrer alertes Key Vault (retrievals anormaux, 403).
- [ ] Enrichir tests fuzzing SCIM (OWASP ZAP / Motherload).
- [ ] Ajouter journaux structurés (App Insights) → pipeline SOC.
