# 🧪 Testing Guide — Mini IAM Lab

> **Guide complet des tests** : stratégie, commandes, et workflow de couverture de code

---

## 📊 Métriques Actuelles

- **Tests totaux** : 328 tests (300+ unitaires, 27 intégration)
- **Couverture** : 92% sur le code métier (`app/`)
- **Temps d'exécution** : ~3.5s (parallélisé avec pytest-xdist)
- **Stack de test** : pytest + pytest-cov + pytest-xdist + pytest-mock

---

## 🎯 Stratégie de Test

### **Tests Unitaires** (300+ tests)
**Objectif** : Valider la logique métier de manière isolée (mocks Keycloak)

**Commande** :
```bash
make test
```

**Couverture** :
- `app/core/` : Validation SCIM, RBAC, provisioning (100% sur validators)
- `app/api/` : Endpoints Flask, decorators, error handling (>90%)
- `app/config/` : Validation configuration, settings (96%)

**Exécution** : Parallélisée avec `-n auto` (pytest-xdist)

---

### **Tests d'Intégration** (27 tests E2E)
**Objectif** : Valider les flux complets avec stack Docker réelle (Keycloak + Flask + Nginx)

**Commande** :
```bash
make test-e2e
```

**Pré-requis** : Stack démarrée (`make ensure-stack` vérifie automatiquement)

**Couverture** :
- OIDC/JWT validation (token parsing, claims, expiration)
- OAuth 2.0 SCIM authentication (Bearer tokens)
- Nginx security headers (HSTS, CSP, X-Frame-Options)
- Secrets security (Key Vault, Docker secrets)
- E2E SCIM flows (Joiner/Mover/Leaver)

**Skip automatique** : Si le stack n'est pas accessible ou si les credentials OAuth sont invalides, les tests se désactivent proprement (pytest.skip) au lieu de générer des erreurs en cascade.

---

### **Tests de Couverture** (328 tests complets)
**Objectif** : Générer un rapport HTML détaillé de la couverture de code

**Commande** :
```bash
make test-coverage
```

**Sortie** : Rapport HTML dans `htmlcov/index.html` + résumé terminal

**Workflow recommandé** :
```bash
# 1. Lancer les tests avec couverture
make test-coverage

# 2. Voir les options d'affichage
make test-coverage-report

# 3. Ouvrir dans VS Code (recommandé pour environnements CLI)
make test-coverage-vscode

# Alternatives selon l'environnement
make test-coverage-open    # Navigateur système (Linux GUI, macOS)
make test-coverage-serve   # HTTP server localhost:8888
```

**Pourquoi plusieurs options ?**
- **Environnement CLI** (WSL, serveurs SSH) : `test-coverage-vscode` ou `test-coverage-serve`
- **Environnement GUI** (Linux desktop, macOS) : `test-coverage-open`
- **Review distant** : `test-coverage-serve` + tunnel SSH

---

## 🛡️ Tests de Sécurité Critiques

**Commande** :
```bash
make test/security
```

**Couverture** :
- JWT signature validation (JWKS, algorithms, expiration)
- RBAC enforcement (permissions, role hierarchy)
- Rate limiting (Nginx + Flask)
- Audit log signatures (HMAC-SHA256 verification)

**Marqueurs pytest** : `-m critical` (tests non-négociables)

---

## 🔄 Workflow CI/CD (GitHub Actions)

```yaml
- name: Run tests with coverage
  run: make test-coverage

- name: Upload coverage report
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage.xml
```

**Checks obligatoires** :
- ✅ Tous les tests unitaires passent (300+)
- ✅ Couverture >= 90% maintenue
- ✅ Aucun test critique (security) échoué
- ✅ Aucune régression détectée

---

## 🐛 Troubleshooting

### **Problème : Tests d'intégration échouent avec erreur 401**
**Cause** : Credentials OAuth invalides ou stack non démarré

**Solution** :
```bash
# Vérifier que le stack est running
make ensure-stack

# Vérifier les secrets
cat .runtime/secrets/keycloak_service_client_secret

# Re-générer les secrets si nécessaire
make fresh-demo
```

**Note** : Depuis la correction récente, les fixtures OAuth utilisent `pytest.skip()` si les credentials sont invalides, évitant les erreurs en cascade.

---

### **Problème : Impossible d'ouvrir le rapport de couverture**
**Cause** : Environnement Linux CLI sans navigateur

**Solution** :
```bash
# Option 1 : Ouvrir dans VS Code
make test-coverage-vscode

# Option 2 : Servir via HTTP
make test-coverage-serve
# Puis ouvrir http://localhost:8888 dans un navigateur local ou tunnelé
```

---

### **Problème : Tests lents ou timeouts**
**Cause** : Stack Docker non optimal, ou tests séquentiels

**Solution** :
```bash
# Vérifier la santé du stack
docker compose ps

# Redémarrer si nécessaire
make restart

# Les tests unitaires sont parallélisés par défaut (-n auto)
# Les tests d'intégration sont séquentiels (rate limiting)
```

---

## 📚 Références

- **pytest** : https://docs.pytest.org/
- **pytest-cov** : https://pytest-cov.readthedocs.io/
- **Coverage.py** : https://coverage.readthedocs.io/
- **pytest-xdist** : https://pytest-xdist.readthedocs.io/ (parallélisation)

---

## 🎓 Bonnes Pratiques Appliquées

1. **Tests isolés** : Mocks pour tests unitaires, stack réelle pour intégration
2. **Skip intelligent** : `pytest.skip()` pour dépendances externes manquantes
3. **Parallélisation** : `-n auto` pour tests unitaires (gain 3-4x)
4. **Fixtures scope** : `module` pour setup coûteux (OAuth tokens), `function` pour isolation
5. **Marqueurs pytest** : `@pytest.mark.integration`, `@pytest.mark.critical`
6. **Coverage ciblée** : Seulement `app/`, pas les tests ou dépendances
7. **CI/CD friendly** : Rapport XML pour CodeCov, skip automatique en l'absence de stack

---

**Retour** : [Documentation Hub](README.md) | [README Principal](../README.md)
