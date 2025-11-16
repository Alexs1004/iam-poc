# 📚 Phase C1 - Explication détaillée

## ✅ Ce qui a été implémenté

La phase C1 crée le **squelette de l'infrastructure Terraform** - une base solide et sécurisée pour déployer votre application sur Azure.

---

## 🧩 Fichiers créés et leur rôle

### 1. `providers.tf` - Configuration du fournisseur Azure

**Ce qu'il fait:**
- Déclare qu'on utilise Terraform >= 1.5.0
- Configure le provider **azurerm** (Azure Resource Manager) en version 3.x
- Active des fonctionnalités de sécurité pour Key Vault

**Pourquoi c'est important:**
- Le provider azurerm permet à Terraform de communiquer avec Azure
- La version `~> 3.0` signifie "3.x.x" mais pas 4.0 (compatibilité contrôlée)
- `purge_soft_delete_on_destroy = false` **empêche la suppression définitive accidentelle** des Key Vaults (sécurité)

**Bonne pratique:**
> Toujours épingler les versions de providers pour éviter les surprises lors des mises à jour automatiques.

---

### 2. `variables.tf` - Variables d'entrée

**Ce qu'il fait:**
- Définit les paramètres configurables de l'infrastructure
- Inclut des validations pour éviter les erreurs

**Variables clés:**

| Variable | Description | Pourquoi c'est important |
|----------|-------------|--------------------------|
| `prefix` | Préfixe pour nommer les ressources | Permet d'identifier facilement vos ressources Azure |
| `location` | Région Azure (défaut: `switzerlandnorth`) | **Conformité LPD/FINMA**: données en Suisse 🇨🇭 |
| `tenant_id` | ID du tenant Azure AD | Nécessaire pour donner des permissions au Key Vault |
| `environment` | dev/staging/prod | Évite de mélanger les environnements |
| `tags` | Étiquettes communes | Traçabilité et gestion des coûts |

**Sécurité - Validation du prefix:**
```hcl
validation {
  condition     = length(var.prefix) <= 20 && can(regex("^[a-z0-9-]+$", var.prefix))
  error_message = "Prefix must be <= 20 characters..."
}
```

**Pourquoi?**
- Certains services Azure ont des limites de longueur de nom
- Les caractères spéciaux peuvent causer des problèmes
- **C'est une garde-fou contre les erreurs de configuration**

---

### 3. `outputs.tf` - Sorties (pour l'instant en commentaire)

**Ce qu'il fait:**
- Définit ce que Terraform va afficher après le déploiement
- Permet à d'autres modules Terraform d'utiliser ces valeurs

**Exemple d'output futur:**
```hcl
output "key_vault_uri" {
  description = "URI of the Key Vault"
  value       = azurerm_key_vault.main.vault_uri
}
```

**Pourquoi c'est utile:**
- Votre application aura besoin de l'URI du Key Vault (phase C4)
- Évite de chercher manuellement dans le portail Azure
- Permet l'automatisation (CI/CD peut récupérer ces valeurs)

---

### 4. `main.tf` - Configuration principale

**Ce qu'il fait:**
- Définit des **locals** (variables calculées)
- Prépare la structure pour les phases suivantes

**Les locals expliqués:**

```hcl
locals {
  # Auto-génère le nom du Resource Group si non fourni
  rg_name = var.rg_name != "" ? var.rg_name : "${var.prefix}-rg-${var.environment}"
  
  # Fusionne les tags par défaut avec l'environnement
  common_tags = merge(var.tags, {
    Environment = var.environment
    Location    = var.location
  })
}
```

**Pourquoi utiliser des locals?**
- **DRY (Don't Repeat Yourself)**: calcule une fois, utilise partout
- Si `rg_name` n'est pas fourni, il génère automatiquement: `iam-poc-rg-dev`
- Les tags sont appliqués uniformément à toutes les ressources (conformité!)

---

### 5. `.gitignore` - Sécurité Git

**Ce qu'il fait:**
- Empêche de commiter des fichiers sensibles ou temporaires

**Fichiers exclus et pourquoi:**

| Fichier | Danger si commité |
|---------|-------------------|
| `*.tfstate` | **Contient l'état complet de l'infra, potentiellement des secrets** |
| `*.tfvars` | **Peut contenir des IDs de tenant, clés, mots de passe** |
| `.terraform/` | Fichiers binaires volumineux, inutiles dans Git |

**Erreur fréquente à éviter:**
> ⚠️ Ne JAMAIS commiter un fichier `.tfvars` contenant `tenant_id` ou d'autres identifiants. Utilisez des variables d'environnement ou Azure Key Vault.

**Bonne pratique OWASP:**
- Secrets Management: jamais de secrets en clair dans le code source
- Defense in Depth: même si le repo est privé, on applique le principe du moindre privilège

---

### 6. `README.md` - Documentation

**Ce qu'il fait:**
- Guide d'installation de Terraform
- Commandes pour init/plan/apply/destroy
- Exemples d'utilisation avec variables

**Pourquoi c'est crucial:**
- Un recruteur ou collègue doit pouvoir déployer en 5 minutes
- La documentation est partie de la sécurité (configuration correcte = sécurité)

---

## 🔐 Bonnes pratiques appliquées

### 1. **Séparation des préoccupations**
- Chaque fichier a un rôle clair (providers, variables, outputs, main)
- Facilite la maintenance et les revues de code

### 2. **Infrastructure as Code (IaC)**
- L'infrastructure est versionnée, reproductible, auditable
- Conforme aux exigences FINMA (traçabilité des changements)

### 3. **Validation en amont**
- Les validations dans `variables.tf` détectent les erreurs **avant** le déploiement
- Économise du temps et évite les ressources mal configurées

### 4. **Sécurité par défaut**
- Key Vault: soft delete activé (protection contre suppression accidentelle)
- Région par défaut: Suisse (conformité LPD)
- Tags obligatoires (gouvernance)

### 5. **Principe de moindre privilège**
- `tenant_id` requis mais pas de secrets en dur
- L'authentification se fait via `az login` (OAuth2, pas de clés API statiques)

---

## 🎯 Prochaines étapes

**Phase C2** créera:
- Un **Resource Group** (conteneur logique pour les ressources)
- Un **Log Analytics Workspace** (collecte des logs pour la détection d'incidents)

**Pourquoi Log Analytics dès maintenant?**
- Tous les services Azure (App Service, Key Vault) enverront leurs logs là
- Permet les requêtes KQL pour la détection de menaces (phase D)
- Conformité: rétention de logs obligatoire (LPD/FINMA)

---

## ❓ Questions fréquentes

**Q: Pourquoi Switzerland North et pas West Europe?**
- LPD (Loi sur la Protection des Données suisse) exige que les données restent en Suisse
- FINMA (autorité de surveillance financière) impose la résidence des données

**Q: Pourquoi ne pas utiliser azurerm 4.x?**
- Version 3.x est stable et largement adoptée
- `~> 3.0` permet les mises à jour mineures (3.x.x) sans risque de breaking changes

**Q: Terraform.tfstate contient quoi de sensible?**
- Tous les attributs des ressources (IPs, IDs, parfois des outputs sensibles)
- En production, il faut utiliser un **backend distant** (Azure Storage avec encryption)

---

## 🚀 Validation

Pour vérifier que tout fonctionne (après installation de Terraform):

```bash
# Initialiser Terraform
terraform -chdir=infra init

# Valider la syntaxe
terraform -chdir=infra validate

# Simuler le déploiement (aucune ressource créée)
terraform -chdir=infra plan -var="tenant_id=$(az account show --query tenantId -o tsv)"
```

**Ce que vous devriez voir:**
- ✅ `Terraform has been successfully initialized!`
- ✅ `Success! The configuration is valid.`
- ✅ `No changes. Your infrastructure matches the configuration.` (normal, aucune ressource définie encore)

---

**Fait avec ❤️ en suivant les principes de sécurité cloud et conformité suisse.**
