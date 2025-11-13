# 🔐 Backend Terraform - Sécurité du State

## ⚠️ Pourquoi c'est critique pour votre employabilité

En entretien d'embauche cloud, vous serez **certainement** interrogé sur :
- *"Comment gérez-vous le state Terraform en production ?"*
- *"Quels sont les risques de sécurité liés au state ?"*
- *"Comment évitez-vous les modifications concurrentes ?"*

**Avoir un backend distant configuré = différenciateur majeur** 🚀

---

## 🎯 Ce que contient le tfstate (exemples réels)

### Données sensibles exposées

```json
{
  "resources": [
    {
      "type": "azurerm_linux_web_app",
      "instances": [{
        "attributes": {
          "site_credential": {
            "name": "$iam-poc-app",
            "password": "xzy123ABC..."  ← Credential de déploiement FTP/Git
          },
          "outbound_ip_addresses": "20.203.45.67,20.203.45.68"
        }
      }]
    },
    {
      "type": "azurerm_key_vault",
      "instances": [{
        "attributes": {
          "vault_uri": "https://iam-poc-kv.vault.azure.net/",
          "tenant_id": "12345678-...",
          "network_acls": {
            "ip_rules": ["203.0.113.42"]  ← Votre IP publique !
          }
        }
      }]
    }
  ]
}
```

### Risques si le state fuite

| Donnée exposée | Risque | Impact |
|----------------|--------|--------|
| **Site credentials** | Accès FTP/Git/deployment | Compromission complète de l'app |
| **IPs publiques** | Reconnaissance réseau | Ciblage d'attaques (DDoS, scan) |
| **Tenant/Subscription IDs** | Énumération de ressources | Cartographie de votre infra Azure |
| **Network ACLs** | Connaissance des règles firewall | Bypass de sécurité |
| **Connection strings** | Accès bases de données | Fuite de données |

**Scénario d'attaque réel** :
1. Attaquant trouve un `terraform.tfstate` commité par erreur sur GitHub
2. Extrait les IPs publiques et site credentials
3. Se connecte en FTP avec les credentials
4. Déploie un webshell → compromission complète

---

## ✅ Solution : Backend Azure Storage

### Avantages pour votre projet

| Fonctionnalité | Bénéfice sécurité | Bénéfice employabilité |
|----------------|-------------------|------------------------|
| **Encryption at rest** (AES-256) | Données chiffrées sur disque | Standard industrie (NIST SP 800-53) |
| **State locking** | Évite les modifications concurrentes | Démontrable en démo (2 personnes) |
| **Versioning** | Rollback en cas d'erreur | Récupération après incident |
| **Audit trail** | Traçabilité (qui/quand/quoi) | Conformité LPD/FINMA |
| **HTTPS only** (TLS 1.2+) | Chiffrement en transit | Prévention MITM |
| **Soft delete** (30j) | Protection suppression accidentelle | Résilience |

### Architecture de sécurité

```
┌─────────────────────────────────────────────────────┐
│ Développeur / CI/CD                                  │
│  terraform apply                                     │
└──────────────┬──────────────────────────────────────┘
               │ Azure CLI auth (OAuth2)
               │ ou Service Principal (RBAC)
               ↓
┌─────────────────────────────────────────────────────┐
│ Azure Storage Account (tfstate-rg)                   │
│  ┌─────────────────────────────────────────────┐   │
│  │ Blob Container: tfstate                      │   │
│  │  └─ iam-poc.terraform.tfstate                │   │
│  │     ├─ Encryption: AES-256 (SSE)             │   │
│  │     ├─ Versioning: enabled                   │   │
│  │     ├─ Soft delete: 30 days                  │   │
│  │     └─ Lock: prevents concurrent writes      │   │
│  └─────────────────────────────────────────────┘   │
│                                                       │
│  Security:                                           │
│  ✓ HTTPS only (TLS 1.2+)                            │
│  ✓ Public access: disabled                          │
│  ✓ Network rules: optional (restrict to VNet)      │
│  ✓ Location: Switzerland North (LPD compliant)     │
└─────────────────────────────────────────────────────┘
```

---

## 🛠️ Configuration pas-à-pas

### 1. Créer l'infrastructure de backend (une seule fois)

```bash
# Exécuter le script fourni
cd /home/alex/iam-poc
./infra/setup-backend.sh
```

**Ce que fait le script :**
1. Crée un Resource Group dédié (`tfstate-rg`)
2. Crée un Storage Account avec :
   - Encryption SSE activée
   - HTTPS only + TLS 1.2 minimum
   - Public access désactivé
   - Versioning + soft delete (30j)
3. Crée un blob container `tfstate`
4. Affiche les commandes pour créer `backend.hcl`

### 2. Créer le fichier backend.hcl (à ne PAS commiter)

```bash
cat > infra/backend.hcl <<EOF
resource_group_name  = "tfstate-rg"
storage_account_name = "tfstateiam123456"  # Remplacer par la sortie du script
container_name       = "tfstate"
key                  = "iam-poc.terraform.tfstate"
EOF
```

**⚠️ Important** : `backend.hcl` est dans `.gitignore` (contient le nom du storage account)

### 3. Initialiser Terraform avec le backend

```bash
terraform -chdir=infra init -backend-config=backend.hcl
```

**Output attendu :**
```
Initializing the backend...

Successfully configured the backend "azurerm"! Terraform will automatically
use this backend unless the backend configuration changes.
```

### 4. Authentification

**Option 1 : Azure CLI (recommandé)**
```bash
az login
# Terraform utilisera automatiquement vos credentials
```

**Option 2 : Service Principal (CI/CD)**
```bash
export ARM_CLIENT_ID="..."
export ARM_CLIENT_SECRET="..."
export ARM_TENANT_ID="..."
export ARM_SUBSCRIPTION_ID="..."
```

**Option 3 : Access Key (moins sécurisé, éviter)**
```bash
export ARM_ACCESS_KEY="..."  # Clé du storage account
```

---

## 🧪 Tester le backend

### Scénario 1 : State locking (prévention modifications concurrentes)

**Terminal 1 :**
```bash
terraform -chdir=infra apply -var="tenant_id=xxx" -auto-approve
# (en cours d'exécution)
```

**Terminal 2 (simultanément) :**
```bash
terraform -chdir=infra apply -var="tenant_id=xxx" -auto-approve
```

**Résultat attendu :**
```
Error acquiring the state lock:
Error: Error locking state: Error acquiring the state lock: storage: service returned error: StatusCode=409, ErrorCode=LeaseAlreadyPresent
```

**✅ Démo parfaite en entretien** : prouve que vous comprenez les risques de concurrence.

### Scénario 2 : Versioning (rollback)

```bash
# Lister les versions du state
az storage blob list \
  --account-name tfstateiam123456 \
  --container-name tfstate \
  --include v \
  --query "[?name=='iam-poc.terraform.tfstate'].{Name:name, Version:versionId, LastModified:properties.lastModified}"

# Télécharger une ancienne version si besoin
az storage blob download \
  --account-name tfstateiam123456 \
  --container-name tfstate \
  --name iam-poc.terraform.tfstate \
  --version-id "<version-id>" \
  --file terraform.tfstate.backup
```

---

## 🎓 Points à mentionner en entretien

### Question : "Pourquoi un backend distant ?"

**Votre réponse (30 secondes) :**

> "Le state Terraform contient des données sensibles comme les credentials de déploiement et les IPs publiques. J'ai configuré un backend Azure Storage avec encryption AES-256, state locking pour éviter les modifications concurrentes, et versioning pour le rollback. C'est aussi conforme aux exigences LPD/FINMA pour la traçabilité et la résidence des données en Suisse. En production, j'utilise l'authentification Azure CLI ou Service Principal plutôt que des access keys statiques."

**Points qui impressionnent** :
- ✅ Vous citez des risques concrets (credentials, IPs)
- ✅ Vous mentionnez la conformité réglementaire
- ✅ Vous connaissez les features de sécurité (locking, versioning)
- ✅ Vous savez éviter les mauvaises pratiques (access keys)

### Question : "Comment gérez-vous le state en équipe ?"

**Votre réponse :**

> "Le backend Azure Storage offre le state locking natif via blob leases. Quand un `terraform apply` est en cours, Terraform acquiert un lease qui empêche d'autres exécutions simultanées. J'ai aussi activé le versioning pour pouvoir rollback si une erreur est introduite, et soft delete avec 30 jours de rétention pour la conformité."

### Question : "Quels sont les risques d'un state local ?"

**Votre réponse :**

> "Trois risques principaux : 1) Fuite de credentials si le state est commité dans Git, 2) Modifications concurrentes qui peuvent corrompre l'infrastructure, 3) Pas de traçabilité ni d'audit trail. Pour un projet professionnel, j'utilise toujours un backend distant avec encryption et contrôle d'accès RBAC."

---

## 📊 Comparaison : Local vs Remote

| Critère | Backend local | Backend Azure Storage |
|---------|---------------|----------------------|
| **Encryption** | ❌ Non (fichier texte) | ✅ AES-256 au repos + TLS en transit |
| **State locking** | ❌ Non | ✅ Via blob leases |
| **Versioning** | ❌ Manuel (Git?) | ✅ Automatique |
| **Audit trail** | ❌ Non | ✅ Logs Azure Monitor |
| **Partage équipe** | ❌ Problématique | ✅ Natif |
| **CI/CD** | ❌ Complexe | ✅ Simple (auth Azure) |
| **Conformité LPD/FINMA** | ❌ Non conforme | ✅ Conforme (si Suisse) |
| **Coût** | Gratuit | ~0.02 EUR/mois (négligeable) |

---

## 🔒 Bonnes pratiques appliquées

| Pratique | Implémentation | Référence |
|----------|----------------|-----------|
| **Encryption at rest** | Azure Storage SSE (AES-256) | NIST SP 800-53 SC-28 |
| **Encryption in transit** | HTTPS only, TLS 1.2+ | NIST SP 800-52 |
| **Access control** | RBAC Azure + optional private endpoint | NIST SP 800-53 AC-3 |
| **State locking** | Blob lease mechanism | HashiCorp best practices |
| **Versioning** | Blob versioning enabled | Change management (ITIL) |
| **Soft delete** | 30 days retention | LPD Art. 5 / FINMA |
| **Résidence données** | Switzerland North | LPD Art. 6 |
| **Secrets management** | Azure CLI auth (pas d'access keys) | OWASP ASVS 2.7.1 |

---

## 🚨 Erreurs fréquentes à éviter

### ❌ Commiter le state dans Git

```bash
# MAUVAIS
git add terraform.tfstate
git commit -m "Update state"
```

**Pourquoi c'est grave** : Tout l'historique Git contiendra vos credentials. Même si vous supprimez le commit, il reste dans l'historique.

**Solution** : `.gitignore` + backend distant.

### ❌ Utiliser des access keys en clair

```bash
# MAUVAIS
export ARM_ACCESS_KEY="xyz123..."  # Ne jamais mettre dans un script commité
```

**Solution** : Utiliser Azure CLI auth ou Service Principal avec RBAC.

### ❌ Pas de locking en équipe

Sans locking, deux personnes peuvent faire `terraform apply` simultanément → **corruption du state**.

**Solution** : Backend distant avec locking automatique.

### ❌ Pas de backup du state

Si le state est corrompu ou supprimé → **perte de la gestion de l'infrastructure**.

**Solution** : Versioning + soft delete activés.

---

## 💼 Démonstration en entretien

**Scénario 1 : Sécurité du state**

*"Regardez, le state contient les site credentials ici (montrer JSON). C'est pourquoi j'utilise un backend Azure Storage avec encryption AES-256. Je peux aussi vous montrer le versioning : voici les 5 dernières versions du state, je peux rollback si besoin."*

**Scénario 2 : State locking**

*"Si je lance un apply ici, et qu'un collègue (ou le pipeline CI/CD) lance un autre apply en même temps, Terraform va bloquer le second avec un lease error. Je peux vous montrer en temps réel."*

**Scénario 3 : Conformité**

*"Le storage account est en Switzerland North pour la conformité LPD, avec soft delete 30 jours pour la traçabilité FINMA. Tous les accès sont loggés dans Azure Monitor."*

---

## 📚 Références

- [Terraform Backend Types](https://www.terraform.io/language/settings/backends)
- [Azure Storage Backend](https://www.terraform.io/language/settings/backends/azurerm)
- [NIST SP 800-53 - Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [OWASP ASVS - Secrets Management](https://owasp.org/www-project-application-security-verification-standard/)
- [LPD - Loi fédérale sur la protection des données](https://www.admin.ch/gov/fr/accueil/droit-federal/recueil-systematique/cc/19/235_1.html)

---

**TL;DR** : Backend distant = **must-have** pour employabilité cloud. Coût quasi nul, impact énorme en entretien. 🚀
