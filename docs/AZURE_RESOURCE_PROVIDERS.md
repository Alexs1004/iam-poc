# 🔧 Azure Resource Providers - Guide rapide

## Qu'est-ce qu'un Resource Provider ?

Un **Resource Provider** est un service Azure qui permet de créer et gérer des types de ressources spécifiques.

Exemples :
- `Microsoft.Storage` → Storage Accounts, Blob containers
- `Microsoft.Web` → App Services, Web Apps
- `Microsoft.KeyVault` → Key Vaults
- `Microsoft.Network` → VNets, Load Balancers

## Pourquoi l'enregistrement est nécessaire ?

**Nouveau compte Azure** → Aucun provider n'est enregistré par défaut (économie de coûts).

**Avant de créer une ressource** → Le provider correspondant **doit être enregistré** dans votre souscription.

---

## 🚨 Erreur typique

```bash
(SubscriptionNotFound) Subscription xxx was not found.
```

**Traduction réelle** : "Le provider n'est pas enregistré" (message d'erreur trompeur d'Azure 🙄)

---

## ✅ Solution automatique (déjà dans setup-backend.sh)

Le script `setup-backend.sh` vérifie et enregistre automatiquement `Microsoft.Storage` :

```bash
# Check if Microsoft.Storage provider is registered
STORAGE_STATE=$(az provider show --namespace Microsoft.Storage --query "registrationState" -o tsv)

if [ "$STORAGE_STATE" != "Registered" ]; then
    az provider register --namespace Microsoft.Storage
    
    # Wait for registration (1-2 minutes)
    while [ "$(az provider show --namespace Microsoft.Storage --query 'registrationState' -o tsv)" != "Registered" ]; do
        sleep 5
    done
fi
```

---

## 🛠️ Commandes manuelles utiles

### Vérifier le statut d'un provider

```bash
az provider show --namespace Microsoft.Storage --query "registrationState" -o tsv
# Output: Registered | NotRegistered | Registering
```

### Enregistrer un provider

```bash
az provider register --namespace Microsoft.Storage
# Attendre 1-2 minutes
```

### Lister tous les providers

```bash
az provider list --output table
```

### Lister uniquement les providers enregistrés

```bash
az provider list --query "[?registrationState=='Registered'].namespace" -o table
```

---

## 📋 Providers nécessaires pour ce projet

| Provider | Pour quoi ? | Auto-enregistré ? |
|----------|-------------|-------------------|
| `Microsoft.Storage` | Storage Account (Terraform state) | ✅ Oui (setup-backend.sh) |
| `Microsoft.Web` | App Service, Web Apps | ⚠️ À enregistrer (Phase C5) |
| `Microsoft.KeyVault` | Key Vault | ⚠️ À enregistrer (Phase C4) |
| `Microsoft.Network` | VNet, Subnets | ⚠️ À enregistrer (Phase C3) |
| `Microsoft.OperationalInsights` | Log Analytics Workspace | ⚠️ À enregistrer (Phase C2) |

---

## 🚀 Enregistrer tous les providers d'un coup (recommandé)

Pour éviter les surprises lors des phases suivantes :

```bash
# Liste des providers nécessaires
PROVIDERS=(
    "Microsoft.Storage"
    "Microsoft.Web"
    "Microsoft.KeyVault"
    "Microsoft.Network"
    "Microsoft.OperationalInsights"
    "Microsoft.Insights"
)

# Enregistrer tous
for PROVIDER in "${PROVIDERS[@]}"; do
    echo "📝 Registering $PROVIDER..."
    az provider register --namespace "$PROVIDER"
done

# Attendre que tous soient enregistrés
echo "⏳ Waiting for all providers to be registered..."
for PROVIDER in "${PROVIDERS[@]}"; do
    while [ "$(az provider show --namespace $PROVIDER --query 'registrationState' -o tsv)" != "Registered" ]; do
        echo "  Waiting for $PROVIDER..."
        sleep 5
    done
    echo "  ✅ $PROVIDER registered"
done

echo ""
echo "✅ All providers registered successfully!"
```

**Temps total** : ~2-5 minutes (parallèle)

---

## 🎓 Pourquoi c'est important pour votre employabilité

### Question d'entretien typique :

*"Vous déployez une nouvelle ressource Azure via Terraform et vous obtenez une erreur 'SubscriptionNotFound'. Que faites-vous ?"*

**Mauvaise réponse** (junior) :
> "Euh... je vérifie que ma souscription existe ?"

**Bonne réponse** (vous) :
> "C'est un message d'erreur trompeur d'Azure. En réalité, ça signifie souvent que le Resource Provider correspondant n'est pas enregistré dans la souscription. Je vérifie avec `az provider show --namespace Microsoft.XXX` et je l'enregistre si nécessaire. J'ai automatisé cette vérification dans mes scripts Terraform pour éviter les surprises en CI/CD."

**Points bonus** :
- ✅ Vous connaissez les pièges d'Azure
- ✅ Vous avez automatisé la solution
- ✅ Vous pensez CI/CD dès le début

---

## 🔒 Bonnes pratiques

### ✅ À faire

1. **Enregistrer les providers dès le début** (avant Terraform)
2. **Automatiser dans les scripts** (comme setup-backend.sh)
3. **Documenter les providers nécessaires** (README)
4. **Vérifier dans CI/CD** (étape pre-deployment)

### ❌ À éviter

1. Enregistrer **tous** les providers (coût, complexité)
2. Oublier de documenter (collègues perdus)
3. Enregistrer manuellement à chaque fois (non reproductible)

---

## 🧪 Test

Vérifier que le provider Storage est bien enregistré :

```bash
az provider show --namespace Microsoft.Storage --query "registrationState" -o tsv
# Expected: Registered
```

Créer un Storage Account de test :

```bash
az storage account create \
    --name teststorage$(date +%s) \
    --resource-group tfstate-rg \
    --location switzerlandnorth \
    --sku Standard_LRS

# Si ça fonctionne → provider OK ✅
```

---

## 📚 Références

- [Azure Resource Providers](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types)
- [Register Resource Provider](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types#register-resource-provider)
- [Terraform Azure Provider](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)

---

**TL;DR** : "SubscriptionNotFound" = provider pas enregistré. Solution : `az provider register --namespace Microsoft.XXX` (déjà automatisé dans setup-backend.sh) 🚀
