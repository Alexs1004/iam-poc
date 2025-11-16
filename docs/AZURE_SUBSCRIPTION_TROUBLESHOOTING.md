# 🚨 Résolution : Souscription Azure "Warned"

## Problème détecté

```json
{
  "state": "Warned",
  "name": "Azure subscription 1"
}
```

**Signification** : Votre souscription Azure est dans un état d'avertissement, probablement :
- Essai gratuit expiré (30 jours / $200 de crédit)
- Carte bancaire non ajoutée pour passer en Pay-As-You-Go
- Dépassement de quota ou limite de dépense

**Impact** : Vous ne pouvez pas créer de nouvelles ressources Azure.

---

## ✅ Solutions

### Option 1 : Passer en Pay-As-You-Go (recommandé pour le projet)

**Avantages** :
- Utilisation réelle de l'infra Azure (démo crédible)
- Coût très faible si bien géré (~5-10 EUR/mois pour ce projet)
- Expérience professionnelle authentique

**Procédure** :

1. **Aller sur le portail Azure**
   - https://portal.azure.com
   - Rechercher "Subscriptions"
   - Cliquer sur "Azure subscription 1"

2. **Upgrade vers Pay-As-You-Go**
   - Bouton "Upgrade" visible si éligible
   - Ajouter une carte bancaire (validation seulement, pas de charge immédiate)
   - Confirmer l'upgrade

3. **Vérifier l'état**
   ```bash
   az account show --query state -o tsv
   # Devrait afficher: Enabled
   ```

4. **Relancer le script**
   ```bash
   ./infra/setup-backend.sh
   ```

**Coût estimé pour ce projet** :
- Storage Account (state Terraform) : ~0.02 EUR/mois
- App Service Plan B1 : ~13 EUR/mois (peut être arrêté quand non utilisé)
- Key Vault : ~0.03 EUR/mois
- **Total si optimisé** : ~5-15 EUR/mois

**Comment minimiser les coûts** :
```bash
# Arrêter l'App Service quand non utilisé
az webapp stop --name <app-name> --resource-group <rg-name>

# Détruire l'infra après démonstration
cd infra && make destroy
```

---

### Option 2 : Créer un nouveau compte Azure (gratuit)

**Si vous n'avez jamais utilisé Azure avant** :

1. **Créer un nouveau compte Microsoft**
   - Email différent de `alexandre.stutz@hotmail.com`
   - Exemple : `alex.stutz.iam@outlook.com`

2. **S'inscrire à l'essai gratuit Azure**
   - https://azure.microsoft.com/free/
   - 30 jours / $200 de crédit
   - Carte bancaire requise (validation, pas de charge)

3. **Se connecter avec le nouveau compte**
   ```bash
   az logout
   az login
   # Utiliser le nouveau compte
   ```

4. **Mettre à jour `.env`**
   ```bash
   # Nouveau tenant ID
   ARM_TENANT_ID=<nouveau-tenant-id>
   ARM_SUBSCRIPTION_ID=<nouvelle-subscription-id>
   ```

---

### Option 3 : Mode local uniquement (sans Azure, pour apprentissage)

**Si vous voulez éviter les coûts Azure pour l'instant** :

#### A. Terraform en local (sans backend distant)

1. **Commenter le backend dans `infra/backend.tf`**
   ```hcl
   # terraform {
   #   backend "azurerm" {
   #     ...
   #   }
   # }
   ```

2. **Utiliser le backend local**
   ```bash
   cd infra
   terraform init
   terraform plan -var="tenant_id=dummy"
   ```

**Limitations** :
- ❌ Pas de déploiement réel sur Azure
- ❌ Pas de démonstration du backend distant sécurisé
- ✅ Validation de la syntaxe Terraform OK
- ✅ Structure du projet démontrée

#### B. Simulation avec LocalStack (Azure local)

**Installation** :
```bash
pip install localstack azurite
localstack start
```

**Limitations** :
- Émulation limitée (pas tous les services Azure)
- Configuration complexe
- Pas recommandé pour votre cas d'usage

---

### Option 4 : Azure for Students (si étudiant)

**Si vous êtes étudiant** :
- https://azure.microsoft.com/free/students/
- $100 de crédit sans carte bancaire
- 12 mois de services gratuits

**Vérification** :
- Nécessite email étudiant (`.edu`, `.ac.*`)
- Vérification via Azure for Students portal

---

## 🎯 Recommandation pour votre projet (employabilité)

### ✅ **Option 1 : Pay-As-You-Go**

**Pourquoi** :
1. **Expérience réelle** : En entretien, dire "j'ai déployé sur Azure en production" > "j'ai fait du local"
2. **Coût maîtrisé** : ~10-15 EUR/mois, arrêtable à tout moment
3. **Démo crédible** : Infrastructure réelle, logs Azure Monitor, Key Vault, etc.
4. **ROI énorme** : 10 EUR d'investissement peuvent faire la différence pour un poste à 80k CHF/an

**Gestion du budget** :
```bash
# Alertes de coût (gratuit)
az consumption budget create \
  --amount 20 \
  --budget-name iam-poc-monthly \
  --time-period month \
  --threshold 80

# Auto-shutdown App Service tous les soirs (économie 70%)
az webapp config set --always-on false
```

---

## 🔧 Prochaines étapes

### Si vous choisissez l'Option 1 (Pay-As-You-Go)

```bash
# 1. Upgrade sur portal.azure.com
# 2. Vérifier l'état
az account show --query state -o tsv

# 3. Relancer le setup backend
./infra/setup-backend.sh

# 4. Continuer normalement
cd infra && make init
```

### Si vous choisissez l'Option 3 (local uniquement)

```bash
# 1. Commenter le backend distant
sed -i 's/^terraform {/# terraform {/' infra/backend.tf
sed -i 's/^  backend/# backend/' infra/backend.tf
sed -i 's/^}/# }/' infra/backend.tf

# 2. Init local
cd infra && terraform init

# 3. Valider
terraform validate
```

---

## 📊 Comparaison des options

| Critère | Pay-As-You-Go | Nouveau compte gratuit | Local uniquement |
|---------|---------------|------------------------|------------------|
| **Coût** | ~10-15 EUR/mois | 0 EUR (30j) | 0 EUR |
| **Démo réelle** | ✅ Complète | ✅ Complète | ❌ Simulation |
| **Backend distant** | ✅ Oui | ✅ Oui | ❌ Non |
| **Employabilité** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ |
| **Complexité** | Faible | Moyenne | Faible |
| **Durée** | Illimitée | 30 jours | Illimitée |

---

## 🎓 Ce que les recruteurs veulent voir

**Questions d'entretien typiques** :
- *"Avez-vous déjà déployé sur Azure en production ?"*
- *"Comment gérez-vous les coûts cloud ?"*
- *"Quelle est votre expérience avec l'infra as code ?"*

**Avec Pay-As-You-Go, vous pouvez répondre** :
> "J'ai déployé une application IAM complète sur Azure avec App Service, Key Vault privé, et Log Analytics. J'ai mis en place des alertes de coût et optimisé pour rester sous 15 EUR/mois en éteignant les ressources hors démo. Tout est géré via Terraform avec un backend distant sécurisé."

**Avec local uniquement, vous devez dire** :
> "J'ai validé l'infrastructure Terraform localement mais je n'ai pas déployé sur Azure pour des raisons de budget."

→ **La première réponse est infiniment plus forte.** 🚀

---

## 💡 Mon conseil

**Investissez les 10-15 EUR/mois** pour 2-3 mois pendant votre recherche d'emploi.

**ROI calculé** :
- Investissement : 30-45 EUR sur 3 mois
- Différence de salaire si vous décrochez le poste : +5k-10k CHF/an
- **ROI : 10,000% minimum** 🎯

C'est le meilleur investissement que vous puissiez faire pour votre carrière cloud.

---

**Besoin d'aide ?** Faites-moi savoir quelle option vous choisissez et je vous guide pour la suite !
