#!/bin/bash
# Upload ARM_CLIENT_SECRET to Azure Key Vault
# Usage: ./upload-terraform-secret.sh <service-principal-secret>

set -e

VAULT_NAME="${AZURE_KEY_VAULT_NAME}"
SECRET_NAME="arm-client-secret"

if [ -z "$VAULT_NAME" ]; then
    echo "❌ AZURE_KEY_VAULT_NAME not set in .env"
    exit 1
fi

if [ -z "$1" ]; then
    echo "Usage: $0 <arm-client-secret-value>"
    echo ""
    echo "Example:"
    echo "  # Create Service Principal"
    echo "  az ad sp create-for-rbac --name iam-poc-terraform --role Contributor --scopes /subscriptions/\$(az account show --query id -o tsv)"
    echo ""
    echo "  # Upload the secret"
    echo "  ./scripts/upload-terraform-secret.sh '<secret-from-above-command>'"
    exit 1
fi

ARM_CLIENT_SECRET="$1"

echo "🔐 Uploading ARM_CLIENT_SECRET to Azure Key Vault"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check Azure CLI auth
if ! az account show &>/dev/null; then
    echo "❌ Not logged in to Azure. Run 'az login' first."
    exit 1
fi

echo "📥 Uploading secret: $SECRET_NAME to $VAULT_NAME..."

az keyvault secret set \
    --vault-name "$VAULT_NAME" \
    --name "$SECRET_NAME" \
    --value "$ARM_CLIENT_SECRET" \
    --output none

echo "✅ Secret uploaded successfully!"
echo ""
echo "🔄 Next steps:"
echo "  1. Load secrets: ./scripts/load_secrets_from_keyvault.sh"
echo "  2. Verify: ls -la .runtime/secrets/arm_client_secret"
echo "  3. Use Terraform: cd infra && make init"
