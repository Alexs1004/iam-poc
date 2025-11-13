#!/bin/bash
# Setup Azure Storage backend for Terraform state
# This script creates the infrastructure needed to store Terraform state securely

set -e

RESOURCE_GROUP_NAME="tfstate-rg"
STORAGE_ACCOUNT_NAME="tfstateiam$(date +%s)"  # Add timestamp for uniqueness
CONTAINER_NAME="tfstate"
LOCATION="switzerlandnorth"

echo "🔧 Creating Terraform backend infrastructure..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if logged in to Azure
if ! az account show &>/dev/null; then
    echo "❌ Not logged in to Azure. Run 'az login' first."
    exit 1
fi

SUBSCRIPTION_ID=$(az account show --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)

echo "📋 Subscription: $SUBSCRIPTION_ID"
echo "📋 Tenant: $TENANT_ID"
echo ""

# Create resource group
echo "📦 Creating resource group: $RESOURCE_GROUP_NAME"
az group create \
    --name "$RESOURCE_GROUP_NAME" \
    --location "$LOCATION" \
    --tags "Purpose=TerraformState" "Project=IAM-POC" "ManagedBy=Script"

# Create storage account with security features
echo "🗄️  Creating storage account: $STORAGE_ACCOUNT_NAME"
az storage account create \
    --name "$STORAGE_ACCOUNT_NAME" \
    --resource-group "$RESOURCE_GROUP_NAME" \
    --location "$LOCATION" \
    --sku Standard_LRS \
    --encryption-services blob \
    --https-only true \
    --min-tls-version TLS1_2 \
    --allow-blob-public-access false \
    --tags "Purpose=TerraformState" "Project=IAM-POC"

# Enable versioning (rollback capability)
echo "📚 Enabling blob versioning..."
az storage account blob-service-properties update \
    --account-name "$STORAGE_ACCOUNT_NAME" \
    --resource-group "$RESOURCE_GROUP_NAME" \
    --enable-versioning true

# Enable soft delete (compliance requirement)
echo "🛡️  Enabling soft delete (30 days retention)..."
az storage account blob-service-properties update \
    --account-name "$STORAGE_ACCOUNT_NAME" \
    --resource-group "$RESOURCE_GROUP_NAME" \
    --enable-delete-retention true \
    --delete-retention-days 30

# Create blob container
echo "📂 Creating blob container: $CONTAINER_NAME"
az storage container create \
    --name "$CONTAINER_NAME" \
    --account-name "$STORAGE_ACCOUNT_NAME" \
    --auth-mode login

# Get storage account key (needed for Terraform backend auth)
ACCOUNT_KEY=$(az storage account keys list \
    --resource-group "$RESOURCE_GROUP_NAME" \
    --account-name "$STORAGE_ACCOUNT_NAME" \
    --query '[0].value' -o tsv)

echo ""
echo "✅ Backend infrastructure created successfully!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📝 Next steps:"
echo ""
echo "1. Create backend.hcl file:"
echo "   cat > infra/backend.hcl <<EOF"
echo "resource_group_name  = \"$RESOURCE_GROUP_NAME\""
echo "storage_account_name = \"$STORAGE_ACCOUNT_NAME\""
echo "container_name       = \"$CONTAINER_NAME\""
echo "key                  = \"iam-poc.terraform.tfstate\""
echo "EOF"
echo ""
echo "2. Initialize Terraform with backend:"
echo "   terraform -chdir=infra init -backend-config=backend.hcl"
echo ""
echo "3. (Optional) Set environment variable for authentication:"
echo "   export ARM_ACCESS_KEY=\"$ACCOUNT_KEY\""
echo "   # Or use Azure CLI auth (recommended): az login"
echo ""
echo "🔐 Security features enabled:"
echo "   ✓ Encryption at rest (AES-256)"
echo "   ✓ HTTPS only (TLS 1.2+)"
echo "   ✓ Blob versioning (rollback capability)"
echo "   ✓ Soft delete (30 days retention)"
echo "   ✓ Public access disabled"
echo ""
echo "📍 Location: $LOCATION (Switzerland - LPD/FINMA compliant)"
