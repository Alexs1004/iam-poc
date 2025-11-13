#!/bin/bash
# Configure Terraform for local-only mode (no Azure deployment)
# Use this if Azure subscription is not available

set -e

echo "🔧 Configuring Terraform for local-only mode..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "⚠️  WARNING: This will disable Azure backend and remote state."
echo "   You won't be able to deploy to Azure, but you can:"
echo "   - Validate Terraform syntax"
echo "   - Generate execution plans"
echo "   - Demonstrate infrastructure code structure"
echo ""

read -p "Continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

BACKEND_FILE="infra/backend.tf"
BACKEND_BACKUP="infra/backend.tf.azure"

# Backup original backend.tf
if [ -f "$BACKEND_FILE" ]; then
    echo "📦 Backing up $BACKEND_FILE to $BACKEND_BACKUP"
    cp "$BACKEND_FILE" "$BACKEND_BACKUP"
fi

# Create local backend configuration
cat > "$BACKEND_FILE" <<'EOF'
# Backend configuration for Terraform state (LOCAL MODE)
# 
# ⚠️ WARNING: This is for local development/testing only.
# For production, use Azure Storage backend (see backend.tf.azure)
#
# To restore Azure backend:
#   mv infra/backend.tf.azure infra/backend.tf
#   terraform init -migrate-state

terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# Original Azure backend (commented out):
# terraform {
#   backend "azurerm" {
#     # Configuration via backend.hcl
#   }
# }
EOF

echo "✅ Local backend configured"
echo ""
echo "📝 Next steps:"
echo ""
echo "1. Initialize Terraform (local state):"
echo "   cd infra && terraform init"
echo ""
echo "2. Validate configuration:"
echo "   terraform validate"
echo ""
echo "3. Generate plan (dry-run, won't create resources):"
echo "   terraform plan -var='tenant_id=00000000-0000-0000-0000-000000000000'"
echo ""
echo "4. To restore Azure backend later:"
echo "   mv infra/backend.tf.azure infra/backend.tf"
echo "   terraform init -migrate-state"
echo ""
echo "⚠️  Remember: This is for LEARNING ONLY."
echo "   In interviews, mention you understand the limitations of local state."
