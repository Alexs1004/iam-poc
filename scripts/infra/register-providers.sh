#!/bin/bash
# Register all Azure Resource Providers needed for this project
# Run this once to avoid "SubscriptionNotFound" errors during deployment

set -e

echo "🔧 Registering Azure Resource Providers..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if logged in to Azure
if ! az account show &>/dev/null; then
    echo "❌ Not logged in to Azure. Run 'az login' first."
    exit 1
fi

SUBSCRIPTION_ID=$(az account show --query id -o tsv)
echo "📋 Subscription: $SUBSCRIPTION_ID"
echo ""

# List of providers needed for IAM-POC project
PROVIDERS=(
    "Microsoft.Storage"              # Storage Accounts (Terraform state, Phase C2)
    "Microsoft.OperationalInsights"  # Log Analytics Workspace (Phase C2)
    "Microsoft.Network"              # VNet, Subnets, Private Endpoints (Phase C3)
    "Microsoft.KeyVault"             # Key Vault (Phase C4)
    "Microsoft.Web"                  # App Service Plan, Web Apps (Phase C5)
    "Microsoft.Insights"             # Application Insights, Diagnostics (Phase C6)
)

echo "📝 Providers to register:"
for PROVIDER in "${PROVIDERS[@]}"; do
    echo "  - $PROVIDER"
done
echo ""

# Check current status
echo "🔍 Checking current registration status..."
for PROVIDER in "${PROVIDERS[@]}"; do
    STATE=$(az provider show --namespace "$PROVIDER" --query "registrationState" -o tsv 2>/dev/null || echo "Unknown")
    printf "  %-35s %s\n" "$PROVIDER" "$STATE"
done
echo ""

# Register all providers
echo "📝 Registering providers (this will run in parallel)..."
for PROVIDER in "${PROVIDERS[@]}"; do
    STATE=$(az provider show --namespace "$PROVIDER" --query "registrationState" -o tsv 2>/dev/null || echo "NotRegistered")
    
    if [ "$STATE" = "Registered" ]; then
        echo "  ✅ $PROVIDER already registered"
    else
        echo "  📝 Registering $PROVIDER..."
        az provider register --namespace "$PROVIDER" --output none
    fi
done
echo ""

# Wait for all registrations to complete
echo "⏳ Waiting for all providers to be registered (1-3 minutes)..."
echo "   You can monitor progress: az provider list --output table"
echo ""

ALL_REGISTERED=false
WAIT_COUNT=0
MAX_WAIT=60  # 5 minutes max

while [ "$ALL_REGISTERED" = false ] && [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    ALL_REGISTERED=true
    
    for PROVIDER in "${PROVIDERS[@]}"; do
        STATE=$(az provider show --namespace "$PROVIDER" --query "registrationState" -o tsv)
        
        if [ "$STATE" != "Registered" ]; then
            ALL_REGISTERED=false
            echo "  ⏳ $PROVIDER: $STATE"
        fi
    done
    
    if [ "$ALL_REGISTERED" = false ]; then
        sleep 5
        ((WAIT_COUNT++))
    fi
done

echo ""

if [ "$ALL_REGISTERED" = true ]; then
    echo "✅ All providers registered successfully!"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "📝 Final status:"
    for PROVIDER in "${PROVIDERS[@]}"; do
        STATE=$(az provider show --namespace "$PROVIDER" --query "registrationState" -o tsv)
        printf "  ✅ %-35s %s\n" "$PROVIDER" "$STATE"
    done
    echo ""
    echo "🚀 You can now deploy Azure resources without provider errors!"
    echo ""
    echo "Next steps:"
    echo "  1. Setup Terraform backend: ./scripts/infra/setup-backend.sh"
    echo "  2. Initialize Terraform: make infra/init"
    echo "  3. Deploy infrastructure: make infra/apply"
else
    echo "⚠️  Provider registration timed out after 5 minutes."
    echo "   This is normal for the first registration."
    echo "   Please wait a few more minutes and check status:"
    echo ""
    echo "   az provider list --query \"[?registrationState=='Registering'].namespace\" -o table"
    echo ""
    echo "   Re-run this script to verify all are registered."
    exit 1
fi
