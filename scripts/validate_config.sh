#!/usr/bin/env bash
# Validate .env configuration for common issues

set -euo pipefail

ENV_FILE="${1:-.env}"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "❌ Configuration file not found: $ENV_FILE" >&2
    exit 1
fi

echo "🔍 Validating configuration in $ENV_FILE..."

# Source the env file
set -a
source "$ENV_FILE"
set +a

# Check DEMO_MODE and AZURE_USE_KEYVAULT compatibility
DEMO_MODE="${DEMO_MODE:-false}"
AZURE_USE_KEYVAULT="${AZURE_USE_KEYVAULT:-false}"

if [[ "${DEMO_MODE,,}" == "true" ]] && [[ "${AZURE_USE_KEYVAULT,,}" == "true" ]]; then
    echo "⚠️  WARNING: DEMO_MODE=true is incompatible with AZURE_USE_KEYVAULT=true"
    echo "   The application will automatically force AZURE_USE_KEYVAULT=false at runtime."
    echo "   Recommendation: Set AZURE_USE_KEYVAULT=false in $ENV_FILE"
fi

# Check service client secret in demo mode
if [[ "${DEMO_MODE,,}" == "true" ]]; then
    if [[ -z "${KEYCLOAK_SERVICE_CLIENT_SECRET}" ]]; then
        echo "ℹ️  DEMO_MODE=true: KEYCLOAK_SERVICE_CLIENT_SECRET will default to 'demo-service-secret'"
    fi
    if [[ -z "${KEYCLOAK_ADMIN_PASSWORD}" ]]; then
        echo "ℹ️  DEMO_MODE=true: KEYCLOAK_ADMIN_PASSWORD will default to 'admin'"
    fi
else
    # Production mode checks
    if [[ "${AZURE_USE_KEYVAULT,,}" == "true" ]]; then
        if [[ -z "${AZURE_KEY_VAULT_NAME}" ]]; then
            echo "❌ ERROR: AZURE_USE_KEYVAULT=true requires AZURE_KEY_VAULT_NAME" >&2
            exit 1
        fi
        echo "✅ Production mode with Azure Key Vault: ${AZURE_KEY_VAULT_NAME}"
    else
        if [[ -z "${KEYCLOAK_SERVICE_CLIENT_SECRET}" ]]; then
            echo "❌ ERROR: Production mode without Key Vault requires KEYCLOAK_SERVICE_CLIENT_SECRET" >&2
            exit 1
        fi
        echo "✅ Production mode with direct environment variables"
    fi
fi

# Check required URLs
if [[ -z "${KEYCLOAK_URL}" ]]; then
    echo "⚠️  WARNING: KEYCLOAK_URL is not set"
fi

if [[ -z "${KEYCLOAK_ISSUER}" ]]; then
    echo "⚠️  WARNING: KEYCLOAK_ISSUER is not set"
fi

echo ""
echo "✅ Configuration validation complete"
echo ""
echo "Current mode: $([ "${DEMO_MODE,,}" == "true" ] && echo "DEMO" || echo "PRODUCTION")"
echo "Key Vault:    $([ "${AZURE_USE_KEYVAULT,,}" == "true" ] && echo "ENABLED" || echo "DISABLED")"
echo "Realm:        ${KEYCLOAK_REALM:-demo}"
echo ""
