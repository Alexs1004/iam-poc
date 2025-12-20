#!/usr/bin/env bash
# =============================================================================
# load_env.sh - Environment loader with Azure Key Vault support
# =============================================================================
# Usage: source scripts/load_env.sh
#        or: eval "$(scripts/load_env.sh --export)"
#
# This script:
# 1. Loads .env file
# 2. Fetches secrets from Azure Key Vault if AZURE_USE_KEYVAULT=true
# 3. Exports all required environment variables
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[load_env]${NC} $*" >&2; }
log_warn()  { echo -e "${YELLOW}[load_env]${NC} $*" >&2; }
log_error() { echo -e "${RED}[load_env]${NC} $*" >&2; }

# Check if .env exists
if [[ ! -f .env ]]; then
    log_error ".env file not found. Run 'make ensure-env' first."
    exit 1
fi

# Load .env
set -a
# shellcheck disable=SC1091
source .env
set +a

# Check if Azure Key Vault is enabled
shopt -s nocasematch
if [[ "${AZURE_USE_KEYVAULT:-}" == "true" ]]; then
    log_info "Azure Key Vault mode enabled"

    # Validate required config
    if [[ -z "${AZURE_KEY_VAULT_NAME:-}" ]]; then
        log_error "AZURE_KEY_VAULT_NAME is required when AZURE_USE_KEYVAULT=true."
        exit 1
    fi

    if ! command -v az >/dev/null 2>&1; then
        log_error "Azure CLI is required when AZURE_USE_KEYVAULT=true."
        exit 1
    fi

    # Helper function to fetch secrets
    fetch_secret() {
        local name="$1"
        if [[ -z "$name" ]]; then
            echo ""
            return 0
        fi
        az keyvault secret show \
            --vault-name "${AZURE_KEY_VAULT_NAME}" \
            --name "$name" \
            --query value -o tsv 2>/dev/null || echo ""
    }

    # Fetch missing secrets from Key Vault
    declare -A SECRETS_MAP=(
        ["KEYCLOAK_SERVICE_CLIENT_SECRET"]="${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET:-}"
        ["KEYCLOAK_ADMIN_PASSWORD"]="${AZURE_SECRET_KEYCLOAK_ADMIN_PASSWORD:-}"
        ["ALICE_TEMP_PASSWORD"]="${AZURE_SECRET_ALICE_TEMP_PASSWORD:-}"
        ["BOB_TEMP_PASSWORD"]="${AZURE_SECRET_BOB_TEMP_PASSWORD:-}"
        ["AUDIT_LOG_SIGNING_KEY"]="${AZURE_SECRET_AUDIT_LOG_SIGNING_KEY:-}"
    )

    for var_name in "${!SECRETS_MAP[@]}"; do
        kv_secret_name="${SECRETS_MAP[$var_name]}"
        current_value="${!var_name:-}"
        
        if [[ -z "$current_value" && -n "$kv_secret_name" ]]; then
            log_info "Fetching $var_name from Key Vault..."
            value=$(fetch_secret "$kv_secret_name")
            if [[ -n "$value" ]]; then
                export "$var_name=$value"
                log_info "✓ $var_name loaded from Key Vault"
            else
                log_warn "⚠ $var_name not found in Key Vault"
            fi
        fi
    done
else
    log_info "Local mode (AZURE_USE_KEYVAULT=${AZURE_USE_KEYVAULT:-false})"
fi
shopt -u nocasematch

log_info "Environment loaded successfully"
