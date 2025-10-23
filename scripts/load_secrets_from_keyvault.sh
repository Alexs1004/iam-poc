#!/usr/bin/env bash
# Load secrets from Azure Key Vault and write them to /run/secrets pattern
# This script is called by the Makefile before starting Docker containers
#
# Security features:
# - Validates Azure CLI authentication before accessing Key Vault
# - Creates secret files in .runtime/secrets/ with restrictive permissions (400)
# - Logs secret loading without exposing values
# - Provides graceful fallback for missing secrets
# - Compatible with Docker Swarm and Kubernetes secret patterns

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
SECRETS_DIR="${PROJECT_ROOT}/.runtime/secrets"

# Colors for logging
readonly GREEN="\033[1;32m"
readonly YELLOW="\033[1;33m"
readonly RED="\033[1;31m"
readonly BLUE="\033[1;34m"
readonly RESET="\033[0m"

# Load environment from .env
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
  set -a
  source "${PROJECT_ROOT}/.env"
  set +a
fi

# Check if Key Vault is enabled
USE_KEYVAULT="${AZURE_USE_KEYVAULT:-false}"

if [[ "${USE_KEYVAULT,,}" != "true" ]]; then
  echo -e "${YELLOW}[keyvault] Skipping Azure Key Vault (AZURE_USE_KEYVAULT != true)${RESET}"
  exit 0
fi

# Validate required environment variables
VAULT_NAME="${AZURE_KEY_VAULT_NAME:?AZURE_KEY_VAULT_NAME is required when AZURE_USE_KEYVAULT=true}"

echo -e "${BLUE}[keyvault] Loading secrets from Azure Key Vault: ${VAULT_NAME}${RESET}"

# Validate Azure CLI is installed
if ! command -v az >/dev/null 2>&1; then
  echo -e "${RED}[keyvault] ERROR: Azure CLI is not installed${RESET}"
  echo -e "${RED}[keyvault] Install: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli${RESET}"
  exit 1
fi

# Validate Azure authentication
if ! az account show >/dev/null 2>&1; then
  echo -e "${RED}[keyvault] ERROR: Not authenticated to Azure${RESET}"
  echo -e "${RED}[keyvault] Run: az login${RESET}"
  exit 1
fi

echo -e "${GREEN}[keyvault] Azure authentication validated${RESET}"

# Create secrets directory with strict permissions
if [[ -d "$SECRETS_DIR" ]]; then
  echo -e "${YELLOW}[keyvault] Cleaning existing secrets directory${RESET}"
  rm -rf "$SECRETS_DIR"
fi

mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

echo -e "${BLUE}[keyvault] Secrets directory: ${SECRETS_DIR} (chmod 700)${RESET}"

# Function to write a secret to a file
write_secret_file() {
  local secret_name="$1"
  local file_name="$2"
  local required="${3:-true}"
  local file_path="${SECRETS_DIR}/${file_name}"
  
  # Retrieve from Key Vault
  local secret_value
  if secret_value=$(az keyvault secret show \
    --vault-name "$VAULT_NAME" \
    --name "$secret_name" \
    --query "value" \
    --output tsv 2>/dev/null); then
    
    if [[ -n "$secret_value" ]]; then
      # Write secret to file with strict permissions
      echo -n "$secret_value" > "$file_path"
      chmod 400 "$file_path"  # Read-only for owner
      echo -e "${GREEN}[keyvault] ✓ ${file_name} loaded${RESET}" >&2
      return 0
    fi
  fi
  
  # Handle missing secret
  if [[ "$required" == "true" ]]; then
    echo -e "${RED}[keyvault] ✗ REQUIRED secret ${secret_name} not found${RESET}"
    return 1
  else
    echo -e "${YELLOW}[keyvault] ⚠ Optional secret ${secret_name} not found${RESET}"
    return 0
  fi
}

# Load all secrets and write to files
echo -e "${BLUE}[keyvault] Retrieving secrets from Azure Key Vault...${RESET}"

# Required secrets
write_secret_file "keycloak-admin-password" "keycloak_admin_password" "true"
write_secret_file "keycloak-service-client-secret" "keycloak_service_client_secret" "true"
write_secret_file "flask-secret-key" "flask_secret_key" "true"
write_secret_file "audit-log-signing-key" "audit_log_signing_key" "true"

# Optional secrets (user temporary passwords)
write_secret_file "alice-temp-password" "alice_temp_password" "false"
write_secret_file "bob-temp-password" "bob_temp_password" "false"
write_secret_file "carol-temp-password" "carol_temp_password" "false"
write_secret_file "joe-temp-password" "joe_temp_password" "false"

# Display summary
echo ""
echo -e "${GREEN}[keyvault] ✓ All secrets written to ${SECRETS_DIR}/ (chmod 400)${RESET}"
echo -e "${GREEN}[keyvault] ✓ Secrets will be mounted as /run/secrets in containers${RESET}"
echo ""
echo -e "${BLUE}[keyvault] Next steps:${RESET}"
echo -e "${BLUE}[keyvault]   1. Verify secrets: ls -la ${SECRETS_DIR}${RESET}"
echo -e "${BLUE}[keyvault]   2. Start containers: docker-compose up -d${RESET}"
echo -e "${BLUE}[keyvault]   3. Bootstrap realm: bash scripts/demo_jml.sh${RESET}"
