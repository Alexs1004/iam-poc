#!/usr/bin/env bash
# Script to validate and auto-correct .env configuration
# Ensures DEMO_MODE=true implies AZURE_USE_KEYVAULT=false

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
ENV_FILE="${PROJECT_ROOT}/.env"

if [[ ! -f "${ENV_FILE}" ]]; then
    echo "Error: .env file not found at ${ENV_FILE}"
    exit 1
fi

# Read current values
DEMO_MODE=$(grep -E "^DEMO_MODE=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d ' ' || echo "false")
AZURE_USE_KEYVAULT=$(grep -E "^AZURE_USE_KEYVAULT=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d ' ' || echo "false")

echo "Current configuration:"
echo "  DEMO_MODE=${DEMO_MODE}"
echo "  AZURE_USE_KEYVAULT=${AZURE_USE_KEYVAULT}"

# Check if correction is needed
if [[ "${DEMO_MODE,,}" == "true" ]] && [[ "${AZURE_USE_KEYVAULT,,}" == "true" ]]; then
    echo ""
    echo "⚠️  WARNING: DEMO_MODE=true is incompatible with AZURE_USE_KEYVAULT=true"
    echo "   Auto-correcting: Setting AZURE_USE_KEYVAULT=false in .env"
    
    # Create backup
    cp "${ENV_FILE}" "${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Fix the configuration
    sed -i.tmp 's/^AZURE_USE_KEYVAULT=true/AZURE_USE_KEYVAULT=false/' "${ENV_FILE}"
    rm -f "${ENV_FILE}.tmp"
    
    echo "✅ Configuration corrected!"
    echo ""
elif [[ "${DEMO_MODE,,}" == "true" ]]; then
    echo "✅ Configuration is valid (DEMO_MODE=true, AZURE_USE_KEYVAULT=false)"
    echo ""
else
    echo "✅ Configuration is valid (Production mode)"
    echo ""
fi
