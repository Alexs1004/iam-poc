#!/bin/bash
# ==============================================================================
# IAM-POC Doctor Script
# ==============================================================================
# Performs operational health checks on the environment.
# Checks: .env, Containers, HTTPS Connectivity, Secrets, Audit Log Integrity.
# ==============================================================================

set -uo pipefail

# 🎨 Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Symbols
CHECK="✓"
CROSS="✗"
WARN="!"

echo -e "\n${BLUE}${BOLD}🩺 IAM-POC Doctor${NC} - environment health check\n"

# ------------------------------------------------------------------------------
# 1. Environment Configuration (.env)
# ------------------------------------------------------------------------------
echo -e "${BOLD}1. Checking Configuration (.env)...${NC}"

if [ ! -f .env ]; then
    echo -e "  ${RED}${CROSS} Missing .env file!${NC}"
    echo -e "  > Run 'make ensure-env' to fix."
    exit 1
fi

DEMO_MODE=$(grep -E "^DEMO_MODE=" .env | cut -d'=' -f2 | tr -d ' "' || echo "unknown")
echo -e "  ${GREEN}${CHECK} .env exists${NC} (DEMO_MODE=${DEMO_MODE})"

# ------------------------------------------------------------------------------
# 2. Docker Containers Status
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}2. Checking Container Status...${NC}"

# Define expected containers (service names to display names mapping)
declare -A CONTAINERS=( ["keycloak"]="Keycloak" ["flask-app"]="IAM App" ["reverse-proxy"]="Nginx" )
RUNNING_COUNT=0
TOTAL_CONTAINERS=${#CONTAINERS[@]}

for SERVICE in "${!CONTAINERS[@]}"; do
    NAME=${CONTAINERS[$SERVICE]} 
    # Check if container is running (generic matching because compose project name might vary)
    if docker compose ps --services --filter "status=running" | grep -q "^${SERVICE}$"; then
        echo -e "  ${GREEN}${CHECK} ${NAME} (${SERVICE})${NC} is running"
        ((RUNNING_COUNT++))
    else
        echo -e "  ${RED}${CROSS} ${NAME} (${SERVICE})${NC} is NOT running"
    fi
done

if [ "$RUNNING_COUNT" -lt "$TOTAL_CONTAINERS" ]; then
    echo -e "  ${ORANGE}${WARN} Some services are down. Stack might be incomplete.${NC}"
else
    echo -e "  ${GREEN}${CHECK} All systems operational.${NC}"
fi

# ------------------------------------------------------------------------------
# 3. HTTPS Connectivity
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}3. Checking Connectivity (HTTPS)...${NC}"

# Check Nginx (Self-signed cert accepted with -k)
HTTP_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" https://localhost/health || echo "000")

if [[ "$HTTP_STATUS" =~ ^2 ]]; then
    echo -e "  ${GREEN}${CHECK} https://localhost/health${NC} responded ${HTTP_STATUS}"
elif [ "$HTTP_STATUS" == "000" ]; then
    echo -e "  ${RED}${CROSS} https://localhost/health${NC} is unreachable"
else
    echo -e "  ${ORANGE}${WARN} https://localhost/health${NC} responded ${HTTP_STATUS} (Expected 2xx)"
fi

# ------------------------------------------------------------------------------
# 4. Secrets Integrity
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}4. Checking Secrets Management...${NC}"

SECRETS_DIR=".runtime/secrets"
KEY_VAULT_ENABLED=$(grep -E "^AZURE_USE_KEYVAULT=" .env | cut -d'=' -f2 | tr -d ' "' || echo "false")

if [ "$KEY_VAULT_ENABLED" == "true" ]; then
    SOURCE="Azure Key Vault"
else
    SOURCE="Local Generation (Demo)"
fi
echo -e "  ℹ Source: ${SOURCE}"

if [ -d "$SECRETS_DIR" ]; then
    COUNT=$(find "$SECRETS_DIR" -type f | wc -l)
    if [ "$COUNT" -gt 0 ]; then
        echo -e "  ${GREEN}${CHECK} Secrets directory populated${NC} (${COUNT} files in ${SECRETS_DIR})"
    else
        echo -e "  ${ORANGE}${WARN} Secrets directory exists but is empty.${NC} (Normal if first run or Key Vault error)"
    fi
else
    echo -e "  ${ORANGE}${WARN} Secrets directory missing.${NC} Run 'make quickstart' or 'make load-secrets'."
fi

# ------------------------------------------------------------------------------
# 5. Audit Log Integrity
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}5. Checking Audit Log Integrity (Non-Repudiation)...${NC}"

# Use existing verify logic via make or python directly
if [ -f ".runtime/audit/jml-events.jsonl" ]; then
    # Capture output of python verifier
    if OUTPUT=$(python3 scripts/audit.py 2>&1); then
        echo -e "  ${GREEN}${CHECK} Integrity Check Passed${NC}"
        echo -e "  > ${OUTPUT}"
    else
        echo -e "  ${RED}${CROSS} Integrity Check FAILED${NC}"
        echo -e "  > ${OUTPUT}"
    fi
else
    echo -e "  ${ORANGE}${WARN} No audit logs found.${NC} (Normal if no actions performed yet)"
fi

echo -e "\n${BLUE}${BOLD}Diagnostic Complete.${NC}\n"
