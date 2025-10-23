#!/usr/bin/env bash
set -Eeuo pipefail

# Colors for logging
readonly GREEN="\033[1;32m"
readonly YELLOW="\033[1;33m"
readonly RED="\033[1;31m"
readonly RESET="\033[0m"

# ─────────────────────────────────────────────────────────────────────────────
# Load secrets from /run/secrets (Docker secrets pattern)
# Priority: /run/secrets > environment variable
# ─────────────────────────────────────────────────────────────────────────────
load_secret_from_file() {
  local secret_name="$1"
  local env_var="$2"
  local secret_file="/run/secrets/${secret_name}"
  
  if [[ -r "$secret_file" ]]; then
    local secret_value
    secret_value=$(cat "$secret_file")
    if [[ -n "$secret_value" ]]; then
      export "${env_var}=${secret_value}"
      echo -e "${GREEN}[entrypoint]${RESET} Loaded ${env_var} from /run/secrets/${secret_name}" >&2
      return 0
    fi
  fi
  return 1
}

# Try to load from /run/secrets first, fallback to environment variable, then demo default
if ! load_secret_from_file "keycloak_admin_password" "KEYCLOAK_ADMIN_PASSWORD"; then
  if [[ -n "${KEYCLOAK_ADMIN_PASSWORD:-}" ]]; then
    echo -e "${YELLOW}[entrypoint]${RESET} Using KEYCLOAK_ADMIN_PASSWORD from environment (fallback)" >&2
  else
    # Demo mode: Use default password
    export KEYCLOAK_ADMIN_PASSWORD="admin"
    echo -e "${YELLOW}[entrypoint]${RESET} Using default KEYCLOAK_ADMIN_PASSWORD='admin' (DEMO MODE)" >&2
  fi
fi

echo -e "${GREEN}[entrypoint]${RESET} Starting Keycloak with admin: ${KEYCLOAK_ADMIN}" >&2

exec /opt/keycloak/bin/kc.sh start-dev --health-enabled=true

