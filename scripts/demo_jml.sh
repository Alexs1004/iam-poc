#!/usr/bin/env bash
set -e

BLUE="\033[1;34m"
YELLOW="\033[1;33m"
GREEN="\033[1;32m"
PURPLE="\033[1;35m"
RED="\033[1;31m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
cd "${PROJECT_ROOT}"

# Allow overriding the python interpreter via $PYTHON, defaulting to python3.
PYTHON_BIN=${PYTHON:-python3}
JML_CMD="${PYTHON_BIN} ${SCRIPT_DIR}/jml.py"

# Load environment variables from .env if it exists
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
  set -a
  source "${PROJECT_ROOT}/.env"
  set +a
fi

# Enforce DEMO_MODE consistency: Demo mode must never use Azure Key Vault
# This is a safety guard; normally validate_env.sh should correct .env via `make` targets
if [[ "${DEMO_MODE,,}" == "true" ]]; then
  if [[ "${AZURE_USE_KEYVAULT,,}" == "true" ]]; then
    echo "[demo] WARNING: DEMO_MODE=true requires AZURE_USE_KEYVAULT=false (runtime guard)"
    echo "[demo] Forcing AZURE_USE_KEYVAULT=false | Run 'make validate-env' to fix .env permanently"
    export AZURE_USE_KEYVAULT="false"
  fi
fi

# Priority order for sensitive data:
# 1. Environment variables (if already set)
# 2. Demo defaults (if DEMO_MODE=true)
# 3. Azure Key Vault (if AZURE_USE_KEYVAULT=true and variables still unset)

# Step 1: Apply demo defaults if DEMO_MODE=true
if [[ "${DEMO_MODE,,}" == "true" ]]; then
  # Priority: 1. Already set env var, 2. *_DEMO var, 3. Hardcoded fallback
  ALICE_TEMP_PASSWORD="${ALICE_TEMP_PASSWORD:-${ALICE_TEMP_PASSWORD_DEMO:-Passw0rd!}}"
  BOB_TEMP_PASSWORD="${BOB_TEMP_PASSWORD:-${BOB_TEMP_PASSWORD_DEMO:-Passw0rd!}}"
  CAROL_TEMP_PASSWORD="${CAROL_TEMP_PASSWORD:-${CAROL_TEMP_PASSWORD_DEMO:-Passw0rd!}}"
  JOE_TEMP_PASSWORD="${JOE_TEMP_PASSWORD:-${JOE_TEMP_PASSWORD_DEMO:-Passw0rd!}}"
  echo "[demo] Using demo default passwords (DEMO_MODE=true)"
fi

# Step 2: Fetch from Key Vault only if still unset and AZURE_USE_KEYVAULT=true
if [[ -z "${ALICE_TEMP_PASSWORD:-}" || -z "${BOB_TEMP_PASSWORD:-}" || -z "${CAROL_TEMP_PASSWORD:-}" || -z "${JOE_TEMP_PASSWORD:-}" ]]; then
  if [[ "${AZURE_USE_KEYVAULT,,}" == "true" ]]; then
    if ! command -v az >/dev/null 2>&1; then
      echo "[demo] Azure CLI is required to fetch secrets from Key Vault when environment variables are unset." >&2
      exit 1
    fi
    fetch_secret() {
      local secret_name="$1"
      if [[ -z "${secret_name}" ]]; then
        echo ""
        return 0
      fi
      az keyvault secret show \
        --vault-name "${AZURE_KEY_VAULT_NAME}" \
        --name "${secret_name}" \
        --query value \
        -o tsv
    }
    if [[ -z "${ALICE_TEMP_PASSWORD:-}" ]]; then
      ALICE_TEMP_PASSWORD="$(fetch_secret "${AZURE_SECRET_ALICE_TEMP_PASSWORD}")"
      export ALICE_TEMP_PASSWORD
    fi
    if [[ -z "${BOB_TEMP_PASSWORD:-}" ]]; then
      BOB_TEMP_PASSWORD="$(fetch_secret "${AZURE_SECRET_BOB_TEMP_PASSWORD}")"
      export BOB_TEMP_PASSWORD
    fi
    if [[ -z "${CAROL_TEMP_PASSWORD:-}" ]]; then
      CAROL_TEMP_PASSWORD="$(fetch_secret "${AZURE_SECRET_CAROL_TEMP_PASSWORD}")"
      export CAROL_TEMP_PASSWORD
    fi
    if [[ -z "${JOE_TEMP_PASSWORD:-}" ]]; then
      JOE_TEMP_PASSWORD="$(fetch_secret "${AZURE_SECRET_JOE_TEMP_PASSWORD}")"
      export JOE_TEMP_PASSWORD
    fi
    echo "[production] User passwords loaded from Azure Key Vault"
  fi
fi

if [[ -z "${ALICE_TEMP_PASSWORD:-}" ]]; then
  echo "[demo] ALICE_TEMP_PASSWORD is required; set it in the environment or store it in Key Vault." >&2
  exit 1
fi
if [[ -z "${BOB_TEMP_PASSWORD:-}" ]]; then
  echo "[demo] BOB_TEMP_PASSWORD is required; set it in the environment or store it in Key Vault." >&2
  exit 1
fi
if [[ -z "${CAROL_TEMP_PASSWORD:-}" ]]; then
  echo "[demo] CAROL_TEMP_PASSWORD is required; set it in the environment or store it in Key Vault." >&2
  exit 1
fi
if [[ -z "${JOE_TEMP_PASSWORD:-}" ]]; then
  echo "[demo] JOE_TEMP_PASSWORD is required; set it in the environment or store it in Key Vault." >&2
  exit 1
fi

# Load service client secret
if [[ "${DEMO_MODE,,}" == "true" ]]; then
  # Demo mode: use fixed secret
  if [[ -z "${KEYCLOAK_SERVICE_CLIENT_SECRET:-}" ]]; then
    KEYCLOAK_SERVICE_CLIENT_SECRET="demo-service-secret"
    echo "[demo] Using demo default for KEYCLOAK_SERVICE_CLIENT_SECRET"
  fi
else
  # Production mode: load from Key Vault if not set
  if [[ -z "${KEYCLOAK_SERVICE_CLIENT_SECRET:-}" ]]; then
    if [[ "${AZURE_USE_KEYVAULT,,}" == "true" ]]; then
      if ! command -v az >/dev/null 2>&1; then
        echo "[production] Azure CLI is required to fetch service secret from Key Vault." >&2
        exit 1
      fi
      KEYCLOAK_SERVICE_CLIENT_SECRET=$(az keyvault secret show \
        --vault-name "${AZURE_KEY_VAULT_NAME}" \
        --name "${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET}" \
        --query value \
        -o tsv 2>/dev/null || echo "")
      if [[ -n "${KEYCLOAK_SERVICE_CLIENT_SECRET}" ]]; then
        echo "[production] Service client secret loaded from Azure Key Vault"
        export KEYCLOAK_SERVICE_CLIENT_SECRET
      fi
    fi
  fi
fi

KC_URL=${KEYCLOAK_URL_HOST:?Variable KEYCLOAK_URL_HOST required}
KC_SERVICE_REALM=${KEYCLOAK_SERVICE_REALM:-demo}
KC_SERVICE_CLIENT_ID=${KEYCLOAK_SERVICE_CLIENT_ID:?Variable KEYCLOAK_SERVICE_CLIENT_ID required}
KC_SERVICE_CLIENT_SECRET=${KEYCLOAK_SERVICE_CLIENT_SECRET:?Variable KEYCLOAK_SERVICE_CLIENT_SECRET required}
REALM=${KEYCLOAK_REALM:-demo}
CLIENT_ID=${OIDC_CLIENT_ID:?Variable OIDC_CLIENT_ID required}
REDIRECT_URI=${OIDC_REDIRECT_URI:?Variable OIDC_REDIRECT_URI required}
POST_LOGOUT_REDIRECT_URI=${POST_LOGOUT_REDIRECT_URI:?Variable POST_LOGOUT_REDIRECT_URI required}
ALICE_TEMP=${ALICE_TEMP_PASSWORD:?Variable ALICE_TEMP_PASSWORD required}
BOB_TEMP=${BOB_TEMP_PASSWORD:?Variable BOB_TEMP_PASSWORD required}
CAROL_TEMP=${CAROL_TEMP_PASSWORD:?Variable CAROL_TEMP_PASSWORD required}
JOE_TEMP=${JOE_TEMP_PASSWORD:?Variable JOE_TEMP_PASSWORD required}

# Bootstrap: Create automation-cli client if needed
printf "%b\n" "${BLUE}=== Bootstrap automation service account ===${RESET}"

if [[ "${DEMO_MODE,,}" == "true" ]]; then
  # Demo mode: Use fixed secret and restore it after bootstrap
  export KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
  export KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
  DEMO_FIXED_SECRET="${KEYCLOAK_SERVICE_CLIENT_SECRET:-demo-service-secret}"
  
  NEW_SECRET=$(${JML_CMD} --kc-url "${KC_URL}" --auth-realm master --svc-client-id "${KC_SERVICE_CLIENT_ID}" bootstrap-service-account --realm "${REALM}" --admin-user "${KEYCLOAK_ADMIN}" --admin-pass "${KEYCLOAK_ADMIN_PASSWORD}")
  
  if [[ -z "${NEW_SECRET}" ]]; then
    echo "[demo] Failed to bootstrap service account" >&2
    exit 1
  fi
  
  # Restore the fixed secret for consistency with Flask
  echo "[demo] Restoring demo-mode fixed secret for consistency with Flask..."
  # Use the admin token to set the client secret back to the demo default
  ADMIN_TOKEN=$(curl -s -X POST "${KC_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${KEYCLOAK_ADMIN}" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" | ${PYTHON_BIN} -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
  
  # Get the client's internal ID and current representation
  CLIENT_INTERNAL_ID=$(curl -s -X GET "${KC_URL}/admin/realms/${REALM}/clients?clientId=${KC_SERVICE_CLIENT_ID}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" | ${PYTHON_BIN} -c "import sys,json; clients=json.load(sys.stdin); print(clients[0]['id'] if clients else '')")
  
  if [[ -n "${CLIENT_INTERNAL_ID}" ]]; then
    # Get the full client representation
    CLIENT_JSON=$(curl -s -X GET "${KC_URL}/admin/realms/${REALM}/clients/${CLIENT_INTERNAL_ID}" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}")
    
    # Update the client with the fixed secret
    echo "${CLIENT_JSON}" | ${PYTHON_BIN} -c "import sys,json; data=json.load(sys.stdin); data['secret']='${DEMO_FIXED_SECRET}'; json.dump(data, sys.stdout)" | \
      curl -s -X PUT "${KC_URL}/admin/realms/${REALM}/clients/${CLIENT_INTERNAL_ID}" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d @- > /dev/null
    
    KC_SERVICE_CLIENT_SECRET="${DEMO_FIXED_SECRET}"
    echo "[demo] Service account secret restored to demo default (${DEMO_FIXED_SECRET})"
  else
    echo "[demo] Warning: Could not restore demo secret, using rotated secret" >&2
    KC_SERVICE_CLIENT_SECRET="${NEW_SECRET}"
  fi
else
  # Production mode: Use the secret from Key Vault (already loaded in KEYCLOAK_SERVICE_CLIENT_SECRET)
  # Check if the client already exists
  export KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:?KEYCLOAK_ADMIN required}"
  export KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:?KEYCLOAK_ADMIN_PASSWORD required}"
  
  ADMIN_TOKEN=$(curl -s -X POST "${KC_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${KEYCLOAK_ADMIN}" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" | ${PYTHON_BIN} -c "import sys,json; print(json.load(sys.stdin).get('access_token', ''))" 2>/dev/null)
  
  if [[ -n "${ADMIN_TOKEN}" ]]; then
    # Check if realm exists first
    REALM_EXISTS=$(curl -s -X GET "${KC_URL}/admin/realms/${REALM}" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null | ${PYTHON_BIN} -c "import sys,json; data=json.load(sys.stdin); print('yes' if data.get('realm') else 'no')" 2>/dev/null || echo "no")
    
    if [[ "${REALM_EXISTS}" == "yes" ]]; then
      # Realm exists, check if client exists
      CLIENT_EXISTS=$(curl -s -X GET "${KC_URL}/admin/realms/${REALM}/clients?clientId=${KC_SERVICE_CLIENT_ID}" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null | ${PYTHON_BIN} -c "import sys,json; print('yes' if json.load(sys.stdin) else 'no')" 2>/dev/null || echo "no")
      
      if [[ "${CLIENT_EXISTS}" == "yes" ]]; then
        echo "[production] Service account client already exists, using Key Vault secret"
        KC_SERVICE_CLIENT_SECRET="${KEYCLOAK_SERVICE_CLIENT_SECRET:?KEYCLOAK_SERVICE_CLIENT_SECRET required from Key Vault}"
      else
        # Realm exists but client doesn't, create it with bootstrap
        echo "[production] Service account client doesn't exist, creating with bootstrap..."
        NEW_SECRET=$(${JML_CMD} --kc-url "${KC_URL}" --auth-realm master --svc-client-id "${KC_SERVICE_CLIENT_ID}" bootstrap-service-account --realm "${REALM}" --admin-user "${KEYCLOAK_ADMIN}" --admin-pass "${KEYCLOAK_ADMIN_PASSWORD}")
        
        if [[ -z "${NEW_SECRET}" ]]; then
          echo "[production] Failed to bootstrap service account" >&2
          exit 1
        fi
        
        # Automatically update Azure Key Vault with the new secret
        echo "[production] Service account created successfully"
        echo "[production] Updating Azure Key Vault secret '${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET}'..."
        if az keyvault secret set \
          --vault-name "${AZURE_KEY_VAULT_NAME}" \
          --name "${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET}" \
          --value "${NEW_SECRET}" \
          --only-show-errors >/dev/null 2>&1; then
          echo "[production] ✅ Azure Key Vault updated successfully"
          echo "[production] Restart Flask to load the new secret: make restart-flask"
        else
          echo "[production] ❌ Failed to update Azure Key Vault" >&2
          echo "[production] Manually update secret '${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET}' in Key Vault" >&2
          exit 1
        fi
        
        KC_SERVICE_CLIENT_SECRET="${NEW_SECRET}"
      fi
    else
      # Realm doesn't exist yet - this is initial setup
      # We'll bootstrap after creating the realm (see below)
      echo "[production] Realm doesn't exist yet, will bootstrap service account after realm creation"
      KC_SERVICE_CLIENT_SECRET=""  # Will be set after bootstrap
      NEEDS_BOOTSTRAP=true
    fi
  else
    # Can't check, assume everything exists and use Key Vault secret
    echo "[production] Using service account secret from Key Vault"
    KC_SERVICE_CLIENT_SECRET="${KEYCLOAK_SERVICE_CLIENT_SECRET:?KEYCLOAK_SERVICE_CLIENT_SECRET required from Key Vault}"
  fi
fi

# Handle initial setup when realm doesn't exist
if [[ "${NEEDS_BOOTSTRAP:-false}" == "true" ]]; then
  printf "%b\n" "${BLUE}=== Initial setup: Bootstrapping service account (creates realm) ===${RESET}"
  
  # Bootstrap will create the realm AND the service account client
  NEW_SECRET=$(${JML_CMD} --kc-url "${KC_URL}" --auth-realm master --svc-client-id "${KC_SERVICE_CLIENT_ID}" bootstrap-service-account --realm "${REALM}" --admin-user "${KEYCLOAK_ADMIN}" --admin-pass "${KEYCLOAK_ADMIN_PASSWORD}")
  
  if [[ -z "${NEW_SECRET}" ]]; then
    echo "[production] Failed to bootstrap service account" >&2
    exit 1
  fi
  
  echo "[production] Realm '${REALM}' and service account created successfully"
  
  # Automatically update Azure Key Vault with the new secret
  echo "[production] Updating Azure Key Vault secret '${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET}'..."
  if az keyvault secret set \
    --vault-name "${AZURE_KEY_VAULT_NAME}" \
    --name "${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET}" \
    --value "${NEW_SECRET}" \
    --only-show-errors >/dev/null 2>&1; then
    echo "[production] ✅ Azure Key Vault updated successfully"
    echo "[production] Restart Flask to load the new secret: make restart-flask"
  else
    echo "[production] ❌ Failed to update Azure Key Vault" >&2
    echo "[production] Manually update secret '${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET}' in Key Vault" >&2
    exit 1
  fi
  
  KC_SERVICE_CLIENT_SECRET="${NEW_SECRET}"
fi

# For remaining operations, use service account against the realm
COMMON_FLAGS=(
  "--kc-url" "${KC_URL}"
  "--auth-realm" "${REALM}"
  "--svc-client-id" "${KC_SERVICE_CLIENT_ID}"
  "--svc-client-secret" "${KC_SERVICE_CLIENT_SECRET}"
)

# Always run init to create client, roles, and required actions
# (bootstrap only creates the realm and service account, not the application roles)
printf "%b\n" "${BLUE}=== Création du realm et du client public ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" init --realm "${REALM}" --client-id "${CLIENT_ID}" --redirect-uri "${REDIRECT_URI}" --post-logout-redirect-uri "${POST_LOGOUT_REDIRECT_URI}"

printf "%b\n" "${YELLOW}=== Provision de l'utilisatrice alice (joiner) ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" joiner --realm "${REALM}" --username alice --email alice@example.com --first Alice --last Demo --role analyst --temp-password "${ALICE_TEMP}"

printf "%b\n" "${YELLOW}=== Provision de l'utilisateur bob (joiner) ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" joiner --realm "${REALM}" --username bob --email bob@example.com --first Bob --last Demo --role analyst --temp-password "${BOB_TEMP}"

printf "%b\n" "${YELLOW}=== Provision de l'utilisatrice carol (joiner) ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" joiner --realm "${REALM}" --username carol --email carol@example.com --first Carol --last Demo --role manager --temp-password "${CAROL_TEMP}" --no-totp

printf "%b\n" "${YELLOW}=== Provision de l'utilisateur joe (joiner) ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" joiner --realm "${REALM}" --username joe --email joe@example.com --first Joe --last Demo --role iam-operator --temp-password "${JOE_TEMP}" --no-password-update --no-totp
${JML_CMD} "${COMMON_FLAGS[@]}" grant-role --realm "${REALM}" --username joe --role realm-admin

printf "%b\n" "${PURPLE}=== Attribution du rôle realm-management/realm-admin à joe ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" client-role --realm "${REALM}" --username joe --client-id realm-management --role realm-admin

printf "%b\n" "${PURPLE}=== Promotion d'alice vers le rôle iam-operator (mover) ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" mover --realm "${REALM}" --username alice --from-role analyst --to-role iam-operator

printf "%b\n" "${RED}=== Désactivation de bob (leaver) ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" leaver --realm "${REALM}" --username bob

printf "%b\n" "${GREEN}✓ Démo terminée${RESET}"
