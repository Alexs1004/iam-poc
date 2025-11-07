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

# ─────────────────────────────────────────────────────────────────────────────
# Load secrets from .runtime/secrets/ (same location mounted as /run/secrets)
# ─────────────────────────────────────────────────────────────────────────────
load_secret_from_local_file() {
  local secret_name="$1"
  local secret_file="${PROJECT_ROOT}/.runtime/secrets/${secret_name}"
  
  if [[ -f "$secret_file" ]]; then
    cat "$secret_file"
    return 0
  fi
  return 1
}

store_service_secret_locally() {
  local secret_value="$1"
  local secrets_dir="${PROJECT_ROOT}/.runtime/secrets"
  local secret_file="${secrets_dir}/keycloak_service_client_secret"

  mkdir -p "${secrets_dir}"
  chmod 700 "${secrets_dir}" 2>/dev/null || true

  chmod 600 "${secret_file}" 2>/dev/null || true
  echo -n "${secret_value}" > "${secret_file}"
  chmod 400 "${secret_file}" 2>/dev/null || true

  echo "[production] ✓ Local secret file updated (${secret_file})"
}

sync_service_secret_to_keyvault() {
  local secret_value="$1"

  if [[ "${AZURE_USE_KEYVAULT,,}" != "true" ]]; then
    return 0
  fi

  if [[ -z "${AZURE_KEY_VAULT_NAME:-}" || -z "${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET:-}" ]]; then
    echo "[production] ✗ Key Vault sync impossible : AZURE_KEY_VAULT_NAME ou AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET manquant." >&2
    return 1
  fi

  if ! command -v az >/dev/null 2>&1; then
    echo "[production] ✗ Azure CLI absent; impossible de pousser le secret dans Key Vault." >&2
    return 1
  fi

  if ! az account show >/dev/null 2>&1; then
    echo "[production] ✗ Session Azure invalide; exécutez 'az login' avant de relancer." >&2
    return 1
  fi

  if [[ -z "${secret_value}" ]]; then
    echo "[production] ✗ Secret vide : synchronisation Key Vault annulée." >&2
    return 1
  fi

  if az keyvault secret set \
    --vault-name "${AZURE_KEY_VAULT_NAME}" \
    --name "${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET}" \
    --value "${secret_value}" \
    --only-show-errors >/dev/null; then
    echo "[production] ✓ Key Vault secret '${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET}' updated"
  else
    echo "[production] ✗ Echec de mise à jour du secret '${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET}' dans Key Vault." >&2
    return 1
  fi

  return 0
}

# Allow overriding the python interpreter via $PYTHON, defaulting to python3.
PYTHON_BIN=${PYTHON:-python3}
JML_CMD="${PYTHON_BIN} ${SCRIPT_DIR}/jml.py"

# Load environment variables from .env if it exists
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
  set -a
  source "${PROJECT_ROOT}/.env"
  set +a
else
  # No .env file: Set demo mode defaults
  echo "[demo] No .env file found, using hardcoded demo defaults"
  export DEMO_MODE="${DEMO_MODE:-true}"
  export AZURE_USE_KEYVAULT="${AZURE_USE_KEYVAULT:-false}"
  
  # Keycloak URLs and configuration
  export KEYCLOAK_URL_HOST="${KEYCLOAK_URL_HOST:-http://127.0.0.1:8080}"
  export KEYCLOAK_REALM="${KEYCLOAK_REALM:-demo}"
  export KEYCLOAK_SERVICE_REALM="${KEYCLOAK_SERVICE_REALM:-demo}"
  export KEYCLOAK_SERVICE_CLIENT_ID="${KEYCLOAK_SERVICE_CLIENT_ID:-automation-cli}"
  export KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
  
  # OIDC configuration
  export OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-flask-app}"
  export OIDC_REDIRECT_URI="${OIDC_REDIRECT_URI:-https://localhost/callback}"
  export POST_LOGOUT_REDIRECT_URI="${POST_LOGOUT_REDIRECT_URI:-https://localhost/}"
  
  # Demo secrets (hardcoded for demo mode only)
  export KEYCLOAK_ADMIN_PASSWORD_DEMO="${KEYCLOAK_ADMIN_PASSWORD_DEMO:-admin}"
  export KEYCLOAK_SERVICE_CLIENT_SECRET_DEMO="${KEYCLOAK_SERVICE_CLIENT_SECRET_DEMO:-demo-service-secret}"
  export AUDIT_LOG_SIGNING_KEY_DEMO="${AUDIT_LOG_SIGNING_KEY_DEMO:-demo-audit-signing-key-change-in-production}"
  
  # Demo user passwords
  export ALICE_TEMP_PASSWORD_DEMO="${ALICE_TEMP_PASSWORD_DEMO:-Temp123!}"
  export BOB_TEMP_PASSWORD_DEMO="${BOB_TEMP_PASSWORD_DEMO:-Temp123!}"
  export CAROL_TEMP_PASSWORD_DEMO="${CAROL_TEMP_PASSWORD_DEMO:-Temp123!}"
  export JOE_TEMP_PASSWORD_DEMO="${JOE_TEMP_PASSWORD_DEMO:-Temp123!}"
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
# 1. .runtime/secrets/ (if files exist - loaded by load_secrets_from_keyvault.sh)
# 2. Environment variables (if already set)
# 3. Demo defaults (if DEMO_MODE=true)
# 4. Azure Key Vault inline fetch (legacy fallback)

# Step 1: Load from .runtime/secrets/ if available (production mode with make load-secrets)
if [[ -d "${PROJECT_ROOT}/.runtime/secrets" ]]; then
  KEYCLOAK_ADMIN_PASSWORD=$(load_secret_from_local_file "keycloak_admin_password" || echo "")
  KEYCLOAK_SERVICE_CLIENT_SECRET=$(load_secret_from_local_file "keycloak_service_client_secret" || echo "")
  ALICE_TEMP_PASSWORD=$(load_secret_from_local_file "alice_temp_password" || echo "")
  BOB_TEMP_PASSWORD=$(load_secret_from_local_file "bob_temp_password" || echo "")
  CAROL_TEMP_PASSWORD=$(load_secret_from_local_file "carol_temp_password" || echo "")
  JOE_TEMP_PASSWORD=$(load_secret_from_local_file "joe_temp_password" || echo "")
  
  if [[ -n "${KEYCLOAK_ADMIN_PASSWORD}" ]]; then
    echo "[production] Secrets loaded from .runtime/secrets/ (Azure Key Vault cache)"
  fi
fi

# Step 2: Apply demo defaults if DEMO_MODE=true
if [[ "${DEMO_MODE,,}" == "true" ]]; then
  # Priority: 1. Already set env var, 2. *_DEMO var, 3. Hardcoded fallback
  ALICE_TEMP_PASSWORD="${ALICE_TEMP_PASSWORD:-${ALICE_TEMP_PASSWORD_DEMO:-Temp123!}}"
  BOB_TEMP_PASSWORD="${BOB_TEMP_PASSWORD:-${BOB_TEMP_PASSWORD_DEMO:-Temp123!}}"
  CAROL_TEMP_PASSWORD="${CAROL_TEMP_PASSWORD:-${CAROL_TEMP_PASSWORD_DEMO:-Temp123!}}"
  JOE_TEMP_PASSWORD="${JOE_TEMP_PASSWORD:-${JOE_TEMP_PASSWORD_DEMO:-Temp123!}}"
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

# Load audit signing key for event signatures
if [[ -f "${PROJECT_ROOT}/.runtime/secrets/audit_log_signing_key" ]]; then
  AUDIT_LOG_SIGNING_KEY=$(cat "${PROJECT_ROOT}/.runtime/secrets/audit_log_signing_key")
  export AUDIT_LOG_SIGNING_KEY
elif [[ "${DEMO_MODE,,}" == "true" ]]; then
  # Demo mode: Use demo default signing key
  AUDIT_LOG_SIGNING_KEY="${AUDIT_LOG_SIGNING_KEY_DEMO:-demo-audit-signing-key-change-in-production}"
  export AUDIT_LOG_SIGNING_KEY
  echo "[demo] Using demo audit signing key"
fi

KC_URL=${KEYCLOAK_URL_HOST:?Variable KEYCLOAK_URL_HOST required}
KC_SERVICE_REALM=${KEYCLOAK_SERVICE_REALM:-demo}
KC_SERVICE_CLIENT_ID=${KEYCLOAK_SERVICE_CLIENT_ID:?Variable KEYCLOAK_SERVICE_CLIENT_ID required}
KC_SERVICE_CLIENT_SECRET=${KEYCLOAK_SERVICE_CLIENT_SECRET:-}
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
  
  # Load admin password from Docker secret file if available
  if ADMIN_PASS_FROM_FILE=$(load_secret_from_local_file "keycloak_admin_password"); then
    export KEYCLOAK_ADMIN_PASSWORD="${ADMIN_PASS_FROM_FILE}"
    echo "[demo] Loaded admin password from .runtime/secrets/keycloak_admin_password"
  else
    export KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
    echo "[demo] Using admin password from environment (fallback: 'admin')"
  fi
  
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
    --data-urlencode "username=${KEYCLOAK_ADMIN}" \
    --data-urlencode "password=${KEYCLOAK_ADMIN_PASSWORD}" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=admin-cli" | ${PYTHON_BIN} -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
  
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
  
  # Wait for Keycloak to be fully ready (retry up to 30 seconds)
  echo "[production] Waiting for Keycloak to be fully ready..."
  ADMIN_TOKEN=""
  for i in {1..30}; do
    ADMIN_TOKEN=$(curl -s -X POST "${KC_URL}/realms/master/protocol/openid-connect/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      --data-urlencode "username=${KEYCLOAK_ADMIN}" \
      --data-urlencode "password=${KEYCLOAK_ADMIN_PASSWORD}" \
      --data-urlencode "grant_type=password" \
      --data-urlencode "client_id=admin-cli" 2>/dev/null | ${PYTHON_BIN} -c "import sys,json; print(json.load(sys.stdin).get('access_token', ''))" 2>/dev/null || echo "")
    
    if [[ -n "${ADMIN_TOKEN}" ]]; then
      echo "[production] ✓ Keycloak admin API is ready (attempt $i)"
      break
    fi
    
    if [[ $i -eq 30 ]]; then
      echo "[production] ✗ Timeout: Keycloak admin API not responding after 30 seconds" >&2
      exit 1
    fi
    
    sleep 1
  done
  
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
        
        echo "[production] Service account created with secret: ${NEW_SECRET:0:10}..."

        store_service_secret_locally "${NEW_SECRET}"
        if ! sync_service_secret_to_keyvault "${NEW_SECRET}"; then
          echo "[production] ✗ Aborting: unable to persist service secret in Key Vault." >&2
          exit 1
        fi

        # Restart Flask to load the new secret
        echo "[production] Restarting Flask to load new secret..."
        docker compose restart flask-app >/dev/null 2>&1 || true
        echo "[production] ✅ Flask restarted"

        KC_SERVICE_CLIENT_SECRET="${NEW_SECRET}"
        KEYCLOAK_SERVICE_CLIENT_SECRET="${NEW_SECRET}"
        export KEYCLOAK_SERVICE_CLIENT_SECRET
      fi
    else
      # Realm doesn't exist yet - this is initial setup
      # We'll bootstrap after creating the realm (see below)
      echo "[production] Realm doesn't exist yet, will bootstrap service account after realm creation"
      KC_SERVICE_CLIENT_SECRET=""  # Will be set after bootstrap
      NEEDS_BOOTSTRAP=true
    fi
  else
    # This should never happen now with retry logic above
    echo "[production] ✗ Failed to authenticate to Keycloak admin API" >&2
    exit 1
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
  echo "[production] Service account secret generated (value hidden)"
  
  store_service_secret_locally "${NEW_SECRET}"
  if ! sync_service_secret_to_keyvault "${NEW_SECRET}"; then
    echo "[production] ✗ Aborting: unable to persist service secret in Key Vault." >&2
    exit 1
  fi

  # Restart Flask to load new secret
  echo "[production] Restarting Flask to load new secret..."
  docker compose restart flask-app >/dev/null 2>&1 || true
  echo "[production] ✅ Flask restarted"

  KC_SERVICE_CLIENT_SECRET="${NEW_SECRET}"
  KEYCLOAK_SERVICE_CLIENT_SECRET="${NEW_SECRET}"
  export KEYCLOAK_SERVICE_CLIENT_SECRET
fi

# For remaining operations, use service account against the realm
COMMON_FLAGS=(
  "--kc-url" "${KC_URL}"
  "--auth-realm" "${REALM}"
  "--svc-client-id" "${KC_SERVICE_CLIENT_ID}"
  "--svc-client-secret" "${KC_SERVICE_CLIENT_SECRET}"
  "--operator" "demo-script"
)

# Always run init to create client, roles, and required actions
# (bootstrap only creates the realm and service account, not the application roles)
printf "%b\n" "${BLUE}=== Création du realm et du client public ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" init --realm "${REALM}" --client-id "${CLIENT_ID}" --redirect-uri "${REDIRECT_URI}" --post-logout-redirect-uri "${POST_LOGOUT_REDIRECT_URI}"

# Configure SMTP for password reset emails (production mode only)
if [[ "${DEMO_MODE,,}" != "true" ]] && [[ -n "${SMTP_HOST}" ]] && [[ -n "${SMTP_USER}" ]]; then
  printf "%b\n" "${BLUE}=== Configuration SMTP pour les emails de réinitialisation ===${RESET}"
  if docker compose exec flask-app ${PYTHON_BIN} scripts/configure_smtp.py; then
    printf "%b\n" "${GREEN}✓ SMTP configuré dans Keycloak${RESET}"
  else
    printf "%b\n" "${YELLOW}⚠ SMTP non configuré (vérifiez les variables SMTP_*)${RESET}"
  fi
else
  if [[ "${DEMO_MODE,,}" == "true" ]]; then
    printf "%b\n" "${YELLOW}[demo] Mode démo: SMTP non requis (mots de passe affichés dans l'UI)${RESET}"
  fi
fi

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
