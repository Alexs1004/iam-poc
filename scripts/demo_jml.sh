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

# Sensitive data supplied via environment (ensure .env is excluded from VCS)
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
    fi
    if [[ -z "${BOB_TEMP_PASSWORD:-}" ]]; then
      BOB_TEMP_PASSWORD="$(fetch_secret "${AZURE_SECRET_BOB_TEMP_PASSWORD}")"
    fi
    if [[ -z "${CAROL_TEMP_PASSWORD:-}" ]]; then
      CAROL_TEMP_PASSWORD="$(fetch_secret "${AZURE_SECRET_CAROL_TEMP_PASSWORD}")"
    fi
    if [[ -z "${JOE_TEMP_PASSWORD:-}" ]]; then
      JOE_TEMP_PASSWORD="$(fetch_secret "${AZURE_SECRET_JOE_TEMP_PASSWORD}")"
    fi
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

KC_URL=${KEYCLOAK_URL:?Variable KEYCLOAK_URL required}
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

COMMON_FLAGS=(
  "--kc-url" "${KC_URL}"
  "--auth-realm" "${KC_SERVICE_REALM}"
  "--svc-client-id" "${KC_SERVICE_CLIENT_ID}"
  "--svc-client-secret" "${KC_SERVICE_CLIENT_SECRET}"
)

printf "%b\n" "${BLUE}=== Création du realm et du client ===${RESET}"
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
