#!/usr/bin/env bash
# Rotation orchestrée du secret Keycloak -> Key Vault -> Flask (restart) -> Health-check
# Usage: scripts/rotate_secret.sh [--dry-run]
# Dépendances: bash, curl, jq, az (Azure CLI), docker compose

set -euo pipefail

### ──────────────────────────────────────────────────────────────────────────────
### Helpers
### ──────────────────────────────────────────────────────────────────────────────
log()   { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
warn()  { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err()   { printf "\033[1;31m[ERR ]\033[0m %s\n" "$*" >&2; }
die()   { err "$*"; exit 1; }

require_bin() {
  command -v "$1" >/dev/null 2>&1 || die "Binaire requis introuvable: $1"
}

DRY_RUN="${1:-}"
if [[ "${DRY_RUN}" == "--dry-run" ]]; then
  warn "Mode DRY-RUN: aucune modification ne sera appliquée."
fi

### ──────────────────────────────────────────────────────────────────────────────
### Chargement configuration (.env)
### ──────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/.env"

if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC2046
  set -a
  source "${ENV_FILE}"
  set +a
  log "Variables chargées depuis ${ENV_FILE}"
else
  warn "Fichier .env non trouvé, on continue avec l'environnement courant."
fi

### Variables attendues (override via .env)
DEMO_MODE="${DEMO_MODE:-false}"
AZURE_USE_KEYVAULT="${AZURE_USE_KEYVAULT:-true}"

KEYCLOAK_URL_INTERNAL="${KEYCLOAK_URL:-}"
KEYCLOAK_URL_HOST="${KEYCLOAK_URL_HOST:-}"

if [[ -n "${KEYCLOAK_URL_HOST}" ]]; then
  KEYCLOAK_URL="${KEYCLOAK_URL_HOST}"
else
  KEYCLOAK_URL="${KEYCLOAK_URL_INTERNAL:-http://127.0.0.1:8080}"
fi
log "Cible Keycloak pour la rotation: ${KEYCLOAK_URL}"

KEYCLOAK_REALM="${KEYCLOAK_SERVICE_REALM:-demo}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-}"

KEYCLOAK_CLIENT_ID="${KEYCLOAK_SERVICE_CLIENT_ID:-automation-cli}"

AZURE_KEY_VAULT_NAME="${AZURE_KEY_VAULT_NAME:-}"
AKV_SECRET_NAME="${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET:-keycloak-service-client-secret}"

# Service Docker à redémarrer (nom dans docker-compose.yml)
FLASK_SERVICE="${FLASK_SERVICE:-flask-app}"

# Endpoint simple de health-check (protégé en prod → utilisez un endpoint public sain ou un /healthz)
HEALTHCHECK_URL="${HEALTHCHECK_URL:-https://localhost/health}"

SECRETS_DIR="${PROJECT_ROOT}/.runtime/secrets"
load_secret_if_empty() {
  local var_name="$1"
  local file_name="$2"
  local current_value="${!var_name:-}"

  if [[ -z "${current_value}" && -f "${SECRETS_DIR}/${file_name}" ]]; then
    local value
    value=$(<"${SECRETS_DIR}/${file_name}")
    export "${var_name}=${value}"
  fi
}

load_secret_if_empty "KEYCLOAK_ADMIN_PASSWORD" "keycloak_admin_password"
load_secret_if_empty "KEYCLOAK_CLIENT_SECRET" "keycloak_service_client_secret"

[[ -n "${KEYCLOAK_ADMIN_PASSWORD}" ]] || die "Impossible de déterminer KEYCLOAK_ADMIN_PASSWORD (vérifiez .runtime/secrets ou .env)."

### ──────────────────────────────────────────────────────────────────────────────
### Prérequis
### ──────────────────────────────────────────────────────────────────────────────
require_bin curl
require_bin jq
require_bin docker
require_bin az

# Vérifs de contexte
if [[ "${DEMO_MODE,,}" == "true" ]]; then
  warn "DEMO_MODE=true → On ne fait pas de rotation réelle en démo."
  warn "Astuce: conservez un secret stable (demo-service-secret) et testez la rotation seulement en PROD."
  exit 0
fi

[[ "${AZURE_USE_KEYVAULT,,}" == "true" ]] || die "AZURE_USE_KEYVAULT=false → rotation incohérente. Activez Key Vault pour la PROD."
[[ -n "${AZURE_KEY_VAULT_NAME}" ]] || die "AZURE_KEY_VAULT_NAME manquant."
[[ -n "${AKV_SECRET_NAME}"     ]] || die "Nom de secret Key Vault manquant (AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET)."

# Vérif login Azure
if ! az account show >/dev/null 2>&1; then
  die "Pas de session Azure. Exécutez: az login"
fi

### ──────────────────────────────────────────────────────────────────────────────
### Étape 1: Récupérer un access token admin Keycloak
### ──────────────────────────────────────────────────────────────────────────────
log "Obtention d'un token admin Keycloak…"
KC_TOKEN_JSON=$(curl -sS "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=admin-cli" \
  --data-urlencode "username=${KEYCLOAK_ADMIN}" \
  --data-urlencode "password=${KEYCLOAK_ADMIN_PASSWORD}" || true)

KC_ACCESS_TOKEN=$(echo "${KC_TOKEN_JSON}" | jq -r '.access_token // empty')

[[ -n "${KC_ACCESS_TOKEN}" ]] || die "Impossible d'obtenir un access token admin (vérifiez KEYCLOAK_URL/admin creds)."

### ──────────────────────────────────────────────────────────────────────────────
### Étape 2: Trouver l'ID interne du client (UUID Keycloak)
### ──────────────────────────────────────────────────────────────────────────────
log "Recherche du client '${KEYCLOAK_CLIENT_ID}' dans le realm '${KEYCLOAK_REALM}'…"
CLIENTS_JSON=$(curl -sS -H "Authorization: Bearer ${KC_ACCESS_TOKEN}" \
  "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${KEYCLOAK_CLIENT_ID}")

CLIENT_ID_UUID=$(echo "${CLIENTS_JSON}" | jq -r '.[0].id // empty')
[[ -n "${CLIENT_ID_UUID}" ]] || die "Client '${KEYCLOAK_CLIENT_ID}' introuvable dans le realm '${KEYCLOAK_REALM}'."

### ──────────────────────────────────────────────────────────────────────────────
### Étape 3: Régénérer le secret côté Keycloak (rotation)
### ──────────────────────────────────────────────────────────────────────────────
log "Régénération du secret Keycloak pour le client ${KEYCLOAK_CLIENT_ID} (${CLIENT_ID_UUID})…"

if [[ "${DRY_RUN}" == "--dry-run" ]]; then
  warn "DRY-RUN: on simule la rotation Keycloak (POST /client-secret)."
  NEW_SECRET="<dry-run-secret>"
else
  ROTATE_JSON=$(curl -sS -X POST -H "Authorization: Bearer ${KC_ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_ID_UUID}/client-secret")

  NEW_SECRET=$(echo "${ROTATE_JSON}" | jq -r '.value // empty')
  [[ -n "${NEW_SECRET}" ]] || die "La régénération du secret a échoué (réponse vide)."
  
  # Validation de sécurité du secret (OWASP ASVS 2.7.1)
  [[ ${#NEW_SECRET} -ge 16 ]] || die "Secret trop court (${#NEW_SECRET} chars < 16 requis par OWASP)"
fi

log "Nouveau secret obtenu (longueur $(echo -n "${NEW_SECRET}" | wc -c | tr -d ' ') chars)."

### ──────────────────────────────────────────────────────────────────────────────
### Étape 4: Mettre à jour Azure Key Vault
### ──────────────────────────────────────────────────────────────────────────────
log "Mise à jour du secret dans Azure Key Vault: ${AZURE_KEY_VAULT_NAME}/${AKV_SECRET_NAME}"

SECRET_ID=""
SECRET_VERSION=""

if [[ "${DRY_RUN}" == "--dry-run" ]]; then
  warn "DRY-RUN: on n'écrit pas dans Key Vault."
  SECRET_ID="https://${AZURE_KEY_VAULT_NAME}.vault.azure.net/secrets/${AKV_SECRET_NAME}/dry-run"
  SECRET_VERSION="dry-run"
else
  ROTATION_JSON=$(az keyvault secret set \
    --vault-name "${AZURE_KEY_VAULT_NAME}" \
    --name "${AKV_SECRET_NAME}" \
    --value "${NEW_SECRET}" \
    -o json \
    --only-show-errors)
  
  SECRET_ID=$(echo "${ROTATION_JSON}" | jq -r '.id // empty')
  
  # Extraire la version depuis l'ID (format: https://vault.../secrets/name/VERSION)
  SECRET_VERSION=$(echo "${SECRET_ID}" | grep -oP '/[^/]+$' | tr -d '/')
  
  [[ -n "${SECRET_ID}" && -n "${SECRET_VERSION}" ]] || die "Impossible de récupérer l'identifiant du secret depuis Key Vault."
fi

log "Key Vault synchronisé (version ${SECRET_VERSION})."

### ──────────────────────────────────────────────────────────────────────────────
### Étape 4b: Enregistrer une entrée d'audit signée (HMAC-SHA256)
### ──────────────────────────────────────────────────────────────────────────────
AUDIT_LOG_SIGNING_KEY="${AUDIT_LOG_SIGNING_KEY:-}"
load_secret_if_empty "AUDIT_LOG_SIGNING_KEY" "audit_log_signing_key"

if [[ -z "${AUDIT_LOG_SIGNING_KEY}" ]]; then
  warn "AUDIT_LOG_SIGNING_KEY manquant, tentative de récupération depuis Key Vault..."
  AKV_AUDIT_KEY_NAME="${AZURE_SECRET_AUDIT_LOG_SIGNING_KEY:-audit-log-signing-key}"
  AUDIT_LOG_SIGNING_KEY=$(az keyvault secret show \
    --vault-name "${AZURE_KEY_VAULT_NAME}" \
    --name "${AKV_AUDIT_KEY_NAME}" \
    --query value -o tsv 2>/dev/null || true)
  [[ -n "${AUDIT_LOG_SIGNING_KEY}" ]] || warn "Impossible de récupérer AUDIT_LOG_SIGNING_KEY, audit non signé."
fi

if [[ -n "${AUDIT_LOG_SIGNING_KEY}" ]]; then
  log "Enregistrement de l'entrée d'audit signée..."
  
  # Récupérer l'opérateur Azure
  OPERATOR=$(az account show --query "user.name" -o tsv 2>/dev/null || true)
  [[ -z "${OPERATOR}" ]] && OPERATOR=$(az account show --query "user.userPrincipalName" -o tsv 2>/dev/null || true)
  [[ -z "${OPERATOR}" ]] && OPERATOR=$(az account show --query "name" -o tsv 2>/dev/null || echo "unknown")
  
  TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  AUDIT_DIR="${PROJECT_ROOT}/.runtime/audit"
  mkdir -p "${AUDIT_DIR}"
  chmod 700 "${AUDIT_DIR}"
  
  AUDIT_MESSAGE="timestamp=${TIMESTAMP} operator=${OPERATOR} secret_id=${SECRET_ID} version=${SECRET_VERSION}"
  
  # Signature HMAC-SHA256 (passage par variable d'environnement pour éviter injection)
  SIGNATURE=$(AUDIT_LOG_MESSAGE="${AUDIT_MESSAGE}" python3 -c "import os,hmac,hashlib; key=os.environ['AUDIT_LOG_SIGNING_KEY'].encode(); msg=os.environ['AUDIT_LOG_MESSAGE'].encode(); print(hmac.new(key, msg, hashlib.sha256).hexdigest())")
  
  AUDIT_FILE="${AUDIT_DIR}/secret-rotation.log"
  touch "${AUDIT_FILE}"
  chmod 600 "${AUDIT_FILE}"
  
  if [[ "${DRY_RUN}" == "--dry-run" ]]; then
    warn "DRY-RUN: audit non écrit (serait: ${AUDIT_MESSAGE} signature=${SIGNATURE})"
  else
    printf '%s signature=%s\n' "${AUDIT_MESSAGE}" "${SIGNATURE}" >> "${AUDIT_FILE}"
    log "✅ Audit entry recorded for operator '${OPERATOR}'."
  fi
else
  warn "Audit non signé: AUDIT_LOG_SIGNING_KEY indisponible."
fi

### ──────────────────────────────────────────────────────────────────────────────
### Étape 5: Synchroniser les secrets locaux depuis Key Vault
### ──────────────────────────────────────────────────────────────────────────────
log "Synchronisation des secrets locaux depuis Key Vault..."
if [[ "${DRY_RUN}" == "--dry-run" ]]; then
  warn "DRY-RUN: pas de synchronisation des secrets."
else
  mkdir -p "${SECRETS_DIR}"
  chmod 700 "${SECRETS_DIR}"
  
  # Sauvegarder l'ancien secret pour rollback potentiel (CIS Benchmark 5.5.1)
  OLD_SECRET=""
  if [[ -f "${SECRETS_DIR}/keycloak_service_client_secret" ]]; then
    OLD_SECRET=$(<"${SECRETS_DIR}/keycloak_service_client_secret")
    chmod 600 "${SECRETS_DIR}/keycloak_service_client_secret"
  fi
  
  # Écrire le nouveau secret de manière atomique et sécurisée (NIST SP 800-53 SC-28)
  TEMP_SECRET_FILE=$(mktemp -u "${SECRETS_DIR}/keycloak_service_client_secret.XXXXXX")
  (umask 077 && echo -n "${NEW_SECRET}" > "${TEMP_SECRET_FILE}")
  chmod 600 "${TEMP_SECRET_FILE}"
  mv -f "${TEMP_SECRET_FILE}" "${SECRETS_DIR}/keycloak_service_client_secret"
  
  log "✅ Secret local synchronisé (${SECRETS_DIR}/keycloak_service_client_secret)"
fi

### ──────────────────────────────────────────────────────────────────────────────
### Étape 6: Redémarrer l'app Flask (pour recharger le secret)
### ──────────────────────────────────────────────────────────────────────────────
log "Redémarrage du service Docker '${FLASK_SERVICE}'…"
if [[ "${DRY_RUN}" == "--dry-run" ]]; then
  warn "DRY-RUN: pas de redémarrage docker."
else
  cd "${PROJECT_ROOT}"
  docker compose restart "${FLASK_SERVICE}" >/dev/null
fi

### ──────────────────────────────────────────────────────────────────────────────
### Étape 7: Health-check de l'application
### ──────────────────────────────────────────────────────────────────────────────
log "Health-check sur ${HEALTHCHECK_URL}…"
CURL_FLAGS="-sS"
# Support https self-signed en dev/proxy
if [[ "${HEALTHCHECK_URL}" == https://* ]]; then
  CURL_FLAGS="${CURL_FLAGS} -k"
fi

if [[ "${DRY_RUN}" == "--dry-run" ]]; then
  warn "DRY-RUN: health-check non exécuté."
else
  # 10 tentatives max, 2s d'intervalle
  HEALTH_OK=false
  for i in {1..10}; do
    HTTP_CODE=$(curl ${CURL_FLAGS} -o /dev/null -w "%{http_code}" "${HEALTHCHECK_URL}" || true)
    if [[ "${HTTP_CODE}" =~ ^2[0-9][0-9]$ ]]; then
      log "✅ Application OK (HTTP ${HTTP_CODE})."
      HEALTH_OK=true
      break
    fi
    warn "Tentative ${i}/10: HTTP ${HTTP_CODE}. Nouvelle tentative dans 2s…"
    sleep 2
  done
  
  # Rollback si health-check échoue (NIST SP 800-53 CP-10)
  if [[ "${HEALTH_OK}" == "false" ]]; then
    err "Health-check KO après 10 tentatives."
    if [[ -n "${OLD_SECRET}" ]]; then
      warn "Rollback vers l'ancien secret..."
      (umask 077 && echo -n "${OLD_SECRET}" > "${SECRETS_DIR}/keycloak_service_client_secret")
      chmod 600 "${SECRETS_DIR}/keycloak_service_client_secret"
      docker compose restart "${FLASK_SERVICE}" >/dev/null
      warn "Service restauré avec l'ancien secret. Nouvelle version Key Vault non utilisée."
      die "Rotation annulée suite à l'échec du health-check."
    else
      die "Aucun backup disponible pour le rollback."
    fi
  fi
fi

log "✅ Rotation orchestrée terminée avec succès."
