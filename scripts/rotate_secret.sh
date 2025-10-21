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

KEYCLOAK_URL="${KEYCLOAK_URL:-http://127.0.0.1:8080}"
KEYCLOAK_REALM="${KEYCLOAK_SERVICE_REALM:-demo}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"

KEYCLOAK_CLIENT_ID="${KEYCLOAK_SERVICE_CLIENT_ID:-automation-cli}"

AZURE_KEY_VAULT_NAME="${AZURE_KEY_VAULT_NAME:-}"
AKV_SECRET_NAME="${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET:-keycloak-service-client-secret}"

# Service Docker à redémarrer (nom dans docker-compose.yml)
FLASK_SERVICE="${FLASK_SERVICE:-flask-app}"

# Endpoint simple de health-check (protégé en prod → utilisez un endpoint public sain ou un /healthz)
HEALTHCHECK_URL="${HEALTHCHECK_URL:-https://localhost/health}"

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
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=${KEYCLOAK_ADMIN}" \
  -d "password=${KEYCLOAK_ADMIN_PASSWORD}" || true)

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
fi

log "Nouveau secret obtenu (longueur $(echo -n "${NEW_SECRET}" | wc -c | tr -d ' ') chars)."

### ──────────────────────────────────────────────────────────────────────────────
### Étape 4: Mettre à jour Azure Key Vault
### ──────────────────────────────────────────────────────────────────────────────
log "Mise à jour du secret dans Azure Key Vault: ${AZURE_KEY_VAULT_NAME}/${AKV_SECRET_NAME}"

if [[ "${DRY_RUN}" == "--dry-run" ]]; then
  warn "DRY-RUN: on n'écrit pas dans Key Vault."
else
  az keyvault secret set \
    --vault-name "${AZURE_KEY_VAULT_NAME}" \
    --name "${AKV_SECRET_NAME}" \
    --value "${NEW_SECRET}" \
    --only-show-errors >/dev/null
fi

log "Key Vault synchronisé."

### ──────────────────────────────────────────────────────────────────────────────
### Étape 5: Redémarrer l'app Flask (pour recharger le secret)
### ──────────────────────────────────────────────────────────────────────────────
log "Redémarrage du service Docker '${FLASK_SERVICE}'…"
if [[ "${DRY_RUN}" == "--dry-run" ]]; then
  warn "DRY-RUN: pas de redémarrage docker."
else
  cd "${PROJECT_ROOT}"
  docker compose restart "${FLASK_SERVICE}" >/dev/null
fi

### ──────────────────────────────────────────────────────────────────────────────
### Étape 6: Health-check de l'application
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
  for i in {1..10}; do
    HTTP_CODE=$(curl ${CURL_FLAGS} -o /dev/null -w "%{http_code}" "${HEALTHCHECK_URL}" || true)
    if [[ "${HTTP_CODE}" =~ ^2[0-9][0-9]$ ]]; then
      log "✅ Application OK (HTTP ${HTTP_CODE})."
      break
    fi
    warn "Tentative ${i}/10: HTTP ${HTTP_CODE}. Nouvelle tentative dans 2s…"
    sleep 2
    [[ "${i}" -lt 10 ]] || die "Health-check KO après 10 tentatives."
  done
fi

log "✅ Rotation orchestrée terminée avec succès."
