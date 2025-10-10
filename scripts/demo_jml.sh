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

JML_CMD="python ${SCRIPT_DIR}/jml.py"

# Sensitive data supplied via environment (ensure .env is excluded from VCS)
KC_URL=${KEYCLOAK_URL:?Variable KEYCLOAK_URL required}
KC_SERVICE_REALM=${KEYCLOAK_SERVICE_REALM:-demo}
KC_SERVICE_CLIENT_ID=${KEYCLOAK_SERVICE_CLIENT_ID:?Variable KEYCLOAK_SERVICE_CLIENT_ID required}
KC_SERVICE_CLIENT_SECRET=${KEYCLOAK_SERVICE_CLIENT_SECRET:?Variable KEYCLOAK_SERVICE_CLIENT_SECRET required}
REALM=${KEYCLOAK_REALM:-demo}
CLIENT_ID=${OIDC_CLIENT_ID:?Variable OIDC_CLIENT_ID required}
REDIRECT_URI=${OIDC_REDIRECT_URI:?Variable OIDC_REDIRECT_URI required}
ALICE_TEMP=${ALICE_TEMP_PASSWORD:?Variable ALICE_TEMP_PASSWORD required}
BOB_TEMP=${BOB_TEMP_PASSWORD:?Variable BOB_TEMP_PASSWORD required}

COMMON_FLAGS=(
  "--kc-url" "${KC_URL}"
  "--auth-realm" "${KC_SERVICE_REALM}"
  "--svc-client-id" "${KC_SERVICE_CLIENT_ID}"
  "--svc-client-secret" "${KC_SERVICE_CLIENT_SECRET}"
)

printf "%b\n" "${BLUE}=== Création du realm et du client ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" init --realm "${REALM}" --client-id "${CLIENT_ID}" --redirect-uri "${REDIRECT_URI}"

printf "%b\n" "${YELLOW}=== Provision de l'utilisatrice alice (joiner) ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" joiner --realm "${REALM}" --username alice --email alice@example.com --first Alice --last Demo --role analyst --temp-password "${ALICE_TEMP}"

printf "%b\n" "${YELLOW}=== Provision de l'utilisateur bob (joiner) ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" joiner --realm "${REALM}" --username bob --email bob@example.com --first Bob --last Demo --role analyst --temp-password "${BOB_TEMP}"

printf "%b\n" "${PURPLE}=== Promotion d'alice vers le rôle admin (mover) ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" mover --realm "${REALM}" --username alice --from-role analyst --to-role admin

printf "%b\n" "${RED}=== Désactivation de bob (leaver) ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" leaver --realm "${REALM}" --username bob

printf "%b\n" "${GREEN}✓ Démo terminée${RESET}"
