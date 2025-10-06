#!/usr/bin/env bash
set -e

BLUE="\033[1;34m"
YELLOW="\033[1;33m"
GREEN="\033[1;32m"
PURPLE="\033[1;35m"
RED="\033[1;31m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

JML_CMD="python scripts/jml.py"

# Allow overriding the Keycloak admin endpoint via environment (defaults to sandbox port).
KC_URL=${KEYCLOAK_URL:-http://localhost:8081}
COMMON_FLAGS=("--kc-url" "${KC_URL}" "--admin-user" "admin" "--admin-pass" "admin")

printf "%b\n" "${BLUE}=== Création du realm et du client ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" init --realm demo --client-id flask-app --redirect-uri http://localhost:5000/callback

printf "%b\n" "${YELLOW}=== Provision de l'utilisatrice alice (joiner) ===${RESET}"
ALICE_TEMP=${ALICE_TEMP_PASSWORD:-Passw0rd!}
${JML_CMD} "${COMMON_FLAGS[@]}" joiner --realm demo --username alice --email alice@example.com --first Alice --last Demo --role analyst --temp-password "${ALICE_TEMP}"

printf "%b\n" "${YELLOW}=== Provision de l'utilisateur bob (joiner) ===${RESET}"
BOB_TEMP=${BOB_TEMP_PASSWORD:-Passw0rd!}
${JML_CMD} "${COMMON_FLAGS[@]}" joiner --realm demo --username bob --email bob@example.com --first Bob --last Demo --role analyst --temp-password "${BOB_TEMP}"

printf "%b\n" "${PURPLE}=== Promotion d'alice vers le rôle admin (mover) ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" mover --realm demo --username alice --from-role analyst --to-role admin

printf "%b\n" "${RED}=== Désactivation de bob (leaver) ===${RESET}"
${JML_CMD} "${COMMON_FLAGS[@]}" leaver --realm demo --username bob

printf "%b\n" "${GREEN} Démo terminée${RESET}"
