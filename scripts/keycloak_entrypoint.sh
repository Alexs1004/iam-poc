#!/usr/bin/env bash
set -Eeuo pipefail

SECRET_DIR="/run/secrets"
SECRET_FILE="${SECRET_DIR}/keycloak-admin-password"

if [[ ! -r "${SECRET_FILE}" ]]; then
  echo "[keycloak-entrypoint] Required secret missing at ${SECRET_FILE}" >&2
  exit 1
fi

KEYCLOAK_ADMIN_PASSWORD="$(cat "${SECRET_FILE}")"
if [[ -z "${KEYCLOAK_ADMIN_PASSWORD}" ]]; then
  echo "[keycloak-entrypoint] Keycloak admin password secret is empty" >&2
  exit 1
fi

export KEYCLOAK_ADMIN_PASSWORD

exec /opt/keycloak/bin/kc.sh start-dev --health-enabled=true
