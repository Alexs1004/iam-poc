#!/usr/bin/env bash
set -euo pipefail

# Resolve project root directory from script location
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT_DIR}/certs"
CERT_PATH="${CERT_DIR}/localhost.crt"
KEY_PATH="${CERT_DIR}/localhost.key"
# Certificate validity period (default: 30 days, override via env var)
CERT_DAYS="${CERT_DAYS:-30}"

# Check if certificate rotation is requested
FORCE_RENEW=false
if [[ "${1:-}" == "--rotate" ]]; then
  FORCE_RENEW=true
fi

# Ensure certificate directory exists
mkdir -p "${CERT_DIR}"

# Load environment variables from .env if present so we can read Azure configuration.
if [[ -f "${ROOT_DIR}/.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  source "${ROOT_DIR}/.env"
  set +a
fi

fetch_secret() {
  local secret_name="$1"
  if [[ -z "${secret_name}" ]]; then
    echo ""
    return 0
  fi
  local value
  if ! value=$(az keyvault secret show \
    --vault-name "${AZURE_KEY_VAULT_NAME}" \
    --name "${secret_name}" \
    --query value \
    -o tsv 2>/dev/null); then
    echo ""
    return 0
  fi
  echo "${value}"
}

if [[ "${AZURE_USE_KEYVAULT,,}" == "true" ]]; then
  if ! command -v az >/dev/null 2>&1; then
    echo "[https] Azure CLI not found but AZURE_USE_KEYVAULT=true; aborting." >&2
    exit 1
  fi
  echo "[https] Retrieving secrets from Azure Key Vault '${AZURE_KEY_VAULT_NAME}'..."
  export FLASK_SECRET_KEY="$(fetch_secret "${AZURE_SECRET_FLASK_SECRET_KEY}")"
  export KEYCLOAK_SERVICE_CLIENT_SECRET="$(fetch_secret "${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET}")"
  export KEYCLOAK_ADMIN_PASSWORD="$(fetch_secret "${AZURE_SECRET_KEYCLOAK_ADMIN_PASSWORD}")"
  export ALICE_TEMP_PASSWORD="$(fetch_secret "${AZURE_SECRET_ALICE_TEMP_PASSWORD}")"
  export BOB_TEMP_PASSWORD="$(fetch_secret "${AZURE_SECRET_BOB_TEMP_PASSWORD}")"
fi

generate_self_signed_cert() {
  echo "[https] Generating self-signed certificate for localhost (valid ${CERT_DAYS} days)..."
  openssl req \
    -x509 \
    -nodes \
    -newkey rsa:2048 \
    -days "${CERT_DAYS}" \
    -keyout "${KEY_PATH}" \
    -out "${CERT_PATH}" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
}

download_certificate_from_keyvault() {
  local pem_path="${CERT_DIR}/keyvault-cert.pem"
  az keyvault certificate download \
    --vault-name "${AZURE_KEY_VAULT_NAME}" \
    --name "${AZURE_CERTIFICATE_PROXY_TLS}" \
    --encoding PEM \
    --file "${pem_path}"
  if ! openssl pkey -in "${pem_path}" -out "${KEY_PATH}"; then
    echo "[https] Failed to extract private key from certificate '${AZURE_CERTIFICATE_PROXY_TLS}'." >&2
    rm -f "${pem_path}"
    exit 1
  fi
  if ! openssl x509 -in "${pem_path}" -out "${CERT_PATH}"; then
    echo "[https] Failed to extract certificate chain for '${AZURE_CERTIFICATE_PROXY_TLS}'." >&2
    rm -f "${pem_path}" "${KEY_PATH}"
    exit 1
  fi
  rm -f "${pem_path}"
}

if [[ -n "${AZURE_CERTIFICATE_PROXY_TLS:-}" ]]; then
  if ! command -v az >/dev/null 2>&1; then
    echo "[https] Azure CLI not found but AZURE_CERTIFICATE_PROXY_TLS is set; aborting." >&2
    exit 1
  fi
  echo "[https] Downloading TLS certificate '${AZURE_CERTIFICATE_PROXY_TLS}' from Azure Key Vault..."
  download_certificate_from_keyvault
else
  if [[ "${FORCE_RENEW}" == "true" ]]; then
    rm -f "${CERT_PATH}" "${KEY_PATH}"
  fi
  if [[ ! -f "${CERT_PATH}" || ! -f "${KEY_PATH}" ]]; then
    generate_self_signed_cert
  fi
fi

# Guard against missing critical secrets when not using Azure Key Vault.
if [[ -z "${KEYCLOAK_ADMIN_PASSWORD:-}" ]]; then
  echo "[https] KEYCLOAK_ADMIN_PASSWORD is required. Set it in .env or ensure the Key Vault secret exists." >&2
  exit 1
fi

# Launch containerized services with HTTPS support
echo "[https] Starting Flask app behind HTTPS proxy..."
cd "${ROOT_DIR}"
docker compose up -d reverse-proxy flask-app keycloak
