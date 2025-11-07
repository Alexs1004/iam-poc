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
  az keyvault secret show \
    --vault-name "${AZURE_KEY_VAULT_NAME}" \
    --name "${secret_name}" \
    --query value \
    -o tsv 2>/dev/null || echo ""
}

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

if [[ "${AZURE_USE_KEYVAULT,,}" == "true" && -z "${AZURE_KEY_VAULT_NAME:-}" ]]; then
  echo "[https] AZURE_KEY_VAULT_NAME must be set when AZURE_USE_KEYVAULT=true." >&2
  exit 1
fi

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

# Note: .runtime/azure directory is no longer needed
# Azure CLI authentication was removed from container runtime
# Secrets are pre-loaded via 'make load-secrets' and mounted as /run/secrets

# Validate that secrets exist in .runtime/secrets/ (should be loaded via make load-secrets)
RUNTIME_BASE_DIR="${ROOT_DIR}/.runtime"
RUNTIME_SECRET_DIR="${RUNTIME_BASE_DIR}/secrets"
if [[ "${AZURE_USE_KEYVAULT,,}" == "true" ]]; then
  if [[ ! -f "${RUNTIME_SECRET_DIR}/keycloak_admin_password" ]]; then
    echo "[https] ERROR: Secret files not found in ${RUNTIME_SECRET_DIR}/" >&2
    echo "[https] Run 'make load-secrets' first to fetch secrets from Azure Key Vault." >&2
    exit 1
  fi
  echo "[https] ✓ Secrets validated in ${RUNTIME_SECRET_DIR}/"
elif [[ "${DEMO_MODE,,}" == "true" ]]; then
  echo "[https] DEMO_MODE: Secrets will use demo defaults"
else
  echo "[https] WARNING: Neither AZURE_USE_KEYVAULT nor DEMO_MODE is enabled" >&2
fi

# Launch containerized services with HTTPS support
echo "[https] Starting Flask app behind HTTPS proxy..."
cd "${ROOT_DIR}"
BUILD_MARKER="${RUNTIME_BASE_DIR}/flask_image.hash"
CURRENT_HASH=$(sha256sum Dockerfile.flask requirements.txt | sha256sum | awk '{print $1}')
NEED_BUILD=true
if [[ -f "${BUILD_MARKER}" ]]; then
  RECORDED_HASH=$(cat "${BUILD_MARKER}")
  if [[ "${RECORDED_HASH}" == "${CURRENT_HASH}" ]]; then
    NEED_BUILD=false
  fi
fi

if [[ "${NEED_BUILD}" == "true" ]]; then
  echo "[https] Building Flask image (dependency change detected)..."
  docker compose build flask-app
  mkdir -p "${RUNTIME_BASE_DIR}"
  echo "${CURRENT_HASH}" > "${BUILD_MARKER}"
else
  echo "[https] Flask image up to date; skipping build."
fi

# Note: Azure CLI authentication in container is NOT needed anymore
# Secrets are pre-loaded via 'make load-secrets' and mounted as /run/secrets (read-only)
# Applications read secrets directly from files, no runtime Azure access required

docker compose up -d keycloak flask-app reverse-proxy

echo "[https] ✓ Services started successfully"
echo "[https] Keycloak: http://localhost:8080"
echo "[https] Flask App: https://localhost"
