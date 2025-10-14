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

# Prepare Azure CLI configuration for DefaultAzureCredential (AzureCliCredential).
RUNTIME_BASE_DIR="${ROOT_DIR}/.runtime"
RUNTIME_AZURE_DIR="${RUNTIME_BASE_DIR}/azure"
HOST_AZURE_DIR="${AZURE_CONFIG_DIR:-${HOME}/.azure}"
mkdir -p "${RUNTIME_BASE_DIR}"

if [[ "${AZURE_USE_KEYVAULT,,}" == "true" ]]; then
  if [[ ! -d "${HOST_AZURE_DIR}" ]]; then
    echo "[https] Azure CLI configuration not found at ${HOST_AZURE_DIR}. Run 'az login' locally first." >&2
    exit 1
  fi
  rm -rf "${RUNTIME_AZURE_DIR}"
  mkdir -p "${RUNTIME_AZURE_DIR}"
  chmod 700 "${RUNTIME_AZURE_DIR}"
  cp -a "${HOST_AZURE_DIR}/." "${RUNTIME_AZURE_DIR}/"
fi

# Resolve Keycloak admin password into runtime secret file.
OLD_UMASK=$(umask)
umask 077
RUNTIME_SECRET_DIR="${RUNTIME_BASE_DIR}/secrets"
mkdir -p "${RUNTIME_SECRET_DIR}"
chmod 700 "${RUNTIME_SECRET_DIR}"
umask "${OLD_UMASK}"
KEYCLOAK_SECRET_FILE="${RUNTIME_SECRET_DIR}/keycloak-admin-password"
if [[ -d "${KEYCLOAK_SECRET_FILE}" ]]; then
  rm -rf "${KEYCLOAK_SECRET_FILE}"
fi

KEYCLOAK_ADMIN_PASSWORD_VALUE="${KEYCLOAK_ADMIN_PASSWORD:-}"
if [[ -z "${KEYCLOAK_ADMIN_PASSWORD_VALUE}" && "${AZURE_USE_KEYVAULT,,}" == "true" ]]; then
  if ! command -v az >/dev/null 2>&1; then
    echo "[https] Azure CLI not found but AZURE_USE_KEYVAULT=true; aborting." >&2
    exit 1
  fi
  echo "[https] Fetching Keycloak admin password from Key Vault '${AZURE_KEY_VAULT_NAME}'..."
  KEYCLOAK_ADMIN_PASSWORD_VALUE="$(fetch_secret "${AZURE_SECRET_KEYCLOAK_ADMIN_PASSWORD}")"
fi
if [[ -z "${KEYCLOAK_ADMIN_PASSWORD_VALUE}" ]]; then
  echo "[https] KEYCLOAK_ADMIN_PASSWORD (or the corresponding Key Vault secret) is required; aborting." >&2
  exit 1
fi
printf '%s' "${KEYCLOAK_ADMIN_PASSWORD_VALUE}" > "${KEYCLOAK_SECRET_FILE}"
chmod 600 "${KEYCLOAK_SECRET_FILE}"
chown 1000:0 "${KEYCLOAK_SECRET_FILE}" 2>/dev/null || true

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
  echo "${CURRENT_HASH}" > "${BUILD_MARKER}"
else
  echo "[https] Flask image up to date; skipping build."
fi

if [[ "${AZURE_USE_KEYVAULT,,}" == "true" ]]; then
  AZ_CLI=("docker" "compose" "run" "--rm" "--entrypoint" "az" "flask-app")
  if ! "${AZ_CLI[@]}" account get-access-token --scope https://management.azure.com//.default >/dev/null 2>&1; then
    echo "[https] Azure CLI login required inside container. Follow the device-code flow below."
    if ! "${AZ_CLI[@]}" login --use-device-code; then
      echo "[https] az login inside container failed; aborting." >&2
      exit 1
    fi
    ACCOUNT_INFO=$("${AZ_CLI[@]}" account show --output json 2>/dev/null || true)
    if [[ -n "${ACCOUNT_INFO}" ]]; then
      SUBSCRIPTION_ID=$(echo "${ACCOUNT_INFO}" | python -c "import sys,json; data=json.load(sys.stdin); print(data.get('id',''))" 2>/dev/null)
      if [[ -n "${SUBSCRIPTION_ID}" ]]; then
        "${AZ_CLI[@]}" account set --subscription "${SUBSCRIPTION_ID}" >/dev/null || true
      fi
    fi
    # Re-test token acquisition to ensure success.
    if ! "${AZ_CLI[@]}" account get-access-token --scope https://management.azure.com//.default >/dev/null 2>&1; then
      echo "[https] Unable to obtain access token from Azure CLI after login; aborting." >&2
      exit 1
    fi
  fi
fi

docker compose up -d reverse-proxy flask-app keycloak
