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

# Remove existing certificates if rotation is requested
if [[ "${FORCE_RENEW}" == "true" ]]; then
  rm -f "${CERT_PATH}" "${KEY_PATH}"
fi

# Generate new self-signed certificate if missing
if [[ ! -f "${CERT_PATH}" || ! -f "${KEY_PATH}" ]]; then
  echo "[https] Generating self-signed certificate for localhost (valid ${CERT_DAYS} days)..."
  openssl req \
    -x509 \
    -nodes \
    -newkey rsa:2048 \
    -days "${CERT_DAYS}" \
    -keyout "${KEY_PATH}" \
    -out "${CERT_PATH}" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"  # Enable both hostname and IP access
fi

# Launch containerized services with HTTPS support
echo "[https] Starting Flask app behind HTTPS proxy..."
cd "${ROOT_DIR}"
docker compose up -d reverse-proxy flask-app keycloak