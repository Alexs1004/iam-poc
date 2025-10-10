#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT_DIR}/certs"
CERT_PATH="${CERT_DIR}/localhost.crt"
KEY_PATH="${CERT_DIR}/localhost.key"
CERT_DAYS="${CERT_DAYS:-30}"

FORCE_RENEW=false
if [[ "${1:-}" == "--rotate" ]]; then
  FORCE_RENEW=true
fi

mkdir -p "${CERT_DIR}"

if [[ "${FORCE_RENEW}" == "true" ]]; then
  rm -f "${CERT_PATH}" "${KEY_PATH}"
fi

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
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
fi

echo "[https] Starting Flask app behind HTTPS proxy..."
cd "${ROOT_DIR}"
docker compose up -d reverse-proxy flask-app keycloak
