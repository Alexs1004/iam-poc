#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Entra ID User Provisioning Script
# ═══════════════════════════════════════════════════════════════════════════════
# Provision demo users in Azure Entra ID via Azure CLI.
# Follows the same JML (Joiner/Mover/Leaver) pattern as demo_jml.sh for Keycloak.
#
# Usage:
#   ./scripts/demo_entra.sh              # Provision all demo users
#   ./scripts/demo_entra.sh --cleanup    # Disable demo users (soft delete)
#   ./scripts/demo_entra.sh --hard-cleanup  # Delete demo users permanently
#
# Prerequisites:
#   - Azure CLI installed (az)
#   - Service Principal with User.ReadWrite.All permission
#   - Or: az login with admin privileges
# ═══════════════════════════════════════════════════════════════════════════════
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

# ─────────────────────────────────────────────────────────────────────────────
# Load configuration (same pattern as demo_jml.sh)
# ─────────────────────────────────────────────────────────────────────────────
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
  set -a
  source "${PROJECT_ROOT}/.env"
  set +a
fi

# Load secrets from .runtime/secrets/ if available
load_secret_from_local_file() {
  local secret_name="$1"
  local secret_file="${PROJECT_ROOT}/.runtime/secrets/${secret_name}"
  
  if [[ -f "$secret_file" ]]; then
    cat "$secret_file"
    return 0
  fi
  return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
ENTRA_DOMAIN="${ENTRA_DOMAIN:-${AZURE_DOMAIN:-}}"
ENTRA_TENANT_ID="${ENTRA_TENANT_ID:-${AZURE_TENANT_ID:-}}"

# Auth method: service-principal or interactive
ENTRA_AUTH_METHOD="${ENTRA_AUTH_METHOD:-interactive}"
ENTRA_CLIENT_ID="${ENTRA_CLIENT_ID:-${AZURE_CLIENT_ID:-}}"
ENTRA_CLIENT_SECRET="${ENTRA_CLIENT_SECRET:-}"

# Try to load client secret from Key Vault cache
if [[ -z "${ENTRA_CLIENT_SECRET}" ]]; then
  ENTRA_CLIENT_SECRET=$(load_secret_from_local_file "entra_client_secret" || echo "")
fi

# Demo user passwords (same as Keycloak demo)
ALICE_TEMP_PASSWORD="${ALICE_TEMP_PASSWORD:-${ALICE_TEMP_PASSWORD_DEMO:-Temp123!}}"
BOB_TEMP_PASSWORD="${BOB_TEMP_PASSWORD:-${BOB_TEMP_PASSWORD_DEMO:-Temp123!}}"
CAROL_TEMP_PASSWORD="${CAROL_TEMP_PASSWORD:-${CAROL_TEMP_PASSWORD_DEMO:-Temp123!}}"
JOE_TEMP_PASSWORD="${JOE_TEMP_PASSWORD:-${JOE_TEMP_PASSWORD_DEMO:-Temp123!}}"

# Entra requires stronger passwords than Keycloak demo defaults
# Generate compliant passwords if using weak demo defaults
generate_entra_password() {
  local base="$1"
  # If password is too weak, enhance it for Entra compliance
  if [[ ${#base} -lt 12 ]] || ! [[ "$base" =~ [A-Z] ]] || ! [[ "$base" =~ [0-9] ]]; then
    echo "${base}Azure2024!"
  else
    echo "$base"
  fi
}

ALICE_PASSWORD=$(generate_entra_password "$ALICE_TEMP_PASSWORD")
BOB_PASSWORD=$(generate_entra_password "$BOB_TEMP_PASSWORD")
CAROL_PASSWORD=$(generate_entra_password "$CAROL_TEMP_PASSWORD")
JOE_PASSWORD=$(generate_entra_password "$JOE_TEMP_PASSWORD")

# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────
if [[ -z "${ENTRA_DOMAIN}" ]]; then
  echo -e "${RED}✗ ENTRA_DOMAIN is required (e.g., contoso.onmicrosoft.com)${RESET}" >&2
  echo "Set it in .env or as environment variable" >&2
  exit 1
fi

if ! command -v az >/dev/null 2>&1; then
  echo -e "${RED}✗ Azure CLI (az) is required but not installed${RESET}" >&2
  echo "Install: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli" >&2
  exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Azure Authentication
# ─────────────────────────────────────────────────────────────────────────────
login_entra() {
  echo -e "${BLUE}=== Connexion à Entra ID ===${RESET}"
  
  # Check if already logged in
  if az account show &>/dev/null; then
    local current_tenant
    current_tenant=$(az account show --query tenantId -o tsv 2>/dev/null || echo "")
    
    if [[ -n "${ENTRA_TENANT_ID}" ]] && [[ "${current_tenant}" != "${ENTRA_TENANT_ID}" ]]; then
      echo -e "${YELLOW}⚠ Logged into different tenant, re-authenticating...${RESET}"
    else
      echo -e "${GREEN}✓ Already authenticated to Azure${RESET}"
      return 0
    fi
  fi
  
  if [[ "${ENTRA_AUTH_METHOD}" == "service-principal" ]]; then
    # Service Principal authentication (for CI/CD)
    if [[ -z "${ENTRA_CLIENT_ID}" ]] || [[ -z "${ENTRA_CLIENT_SECRET}" ]]; then
      echo -e "${RED}✗ ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET required for service-principal auth${RESET}" >&2
      exit 1
    fi
    
    az login --service-principal \
      --username "${ENTRA_CLIENT_ID}" \
      --password "${ENTRA_CLIENT_SECRET}" \
      --tenant "${ENTRA_TENANT_ID}" \
      --allow-no-subscriptions >/dev/null
    
    echo -e "${GREEN}✓ Authenticated via Service Principal${RESET}"
  else
    # Interactive login (for development)
    if [[ -n "${ENTRA_TENANT_ID}" ]]; then
      az login --tenant "${ENTRA_TENANT_ID}" --allow-no-subscriptions
    else
      az login --allow-no-subscriptions
    fi
    echo -e "${GREEN}✓ Authenticated interactively${RESET}"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# User Operations
# ─────────────────────────────────────────────────────────────────────────────
user_exists() {
  local upn="$1"
  az ad user show --id "$upn" &>/dev/null
}

create_user() {
  local display_name="$1"
  local nickname="$2"
  local password="$3"
  local job_title="${4:-}"
  local upn="${nickname}@${ENTRA_DOMAIN}"

  echo -e "${YELLOW}=== Provisioning de l'utilisateur $upn (Joiner) ===${RESET}"

  # Idempotence check
  if user_exists "$upn"; then
    echo -e "${BLUE}ℹ L'utilisateur existe déjà, mise à jour...${RESET}"
    az ad user update --id "$upn" \
      --display-name "$display_name" \
      --job-title "$job_title" \
      --account-enabled true >/dev/null 2>&1 || true
    echo -e "${GREEN}✓ Utilisateur mis à jour${RESET}"
    return 0
  fi

  # Create new user
  # --force-change-password-next-sign-in: Security best practice
  az ad user create \
    --display-name "$display_name" \
    --user-principal-name "$upn" \
    --password "$password" \
    --force-change-password-next-sign-in true \
    --mail-nickname "$nickname" >/dev/null
  
  # Set job title (separate call required)
  if [[ -n "$job_title" ]]; then
    az ad user update --id "$upn" --job-title "$job_title" >/dev/null 2>&1 || true
  fi
  
  echo -e "${GREEN}✓ Utilisateur créé${RESET}"
  
  # Audit log (password hidden)
  echo "[AUDIT] User created | UPN=$upn | DisplayName=$display_name | JobTitle=$job_title"
}

assign_group() {
  local nickname="$1"
  local group_name="$2"
  local upn="${nickname}@${ENTRA_DOMAIN}"

  echo -e "${PURPLE}=== Attribution du groupe '$group_name' à $upn ===${RESET}"

  # Get user object ID
  local user_id
  user_id=$(az ad user show --id "$upn" --query id -o tsv 2>/dev/null || echo "")
  
  if [[ -z "$user_id" ]]; then
    echo -e "${RED}✗ Utilisateur $upn non trouvé${RESET}"
    return 1
  fi

  # Get group ID (group must exist)
  local group_id
  group_id=$(az ad group show --group "$group_name" --query id -o tsv 2>/dev/null || echo "")

  if [[ -z "$group_id" ]]; then
    echo -e "${YELLOW}⚠ Le groupe '$group_name' n'existe pas, création...${RESET}"
    az ad group create --display-name "$group_name" --mail-nickname "${group_name// /-}" >/dev/null
    group_id=$(az ad group show --group "$group_name" --query id -o tsv)
    echo -e "${GREEN}✓ Groupe créé${RESET}"
  fi

  # Add member (idempotent - will fail silently if already member)
  if az ad group member add --group "$group_name" --member-id "$user_id" 2>/dev/null; then
    echo -e "${GREEN}✓ Membre ajouté au groupe${RESET}"
  else
    echo -e "${BLUE}ℹ Membre déjà dans le groupe${RESET}"
  fi
  
  echo "[AUDIT] Group assigned | UPN=$upn | Group=$group_name"
}

remove_from_group() {
  local nickname="$1"
  local group_name="$2"
  local upn="${nickname}@${ENTRA_DOMAIN}"

  echo -e "${PURPLE}=== Retrait du groupe '$group_name' pour $upn ===${RESET}"

  local user_id
  user_id=$(az ad user show --id "$upn" --query id -o tsv 2>/dev/null || echo "")
  
  if [[ -z "$user_id" ]]; then
    echo -e "${YELLOW}⚠ Utilisateur $upn non trouvé${RESET}"
    return 0
  fi

  if az ad group member remove --group "$group_name" --member-id "$user_id" 2>/dev/null; then
    echo -e "${GREEN}✓ Membre retiré du groupe${RESET}"
  else
    echo -e "${BLUE}ℹ Membre n'était pas dans le groupe${RESET}"
  fi
  
  echo "[AUDIT] Group removed | UPN=$upn | Group=$group_name"
}

disable_user() {
  local nickname="$1"
  local upn="${nickname}@${ENTRA_DOMAIN}"
  
  echo -e "${RED}=== Désactivation de $upn (Leaver) ===${RESET}"
  
  if ! user_exists "$upn"; then
    echo -e "${YELLOW}⚠ Utilisateur $upn non trouvé, rien à désactiver${RESET}"
    return 0
  fi
  
  # Disable account (soft delete - reversible)
  az ad user update --id "$upn" --account-enabled false >/dev/null
  echo -e "${GREEN}✓ Compte désactivé${RESET}"
  
  echo "[AUDIT] User disabled (leaver) | UPN=$upn"
}

delete_user() {
  local nickname="$1"
  local upn="${nickname}@${ENTRA_DOMAIN}"
  
  echo -e "${RED}=== Suppression de $upn ===${RESET}"
  
  if ! user_exists "$upn"; then
    echo -e "${YELLOW}⚠ Utilisateur $upn non trouvé${RESET}"
    return 0
  fi
  
  az ad user delete --id "$upn"
  echo -e "${GREEN}✓ Utilisateur supprimé${RESET}"
  
  echo "[AUDIT] User deleted | UPN=$upn"
}

# ─────────────────────────────────────────────────────────────────────────────
# Demo Scenarios (same as demo_jml.sh)
# ─────────────────────────────────────────────────────────────────────────────
provision_demo_users() {
  echo -e "${BLUE}════════════════════════════════════════════════════════════${RESET}"
  echo -e "${BLUE}  Provisioning Demo Users in Entra ID                        ${RESET}"
  echo -e "${BLUE}  Domain: ${ENTRA_DOMAIN}                                     ${RESET}"
  echo -e "${BLUE}════════════════════════════════════════════════════════════${RESET}"
  
  login_entra
  
  # Joiners: Create all demo users
  create_user "Alice Demo" "alice" "$ALICE_PASSWORD" "Security Analyst"
  create_user "Bob Demo" "bob" "$BOB_PASSWORD" "Security Analyst"
  create_user "Carol Demo" "carol" "$CAROL_PASSWORD" "Security Manager"
  create_user "Joe Demo (IAM Operator)" "joe" "$JOE_PASSWORD" "IAM Operator"
  
  # Assign initial groups/roles
  assign_group "alice" "Security-Analysts"
  assign_group "bob" "Security-Analysts"
  assign_group "carol" "Security-Managers"
  assign_group "joe" "IAM-Operators"
  
  # Mover: Promote alice from analyst to operator
  echo -e "${PURPLE}=== Promotion d'alice vers IAM-Operators (Mover) ===${RESET}"
  remove_from_group "alice" "Security-Analysts"
  assign_group "alice" "IAM-Operators"
  
  # Leaver: Disable bob
  disable_user "bob"
  
  echo ""
  echo -e "${GREEN}════════════════════════════════════════════════════════════${RESET}"
  echo -e "${GREEN}  ✓ Provisioning Entra ID terminé                           ${RESET}"
  echo -e "${GREEN}════════════════════════════════════════════════════════════${RESET}"
  echo ""
  echo "Users created:"
  echo "  - alice@${ENTRA_DOMAIN} (promoted to IAM-Operators)"
  echo "  - bob@${ENTRA_DOMAIN} (disabled - leaver)"
  echo "  - carol@${ENTRA_DOMAIN} (Security-Managers)"
  echo "  - joe@${ENTRA_DOMAIN} (IAM-Operators)"
}

cleanup_demo_users() {
  local hard_delete="${1:-false}"
  
  echo -e "${RED}════════════════════════════════════════════════════════════${RESET}"
  echo -e "${RED}  Cleanup Demo Users in Entra ID                             ${RESET}"
  echo -e "${RED}════════════════════════════════════════════════════════════${RESET}"
  
  login_entra
  
  if [[ "$hard_delete" == "true" ]]; then
    echo -e "${RED}⚠ PERMANENT DELETION - Users will be removed${RESET}"
    read -p "Type 'DELETE' to confirm: " confirm
    if [[ "$confirm" != "DELETE" ]]; then
      echo "Aborted."
      exit 0
    fi
    
    delete_user "alice"
    delete_user "bob"
    delete_user "carol"
    delete_user "joe"
  else
    disable_user "alice"
    disable_user "bob"
    disable_user "carol"
    disable_user "joe"
  fi
  
  echo -e "${GREEN}✓ Cleanup terminé${RESET}"
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --cleanup)
    cleanup_demo_users false
    ;;
  --hard-cleanup)
    cleanup_demo_users true
    ;;
  --help|-h)
    echo "Usage: $0 [--cleanup|--hard-cleanup]"
    echo ""
    echo "Actions:"
    echo "  (default)       Provision demo users (alice, bob, carol, joe)"
    echo "  --cleanup       Disable demo users (soft delete)"
    echo "  --hard-cleanup  Permanently delete demo users"
    echo ""
    echo "Environment variables:"
    echo "  ENTRA_DOMAIN        Required. Your Entra ID domain (e.g., contoso.onmicrosoft.com)"
    echo "  ENTRA_TENANT_ID     Optional. Tenant ID for authentication"
    echo "  ENTRA_AUTH_METHOD   Optional. 'interactive' (default) or 'service-principal'"
    echo "  ENTRA_CLIENT_ID     Required for service-principal auth"
    echo "  ENTRA_CLIENT_SECRET Required for service-principal auth"
    ;;
  *)
    provision_demo_users
    ;;
esac
