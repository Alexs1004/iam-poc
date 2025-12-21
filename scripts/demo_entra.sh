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

# ─────────────────────────────────────────────────────────────────────────────
# App Roles Configuration (Production-grade)
# ─────────────────────────────────────────────────────────────────────────────
# Why: App Roles provide fine-grained access control at the application level.
# When "User assignment required" is enabled (security best practice),
# users must be assigned to an App Role to access the application.
#
# Security benefits (OWASP/NIST aligned):
# - Principle of Least Privilege: Only assigned users/groups can access
# - Defense in Depth: Groups + App Roles = double layer of authorization
# - Auditability: Clear record of who has access to what
# - AADSTS50105 error prevents unauthorized access attempts
#
# App Roles defined:
# - iam-operator: Can perform JML operations
# - manager: Can view dashboard and reports
# - analyst: Read-only access to security data
# - admin: Full administrative access (equivalent to realm-admin)
# ─────────────────────────────────────────────────────────────────────────────

# App Role definitions (same as Keycloak roles)
# UUIDs are stable identifiers for each role
declare -A APP_ROLE_IDS=(
  ["iam-operator"]="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  ["manager"]="b2c3d4e5-f6a7-8901-bcde-f12345678901"
  ["analyst"]="c3d4e5f6-a7b8-9012-cdef-123456789012"
  ["admin"]="d4e5f6a7-b8c9-0123-defa-234567890123"
)

# Group → App Role mapping
declare -A GROUP_TO_ROLE=(
  ["IAM-Operators"]="iam-operator"
  ["Security-Managers"]="manager"
  ["Security-Analysts"]="analyst"
  ["Administrators"]="admin"
)

create_app_roles() {
  local app_client_id="${1:-${ENTRA_APP_CLIENT_ID:-${ENTRA_CLIENT_ID:-}}}"
  
  if [[ -z "$app_client_id" ]]; then
    echo -e "${YELLOW}⚠ No ENTRA_APP_CLIENT_ID configured, skipping App Roles creation${RESET}"
    return 0
  fi
  
  echo -e "${PURPLE}=== Creating App Roles in App Registration ===${RESET}"
  
  # Get current app roles to preserve existing ones
  local current_roles
  current_roles=$(az ad app show --id "$app_client_id" --query "appRoles" -o json 2>/dev/null || echo "[]")
  
  # Check if our custom roles already exist (check for iam-operator role)
  local has_custom_roles
  has_custom_roles=$(echo "$current_roles" | jq 'map(select(.value == "iam-operator")) | length')
  
  if [[ "$has_custom_roles" -ge 1 ]]; then
    echo -e "${BLUE}ℹ App Roles already configured${RESET}"
    return 0
  fi
  
  # Build new App Roles array by merging existing roles with our custom roles
  # This preserves Azure's default roles (User, msiam_access) while adding ours
  local merged_roles
  merged_roles=$(echo "$current_roles" | jq '. + [
    {
      "allowedMemberTypes": ["User"],
      "description": "IAM Operators can perform Joiner/Mover/Leaver operations",
      "displayName": "IAM Operator",
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "isEnabled": true,
      "value": "iam-operator"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "Security Managers can view dashboard and manage team access",
      "displayName": "Security Manager",
      "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "isEnabled": true,
      "value": "manager"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "Security Analysts have read-only access to security data",
      "displayName": "Security Analyst",
      "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
      "isEnabled": true,
      "value": "analyst"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "Administrators have full access (equivalent to realm-admin)",
      "displayName": "Administrator",
      "id": "d4e5f6a7-b8c9-0123-defa-234567890123",
      "isEnabled": true,
      "value": "admin"
    }
  ]')
  
  # Update App Registration with merged App Roles
  if az ad app update --id "$app_client_id" --app-roles "$merged_roles" 2>/dev/null; then
    echo -e "${GREEN}✓ App Roles created successfully${RESET}"
    echo "  - iam-operator: JML operations"
    echo "  - manager: Dashboard access"
    echo "  - analyst: Read-only access"
    echo "  - admin: Full administrative access"
  else
    echo -e "${RED}✗ Failed to create App Roles${RESET}"
    echo -e "${YELLOW}  Hint: Ensure you have Application.ReadWrite.All permission${RESET}"
    return 1
  fi
  
  echo "[AUDIT] App Roles created | AppId=$app_client_id"
}

enable_user_assignment_required() {
  local app_client_id="${1:-${ENTRA_APP_CLIENT_ID:-${ENTRA_CLIENT_ID:-}}}"
  
  if [[ -z "$app_client_id" ]]; then
    return 0
  fi
  
  echo -e "${PURPLE}=== Enabling 'User assignment required' (security best practice) ===${RESET}"
  
  if az ad sp update --id "$app_client_id" --set appRoleAssignmentRequired=true 2>/dev/null; then
    echo -e "${GREEN}✓ User assignment required enabled${RESET}"
    echo -e "${BLUE}  ℹ Only users/groups assigned to App Roles can access the app${RESET}"
  else
    echo -e "${YELLOW}⚠ Could not enable user assignment requirement${RESET}"
  fi
  
  echo "[AUDIT] appRoleAssignmentRequired=true | AppId=$app_client_id"
}

assign_group_to_app_role() {
  local group_name="$1"
  local role_value="$2"
  local app_client_id="${3:-${ENTRA_APP_CLIENT_ID:-${ENTRA_CLIENT_ID:-}}}"
  
  if [[ -z "$app_client_id" ]]; then
    echo -e "${YELLOW}⚠ No ENTRA_APP_CLIENT_ID configured${RESET}"
    return 0
  fi
  
  echo -e "${PURPLE}=== Assigning group '$group_name' to role '$role_value' ===${RESET}"
  
  # Get Service Principal (Enterprise Application) object ID
  local sp_object_id
  sp_object_id=$(az ad sp show --id "$app_client_id" --query id -o tsv 2>/dev/null || echo "")
  
  if [[ -z "$sp_object_id" ]]; then
    echo -e "${RED}✗ Service Principal not found for app '$app_client_id'${RESET}"
    return 1
  fi
  
  # Get group object ID
  local group_id
  group_id=$(az ad group show --group "$group_name" --query id -o tsv 2>/dev/null || echo "")
  
  if [[ -z "$group_id" ]]; then
    echo -e "${RED}✗ Group '$group_name' not found${RESET}"
    return 1
  fi
  
  # Get App Role ID from our mapping
  local role_id="${APP_ROLE_IDS[$role_value]}"
  
  if [[ -z "$role_id" ]]; then
    echo -e "${RED}✗ Unknown role '$role_value'${RESET}"
    return 1
  fi
  
  # Check if assignment already exists
  local existing
  existing=$(az rest --method GET \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${sp_object_id}/appRoleAssignedTo" \
    --query "value[?principalId=='${group_id}' && appRoleId=='${role_id}'].id" -o tsv 2>/dev/null || echo "")
  
  if [[ -n "$existing" ]]; then
    echo -e "${BLUE}ℹ Group already assigned to role${RESET}"
    return 0
  fi
  
  # Create the assignment via Microsoft Graph API
  local payload
  payload=$(cat <<EOF
{
  "principalId": "${group_id}",
  "resourceId": "${sp_object_id}",
  "appRoleId": "${role_id}"
}
EOF
)
  
  if az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${sp_object_id}/appRoleAssignedTo" \
    --headers "Content-Type=application/json" \
    --body "$payload" >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Group assigned to App Role${RESET}"
  else
    echo -e "${RED}✗ Failed to assign group to App Role${RESET}"
    echo -e "${YELLOW}  Hint: Ensure you have Application.ReadWrite.All or AppRoleAssignment.ReadWrite.All permission${RESET}"
    return 1
  fi
  
  echo "[AUDIT] Group assigned to App Role | Group=$group_name | Role=$role_value | AppId=$app_client_id"
}

configure_app_access() {
  local app_client_id="${1:-${ENTRA_APP_CLIENT_ID:-${ENTRA_CLIENT_ID:-}}}"
  
  if [[ -z "$app_client_id" ]]; then
    echo -e "${YELLOW}⚠ No ENTRA_APP_CLIENT_ID configured, skipping app configuration${RESET}"
    return 0
  fi
  
  echo ""
  echo -e "${BLUE}════════════════════════════════════════════════════════════${RESET}"
  echo -e "${BLUE}  Configuring Enterprise Application (Production Setup)      ${RESET}"
  echo -e "${BLUE}════════════════════════════════════════════════════════════${RESET}"
  
  # Step 1: Create App Roles in App Registration
  create_app_roles "$app_client_id"
  
  # Step 2: Enable "User assignment required" (security best practice)
  enable_user_assignment_required "$app_client_id"
  
  # Step 3: Assign groups to their corresponding App Roles
  echo ""
  echo -e "${PURPLE}=== Assigning groups to App Roles ===${RESET}"
  for group_name in "${!GROUP_TO_ROLE[@]}"; do
    local role_value="${GROUP_TO_ROLE[$group_name]}"
    assign_group_to_app_role "$group_name" "$role_value" "$app_client_id"
  done
  
  echo ""
  echo -e "${GREEN}✓ Enterprise Application configured with production-grade security${RESET}"
  echo "  - App Roles defined for fine-grained access control"
  echo "  - User assignment required (principle of least privilege)"
  echo "  - Groups assigned to appropriate App Roles"
  
  echo "[AUDIT] App access fully configured | AppId=$app_client_id | Mode=production"
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
  
  # Assign initial groups/roles (same structure as Keycloak demo_jml.sh)
  # Keycloak roles → Entra groups mapping:
  # - analyst → Security-Analysts
  # - manager → Security-Managers  
  # - iam-operator → IAM-Operators
  # - realm-admin → Administrators (admin equivalent)
  assign_group "alice" "Security-Analysts"
  assign_group "bob" "Security-Analysts"
  assign_group "carol" "Security-Managers"
  assign_group "joe" "IAM-Operators"
  assign_group "joe" "Administrators"  # Equivalent to realm-admin in Keycloak
  
  # ─────────────────────────────────────────────────────────────────────────────
  # Configure Enterprise Application access
  # ─────────────────────────────────────────────────────────────────────────────
  # For POC: Disable "User assignment required" to allow all tenant users
  # In production: Enable assignment and use App Roles for fine-grained access
  # ─────────────────────────────────────────────────────────────────────────────
  echo ""
  configure_app_access
  
  # Mover: Promote alice from analyst to iam-operator (same as demo_jml.sh)
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
  echo "Users created (same as demo_jml.sh for Keycloak):"
  echo "  - alice@${ENTRA_DOMAIN} (IAM-Operators - promoted from analyst)"
  echo "  - bob@${ENTRA_DOMAIN} (disabled - leaver)"
  echo "  - carol@${ENTRA_DOMAIN} (Security-Managers)"
  echo "  - joe@${ENTRA_DOMAIN} (IAM-Operators + Administrators = full admin)"
  echo ""
  echo "Group → Role mapping:"
  echo "  - IAM-Operators → iam-operator"
  echo "  - Security-Managers → manager"
  echo "  - Security-Analysts → analyst"
  echo "  - Administrators → admin (realm-admin equivalent)"
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
