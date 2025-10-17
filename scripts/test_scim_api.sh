#!/usr/bin/env bash
# Test script for SCIM 2.0 API endpoints

set -euo pipefail

BLUE="\033[1;34m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
cd "${PROJECT_ROOT}"

# Load environment
if [[ -f .env ]]; then
    set -a
    source .env
    set +a
fi

BASE_URL="${SCIM_BASE_URL:-https://localhost/scim/v2}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-demo}"
CLIENT_ID="${KEYCLOAK_SERVICE_CLIENT_ID:-automation-cli}"
CLIENT_SECRET="${KEYCLOAK_SERVICE_CLIENT_SECRET}"

if [[ -z "${CLIENT_SECRET}" ]]; then
    echo -e "${RED}[error] KEYCLOAK_SERVICE_CLIENT_SECRET not set${RESET}" >&2
    exit 1
fi

# Utility functions
log_info() {
    echo -e "${BLUE}[test]${RESET} $*"
}

log_success() {
    echo -e "${GREEN}✓${RESET} $*"
}

log_warning() {
    echo -e "${YELLOW}⚠${RESET} $*"
}

log_error() {
    echo -e "${RED}✗${RESET} $*"
}

# Get OAuth token
get_token() {
    log_info "Obtaining service account token..."
    
    TOKEN=$(curl -sk -X POST \
        "${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token" \
        -d "grant_type=client_credentials" \
        -d "client_id=${CLIENT_ID}" \
        -d "client_secret=${CLIENT_SECRET}" \
        | jq -r '.access_token')
    
    if [[ -z "${TOKEN}" || "${TOKEN}" == "null" ]]; then
        log_error "Failed to obtain token"
        exit 1
    fi
    
    log_success "Token obtained (${#TOKEN} chars)"
}

# Test 1: ServiceProviderConfig
test_service_provider_config() {
    log_info "Test 1: GET /ServiceProviderConfig"
    
    response=$(curl -sk "${BASE_URL}/ServiceProviderConfig" \
        -H "Authorization: Bearer ${TOKEN}")
    
    filter_supported=$(echo "${response}" | jq -r '.filter.supported')
    
    if [[ "${filter_supported}" == "true" ]]; then
        log_success "ServiceProviderConfig OK"
    else
        log_error "ServiceProviderConfig failed"
        echo "${response}" | jq '.'
        return 1
    fi
}

# Test 2: ResourceTypes
test_resource_types() {
    log_info "Test 2: GET /ResourceTypes"
    
    response=$(curl -sk "${BASE_URL}/ResourceTypes" \
        -H "Authorization: Bearer ${TOKEN}")
    
    total=$(echo "${response}" | jq -r '.totalResults')
    
    if [[ "${total}" -ge 1 ]]; then
        log_success "ResourceTypes OK (${total} types)"
    else
        log_error "ResourceTypes failed"
        return 1
    fi
}

# Test 3: Create User
test_create_user() {
    log_info "Test 3: POST /Users (create)"
    
    RANDOM_USER="scimtest$(date +%s)"
    
    response=$(curl -sk -X POST "${BASE_URL}/Users" \
        -H "Content-Type: application/scim+json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "{
            \"schemas\": [\"urn:ietf:params:scim:schemas:core:2.0:User\"],
            \"userName\": \"${RANDOM_USER}\",
            \"emails\": [{\"value\": \"${RANDOM_USER}@example.com\", \"primary\": true}],
            \"name\": {\"givenName\": \"SCIM\", \"familyName\": \"Test\"},
            \"active\": true
        }")
    
    USER_ID=$(echo "${response}" | jq -r '.id')
    created_username=$(echo "${response}" | jq -r '.userName')
    temp_password=$(echo "${response}" | jq -r '._tempPassword // "N/A"')
    
    if [[ "${created_username}" == "${RANDOM_USER}" && "${USER_ID}" != "null" ]]; then
        log_success "User created: ${RANDOM_USER} (ID: ${USER_ID:0:8}...)"
        log_info "Temp password: ${temp_password}"
        echo "${USER_ID}" > /tmp/scim_test_user_id
    else
        log_error "User creation failed"
        echo "${response}" | jq '.'
        return 1
    fi
}

# Test 4: Get User
test_get_user() {
    log_info "Test 4: GET /Users/{id}"
    
    if [[ ! -f /tmp/scim_test_user_id ]]; then
        log_warning "Skipping (no user created)"
        return 0
    fi
    
    USER_ID=$(cat /tmp/scim_test_user_id)
    
    response=$(curl -sk "${BASE_URL}/Users/${USER_ID}" \
        -H "Authorization: Bearer ${TOKEN}")
    
    username=$(echo "${response}" | jq -r '.userName')
    active=$(echo "${response}" | jq -r '.active')
    
    if [[ "${username}" =~ ^scimtest && "${active}" == "true" ]]; then
        log_success "User retrieved: ${username} (active: ${active})"
    else
        log_error "User retrieval failed"
        echo "${response}" | jq '.'
        return 1
    fi
}

# Test 5: List Users
test_list_users() {
    log_info "Test 5: GET /Users (list)"
    
    response=$(curl -sk "${BASE_URL}/Users?count=5" \
        -H "Authorization: Bearer ${TOKEN}")
    
    total=$(echo "${response}" | jq -r '.totalResults')
    count=$(echo "${response}" | jq -r '.Resources | length')
    
    if [[ "${total}" -ge 1 ]]; then
        log_success "Users listed: ${count} returned (total: ${total})"
    else
        log_error "User listing failed"
        return 1
    fi
}

# Test 6: Filter Users
test_filter_users() {
    log_info "Test 6: GET /Users?filter=..."
    
    if [[ ! -f /tmp/scim_test_user_id ]]; then
        log_warning "Skipping (no user created)"
        return 0
    fi
    
    USER_ID=$(cat /tmp/scim_test_user_id)
    
    # Get username first
    username=$(curl -sk "${BASE_URL}/Users/${USER_ID}" \
        -H "Authorization: Bearer ${TOKEN}" \
        | jq -r '.userName')
    
    # Filter by username
    response=$(curl -sk "${BASE_URL}/Users?filter=userName%20eq%20%22${username}%22" \
        -H "Authorization: Bearer ${TOKEN}")
    
    filtered_count=$(echo "${response}" | jq -r '.Resources | length')
    
    if [[ "${filtered_count}" == "1" ]]; then
        log_success "Filtering OK (found ${username})"
    else
        log_error "Filtering failed (expected 1, got ${filtered_count})"
        return 1
    fi
}

# Test 7: Update User (disable)
test_update_user() {
    log_info "Test 7: PUT /Users/{id} (disable)"
    
    if [[ ! -f /tmp/scim_test_user_id ]]; then
        log_warning "Skipping (no user created)"
        return 0
    fi
    
    USER_ID=$(cat /tmp/scim_test_user_id)
    
    # Get current username
    username=$(curl -sk "${BASE_URL}/Users/${USER_ID}" \
        -H "Authorization: Bearer ${TOKEN}" \
        | jq -r '.userName')
    
    # Disable user
    response=$(curl -sk -X PUT "${BASE_URL}/Users/${USER_ID}" \
        -H "Content-Type: application/scim+json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "{
            \"schemas\": [\"urn:ietf:params:scim:schemas:core:2.0:User\"],
            \"userName\": \"${username}\",
            \"active\": false
        }")
    
    active=$(echo "${response}" | jq -r '.active')
    
    if [[ "${active}" == "false" ]]; then
        log_success "User disabled"
    else
        log_error "User update failed"
        echo "${response}" | jq '.'
        return 1
    fi
}

# Test 8: Delete User
test_delete_user() {
    log_info "Test 8: DELETE /Users/{id}"
    
    if [[ ! -f /tmp/scim_test_user_id ]]; then
        log_warning "Skipping (no user created)"
        return 0
    fi
    
    USER_ID=$(cat /tmp/scim_test_user_id)
    
    status_code=$(curl -sk -X DELETE "${BASE_URL}/Users/${USER_ID}" \
        -H "Authorization: Bearer ${TOKEN}" \
        -w "%{http_code}" \
        -o /dev/null)
    
    if [[ "${status_code}" == "204" ]]; then
        log_success "User deleted (HTTP ${status_code})"
        rm -f /tmp/scim_test_user_id
    else
        log_error "User deletion failed (HTTP ${status_code})"
        return 1
    fi
}

# Test 9: Error handling (duplicate user)
test_error_duplicate() {
    log_info "Test 9: Error handling (409 Conflict)"
    
    # Try to create user that already exists
    response=$(curl -sk -X POST "${BASE_URL}/Users" \
        -H "Content-Type: application/scim+json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -w "\nHTTP_STATUS:%{http_code}" \
        -d '{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "alice",
            "emails": [{"value": "alice@example.com", "primary": true}],
            "name": {"givenName": "Alice", "familyName": "Test"},
            "active": true
        }')
    
    status=$(echo "${response}" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
    scim_type=$(echo "${response}" | jq -r '.scimType // "N/A"')
    
    if [[ "${status}" == "409" && "${scim_type}" == "uniqueness" ]]; then
        log_success "Error handling OK (409 Conflict, scimType: uniqueness)"
    else
        log_warning "Error handling partial (HTTP ${status}, scimType: ${scim_type})"
    fi
}

# Run all tests
main() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════${RESET}"
    echo -e "${BLUE}       SCIM 2.0 API Test Suite${RESET}"
    echo -e "${BLUE}═══════════════════════════════════════════════════${RESET}"
    echo ""
    
    get_token
    echo ""
    
    FAILED=0
    
    test_service_provider_config || ((FAILED++))
    test_resource_types || ((FAILED++))
    test_create_user || ((FAILED++))
    test_get_user || ((FAILED++))
    test_list_users || ((FAILED++))
    test_filter_users || ((FAILED++))
    test_update_user || ((FAILED++))
    test_delete_user || ((FAILED++))
    test_error_duplicate || true  # Non-critical
    
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════${RESET}"
    
    if [[ ${FAILED} -eq 0 ]]; then
        echo -e "${GREEN}✓ All tests passed${RESET}"
        exit 0
    else
        echo -e "${RED}✗ ${FAILED} test(s) failed${RESET}"
        exit 1
    fi
}

main "$@"
