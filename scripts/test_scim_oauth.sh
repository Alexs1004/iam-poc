#!/usr/bin/env bash
# Test SCIM OAuth 2.0 Bearer Token authentication implementation
#
# Usage:
#   ./scripts/test_scim_oauth.sh
#
# Expected results:
#   - OAuth implemented: Test 1 returns 401, Test 2 returns 401
#   - OAuth missing: Test 1 returns 200/403, Test 2 ignores token

set -euo pipefail

BASE_URL="${SCIM_API_URL:-https://localhost/scim/v2}"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔍 Testing SCIM OAuth 2.0 Bearer Token Authentication"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Base URL: $BASE_URL"
echo ""

# Test 1: Request without Authorization header
echo "Test 1: Request without Bearer token"
echo "  Command: curl -X GET $BASE_URL/Users"
HTTP_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/Users")

if [ "$HTTP_STATUS" = "401" ]; then
    echo -e "  ${GREEN}✓ PASS${NC} - Returned 401 Unauthorized (OAuth enforced)"
    TEST1_PASS=true
else
    echo -e "  ${RED}✗ FAIL${NC} - Returned $HTTP_STATUS (expected 401)"
    echo -e "  ${YELLOW}⚠ OAuth Bearer token validation NOT implemented${NC}"
    TEST1_PASS=false
fi
echo ""

# Test 2: Request with invalid Bearer token
echo "Test 2: Request with invalid Bearer token"
echo "  Command: curl -H 'Authorization: Bearer invalid-token-123' -X GET $BASE_URL/Users"
HTTP_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer invalid-token-123" \
  -X GET "$BASE_URL/Users")

if [ "$HTTP_STATUS" = "401" ]; then
    echo -e "  ${GREEN}✓ PASS${NC} - Returned 401 Unauthorized (token validation enforced)"
    TEST2_PASS=true
else
    echo -e "  ${RED}✗ FAIL${NC} - Returned $HTTP_STATUS (expected 401)"
    echo -e "  ${YELLOW}⚠ OAuth Bearer token validation NOT implemented${NC}"
    TEST2_PASS=false
fi
echo ""

# Test 3: ServiceProviderConfig should be public (no auth required)
echo "Test 3: ServiceProviderConfig public access (RFC 7644 discovery)"
echo "  Command: curl -X GET $BASE_URL/ServiceProviderConfig"
HTTP_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/ServiceProviderConfig")

if [ "$HTTP_STATUS" = "200" ]; then
    echo -e "  ${GREEN}✓ PASS${NC} - Returned 200 OK (discovery endpoint public)"
    TEST3_PASS=true
else
    echo -e "  ${YELLOW}⚠ WARNING${NC} - Returned $HTTP_STATUS (expected 200)"
    echo -e "  ${YELLOW}⚠ Discovery endpoints should be public per RFC 7644${NC}"
    TEST3_PASS=false
fi
echo ""

# Test 4: Try with real service account token (if credentials available)
if [ -f ".runtime/secrets/keycloak-service-client-secret" ]; then
    echo "Test 4: Request with valid service account token"
    
    SECRET=$(cat .runtime/secrets/keycloak-service-client-secret)
    TOKEN_RESPONSE=$(curl -k -s -X POST \
      "https://localhost/realms/demo/protocol/openid-connect/token" \
      -d "grant_type=client_credentials" \
      -d "client_id=automation-cli" \
      -d "client_secret=$SECRET")
    
    if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
        ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
        echo "  ✓ Obtained OAuth token from Keycloak"
        
        HTTP_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" \
          -H "Authorization: Bearer $ACCESS_TOKEN" \
          -X GET "$BASE_URL/Users")
        
        if [ "$HTTP_STATUS" = "200" ]; then
            echo -e "  ${GREEN}✓ PASS${NC} - Returned 200 OK (valid token accepted)"
            TEST4_PASS=true
        elif [ "$HTTP_STATUS" = "401" ]; then
            echo -e "  ${RED}✗ FAIL${NC} - Returned 401 with valid token (token validation broken)"
            echo -e "  ${YELLOW}⚠ Check JWT signature validation against Keycloak JWKS${NC}"
            TEST4_PASS=false
        elif [ "$HTTP_STATUS" = "403" ]; then
            echo -e "  ${YELLOW}⚠ PARTIAL${NC} - Returned 403 Forbidden (token validated but insufficient roles)"
            echo -e "  ${YELLOW}⚠ Service account may lack realm-admin or iam-operator role${NC}"
            TEST4_PASS=false
        else
            echo -e "  ${RED}✗ FAIL${NC} - Returned $HTTP_STATUS (unexpected)"
            TEST4_PASS=false
        fi
    else
        echo -e "  ${RED}✗ FAIL${NC} - Could not obtain token from Keycloak"
        echo "  Response: $TOKEN_RESPONSE"
        TEST4_PASS=false
    fi
else
    echo "Test 4: SKIPPED (no service account secret found)"
    echo "  Run 'make quickstart' to provision automation-cli service account"
    TEST4_PASS="skipped"
fi
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Test Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$TEST1_PASS" = true ] && [ "$TEST2_PASS" = true ] && [ "$TEST3_PASS" = true ]; then
    echo -e "${GREEN}✓ OAuth 2.0 Bearer Token authentication IMPLEMENTED${NC}"
    echo ""
    echo "RFC 7644 Compliance:"
    echo "  ✓ Missing token rejected (401)"
    echo "  ✓ Invalid token rejected (401)"
    echo "  ✓ Discovery endpoint public (200)"
    
    if [ "$TEST4_PASS" = true ]; then
        echo "  ✓ Valid token accepted (200)"
        echo ""
        echo -e "${GREEN}🎉 All tests passed - SCIM API is RFC 7644 compliant${NC}"
        exit 0
    elif [ "$TEST4_PASS" = "skipped" ]; then
        echo "  ⊘ Valid token test skipped"
        echo ""
        echo -e "${YELLOW}⚠ OAuth implemented but not fully tested (no service account)${NC}"
        exit 0
    else
        echo "  ✗ Valid token rejected (unexpected)"
        echo ""
        echo -e "${YELLOW}⚠ OAuth partially implemented (token validation may be broken)${NC}"
        exit 1
    fi
else
    echo -e "${RED}✗ OAuth 2.0 Bearer Token authentication NOT IMPLEMENTED${NC}"
    echo ""
    echo "Failed tests:"
    [ "$TEST1_PASS" = false ] && echo "  ✗ Test 1: Missing token not rejected"
    [ "$TEST2_PASS" = false ] && echo "  ✗ Test 2: Invalid token not rejected"
    [ "$TEST3_PASS" = false ] && echo "  ⚠ Test 3: Discovery endpoint not public"
    echo ""
    echo -e "${YELLOW}🔧 Implementation required - see docs/SCIM_AUTHENTICATION.md${NC}"
    echo ""
    echo "Quick fix (6h effort):"
    echo "  1. Create app/api/scim_auth.py (OAuth middleware)"
    echo "  2. Apply @require_scim_oauth to SCIM routes"
    echo "  3. Add tests in tests/test_scim_api.py"
    echo "  4. Validate with: ./scripts/test_scim_oauth.sh"
    echo ""
    echo "Documentation:"
    echo "  • Implementation guide: docs/SCIM_AUTHENTICATION.md"
    echo "  • Executive summary: docs/SCIM_AUTH_SUMMARY.md"
    echo "  • E2E workaround: docs/E2E_SCIM_WORKAROUND.md"
    exit 1
fi
