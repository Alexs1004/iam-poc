#!/bin/bash
# Test script for nginx rate limiting on verification endpoint
# This demonstrates DoS protection in action

set -e

echo "🛡️  Testing Rate Limiting on /verification endpoint"
echo "════════════════════════════════════════════════════"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

BASE_URL="https://localhost"
ENDPOINT="/verification"
TOTAL_REQUESTS=15
CONCURRENT_REQUESTS=5

echo -e "${BLUE}Configuration:${NC}"
echo "• Rate limit: 10 requests/minute per IP"
echo "• Burst: 5 additional requests"
echo "• Testing with: $TOTAL_REQUESTS requests"
echo "• Expected: First ~10-15 requests pass, rest get 429"
echo

# Function to make a request and capture response
make_request() {
    local request_num=$1
    local response=$(curl -s -w "HTTPSTATUS:%{http_code}\tTIME:%{time_total}" \
        -k -X GET "$BASE_URL$ENDPOINT" 2>/dev/null || echo "HTTPSTATUS:000\tTIME:0")
    
    local http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    local time_total=$(echo "$response" | grep -o "TIME:[0-9.]*" | cut -d: -f2)
    
    if [[ "$http_code" == "200" ]]; then
        echo -e "${GREEN}Request $request_num: ✅ HTTP $http_code (${time_total}s)${NC}"
    elif [[ "$http_code" == "429" ]]; then
        echo -e "${RED}Request $request_num: 🚫 HTTP $http_code - Rate Limited (${time_total}s)${NC}"
    else
        echo -e "${YELLOW}Request $request_num: ⚠️  HTTP $http_code (${time_total}s)${NC}"
    fi
    
    return $http_code
}

echo -e "${BLUE}🚀 Sending $TOTAL_REQUESTS sequential requests...${NC}"
echo

success_count=0
rate_limited_count=0
error_count=0

for i in $(seq 1 $TOTAL_REQUESTS); do
    make_request $i
    case $? in
        200) ((success_count++)) ;;
        429) ((rate_limited_count++)) ;;
        *) ((error_count++)) ;;
    esac
    
    # Small delay between requests to see rate limiting in action
    sleep 0.1
done

echo
echo -e "${BLUE}📊 Test Results Summary:${NC}"
echo "════════════════════════════"
echo -e "${GREEN}✅ Successful (200): $success_count${NC}"
echo -e "${RED}🚫 Rate Limited (429): $rate_limited_count${NC}"
echo -e "${YELLOW}⚠️  Other errors: $error_count${NC}"
echo

if [[ $rate_limited_count -gt 0 ]]; then
    echo -e "${GREEN}🎯 Rate limiting is working correctly!${NC}"
    echo "   DoS protection is active and functional."
else
    echo -e "${YELLOW}⚠️  No rate limiting detected.${NC}"
    echo "   Check nginx configuration or increase request frequency."
fi

echo
echo -e "${BLUE}🔍 To test concurrent requests (more aggressive):${NC}"
echo "   for i in {1..20}; do curl -k -s -o /dev/null -w \"HTTP: %{http_code}\\n\" $BASE_URL$ENDPOINT & done; wait"

echo
echo -e "${BLUE}📋 Rate Limiting Configuration Details:${NC}"
echo "   • Verification endpoint: 10 req/min + 5 burst"
echo "   • SCIM API: 60 req/min + 10 burst"
echo "   • Admin UI: 30 req/min + 8 burst"
echo "   • Protection level: Infrastructure (nginx)"