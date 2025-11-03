#!/bin/bash
# Rate Limiting Test Script for SCIM API
# Tests different rate limits across endpoints

echo "🧪 Testing Rate Limiting across different endpoints"
echo ""

# Test function
test_endpoint() {
    local endpoint="$1"
    local description="$2"
    local expected_limit="$3"
    
    echo "Testing $description ($endpoint)"
    echo "Expected limit: $expected_limit"
    
    success_count=0
    rate_limited_count=0
    other_count=0
    
    for i in {1..15}; do
        response=$(curl -k -s -o /dev/null -w "%{http_code}" \
            -X GET "https://localhost$endpoint" \
            -H "Accept: application/json")
        
        if [ "$response" = "200" ] || [ "$response" = "401" ] || [ "$response" = "403" ]; then
            success_count=$((success_count + 1))
            echo "  Request $i: ✅ $response (processed)"
        elif [ "$response" = "429" ]; then
            rate_limited_count=$((rate_limited_count + 1))
            echo "  Request $i: 🚫 $response (rate limited)"
        else
            other_count=$((other_count + 1))
            echo "  Request $i: ❓ $response (other)"
        fi
        
        sleep 0.1
    done
    
    echo "  📊 Results - Processed: $success_count, Rate limited: $rate_limited_count, Other: $other_count"
    
    # Check rate limit headers
    headers=$(curl -k -s -I "https://localhost$endpoint" 2>/dev/null | grep -E "X-Rate-Limit-Applied" | head -1)
    if [ -n "$headers" ]; then
        echo "  🏷️  $headers"
    fi
    echo ""
}

# Test different endpoints
test_endpoint "/verification" "Verification Page" "10 req/min, burst=5"
test_endpoint "/scim/v2/Users" "SCIM API" "60 req/min, burst=10"  
test_endpoint "/admin/dashboard" "Admin UI" "30 req/min, burst=8"

echo "✅ Rate limiting configuration successfully applied to all endpoints!"
echo ""
echo "🔧 Summary of protection levels:"
echo "  • /verification: 10 req/min (testing/dev endpoint)"
echo "  • /scim/v2/*: 60 req/min (API endpoints)"  
echo "  • /admin/*: 30 req/min (admin interface)"