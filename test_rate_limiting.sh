#!/bin/bash
# Rate Limiting Test Script for SCIM Verification Page
# Tests the nginx rate limiting configuration

echo "🧪 Testing Rate Limiting on /verification endpoint"
echo "Configuration: 10 requests/minute, burst=5"
echo "Expected behavior: First 15 requests should pass, then 429 errors"
echo ""

success_count=0
rate_limited_count=0

echo "Sending 20 rapid requests to test rate limiting..."
for i in {1..20}; do
    response=$(curl -k -s -o /dev/null -w "%{http_code}" \
        -X GET https://localhost/verification \
        -H "Accept: text/html")
    
    if [ "$response" = "200" ]; then
        success_count=$((success_count + 1))
        echo "Request $i: ✅ $response (allowed)"
    elif [ "$response" = "429" ]; then
        rate_limited_count=$((rate_limited_count + 1))
        echo "Request $i: 🚫 $response (rate limited)"
    else
        echo "Request $i: ❓ $response (unexpected)"
    fi
    
    # Small delay to avoid overwhelming the system
    sleep 0.1
done

echo ""
echo "📊 Results:"
echo "  Successful requests: $success_count"
echo "  Rate limited (429): $rate_limited_count"
echo ""

if [ $rate_limited_count -gt 0 ]; then
    echo "✅ Rate limiting is WORKING! Some requests were blocked."
else
    echo "⚠️  Rate limiting may not be working - all requests succeeded."
fi

echo ""
echo "🔍 Testing with rate limit headers..."
curl -k -s -I https://localhost/verification | grep -E "(X-Rate-Limit|HTTP/)"