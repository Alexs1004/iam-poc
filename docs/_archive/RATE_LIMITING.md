# Rate Limiting Protection

## 🛡️ Overview

This IAM PoC implements **nginx-based rate limiting** to protect against DoS attacks and abuse. Rate limiting is applied at the infrastructure level for optimal performance and security.

## 🔧 Configuration

The rate limiting is configured in `proxy/nginx.conf` with three protection zones:

### Zone Definitions

```nginx
# Zone for verification endpoint: 10 requests per minute per IP
limit_req_zone $binary_remote_addr zone=verification:10m rate=10r/m;

# Zone for SCIM API: 60 requests per minute per IP  
limit_req_zone $binary_remote_addr zone=scim:10m rate=60r/m;

# Zone for admin UI: 30 requests per minute per IP
limit_req_zone $binary_remote_addr zone=admin:10m rate=30r/m;
```

### Applied Protection

| Endpoint | Rate Limit | Burst | Purpose |
|----------|------------|-------|---------|
| `/verification` | 10 req/min | 5 | Development/testing endpoint (allows 5 extra req for spikes) |
| `/scim/v2/*` | 60 req/min | 10 | Production SCIM API (allows 10 extra req for spikes) |
| `/admin/*` | 30 req/min | 8 | Administrative interface (allows 8 extra req for spikes) |

**Burst Values**: Allow temporary spikes above the base rate limit without queuing (processed immediately with `nodelay`).

## 🚨 Security Benefits

### DoS Protection
- Prevents overwhelming the Flask application
- Protects Keycloak backend from abuse
- Maintains service availability during attacks

### Resource Conservation
- Limits CPU/memory usage per IP
- Prevents database overload
- Ensures fair resource allocation

### Attack Detection
- 429 responses logged for monitoring
- Clear indication of abuse attempts
- Enables alerting on suspicious patterns

## 💡 Why Nginx Rate Limiting

### Reject Malicious Traffic Before Python
- **Early filtering**: Blocks requests at nginx level before reaching Flask
- **Resource efficiency**: Saves CPU/memory for legitimate requests
- **Performance**: C-based processing faster than Python interpretation

### Predictable CPU Usage
- **Bounded resources**: Known maximum request rate prevents resource exhaustion
- **Fair allocation**: Each IP gets equal share of rate limit capacity
- **Graceful degradation**: Service remains available under attack

### Defense in Depth
- **Infrastructure layer**: Protection at reverse proxy level
- **Application layer**: OAuth/SCIM validation in Flask
- **Business layer**: Role-based access control in application logic

## 🧪 Testing Rate Limiting

### Manual Testing
```bash
# Test verification endpoint (should hit 429 after ~6 requests)
for i in {1..15}; do curl -k https://localhost/verification; done

# Test SCIM API (should hit 429 after ~12 requests)
for i in {1..15}; do curl -k https://localhost/scim/v2/Users; done
```

### Automated Testing
```bash
# Run comprehensive rate limit tests
./test_rate_limiting.sh
./test_all_rate_limits.sh
```

## 📊 Monitoring

### Response Headers
Rate-limited requests include identifying headers:
```
HTTP/1.1 429 Too Many Requests
X-Rate-Limit-Applied: verification
```

### Nginx Logs
Rate limiting events are logged:
```
2025-11-03 10:30:15 [error] limiting requests, excess: 5.000 by zone "verification"
```

### Expected Response Codes
- **200-299**: Request processed normally
- **401/403**: Authentication/authorization failure (still counted)
- **429**: Rate limit exceeded (blocked)

## 🔧 Configuration Tuning

### Burst Settings
- **burst=5**: Allows temporary spikes up to 5 additional requests
- **nodelay**: Processes burst requests immediately (no queuing)

### Rate Adjustments
For production environments, consider:
- **SCIM API**: Increase to 120 req/min for high-throughput systems
- **Admin UI**: Reduce to 15 req/min for tighter security
- **Verification**: Keep low (10 req/min) as it's a testing endpoint

### Per-User Rate Limiting
For authenticated endpoints, consider switching to per-user limits:
```nginx
# Alternative: Rate limit by user ID instead of IP
limit_req_zone $http_x_user_id zone=user_scim:10m rate=100r/m;
```

## 🎯 Production Considerations

### Load Balancing
When behind a load balancer, ensure real client IPs are preserved:
```nginx
real_ip_header X-Forwarded-For;
set_real_ip_from 10.0.0.0/8;  # Trust load balancer IPs
```

### Whitelisting
For trusted sources (monitoring, automation):
```nginx
geo $rate_limit_bypass {
    default 1;
    10.0.1.100 0;  # Monitoring server
    10.0.1.101 0;  # CI/CD pipeline
}

limit_req_zone $binary_remote_addr zone=api:10m rate=60r/m;
limit_req zone=api burst=10 nodelay;
```

### Custom Error Pages
Provide user-friendly rate limit messages:
```nginx
error_page 429 /rate_limit_exceeded.html;
```

## ✅ Verification

The rate limiting implementation has been tested and verified:

1. **✅ Verification endpoint**: 10 req/min limit enforced
2. **✅ SCIM API**: 60 req/min limit enforced  
3. **✅ Admin UI**: 30 req/min limit enforced
4. **✅ Headers**: X-Rate-Limit-Applied header present
5. **✅ Logging**: Rate limit events logged to nginx

## 🎓 Security Learning Points

### Why Nginx vs Application-Level?
- **Performance**: Nginx handles rate limiting in C, faster than Python
- **Early filtering**: Blocks requests before they reach Flask
- **Resource efficiency**: Prevents unnecessary application processing
- **Infrastructure-level**: Consistent protection across all services

### Integration with OIDC
Rate limiting works alongside OAuth/OIDC authentication:
1. **Rate limit check** (nginx) → Allow/deny request
2. **Authentication check** (Flask) → Validate OAuth token  
3. **Authorization check** (Flask) → Verify user permissions
4. **Business logic** (Flask) → Process request

This multi-layer approach provides **defense in depth** security.