# Error Handling Security Guidelines

## 🔒 **Security Policy**

### ❌ **NEVER expose detailed error traces in production**

Detailed error messages (tracebacks, stack traces) can leak sensitive information:
- Internal file paths (`/srv/app/app/api/verification.py`)
- Function names and business logic
- Framework versions (exploitable CVE lookup)
- Database schemas, API keys, or credentials in variables
- Attack surface mapping for threat actors

---

## ✅ **Implementation**

### **Error Handler Logic** (`app/api/errors.py`)

```python
# SECURITY: Show traceback ONLY in debug/demo mode
show_details = app.debug or app.config.get('DEMO_MODE', False)

return render_template(
    "500.html",
    error_message=error_details if show_details else None,
    show_debug=show_details,
)
```

### **Environment Configuration**

| Mode | `DEMO_MODE` | `app.debug` | Error Details Shown? |
|------|-------------|-------------|---------------------|
| **Demo** | `true` | `True` (dev) | ✅ YES (safe for demos) |
| **Production** | `false` | `False` | ❌ NO (secure) |

### **Template Rendering** (`app/templates/500.html`)

```jinja2
{% if show_debug and error_message %}
  <details>
    <summary>🔍 Error details (debug/demo mode only)</summary>
    <pre>{{ error_message }}</pre>
  </details>
  ⚠️ Security Notice: Details shown because debug/demo mode.
{% else %}
  <p>Generic error message. Check server logs.</p>
{% endif %}
```

---

## 📋 **Compliance Alignment**

### **OWASP Top 10 (2021)**
- **A01:2021 – Broken Access Control**: Error messages don't leak path traversal info
- **A05:2021 – Security Misconfiguration**: Debug mode disabled in production
- **A09:2021 – Security Logging Failures**: Errors logged server-side (secure), not exposed to users

### **SOC 2 / ISO 27001**
- **Availability**: Generic error pages prevent denial-of-service via error manipulation
- **Confidentiality**: Sensitive system details protected from unauthorized disclosure
- **Integrity**: Audit logs capture full errors server-side for forensic analysis

---

## 🛠️ **Best Practices**

### ✅ **DO:**
1. **Log all errors server-side** with full tracebacks (secure logs)
2. **Show generic messages to users** in production (e.g., "An error occurred")
3. **Use correlation IDs** for users to reference when contacting support
4. **Implement custom error pages** (400.html, 403.html, 404.html, 500.html)
5. **Test error handling** in both demo and production modes

### ❌ **DON'T:**
1. **Never expose tracebacks in production** (even in `<details>` tags)
2. **Don't include sensitive data in error messages** (tokens, passwords, API keys)
3. **Don't use the same error page for all errors** (distinguish 403 vs 404 vs 500)
4. **Don't disable logging** to "hide" errors (fix the root cause instead)
5. **Don't rely on client-side error hiding** (use server-side conditionals)

---

## 🧪 **Testing**

### **Verify Production Safety**

```bash
# 1. Set production mode
export DEMO_MODE=false

# 2. Trigger a test error (e.g., invalid URL)
curl https://your-app.com/invalid-endpoint

# 3. Verify response does NOT contain:
# - File paths (/srv/app/...)
# - Function names (def verification_page...)
# - Framework versions (flask/app.py line 870)
```

### **Verify Demo Mode Works**

```bash
# 1. Set demo mode
export DEMO_MODE=true

# 2. Trigger the same error
curl https://your-demo.com/invalid-endpoint

# 3. Verify response INCLUDES:
# - "Error details (debug/demo mode only)"
# - Traceback with file paths
# - Security warning banner
```

---

## 📊 **Logging Strategy**

| Level | Destination | Content | Audience |
|-------|-------------|---------|----------|
| **ERROR** | Server logs | Full traceback, variables | DevOps/Security |
| **INFO** | Server logs | Request path, user ID, timestamp | Auditors |
| **WARNING** | Server logs | Rate limit hits, auth failures | Security analysts |
| **User-facing** | HTTP response | Generic message only | End users |

---

## 🔗 **References**

- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [CWE-209: Information Exposure Through Error Messages](https://cwe.mitre.org/data/definitions/209.html)
- [NIST SP 800-53: SI-11 (Error Handling)](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-11)
- [RFC 7807: Problem Details for HTTP APIs](https://datatracker.ietf.org/doc/html/rfc7807)

---

## 🎓 **Key Takeaway**

> **Errors should be logged, not shown.**  
> Full details → secure server logs (for debugging).  
> Generic messages → user-facing pages (for security).

This prevents **information disclosure** while maintaining **full debuggability** for authorized personnel.
