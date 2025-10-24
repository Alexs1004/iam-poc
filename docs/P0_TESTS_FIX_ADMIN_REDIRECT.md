# Fix: Admin Authentication Redirect

## Problem
The `/admin` route was not redirecting unauthenticated users to `/login` as expected. Tests showed Flask performing a 308 permanent redirect to `/admin/` (URL normalization for trailing slash) before the authentication decorator could execute.

## Root Causes

### 1. Incorrect Decorator Pattern
The `require_admin_view` and `require_jml_operator` decorators were incorrectly implemented:

```python
# ❌ BEFORE: Incorrect - immediately calls the function
def require_admin_view(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        cfg = current_app.config["APP_CONFIG"]
        return require_any_role(...)(fn)(*args, **kwargs)  # Wrong!
    return wrapper
```

This pattern called both the decorator AND the wrapped function immediately, causing unexpected behavior.

### 2. Blueprint before_request Hook Issue
Initially tried using `@bp.before_request` on the admin blueprint:

```python
@bp.before_request
def require_authentication():
    if not is_authenticated():
        return redirect(url_for("auth.login"))
```

This didn't work because Flask's URL normalization (308 redirect for trailing slash) happens **before** blueprint-level request hooks execute.

### 3. Test Path Mismatch
The test accessed `/admin` (no trailing slash) while Flask registered the route as `/admin/` (with trailing slash). Flask automatically redirected `/admin` → `/admin/` with HTTP 308, preventing the authentication check.

## Solution

### 1. Fixed Decorator Implementation
Rewrote decorators to check authentication inline and return proper redirects:

```python
# ✅ AFTER: Correct - checks auth first, then role authorization
def require_admin_view(fn):
    """Allow viewing admin dashboard (analyst, manager, iam-operator, realm-admin)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            # Explicit redirect to login page
            return redirect(url_for("auth.login"), code=302)
        
        cfg = current_app.config["APP_CONFIG"]
        _, _, _, roles = current_user_context()
        
        allowed_roles = ["analyst", "manager", cfg.realm_admin_role, cfg.iam_operator_role]
        
        if not any(role.lower() in [r.lower() for r in roles] for role in allowed_roles):
            return render_template("403.html", ...), 403
        
        return fn(*args, **kwargs)
    return wrapper
```

### 2. Updated require_jml_operator
Applied the same pattern to the JML operator decorator:

```python
def require_jml_operator(fn):
    """Restrict JML operations to operators only (iam-operator, realm-admin)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            return redirect(url_for("auth.login"), code=302)
        
        cfg = current_app.config["APP_CONFIG"]
        _, _, _, roles = current_user_context()
        
        allowed_roles = [cfg.realm_admin_role, cfg.iam_operator_role]
        
        if not any(role.lower() in [r.lower() for r in roles] for role in allowed_roles):
            return render_template("403.html", ...), 403
        
        return fn(*args, **kwargs)
    return wrapper
```

### 3. Fixed Test Path
Updated test to use the correct route with trailing slash:

```python
# ✅ AFTER: Use correct path matching Flask route registration
response = client.get("/admin/", follow_redirects=False)
```

### 4. Updated require_any_role
Added explicit redirect with 302 status code:

```python
def require_any_role(*required_roles):
    """Decorator to require any of the specified roles."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not is_authenticated():
                # Explicit redirect to login page (not back to admin)
                return redirect(url_for("auth.login"), code=302)
            # ... rest of role checking logic
```

## Files Modified

### `app/api/admin.py`
- **Lines 40-56**: Fixed `require_any_role` decorator
- **Lines 61-87**: Rewrote `require_admin_view` decorator
- **Lines 89-110**: Rewrote `require_jml_operator` decorator
- **Removed**: Blueprint `@bp.before_request` hook (lines 33-39)

### `tests/test_oidc_jwt_validation.py`
- **Line 377**: Changed test path from `/admin` → `/admin/`
- **Line 380**: Removed 308 from expected status codes (now only 302/307)

## Verification

### Test Execution
```bash
pytest tests/test_oidc_jwt_validation.py::test_authorization_header_missing_token_rejected -xvs
```

**Result**: ✅ PASSED

### Full Security Test Suite
```bash
pytest tests/test_oidc_jwt_validation.py tests/test_secrets_security.py -v
```

**Result**: ✅ 24 passed, 2 skipped

## Key Learnings

1. **Decorator Patterns**: Always check authentication/authorization in the wrapper function body, not by calling other decorators
2. **Flask URL Routing**: Be aware of `strict_slashes=True` behavior and trailing slash normalization (308 redirects)
3. **Request Processing Order**: URL normalization happens before blueprint hooks, so authentication should be in route decorators
4. **Test Accuracy**: Test paths must match registered routes exactly (including trailing slashes)

## Impact

- ✅ `/admin/` now correctly redirects unauthenticated users to `/login` (302 Found)
- ✅ All admin routes protected by explicit authentication checks
- ✅ Role-based authorization works correctly after authentication
- ✅ Test suite validates the security behavior
- ✅ No breaking changes to existing functionality

## Related Documentation

- `docs/P0_TESTS_IMPLEMENTATION_REPORT.md` - P0 security test implementation
- `docs/P0_TESTS_EXECUTION_REPORT.md` - Test execution results
- `README.md` - Project overview and security features
