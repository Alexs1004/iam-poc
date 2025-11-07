# 🧪 Testing Guide — Mini IAM Lab

> **Complete testing guide**: strategy, commands, and code coverage workflow

---

## 📊 Current Metrics

- **Total tests**: 346 tests (300+ unit, 27 integration)
- **Coverage**: 91% on business code (`app/`)
- **Execution time**: ~3.5s (parallelized with pytest-xdist)
- **Test stack**: pytest + pytest-cov + pytest-xdist + pytest-mock

---

## 🎯 Test Strategy

### **Unit Tests** (300+ tests)
**Objective**: Validate business logic in isolation (Keycloak mocks)

**Command**:
```bash
make test
```

**Coverage**:
- `app/core/`: SCIM validation, RBAC, provisioning (100% on validators)
- `app/api/`: Flask endpoints, decorators, error handling (>90%)
- `app/config/`: Configuration validation, settings (96%)

**Execution**: Parallelized with `-n auto` (pytest-xdist)

---

### **Integration Tests** (27 E2E tests)
**Objective**: Validate complete flows with real Docker stack (Keycloak + Flask + Nginx)

**Command**:
```bash
make test-e2e
```

**Prerequisites**: Stack started (`make ensure-stack` automatically checks)

**Coverage**:
- OIDC/JWT validation (token parsing, claims, expiration)
- OAuth 2.0 SCIM authentication (Bearer tokens)
- Nginx security headers (HSTS, CSP, X-Frame-Options)
- Secrets security (Key Vault, Docker secrets)
- E2E SCIM flows (Joiner/Mover/Leaver)

**Automatic skip**: If stack is not accessible or OAuth credentials are invalid, tests gracefully disable (pytest.skip) instead of generating cascading errors.

---

### **Coverage Tests** (346 complete tests)
**Objective**: Generate detailed HTML report of code coverage

**Command**:
```bash
make test-coverage
```

**Output**: HTML report in `htmlcov/index.html` + terminal summary

**Recommended workflow**:
```bash
# 1. Run tests with coverage
make test-coverage

# 2. See viewing options
make test-coverage-report

# 3. Open in VS Code (recommended for CLI environments)
make test-coverage-vscode

# Alternatives depending on environment
make test-coverage-open    # System browser (Linux GUI, macOS)
make test-coverage-serve   # HTTP server localhost:8888
```

**Why multiple options?**
- **CLI environment** (WSL, SSH servers): `test-coverage-vscode` or `test-coverage-serve`
- **GUI environment** (Linux desktop, macOS): `test-coverage-open`
- **Remote review**: `test-coverage-serve` + SSH tunnel

---

## 🛡️ Critical Security Tests

**Command**:
```bash
make test/security
```

**Coverage**:
- JWT signature validation (JWKS, algorithms, expiration)
- RBAC enforcement (permissions, role hierarchy)
- Rate limiting (Nginx + Flask)
- Audit log signatures (HMAC-SHA256 verification)

**Pytest markers**: `-m critical` (non-negotiable tests)

---

## 🔄 CI/CD Workflow (GitHub Actions)

```yaml
- name: Run tests with coverage
  run: make test-coverage

- name: Upload coverage report
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage.xml
```

**Mandatory checks**:
- ✅ All unit tests pass (300+)
- ✅ Coverage >= 91% maintained
- ✅ No critical (security) test failures
- ✅ No regressions detected

---

## 🐛 Troubleshooting

### **Problem: Integration tests fail with 401 error**
**Cause**: Invalid OAuth credentials or stack not started

**Solution**:
```bash
# Verify stack is running
make ensure-stack

# Verify secrets
cat .runtime/secrets/keycloak_service_client_secret

# Regenerate secrets if necessary
make fresh-demo
```

**Note**: Since recent fix, OAuth fixtures use `pytest.skip()` if credentials are invalid, avoiding cascading errors.

---

### **Problem: Cannot open coverage report**
**Cause**: Linux CLI environment without browser

**Solution**:
```bash
# Option 1: Open in VS Code
make test-coverage-vscode

# Option 2: Serve via HTTP
make test-coverage-serve
# Then open http://localhost:8888 in local or tunneled browser
```

---

### **Problem: Slow tests or timeouts**
**Cause**: Non-optimal Docker stack, or sequential tests

**Solution**:
```bash
# Verify stack health
docker compose ps

# Restart if necessary
make restart

# Unit tests are parallelized by default (-n auto)
# Integration tests are sequential (rate limiting)
```

---

## 📚 References

- **pytest**: https://docs.pytest.org/
- **pytest-cov**: https://pytest-cov.readthedocs.io/
- **Coverage.py**: https://coverage.readthedocs.io/
- **pytest-xdist**: https://pytest-xdist.readthedocs.io/ (parallelization)

---

## 🎓 Applied Best Practices

1. **Isolated tests**: Mocks for unit tests, real stack for integration
2. **Smart skip**: `pytest.skip()` for missing external dependencies
3. **Parallelization**: `-n auto` for unit tests (3-4x gain)
4. **Fixture scope**: `module` for expensive setup (OAuth tokens), `function` for isolation
5. **Pytest markers**: `@pytest.mark.integration`, `@pytest.mark.critical`
6. **Targeted coverage**: Only `app/`, not tests or dependencies
7. **CI/CD friendly**: XML report for CodeCov, automatic skip without stack

---

**Back**: [Documentation Hub](README.md) | [Main README](../README.md)
