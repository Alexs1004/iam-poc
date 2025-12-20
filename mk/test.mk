# ============================================================================
# Testing
# ============================================================================

.PHONY: venv test test-coverage test-coverage-report test-coverage-open test-coverage-serve test-coverage-vscode
.PHONY: test-e2e test-all test/security test/oidc test/nginx

venv: ## Create/refresh venv and install dependencies
	@$(PYTHON) -m venv venv >/dev/null 2>&1 || true
	@venv/bin/pip install -q -r requirements.txt

test: venv ## Run unit tests (no integration)
	@DEMO_MODE=true $(PYTEST) $(PYTEST_UNIT_FLAGS) -m "not integration" $(ARGS)

test-coverage: ensure-stack venv ## Run all tests with coverage report (HTML + terminal)
	@echo "[test-coverage] Running tests with coverage analysis..."
	@DEMO_MODE=true $(PYTEST) tests/ --cov=app --cov-report=html --cov-report=term-missing $(ARGS)
	@echo "[test-coverage] ✓ Coverage report generated"
	@echo "[test-coverage] View with: make test-coverage-report"

test-coverage-report: ## Show coverage report information and viewing options
	@echo "[test-coverage-report] ✓ Coverage report location:"
	@echo "    📊 file://$(PWD)/htmlcov/index.html"
	@echo ""
	@echo "Available commands:"
	@echo "  • make test-coverage-vscode  → Open in VS Code (recommended)"
	@echo "  • make test-coverage-open    → Open in system browser (if available)"
	@echo "  • make test-coverage-serve   → Serve on http://localhost:8888"
	@echo ""

test-coverage-open: ## Try to open coverage report in system browser
	@if [ ! -f htmlcov/index.html ]; then \
		echo "❌ Coverage report not found. Run 'make test-coverage' first."; \
		exit 1; \
	fi
	@echo "[test-coverage-open] Attempting to open in browser..."
	@if command -v xdg-open >/dev/null 2>&1; then \
		xdg-open htmlcov/index.html 2>/dev/null || echo "⚠️  xdg-open failed. Use 'make test-coverage-serve' instead."; \
	elif command -v open >/dev/null 2>&1; then \
		open htmlcov/index.html; \
	else \
		echo "⚠️  No browser opener found. Use 'make test-coverage-serve' instead."; \
	fi

test-coverage-serve: ## Serve coverage report on http://localhost:8888
	@if [ ! -f htmlcov/index.html ]; then \
		echo "❌ Coverage report not found. Run 'make test-coverage' first."; \
		exit 1; \
	fi
	@echo "[test-coverage-serve] 🌐 Serving coverage report on http://localhost:8888"
	@echo "Press Ctrl+C to stop the server."
	@cd htmlcov && $(PYTHON) -m http.server 8888

test-coverage-vscode: ## Open coverage report in VS Code (recommended for CLI environments)
	@if [ ! -f htmlcov/index.html ]; then \
		echo "❌ Coverage report not found. Run 'make test-coverage' first."; \
		exit 1; \
	fi
	@if command -v code >/dev/null 2>&1; then \
		echo "[test-coverage-vscode] Opening in VS Code..."; \
		code htmlcov/index.html; \
	else \
		echo "⚠️  VS Code CLI not found. Using file path instead:"; \
		echo "    file://$(PWD)/htmlcov/index.html"; \
	fi

test-e2e: ensure-stack venv ## Run integration test suite (requires stack)
	@set -a; source .env 2>/dev/null || true; set +a; \
	demo_mode="$${DEMO_MODE:-}"; \
	unset DEMO_MODE AZURE_USE_KEYVAULT FLASK_SECRET_KEY KEYCLOAK_SERVICE_CLIENT_SECRET KEYCLOAK_ADMIN_PASSWORD AUDIT_LOG_SIGNING_KEY KEYCLOAK_URL KEYCLOAK_URL_HOST APP_BASE_URL KEYCLOAK_ISSUER KEYCLOAK_PUBLIC_ISSUER; \
	if [ "$$demo_mode" = "true" ]; then \
		echo "[test-e2e] DEMO_MODE=true: unit tests are sufficient for demo mode (run 'make test')." >&2; \
		exit 1; \
	fi; \
	$(PYTEST) -m integration $(ARGS)

test-all: ## Run unit, integration, and security suites
	@set -a; source .env 2>/dev/null || true; set +a; \
	demo_mode="$${DEMO_MODE:-}"; \
	unset DEMO_MODE AZURE_USE_KEYVAULT FLASK_SECRET_KEY KEYCLOAK_SERVICE_CLIENT_SECRET KEYCLOAK_ADMIN_PASSWORD AUDIT_LOG_SIGNING_KEY KEYCLOAK_URL KEYCLOAK_URL_HOST APP_BASE_URL KEYCLOAK_ISSUER KEYCLOAK_PUBLIC_ISSUER; \
	if [ "$$demo_mode" = "true" ]; then \
		echo "[test-all] DEMO_MODE=true: unit tests are sufficient for demo mode (run 'make test')." >&2; \
		exit 1; \
	fi; \
	true
	@$(MAKE) test $(if $(ARGS),ARGS="$(ARGS)",)
ifneq ($(SKIP_E2E),true)
	@$(MAKE) test-e2e $(if $(ARGS),ARGS="$(ARGS)",)
	@$(MAKE) test/security $(if $(ARGS),ARGS="$(ARGS)",)
else
	@echo "[test-all] SKIP_E2E=true: skipping integration and security suites"
endif
	@echo "[test-all] ✅ All test suites completed"

test/security: venv ## Run critical security tests
	@set -a; source .env 2>/dev/null || true; set +a; \
	demo_mode="$${DEMO_MODE:-}"; \
	unset DEMO_MODE AZURE_USE_KEYVAULT FLASK_SECRET_KEY KEYCLOAK_SERVICE_CLIENT_SECRET KEYCLOAK_ADMIN_PASSWORD AUDIT_LOG_SIGNING_KEY KEYCLOAK_URL KEYCLOAK_URL_HOST APP_BASE_URL KEYCLOAK_ISSUER KEYCLOAK_PUBLIC_ISSUER; \
	if [ "$$demo_mode" = "true" ]; then \
		echo "[test/security] DEMO_MODE=true: unit tests are sufficient for demo mode." >&2; \
		exit 1; \
	fi; \
	secret_dir=".runtime/secrets"; \
	if [ ! -f "$$secret_dir/keycloak_service_client_secret" ]; then \
		$(MAKE) load-secrets >/dev/null; \
	fi; \
	if [ -f "$$secret_dir/keycloak_service_client_secret" ]; then \
		export KEYCLOAK_SERVICE_CLIENT_SECRET="$$(cat $$secret_dir/keycloak_service_client_secret)"; \
	fi; \
	if [ -f "$$secret_dir/keycloak_admin_password" ]; then \
		export KEYCLOAK_ADMIN_PASSWORD="$$(cat $$secret_dir/keycloak_admin_password)"; \
	fi; \
	if [ -f "$$secret_dir/flask_secret_key" ]; then \
		export FLASK_SECRET_KEY="$$(cat $$secret_dir/flask_secret_key)"; \
	fi; \
	if [ -f "$$secret_dir/audit_log_signing_key" ]; then \
		export AUDIT_LOG_SIGNING_KEY="$$(cat $$secret_dir/audit_log_signing_key)"; \
	fi; \
	export AZURE_USE_KEYVAULT=false; \
	export DEMO_MODE=false; \
	export TRUSTED_PROXY_IPS="127.0.0.1/32,::1/128"; \
	export KEYCLOAK_URL="https://localhost"; \
	export APP_BASE_URL="https://localhost"; \
	export KEYCLOAK_ISSUER="https://localhost/realms/demo"; \
	export KEYCLOAK_PUBLIC_ISSUER="https://localhost/realms/demo"; \
	echo "service secret len: $${#KEYCLOAK_SERVICE_CLIENT_SECRET}"; \
	$(PYTEST) -m critical -v $(ARGS)

test/oidc: venv ## Run OIDC/JWT validation tests
	@DEMO_MODE=true $(PYTEST) tests/test_oidc_jwt_validation.py -v $(ARGS)

test/nginx: ensure-stack venv ## Run Nginx/TLS/headers smoke tests
	@$(PYTEST) tests/test_nginx_security_headers.py -v -m integration $(ARGS)
