# =============================================================================
# IAM-POC Makefile
# =============================================================================
# A modular, clean Makefile for the IAM Proof of Concept
#
# Quick Start:
#   make help          Show common commands
#   make quickstart    Start stack + provision demo users
#   make test          Run unit tests
#
# Structure:
#   mk/docker.mk     - Container management (up, down, logs)
#   mk/test.mk       - Testing (test, test-e2e, test-coverage)
#   mk/security.mk   - Security scanning (scan-secrets, scan-vulns, sbom)
#   mk/infra.mk      - Terraform (infra/init, infra/plan, infra/apply)
#   mk/jml.mk        - JML operations (joiner, mover, leaver)
#   mk/secrets.mk    - Secrets management (load-secrets, rotate-secret)
#   mk/entra.mk      - Entra ID provisioning (demo-entra)
# =============================================================================

.DEFAULT_GOAL := help
.ONESHELL:
.SHELLFLAGS := -Eeuo pipefail -c
.DELETE_ON_ERROR:
.NOTPARALLEL:
SHELL := /bin/bash

# =============================================================================
# Configuration
# =============================================================================

PYTHON ?= python3
UNAME_S := $(shell uname -s)
SED_INPLACE := sed -i
ifeq ($(UNAME_S),Darwin)
  SED_INPLACE := sed -i ''
endif

# Tools
SHA256_CMD := $(PYTHON) -c "import sys,hashlib; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())"
JML := $(PYTHON) scripts/jml.py
VENV_PYTHON := venv/bin/python
PYTEST := $(VENV_PYTHON) -m pytest
PYTEST_UNIT_FLAGS ?= -n auto --dist=loadscope --cache-clear

# UX targets shown in `make help`
UX_TARGETS := help quickstart fresh-demo up down logs test test-all infra/check infra/plan security-check doctor

# =============================================================================
# Environment Loading (simplified)
# =============================================================================
# Use `source scripts/load_env.sh` for complex scenarios
# This inline version handles basic Key Vault loading

WITH_ENV := set -a; source .env; set +a; \
	if [[ "$${AZURE_USE_KEYVAULT:-}" =~ ^[Tt]rue$$ ]]; then \
		if [[ -z "$${AZURE_KEY_VAULT_NAME:-}" ]]; then \
			echo "[make] AZURE_KEY_VAULT_NAME required when AZURE_USE_KEYVAULT=true." >&2; \
			exit 1; \
		fi; \
		fetch_secret() { az keyvault secret show --vault-name "$${AZURE_KEY_VAULT_NAME}" --name "$$1" --query value -o tsv 2>/dev/null || echo ""; }; \
		[ -z "$${KEYCLOAK_SERVICE_CLIENT_SECRET:-}" ] && export KEYCLOAK_SERVICE_CLIENT_SECRET=$$(fetch_secret "$${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET}"); \
		[ -z "$${KEYCLOAK_ADMIN_PASSWORD:-}" ] && export KEYCLOAK_ADMIN_PASSWORD=$$(fetch_secret "$${AZURE_SECRET_KEYCLOAK_ADMIN_PASSWORD}"); \
		[ -z "$${ALICE_TEMP_PASSWORD:-}" ] && export ALICE_TEMP_PASSWORD=$$(fetch_secret "$${AZURE_SECRET_ALICE_TEMP_PASSWORD}"); \
		[ -z "$${BOB_TEMP_PASSWORD:-}" ] && export BOB_TEMP_PASSWORD=$$(fetch_secret "$${AZURE_SECRET_BOB_TEMP_PASSWORD}"); \
		[ -z "$${AUDIT_LOG_SIGNING_KEY:-}" ] && export AUDIT_LOG_SIGNING_KEY=$$(fetch_secret "$${AZURE_SECRET_AUDIT_LOG_SIGNING_KEY}"); \
	fi;

# =============================================================================
# Help
# =============================================================================

.PHONY: help help-all

help: ## Show common commands
	@set -a; source .env 2>/dev/null || true; set +a; \
	printf '\n'; \
	printf '  ╔══════════════════════════════════════════════════════════════╗\n'; \
	printf '  ║  \033[1mIAM-POC Makefile\033[0m                                            ║\n'; \
	printf '  ║  Mode: DEMO=\033[1m%-5s\033[0m | KEYVAULT=\033[1m%-5s\033[0m                       ║\n' "$${DEMO_MODE:-?}" "$${AZURE_USE_KEYVAULT:-?}"; \
	printf '  ╚══════════════════════════════════════════════════════════════╝\n'; \
	printf '\n'
	@printf '  \033[1;34m🚀 Getting Started\033[0m\n'
	@printf '    %-20s %s\n' "quickstart" "Start stack + provision demo users"
	@printf '    %-20s %s\n' "fresh-demo" "Reset everything and start fresh"
	@printf '\n'
	@printf '  \033[1;34m🐳 Stack Management\033[0m\n'
	@printf '    %-20s %s\n' "up" "Start services"
	@printf '    %-20s %s\n' "down" "Stop services"
	@printf '    %-20s %s\n' "logs" "Tail logs (SERVICE=name to filter)"
	@printf '    %-20s %s\n' "ps" "Display service status"
	@printf '\n'
	@printf '  \033[1;34m🧪 Testing\033[0m\n'
	@printf '    %-20s %s\n' "test" "Run unit tests"
	@printf '    %-20s %s\n' "test-all" "Run all test suites"
	@printf '    %-20s %s\n' "test-coverage" "Run tests with coverage report"
	@printf '\n'
	@printf '  \033[1;34m🔐 Security\033[0m\n'
	@printf '    %-20s %s\n' "security-check" "Run all security scans"
	@printf '    %-20s %s\n' "rotate-secret" "Rotate Keycloak service secret"
	@printf '    %-20s %s\n' "doctor" "Check environment health"
	@printf '\n'
	@printf '  \033[1;34m☁️  Infrastructure\033[0m\n'
	@printf '    %-20s %s\n' "infra/check" "Validate Terraform (no Azure needed)"
	@printf '    %-20s %s\n' "infra/plan" "Show Terraform plan"
	@printf '    %-20s %s\n' "infra/apply" "Apply Terraform changes"
	@printf '\n'
	@printf '  Run \033[1mmake help-all\033[0m for full list of commands\n\n'

help-all: ## Show all documented commands (sorted by category)
	@printf '\n'
	@printf '  ╔══════════════════════════════════════════════════════════════╗\n'
	@printf '  ║  \033[1mAll Available Commands\033[0m                                      ║\n'
	@printf '  ╚══════════════════════════════════════════════════════════════╝\n'
	@printf '\n'
	@printf '  \033[1;32m━━━ 🚀 Getting Started ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
	@printf '    %-24s %s\n' "quickstart" "Start stack + provision demo users"
	@printf '    %-24s %s\n' "fresh-demo" "Reset everything then run quickstart"
	@printf '    %-24s %s\n' "fresh-demo-keep-audit" "Reset but preserve audit logs"
	@printf '    %-24s %s\n' "demo" "Run the scripted JML demonstration"
	@printf '\n'
	@printf '  \033[1;32m━━━ 🐳 Stack Management ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
	@printf '    %-24s %s\n' "up" "Start services"
	@printf '    %-24s %s\n' "down" "Stop services and remove containers"
	@printf '    %-24s %s\n' "restart" "Restart all services"
	@printf '    %-24s %s\n' "restart-flask" "Restart stack to reload secrets"
	@printf '    %-24s %s\n' "logs" "Tail logs (SERVICE=name to filter)"
	@printf '    %-24s %s\n' "ps" "Display service status"
	@printf '    %-24s %s\n' "ensure-stack" "Ensure stack is running"
	@printf '\n'
	@printf '  \033[1;32m━━━ 🧪 Testing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
	@printf '    %-24s %s\n' "test" "Run unit tests (no integration)"
	@printf '    %-24s %s\n' "test-e2e" "Run integration tests (requires stack)"
	@printf '    %-24s %s\n' "test-all" "Run all test suites"
	@printf '    %-24s %s\n' "test-coverage" "Run tests with coverage report"
	@printf '    %-24s %s\n' "test-coverage-report" "Show coverage report options"
	@printf '    %-24s %s\n' "test/security" "Run critical security tests"
	@printf '    %-24s %s\n' "test/oidc" "Run OIDC/JWT validation tests"
	@printf '    %-24s %s\n' "test/nginx" "Run Nginx/TLS/headers tests"
	@printf '\n'
	@printf '  \033[1;32m━━━ 🔐 Security Scanning ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
	@printf '    %-24s %s\n' "security-check" "Run all security scans"
	@printf '    %-24s %s\n' "scan-secrets" "Detect secrets with Gitleaks"
	@printf '    %-24s %s\n' "scan-vulns" "Scan CVEs with Trivy"
	@printf '    %-24s %s\n' "sbom" "Generate SBOM with Syft"
	@printf '    %-24s %s\n' "scan-sbom" "Scan SBOM with Grype"
	@printf '\n'
	@printf '  \033[1;32m━━━ 🔑 Secrets Management ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
	@printf '    %-24s %s\n' "load-secrets" "Load secrets from Azure Key Vault"
	@printf '    %-24s %s\n' "rotate-secret" "Rotate Keycloak service secret"
	@printf '    %-24s %s\n' "rotate-secret-dry" "Dry-run of secret rotation"
	@printf '    %-24s %s\n' "clean-secrets" "Remove secrets (keep audit logs)"
	@printf '    %-24s %s\n' "clean-all" "Remove all runtime data"
	@printf '    %-24s %s\n' "verify-audit" "Verify audit log signatures"
	@printf '    %-24s %s\n' "archive-audit" "Archive audit log with timestamp"
	@printf '\n'
	@printf '  \033[1;32m━━━ 👤 JML Operations (Keycloak) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
	@printf '    %-24s %s\n' "init" "Provision realm, client, roles"
	@printf '    %-24s %s\n' "joiner-alice" "Create user alice (analyst)"
	@printf '    %-24s %s\n' "joiner-bob" "Create user bob (analyst)"
	@printf '    %-24s %s\n' "mover-alice" "Promote alice to admin"
	@printf '    %-24s %s\n' "leaver-bob" "Disable bob account"
	@printf '    %-24s %s\n' "delete-realm" "Delete realm (irreversible)"
	@printf '\n'
	@printf '  \033[1;32m━━━ 🔷 Entra ID (Azure AD) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
	@printf '    %-24s %s\n' "demo-entra" "Provision demo users in Entra ID"
	@printf '    %-24s %s\n' "demo-entra-cleanup" "Disable demo users (soft delete)"
	@printf '    %-24s %s\n' "demo-entra-delete" "Permanently delete demo users"
	@printf '\n'
	@printf '  \033[1;32m━━━ ☁️  Terraform Infrastructure ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
	@printf '    %-24s %s\n' "infra/check" "Validate syntax (no Azure needed)"
	@printf '    %-24s %s\n' "infra/init" "Initialize Terraform"
	@printf '    %-24s %s\n' "infra/plan" "Show execution plan"
	@printf '    %-24s %s\n' "infra/apply" "Apply changes"
	@printf '    %-24s %s\n' "infra/destroy" "Destroy infrastructure"
	@printf '    %-24s %s\n' "infra/fmt" "Format Terraform files"
	@printf '    %-24s %s\n' "infra/clean" "Remove .terraform cache"
	@printf '\n'
	@printf '  \033[1;32m━━━ 🩺 Diagnostics ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
	@printf '    %-24s %s\n' "doctor" "Check environment health"
	@printf '    %-24s %s\n' "doctor-secrets" "Compare KV vs local secrets"
	@printf '    %-24s %s\n' "check-azure" "Test Azure credentials"
	@printf '    %-24s %s\n' "validate-env" "Validate .env file"
	@printf '\n'
	@printf '  \033[1;32m━━━ ⚙️  Setup & Configuration ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
	@printf '    %-24s %s\n' "ensure-env" "Copy .env.demo to .env if missing"
	@printf '    %-24s %s\n' "ensure-secrets" "Generate secrets (demo mode)"
	@printf '    %-24s %s\n' "reset-demo" "Reset .env to demo defaults"
	@printf '    %-24s %s\n' "init-production" "Initialize for production mode"
	@printf '    %-24s %s\n' "venv" "Create/refresh Python venv"
	@printf '\n'

# =============================================================================
# Quick Start & Demo
# =============================================================================

.PHONY: ensure-env ensure-secrets validate-env quickstart fresh-demo fresh-demo-keep-audit

ensure-env: ## Copy .env.demo to .env if .env doesn't exist
	@if [ ! -f .env ]; then \
		echo "[ensure-env] .env not found, copying from .env.demo..."; \
		cp .env.demo .env; \
		echo "[ensure-env] ✓ .env created from .env.demo"; \
	else \
		echo "[ensure-env] ✓ .env already exists"; \
	fi

ensure-secrets: ensure-env ## Generate strong secrets if empty in .env (demo mode only)
	@set -a; source .env 2>/dev/null || true; set +a; \
	shopt -s nocasematch; \
	if [[ "$${DEMO_MODE:-}" == "false" ]]; then \
		echo "[ensure-secrets] Production mode detected (DEMO_MODE=false)" >&2; \
		if [[ "$${AZURE_USE_KEYVAULT:-}" == "true" ]]; then \
			echo "[ensure-secrets] Azure Key Vault enabled: clearing local secrets in .env" >&2; \
			$(SED_INPLACE) "s|^FLASK_SECRET_KEY=.*|FLASK_SECRET_KEY=|" .env; \
			$(SED_INPLACE) "s|^AUDIT_LOG_SIGNING_KEY=.*|AUDIT_LOG_SIGNING_KEY=|" .env; \
			echo "[ensure-secrets] ✓ FLASK_SECRET_KEY cleared (will load from Key Vault)" >&2; \
			echo "[ensure-secrets] ✓ AUDIT_LOG_SIGNING_KEY cleared (will load from Key Vault)" >&2; \
		else \
			echo "[ensure-secrets] WARNING: Production mode without Azure Key Vault" >&2; \
			echo "[ensure-secrets] You must manually set FLASK_SECRET_KEY and AUDIT_LOG_SIGNING_KEY" >&2; \
		fi; \
	else \
		echo "[ensure-secrets] Demo mode: checking secrets in .env..." >&2; \
		if ! grep -qE "^FLASK_SECRET_KEY=[^[:space:]#]+" .env 2>/dev/null; then \
			SECRET=$$($(PYTHON) -c "import secrets; print(secrets.token_urlsafe(32))"); \
			if grep -q "^FLASK_SECRET_KEY=" .env; then \
				$(SED_INPLACE) "s|^FLASK_SECRET_KEY=.*|FLASK_SECRET_KEY=$$SECRET|" .env; \
			else \
				echo "FLASK_SECRET_KEY=$$SECRET" >> .env; \
			fi; \
			echo "[ensure-secrets] ✓ Generated FLASK_SECRET_KEY" >&2; \
		else \
			echo "[ensure-secrets] ✓ FLASK_SECRET_KEY already set" >&2; \
		fi; \
		if ! grep -qE "^AUDIT_LOG_SIGNING_KEY=[^[:space:]#]+" .env 2>/dev/null; then \
			SECRET=$$($(PYTHON) -c "import secrets; print(secrets.token_urlsafe(48))"); \
			if grep -q "^AUDIT_LOG_SIGNING_KEY=" .env; then \
				$(SED_INPLACE) "s|^AUDIT_LOG_SIGNING_KEY=.*|AUDIT_LOG_SIGNING_KEY=$$SECRET|" .env; \
			else \
				echo "AUDIT_LOG_SIGNING_KEY=$$SECRET" >> .env; \
			fi; \
			echo "[ensure-secrets] ✓ Generated AUDIT_LOG_SIGNING_KEY" >&2; \
		else \
			echo "[ensure-secrets] ✓ AUDIT_LOG_SIGNING_KEY already set" >&2; \
		fi; \
	fi

validate-env: ensure-env ## Validate and auto-correct .env
	@./scripts/validate_env.sh

quickstart: validate-env ensure-secrets ## Start stack + provision demo users
	@if docker compose ps --services --filter "status=running" 2>/dev/null | grep -q "^keycloak$$"; then \
		echo "[quickstart] ⚠️  Stack already running. Run 'make down' first."; \
		exit 1; \
	fi
	@set -a; source .env; set +a; \
	if [[ "$${AZURE_USE_KEYVAULT:-}" =~ ^[Tt]rue$$ ]]; then \
		echo "[quickstart] Loading secrets from Azure Key Vault..."; \
		$(MAKE) load-secrets; \
	fi
	@./scripts/run_https.sh
	@$(WITH_ENV) ./scripts/demo_jml.sh

fresh-demo: validate-env ## Reset everything then run quickstart
	@docker compose down -v || true
	@$(MAKE) clean-all
	@$(MAKE) quickstart

fresh-demo-keep-audit: validate-env ## Reset but preserve audit logs
	@docker compose down -v || true
	@$(MAKE) clean-secrets
	@$(MAKE) quickstart

# =============================================================================
# Production Mode Setup
# =============================================================================

.PHONY: reset-demo init-production check-azure

reset-demo: ## Reset .env to demo defaults (requires confirmation)
	@echo "⚠️  WARNING: This will overwrite .env with .env.demo defaults."
	@read -p "Type 'yes' to confirm: " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		cp .env.demo .env; \
		echo "[reset-demo] ✓ .env reset to demo defaults"; \
	else \
		echo "[reset-demo] Cancelled"; \
	fi

init-production: ## Initialize .env for production mode with Azure Key Vault
	@if [ ! -f .env.production ]; then \
		echo "[init-production] ERROR: .env.production template not found"; \
		exit 1; \
	fi; \
	cp .env.production .env; \
	echo "[init-production] ✓ .env initialized for production mode"; \
	echo "Next steps:"; \
	echo "  1. Edit .env and set AZURE_KEY_VAULT_NAME"; \
	echo "  2. Run 'make validate-env'"; \
	echo "  3. Run 'make load-secrets'"

check-azure: ## Test Azure credential inside Flask container
	@docker compose exec flask-app $(PYTHON) -c "from azure.identity import DefaultAzureCredential; print('✓ Token:', DefaultAzureCredential().get_token('https://management.azure.com/.default').token[:20] + '...')"

# =============================================================================
# Include Modular Makefiles
# =============================================================================

include mk/docker.mk
include mk/test.mk
include mk/security.mk
include mk/infra.mk
include mk/jml.mk
include mk/secrets.mk
include mk/entra.mk
