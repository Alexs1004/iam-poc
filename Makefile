.DEFAULT_GOAL := help
.ONESHELL:
.SHELLFLAGS := -Eeuo pipefail -c
.DELETE_ON_ERROR:
.NOTPARALLEL:
SHELL := /bin/bash

# Use python3 explicitly so we work on systems where only python3 is installed.
PYTHON ?= python3

# Portable helpers
UNAME_S := $(shell uname -s)
SED_INPLACE := sed -i
ifeq ($(UNAME_S),Darwin)
  SED_INPLACE := sed -i ''
endif
SHA256_CMD := $(PYTHON) -c "import sys,hashlib; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())"
JML := $(PYTHON) scripts/jml.py
VENV_PYTHON := venv/bin/python
PYTEST := $(VENV_PYTHON) -m pytest
PYTEST_UNIT_FLAGS ?= -n auto --dist=loadscope --cache-clear


UX_TARGETS := help help-all quickstart fresh-demo up down logs test test-coverage test-coverage-report test-e2e test-all rotate-secret doctor security-check scan-secrets scan-vulns sbom scan-sbom infra/init infra/plan infra/apply

COMMON_FLAGS = --kc-url $${KEYCLOAK_URL} --auth-realm $${KEYCLOAK_SERVICE_REALM} --svc-client-id $${KEYCLOAK_SERVICE_CLIENT_ID} --svc-client-secret $${KEYCLOAK_SERVICE_CLIENT_SECRET}
WITH_ENV := set -a; source .env; set +a; \
	use_keyvault="$${AZURE_USE_KEYVAULT:-}"; \
	shopt -s nocasematch; \
	if [[ "$$use_keyvault" == "true" ]]; then \
		if [[ -z "$${AZURE_KEY_VAULT_NAME:-}" ]]; then \
			echo "[make] AZURE_KEY_VAULT_NAME is required when AZURE_USE_KEYVAULT=true." >&2; \
			exit 1; \
		fi; \
		if ! command -v az >/dev/null 2>&1; then \
			echo "[make] Azure CLI is required when AZURE_USE_KEYVAULT=true." >&2; \
			exit 1; \
		fi; \
		fetch_secret() { \
			local name="$$1"; \
			if [[ -z "$$name" ]]; then \
				echo ""; \
				return 0; \
			fi; \
			az keyvault secret show --vault-name "$${AZURE_KEY_VAULT_NAME}" --name "$$name" --query value -o tsv 2>/dev/null || echo ""; \
		}; \
		if [[ -z "$${KEYCLOAK_SERVICE_CLIENT_SECRET}" ]]; then \
			KEYCLOAK_SERVICE_CLIENT_SECRET="$$(fetch_secret "$${AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET}")"; \
			export KEYCLOAK_SERVICE_CLIENT_SECRET; \
		fi; \
		if [[ -z "$${KEYCLOAK_ADMIN_PASSWORD}" ]]; then \
			KEYCLOAK_ADMIN_PASSWORD="$$(fetch_secret "$${AZURE_SECRET_KEYCLOAK_ADMIN_PASSWORD}")"; \
			export KEYCLOAK_ADMIN_PASSWORD; \
		fi; \
		if [[ -z "$${ALICE_TEMP_PASSWORD}" ]]; then \
			ALICE_TEMP_PASSWORD="$$(fetch_secret "$${AZURE_SECRET_ALICE_TEMP_PASSWORD}")"; \
			export ALICE_TEMP_PASSWORD; \
		fi; \
		if [[ -z "$${BOB_TEMP_PASSWORD}" ]]; then \
			BOB_TEMP_PASSWORD="$$(fetch_secret "$${AZURE_SECRET_BOB_TEMP_PASSWORD}")"; \
			export BOB_TEMP_PASSWORD; \
		fi; \
		if [[ -z "$${AUDIT_LOG_SIGNING_KEY}" ]]; then \
			AUDIT_LOG_SIGNING_KEY="$$(fetch_secret "$${AZURE_SECRET_AUDIT_LOG_SIGNING_KEY}")"; \
			export AUDIT_LOG_SIGNING_KEY; \
		fi; \
	fi;

.PHONY: help help-all
help: ## Show common commands
	@set -a; source .env 2>/dev/null || true; set +a; \
	printf 'Mode: DEMO_MODE=%s  |  AZURE_USE_KEYVAULT=%s\n' "${DEMO_MODE:-unset}" "${AZURE_USE_KEYVAULT:-unset}"; \
	awk -v targets="$(UX_TARGETS)" 'BEGIN{n=split(targets,order," ");print "Available commands:"} match($$0,/^([a-zA-Z0-9_.\/-]+):.*##[ \t]*(.*)$$/,m){docs[m[1]]=sprintf("  %-16s %s",m[1],m[2])} END{for(i=1;i<=n;++i){t=order[i]; if(docs[t]!="") print docs[t];}}' $(MAKEFILE_LIST)

help-all: ## Show full list of documented commands (sorted)
	@awk 'match($$0,/^([a-zA-Z0-9_.\/-]+):.*##[ \t]*(.*)$$/,m){print m[1] "##" m[2]}' $(MAKEFILE_LIST) | sort | awk -F"##" '{ printf "  %-20s %s\n", $$1, $$2 }'

.PHONY: ensure-env
ensure-env: ## Copy .env.demo to .env if .env doesn't exist (zero-config demo mode)
	@if [ ! -f .env ]; then \
		echo "[ensure-env] .env not found, copying from .env.demo..."; \
		cp .env.demo .env; \
		echo "[ensure-env] ✓ .env created from .env.demo (demo mode ready)"; \
	else \
		echo "[ensure-env] ✓ .env already exists"; \
	fi

.PHONY: ensure-secrets
ensure-secrets: ensure-env ## Generate strong secrets if empty in .env (demo mode only)
	@set -a; source .env 2>/dev/null || true; set +a; \
	mode="$${DEMO_MODE:-}"; \
	shopt -s nocasematch; \
	if [[ "$$mode" == "false" ]]; then \
		echo "[ensure-secrets] Production mode detected (DEMO_MODE=false)" >&2; \
		use_keyvault="$${AZURE_USE_KEYVAULT:-}"; \
		if [[ "$$use_keyvault" == "true" ]]; then \
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

.PHONY: reset-demo
reset-demo: ## Reset .env to demo defaults (requires confirmation)
	@echo "⚠️  WARNING: This will overwrite .env with .env.demo defaults." >&2
	@echo "Any custom configuration will be lost." >&2
	@if [ "${FORCE:-}" = "yes" ]; then confirm=yes; else read -p "Type 'yes' to confirm: " confirm; fi; \
	if [ "$$confirm" = "yes" ]; then \
		cp .env.demo .env; \
		echo "[reset-demo] ✓ .env reset to demo defaults" >&2; \
		echo "[reset-demo] Run 'make quickstart' to generate new secrets" >&2; \
	else \
		echo "[reset-demo] Cancelled" >&2; \
	fi

.PHONY: init-production
init-production: ## Initialize .env for production mode with Azure Key Vault
	@if [ -f .env ]; then \
		echo "⚠️  WARNING: .env already exists." >&2; \
		echo "This will overwrite it with production defaults." >&2; \
		if [ "${FORCE:-}" = "yes" ]; then confirm=yes; else read -p "Type 'yes' to confirm: " confirm; fi; \
		if [ "$$confirm" != "yes" ]; then \
			echo "[init-production] Cancelled" >&2; \
			exit 1; \
		fi; \
	fi; \
	if [ ! -f .env.production ]; then \
		echo "[init-production] ERROR: .env.production template not found" >&2; \
		exit 1; \
	fi; \
	cp .env.production .env; \
	echo "[init-production] ✓ .env initialized for production mode" >&2; \
	echo "[init-production] Next steps:" >&2; \
	echo "  1. Edit .env and set AZURE_KEY_VAULT_NAME=<your-vault>" >&2; \
	echo "  2. Update URLs (KEYCLOAK_ISSUER, OIDC_REDIRECT_URI, etc.)" >&2; \
	echo "  3. Run 'make validate-env' to check configuration" >&2; \
	echo "  4. Run 'make ensure-secrets' to clear local secrets" >&2; \
	echo "  5. Run 'make load-secrets' to load from Azure Key Vault" >&2;

.PHONY: validate-env
validate-env: ensure-env ## Validate and auto-correct .env (DEMO_MODE=true forces AZURE_USE_KEYVAULT=false)
	@./scripts/validate_env.sh

.PHONY: load-secrets
load-secrets: ## Load secrets from Azure Key Vault into .env.runtime
	@bash scripts/load_secrets_from_keyvault.sh

.PHONY: require-service-secret
require-service-secret:
	@$(WITH_ENV) test -n "$${KEYCLOAK_SERVICE_CLIENT_SECRET}" || (echo "KEYCLOAK_SERVICE_CLIENT_SECRET missing. Run 'make bootstrap-service-account' to rotate it in Key Vault." >&2; exit 1)

.PHONY: require-admin-creds
require-admin-creds:
	@$(WITH_ENV) test -n "$${KEYCLOAK_ADMIN}" -a -n "$${KEYCLOAK_ADMIN_PASSWORD}" || (echo "Admin credentials missing; ensure KEYCLOAK_ADMIN is set and the Key Vault secret $${AZURE_SECRET_KEYCLOAK_ADMIN_PASSWORD} exists." >&2; exit 1)

.PHONY: bootstrap-service-account
bootstrap-service-account: ## One-time bootstrap (requires master admin; rotates secret)
	@set -a; source .env; set +a; \
	if [ -z "$$KEYCLOAK_ADMIN" ]; then \
		echo "[bootstrap] KEYCLOAK_ADMIN is not set in .env"; \
		exit 1; \
	fi; \
	if [ -z "$$AZURE_KEY_VAULT_NAME" ] || [ -z "$$AZURE_SECRET_KEYCLOAK_ADMIN_PASSWORD" ]; then \
		echo "[bootstrap] Azure Key Vault configuration missing in .env"; \
		exit 1; \
	fi; \
	ADMIN_PASS=$$(az keyvault secret show --vault-name "$$AZURE_KEY_VAULT_NAME" --name "$$AZURE_SECRET_KEYCLOAK_ADMIN_PASSWORD" --query value -o tsv) || exit 1; \
	if [ -z "$$ADMIN_PASS" ]; then \
		echo "[bootstrap] Failed to retrieve admin password from Key Vault"; \
		exit 1; \
	fi; \
	if [ -z "$$AUDIT_LOG_SIGNING_KEY" ]; then \
		if [ -z "$$AZURE_SECRET_AUDIT_LOG_SIGNING_KEY" ]; then \
			echo "[bootstrap] AZURE_SECRET_AUDIT_LOG_SIGNING_KEY must reference the audit HMAC secret in Key Vault." >&2; \
			exit 1; \
		fi; \
		AUDIT_LOG_SIGNING_KEY=$$(az keyvault secret show --vault-name "$$AZURE_KEY_VAULT_NAME" --name "$$AZURE_SECRET_AUDIT_LOG_SIGNING_KEY" --query value -o tsv) || exit 1; \
		if [ -z "$$AUDIT_LOG_SIGNING_KEY" ]; then \
			echo "[bootstrap] Failed to retrieve AUDIT_LOG_SIGNING_KEY from Key Vault." >&2; \
			exit 1; \
		fi; \
		export AUDIT_LOG_SIGNING_KEY; \
	fi; \
	secret=$$($(JML) --kc-url "$$KEYCLOAK_URL" --auth-realm master --svc-client-id "$$KEYCLOAK_SERVICE_CLIENT_ID" bootstrap-service-account --realm "$$KEYCLOAK_REALM" --admin-user "$$KEYCLOAK_ADMIN" --admin-pass "$$ADMIN_PASS"); \
	if [ -z "$$secret" ]; then \
		echo "[bootstrap] No secret returned; .env not updated." >&2; \
		exit 1; \
	fi; \
	if [[ -z "$$AZURE_KEY_VAULT_NAME" ]] || [[ -z "$$AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET" ]]; then \
		echo "[bootstrap] Missing Key Vault mapping for service client secret; aborting." >&2; \
		exit 1; \
	fi; \
	if ! rotation_json=$$(az keyvault secret set --vault-name "$$AZURE_KEY_VAULT_NAME" --name "$$AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET" --value "$$secret" --query "{id:id,version:properties.version}" -o json --only-show-errors); then \
		echo "[bootstrap] Failed to store KEYCLOAK_SERVICE_CLIENT_SECRET in Key Vault." >&2; \
		exit 1; \
	fi; \
	secret_id=$$(printf '%s' "$$rotation_json" | $(PYTHON) -c "import sys,json; data=json.load(sys.stdin); print(data.get('id',''))"); \
	secret_version=$$(printf '%s' "$$rotation_json" | $(PYTHON) -c "import sys,json; data=json.load(sys.stdin); print(data.get('version',''))"); \
	if [ -z "$$secret_id" ] || [ -z "$$secret_version" ]; then \
		echo "[bootstrap] Unable to parse secret identifier from Key Vault response." >&2; \
		exit 1; \
	fi; \
	operator=$$(az account show --query "user.name" -o tsv 2>/dev/null); \
	if [ -z "$$operator" ]; then \
		operator=$$(az account show --query "user.userPrincipalName" -o tsv 2>/dev/null); \
	fi; \
	if [ -z "$$operator" ]; then \
		operator=$$(az account show --query "name" -o tsv 2>/dev/null || echo "unknown"); \
	fi; \
	timestamp=$$(date -u '+%Y-%m-%dT%H:%M:%SZ'); \
	audit_dir=".runtime/audit"; \
	mkdir -p "$$audit_dir"; \
	chmod 700 "$$audit_dir"; \
	audit_message="timestamp=$$timestamp operator=$$operator secret_id=$$secret_id version=$$secret_version"; \
	signature=$$(AUDIT_LOG_MESSAGE="$$audit_message" $(PYTHON) -c 'import os,hmac,hashlib,sys; key=os.environ["AUDIT_LOG_SIGNING_KEY"].encode(); msg=os.environ["AUDIT_LOG_MESSAGE"].encode(); print(hmac.new(key, msg, hashlib.sha256).hexdigest())'); \
	audit_file="$$audit_dir/secret-rotation.log"; \
	touch "$$audit_file"; \
	chmod 600 "$$audit_file"; \
	printf '%s signature=%s\n' "$$audit_message" "$$signature" >> "$$audit_file"; \
	echo "[bootstrap] KEYCLOAK_SERVICE_CLIENT_SECRET rotated in Azure Key Vault (version $$secret_version)." ; \
	echo "[bootstrap] Audit entry recorded for operator '$$operator'." ; \
	echo "Re-run ./scripts/run_https.sh to refresh containers with the new secret."

.PHONY: init
init: require-service-secret ## Provision realm, public client, roles, and required actions
	@$(WITH_ENV) $(JML) $(COMMON_FLAGS) init --realm $${KEYCLOAK_REALM} --client-id $${OIDC_CLIENT_ID} --redirect-uri $${OIDC_REDIRECT_URI} --post-logout-redirect-uri $${POST_LOGOUT_REDIRECT_URI}

.PHONY: joiner-alice
joiner-alice: require-service-secret ## Create analyst user alice with temporary password and MFA requirements
	@$(WITH_ENV) test -n "$${ALICE_TEMP_PASSWORD}" || (echo "Set ALICE_TEMP_PASSWORD." >&2; exit 1)
	@$(WITH_ENV) $(JML) $(COMMON_FLAGS) joiner --realm $${KEYCLOAK_REALM} --username alice --email alice@example.com --first Alice --last Demo --role analyst --temp-password $${ALICE_TEMP_PASSWORD}

.PHONY: joiner-bob
joiner-bob: require-service-secret ## Create analyst user bob with temporary password and MFA requirements
	@$(WITH_ENV) test -n "$${BOB_TEMP_PASSWORD}" || (echo "Set BOB_TEMP_PASSWORD." >&2; exit 1)
	@$(WITH_ENV) $(JML) $(COMMON_FLAGS) joiner --realm $${KEYCLOAK_REALM} --username bob --email bob@example.com --first Bob --last Demo --role analyst --temp-password $${BOB_TEMP_PASSWORD}

.PHONY: mover-alice
mover-alice: require-service-secret ## Promote alice from analyst to admin
	@$(WITH_ENV) $(JML) $(COMMON_FLAGS) mover --realm $${KEYCLOAK_REALM} --username alice --from-role analyst --to-role admin

.PHONY: leaver-bob
leaver-bob: require-service-secret ## Disable bob account
	@$(WITH_ENV) $(JML) $(COMMON_FLAGS) leaver --realm $${KEYCLOAK_REALM} --username bob

.PHONY: delete-realm
delete-realm: require-service-secret ## Delete realm (irreversible; skips master)
	@$(WITH_ENV) $(JML) $(COMMON_FLAGS) delete-realm --realm $${KEYCLOAK_REALM}

.PHONY: demo
demo: ## Run the scripted JML demonstration (starts stack + automation)
	@./scripts/run_https.sh
	@$(WITH_ENV) ./scripts/demo_jml.sh

.PHONY: restart-stack
restart-stack: ## Recreate certificates, rebuild image if needed, and restart containers
	@./scripts/run_https.sh

.PHONY: check-azure
check-azure: ## Test DefaultAzureCredential token acquisition inside the Flask container
	@docker compose exec flask-app $(PYTHON) -c "from azure.identity import DefaultAzureCredential; print(DefaultAzureCredential().get_token('https://management.azure.com/.default').token[:20])"

.PHONY: clean-secrets
clean-secrets: ## Remove secrets only (keep audit logs)
	@rm -rf .runtime/secrets || true
	@chmod -R u+w .runtime/azure 2>/dev/null || true
	@rm -rf .runtime/azure || true
	@echo "[clean-secrets] Removed .runtime/secrets and .runtime/azure (audit logs preserved)"

.PHONY: clean-all
clean-all: ## Remove runtime data (secrets + audit logs)
	@rm -rf .runtime/secrets || true
	@chmod -R u+w .runtime/azure 2>/dev/null || true
	@rm -rf .runtime/azure || true
	@rm -rf .runtime/audit/*.jsonl || true
	@rm -f .runtime/audit/audit_log_signing_key || true
	@echo "[clean-all] Removed .runtime/ (secrets, azure cache, audit logs)"

.PHONY: archive-audit
archive-audit: ## Archive current audit log with timestamp
	@if [ -f .runtime/audit/jml-events.jsonl ]; then \
		timestamp=$$(date +%Y%m%d_%H%M%S); \
		mkdir -p .runtime/audit/archive; \
		cp .runtime/audit/jml-events.jsonl .runtime/audit/archive/jml-events_$$timestamp.jsonl; \
		echo "[archive] Audit log archived to .runtime/audit/archive/jml-events_$$timestamp.jsonl"; \
	else \
		echo "[archive] No audit log to archive"; \
	fi

.PHONY: demo-mode
demo-mode: ## Toggle DEMO_MODE=true le temps d'un fresh-demo, puis restaure la valeur
	@cp .env .env.backup_demo || true
	@$(SED_INPLACE) 's/^DEMO_MODE=.*/DEMO_MODE=true/' .env
	@$(MAKE) fresh-demo || (mv .env.backup_demo .env 2>/dev/null; exit 1)
	@set -a; source .env; set +a; \
	demo_key="$${AUDIT_LOG_SIGNING_KEY_DEMO:-demo-audit-signing-key-change-in-production}"; \
	if [ -n "$$demo_key" ]; then \
		mkdir -p .runtime/audit; \
		chmod 700 .runtime/audit 2>/dev/null || true; \
		( umask 177 && printf '%s' "$$demo_key" > .runtime/audit/audit_log_signing_key.tmp ) && \
		mv .runtime/audit/audit_log_signing_key.tmp .runtime/audit/audit_log_signing_key; \
		echo "[demo-mode] audit_log_signing_key written to .runtime/audit/"; \
	fi
	@mv .env.backup_demo .env 2>/dev/null || true
	@echo "[demo-mode] fresh-demo exécuté en mode démo, configuration restaurée."

.PHONY: quickstart
quickstart: validate-env ensure-secrets ## Run stack + demo_jml.sh (which handles bootstrap)
	@if docker compose ps --services --filter "status=running" 2>/dev/null | grep -q "^keycloak$$"; then \
		echo "[quickstart] Keycloak container is already running. Stop the stack first (e.g. 'make down') before running quickstart."; \
		exit 1; \
	fi
	@set -a; source .env; set +a; \
	use_keyvault="$${AZURE_USE_KEYVAULT:-}"; \
	shopt -s nocasematch; \
	if [[ "$$use_keyvault" == "true" ]]; then \
		echo "[quickstart] Loading secrets from Azure Key Vault..."; \
		$(MAKE) load-secrets; \
	fi
	@./scripts/run_https.sh
	@$(WITH_ENV) ./scripts/demo_jml.sh

.PHONY: fresh-demo
fresh-demo: validate-env ## Reset everything then run quickstart (clean secrets + audit)
	@docker compose down -v || true
	@$(MAKE) clean-all
	@$(MAKE) quickstart

.PHONY: fresh-demo-keep-audit
fresh-demo-keep-audit: validate-env ## Reset but preserve audit logs
	@docker compose down -v || true
	@$(MAKE) clean-secrets
	@$(MAKE) quickstart

.PHONY: up
up: ## Start services (requires run_https.sh for cert/secrets)
	@set -a; source .env 2>/dev/null || true; set +a; \
	use_keyvault="$${AZURE_USE_KEYVAULT:-}"; \
	shopt -s nocasematch; \
	if [[ "$$use_keyvault" == "true" ]] && [ ! -s .runtime/secrets/keycloak_service_client_secret ]; then \
		echo "[up] Local secrets missing, loading from Azure Key Vault..."; \
		$(MAKE) load-secrets; \
	fi
	@./scripts/run_https.sh

.PHONY: down
down: ## Stop services and remove containers
	@docker compose down

.PHONY: ps
ps: ## Display service status
	@docker compose ps

.PHONY: logs
logs: ## Tail logs (SERVICE=name to filter)
	@if [ -n "$(SERVICE)" ]; then \
		docker compose logs -f "$(SERVICE)"; \
	else \
		docker compose logs -f; \
	fi

.PHONY: restart
restart: ## Restart all services
	@$(MAKE) down
	@$(MAKE) up

.PHONY: restart-flask
restart-flask: ## Restart entire stack to reload secrets from files
	@echo "[restart-flask] Restarting stack to reload secrets..."
	@docker compose down
	@./scripts/run_https.sh
	@echo "[restart-flask] Stack restarted with updated secrets"

.PHONY: doctor
doctor: ## Check az login, Key Vault access and docker compose version
	@$(WITH_ENV)
	@az account show >/dev/null || (echo "[doctor] Run 'az login' first." >&2; exit 1)
	@vault="$${AZURE_KEY_VAULT_NAME:-}"; \
	if [ -z "$$vault" ]; then \
		echo "[doctor] Set AZURE_KEY_VAULT_NAME in .env before running doctor."; \
		exit 1; \
	fi; \
	az keyvault secret list --vault-name "$$vault" >/dev/null || (echo "[doctor] Cannot list secrets; check Key Vault permissions." >&2; exit 1)
	@docker compose version >/dev/null || (echo "[doctor] docker compose not available." >&2; exit 1)
	@echo "[doctor] Environment looks good."
	@$(MAKE) --no-print-directory doctor-secrets || true

.PHONY: doctor-secrets
doctor-secrets: ## Compare KV vs local vs Keycloak (hash only) and fail on drift
	@set -e; \
	hash8(){ printf '%s' "$$1" | $(SHA256_CMD) | cut -c1-8; }; \
	kv=$$(az keyvault secret show --vault-name "$$AZURE_KEY_VAULT_NAME" --name "$$AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET" --query value -o tsv 2>/dev/null || true); \
	loc=$$(cat .runtime/secrets/keycloak_service_client_secret 2>/dev/null || true); \
	if [ -n "$$kv" ] && [ -n "$$loc" ] && [ "$$kv" != "$$loc" ]; then \
	  echo "[doctor-secrets] drift KV/local: $$(hash8 $$kv) != $$(hash8 $$loc) — run 'make rotate-secret'"; exit 1; \
	fi; \
	if [ -n "$$kv" ]; then \
	  echo "[doctor-secrets] KV hash=$$(hash8 $$kv)"; \
	fi; \
	if [ -n "$$loc" ]; then \
	  echo "[doctor-secrets] local hash=$$(hash8 $$loc)"; \
	fi

.PHONY: ensure-stack
ensure-stack: ## Ensure stack is running (start if needed)
	@if ! docker compose ps --services --filter "status=running" 2>/dev/null | grep -q keycloak; then \
		echo "[ensure-stack] Stack not running, starting with quickstart..."; \
		$(MAKE) quickstart; \
		echo "[ensure-stack] Waiting for services to be healthy..."; \
		ok=0; for i in $$(seq 1 30); do \
		  unhealthy=$$(docker compose ps --format '{{.Name}} {{.Health}}' 2>/dev/null | awk '$$2!="healthy"{print $$1}'); \
		  if [ -z "$$unhealthy" ]; then echo "[ensure-stack] ✓ healthy"; ok=1; break; fi; \
		  sleep 2; \
		done; \
		[ $$ok -eq 1 ] || { echo "[ensure-stack] ❌ services not healthy in time"; exit 1; }; \
	else \
		echo "[ensure-stack] ✓ Stack already running"; \
	fi

.PHONY: venv
venv: ## Create/refresh venv and install dependencies
	@$(PYTHON) -m venv venv >/dev/null 2>&1 || true
	@venv/bin/pip install -q -r requirements.txt

.PHONY: test
test: venv ## Run unit tests (no integration)
	@DEMO_MODE=true $(PYTEST) $(PYTEST_UNIT_FLAGS) -m "not integration" $(ARGS)

.PHONY: test-coverage
test-coverage: ensure-stack venv ## Run all tests with coverage report (HTML + terminal)
	@echo "[test-coverage] Running tests with coverage analysis..."
	@DEMO_MODE=true $(PYTEST) tests/ --cov=app --cov-report=html --cov-report=term-missing $(ARGS)
	@echo "[test-coverage] ✓ Coverage report generated"
	@echo "[test-coverage] View with: make test-coverage-report"

.PHONY: test-coverage-report
test-coverage-report: ## Show coverage report information and viewing options
	@echo "[test-coverage-report] ✓ Coverage report location:"
	@echo "    📊 file://$(PWD)/htmlcov/index.html"
	@echo ""
	@echo "Available commands:"
	@echo "  • make test-coverage-vscode  → Open in VS Code (recommended)"
	@echo "  • make test-coverage-open    → Open in system browser (if available)"
	@echo "  • make test-coverage-serve   → Serve on http://localhost:8888"
	@echo ""

.PHONY: test-coverage-open
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

.PHONY: test-coverage-serve
test-coverage-serve: ## Serve coverage report on http://localhost:8888
	@if [ ! -f htmlcov/index.html ]; then \
		echo "❌ Coverage report not found. Run 'make test-coverage' first."; \
		exit 1; \
	fi
	@echo "[test-coverage-serve] 🌐 Serving coverage report on http://localhost:8888"
	@echo "Press Ctrl+C to stop the server."
	@cd htmlcov && $(PYTHON) -m http.server 8888

.PHONY: test-coverage-vscode
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

.PHONY: test-e2e
test-e2e: ensure-stack venv ## Run integration test suite (requires stack)
	@set -a; source .env 2>/dev/null || true; set +a; \
	demo_mode="$${DEMO_MODE:-}"; \
	unset DEMO_MODE AZURE_USE_KEYVAULT FLASK_SECRET_KEY KEYCLOAK_SERVICE_CLIENT_SECRET KEYCLOAK_ADMIN_PASSWORD AUDIT_LOG_SIGNING_KEY KEYCLOAK_URL KEYCLOAK_URL_HOST APP_BASE_URL KEYCLOAK_ISSUER KEYCLOAK_PUBLIC_ISSUER; \
	if [ "$$demo_mode" = "true" ]; then \
		echo "[test-e2e] DEMO_MODE=true: unit tests are sufficient for demo mode (run 'make test'). To execute integration suites, switch back to production configuration (DEMO_MODE=false, AZURE_USE_KEYVAULT=true) then run 'make load-secrets' and 'set -a; source .env; set +a'." >&2; \
		exit 1; \
	fi; \
	$(PYTEST) -m integration $(ARGS)

.PHONY: test-all
test-all: ## Run unit, integration, and security suites
	@set -a; source .env 2>/dev/null || true; set +a; \
	demo_mode="$${DEMO_MODE:-}"; \
	unset DEMO_MODE AZURE_USE_KEYVAULT FLASK_SECRET_KEY KEYCLOAK_SERVICE_CLIENT_SECRET KEYCLOAK_ADMIN_PASSWORD AUDIT_LOG_SIGNING_KEY KEYCLOAK_URL KEYCLOAK_URL_HOST APP_BASE_URL KEYCLOAK_ISSUER KEYCLOAK_PUBLIC_ISSUER; \
	if [ "$$demo_mode" = "true" ]; then \
		echo "[test-all] DEMO_MODE=true: unit tests are sufficient for demo mode (run 'make test'). To run the full suites, switch back to production configuration (DEMO_MODE=false, AZURE_USE_KEYVAULT=true) then run 'make load-secrets' and 'set -a; source .env; set +a'." >&2; \
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

.PHONY: test/security
test/security: venv ## Run critical security tests
	@set -a; source .env 2>/dev/null || true; set +a; \
	demo_mode="$${DEMO_MODE:-}"; \
	unset DEMO_MODE AZURE_USE_KEYVAULT FLASK_SECRET_KEY KEYCLOAK_SERVICE_CLIENT_SECRET KEYCLOAK_ADMIN_PASSWORD AUDIT_LOG_SIGNING_KEY KEYCLOAK_URL KEYCLOAK_URL_HOST APP_BASE_URL KEYCLOAK_ISSUER KEYCLOAK_PUBLIC_ISSUER; \
	if [ "$$demo_mode" = "true" ]; then \
		echo "[test/security] DEMO_MODE=true: unit tests are sufficient for demo mode (run 'make test'). To execute security suites, switch back to production configuration (DEMO_MODE=false, AZURE_USE_KEYVAULT=true) then run 'make load-secrets' and 'set -a; source .env; set +a'." >&2; \
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

.PHONY: test/oidc
test/oidc: venv ## Run OIDC/JWT validation tests
	@DEMO_MODE=true $(PYTEST) tests/test_oidc_jwt_validation.py -v $(ARGS)

.PHONY: test/nginx
test/nginx: ensure-stack venv ## Run Nginx/TLS/headers smoke tests
	@$(PYTEST) tests/test_nginx_security_headers.py -v -m integration $(ARGS)

.PHONY: verify-audit
verify-audit: ## Verify integrity of audit log signatures
	@if [ -f .runtime/audit/audit_log_signing_key ]; then \
		AUDIT_LOG_SIGNING_KEY_FILE=.runtime/audit/audit_log_signing_key AZURE_USE_KEYVAULT=false $(PYTHON) scripts/audit.py; \
	elif [ -f .runtime/secrets/audit_log_signing_key ]; then \
		AUDIT_LOG_SIGNING_KEY="$$(tr -d '\n' < .runtime/secrets/audit_log_signing_key)" AZURE_USE_KEYVAULT=false $(PYTHON) scripts/audit.py; \
	else \
		$(WITH_ENV) $(PYTHON) scripts/audit.py; \
	fi

# Security Scanning (Docker-based)
.PHONY: scan-secrets
scan-secrets: ## Run Gitleaks to detect secrets in codebase
	@echo "[scan-secrets] 🔍 Scanning for secrets with Gitleaks..."
	@docker run --rm -v $(PWD):/path ghcr.io/gitleaks/gitleaks:latest detect \
		--source /path \
		--config /path/.gitleaks.toml \
		--no-git \
		--verbose
	@echo "[scan-secrets] ✅ No secrets found"

.PHONY: scan-vulns
scan-vulns: ## Run Trivy to scan for CVE vulnerabilities
	@echo "[scan-vulns] 🛡️  Scanning for vulnerabilities with Trivy..."
	@docker run --rm -v $(PWD):/workspace aquasec/trivy:latest fs \
		--severity HIGH,CRITICAL \
		--scanners vuln \
		--exit-code 1 \
		/workspace/requirements.txt
	@echo "[scan-vulns] ✅ No HIGH/CRITICAL vulnerabilities found"

.PHONY: scan-vulns-all
scan-vulns-all: ## Run Trivy on entire filesystem (slower, comprehensive)
	@echo "[scan-vulns-all] 🛡️  Scanning entire project with Trivy..."
	@docker run --rm -v $(PWD):/workspace aquasec/trivy:latest fs \
		--severity HIGH,CRITICAL,MEDIUM \
		--scanners vuln \
		/workspace

.PHONY: sbom
sbom: ## Generate Software Bill of Materials with Syft
	@echo "[sbom] 📦 Generating SBOM with Syft (scanning Docker image)..."
	@mkdir -p .runtime/sbom
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		-v $(PWD)/.runtime/sbom:/out anchore/syft:latest \
		iam-poc-flask:latest -o spdx-json=/out/sbom-spdx.json
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		-v $(PWD)/.runtime/sbom:/out anchore/syft:latest \
		iam-poc-flask:latest -o cyclonedx-json=/out/sbom-cyclonedx.json
	@echo "[sbom] ✅ SBOM generated from Docker image 'iam-poc-flask:latest':"
	@echo "    • .runtime/sbom/sbom-spdx.json (SPDX format)"
	@echo "    • .runtime/sbom/sbom-cyclonedx.json (CycloneDX format)"

.PHONY: scan-sbom
scan-sbom: ## Scan SBOM for vulnerabilities with Grype
	@if [ ! -f .runtime/sbom/sbom-spdx.json ]; then \
		echo "[scan-sbom] ⚠️  SBOM not found. Generating first..."; \
		$(MAKE) sbom; \
	fi
	@echo "[scan-sbom] 🔍 Scanning SBOM with Grype..."
	@docker run --rm -v $(PWD):/workspace anchore/grype:latest \
		sbom:/workspace/.runtime/sbom/sbom-spdx.json \
		--fail-on critical \
		-o table
	@echo "[scan-sbom] ✅ No CRITICAL vulnerabilities in SBOM"

.PHONY: security-check
security-check: ## Run all security scans (secrets, vulns, SBOM)
	@echo "🔐 Running comprehensive security checks..."
	@echo ""
	@$(MAKE) scan-secrets
	@echo ""
	@$(MAKE) scan-vulns
	@echo ""
	@$(MAKE) sbom
	@echo ""
	@$(MAKE) scan-sbom
	@echo ""
	@echo "✅ All security checks passed!"

.PHONY: rotate-secret
rotate-secret: ## Rotate Keycloak service client secret (production only)
	@./scripts/rotate_secret.sh

.PHONY: rotate-secret-dry
rotate-secret-dry: ## Dry-run of secret rotation (no changes applied)
	@./scripts/rotate_secret.sh --dry-run

# ============================================================================
# Terraform Infrastructure Management
# ============================================================================

TERRAFORM_DOCKER = docker compose run --rm terraform

.PHONY: infra/init infra/validate infra/plan infra/apply infra/destroy infra/fmt infra/clean

infra/init: ## Initialize Terraform (with Azure backend if configured)
	@$(WITH_ENV) \
	if [ -f infra/backend.hcl ]; then \
		echo "[infra/init] Initializing with Azure backend..."; \
		$(TERRAFORM_DOCKER) init -backend-config=infra/backend.hcl; \
	else \
		echo "[infra/init] Initializing with local backend (run scripts/infra/setup-backend.sh for Azure)..."; \
		$(TERRAFORM_DOCKER) init; \
	fi

infra/validate: infra/init ## Validate Terraform configuration
	@$(TERRAFORM_DOCKER) validate

infra/plan: infra/init ## Show Terraform execution plan
	@$(TERRAFORM_DOCKER) plan

infra/apply: infra/init ## Apply Terraform changes (requires confirmation)
	@$(TERRAFORM_DOCKER) apply

infra/destroy: infra/init ## Destroy Terraform infrastructure (requires confirmation)
	@$(TERRAFORM_DOCKER) destroy

infra/fmt: ## Format Terraform files
	@$(TERRAFORM_DOCKER) fmt -recursive

infra/clean: ## Remove Terraform cache and lock file
	@echo "[infra/clean] Removing .terraform/ and .terraform.lock.hcl..."
	@rm -rf infra/.terraform infra/.terraform.lock.hcl
	@echo "[infra/clean] ✓ Cleaned"
