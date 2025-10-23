SHELL := /bin/bash

# Use python3 explicitly so we work on systems where only python3 is installed.
PYTHON ?= python3
JML := $(PYTHON) scripts/jml.py


COMMON_FLAGS = --kc-url $${KEYCLOAK_URL} --auth-realm $${KEYCLOAK_SERVICE_REALM} --svc-client-id $${KEYCLOAK_SERVICE_CLIENT_ID} --svc-client-secret $${KEYCLOAK_SERVICE_CLIENT_SECRET}
WITH_ENV := set -a; source .env; set +a; \
	if [[ "$${AZURE_USE_KEYVAULT,,}" == "true" ]]; then \
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

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?##' Makefile | sed 's/:.*##/: /'

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
ensure-secrets: ensure-env ## Generate strong secrets if empty in .env (idempotent)
	@echo "[ensure-secrets] Checking secrets in .env..." >&2
	@if ! grep -qE "^FLASK_SECRET_KEY=[^[:space:]#]+" .env 2>/dev/null; then \
		SECRET=$$(python3 -c "import secrets; print(secrets.token_urlsafe(32))"); \
		if grep -q "^FLASK_SECRET_KEY=" .env; then \
			sed -i "s|^FLASK_SECRET_KEY=.*|FLASK_SECRET_KEY=$$SECRET|" .env; \
		else \
			echo "FLASK_SECRET_KEY=$$SECRET" >> .env; \
		fi; \
		echo "[ensure-secrets] ✓ Generated FLASK_SECRET_KEY" >&2; \
	else \
		echo "[ensure-secrets] ✓ FLASK_SECRET_KEY already set" >&2; \
	fi
	@if ! grep -qE "^AUDIT_LOG_SIGNING_KEY=[^[:space:]#]+" .env 2>/dev/null; then \
		SECRET=$$(python3 -c "import secrets; print(secrets.token_urlsafe(48))"); \
		if grep -q "^AUDIT_LOG_SIGNING_KEY=" .env; then \
			sed -i "s|^AUDIT_LOG_SIGNING_KEY=.*|AUDIT_LOG_SIGNING_KEY=$$SECRET|" .env; \
		else \
			echo "AUDIT_LOG_SIGNING_KEY=$$SECRET" >> .env; \
		fi; \
		echo "[ensure-secrets] ✓ Generated AUDIT_LOG_SIGNING_KEY" >&2; \
	else \
		echo "[ensure-secrets] ✓ AUDIT_LOG_SIGNING_KEY already set" >&2; \
	fi

.PHONY: reset-demo
reset-demo: ## Reset .env to demo defaults (requires confirmation)
	@echo "⚠️  WARNING: This will overwrite .env with .env.demo defaults." >&2
	@echo "Any custom configuration will be lost." >&2
	@read -p "Type 'yes' to confirm: " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		cp .env.demo .env; \
		echo "[reset-demo] ✓ .env reset to demo defaults" >&2; \
		echo "[reset-demo] Run 'make quickstart' to generate new secrets" >&2; \
	else \
		echo "[reset-demo] Cancelled" >&2; \
	fi

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
	secret_id=$$(printf '%s' "$$rotation_json" | python3 -c "import sys,json; data=json.load(sys.stdin); print(data.get('id',''))"); \
	secret_version=$$(printf '%s' "$$rotation_json" | python3 -c "import sys,json; data=json.load(sys.stdin); print(data.get('version',''))"); \
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
	signature=$$(AUDIT_LOG_MESSAGE="$$audit_message" python3 -c 'import os,hmac,hashlib,sys; key=os.environ["AUDIT_LOG_SIGNING_KEY"].encode(); msg=os.environ["AUDIT_LOG_MESSAGE"].encode(); print(hmac.new(key, msg, hashlib.sha256).hexdigest())'); \
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
	@docker compose exec flask-app python3 -c "from azure.identity import DefaultAzureCredential; print(DefaultAzureCredential().get_token('https://management.azure.com/.default').token[:20])"

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
	@sed -i 's/^DEMO_MODE=.*/DEMO_MODE=true/' .env
	@$(MAKE) fresh-demo || (mv .env.backup_demo .env 2>/dev/null; exit 1)
	@mv .env.backup_demo .env 2>/dev/null || true
	@echo "[demo-mode] fresh-demo exécuté en mode démo, configuration restaurée."

.PHONY: quickstart
quickstart: validate-env ensure-secrets ## Run stack + demo_jml.sh (which handles bootstrap)
	@set -a; source .env; set +a; \
	if [[ "$${AZURE_USE_KEYVAULT,,}" == "true" ]]; then \
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
	@./scripts/run_https.sh

.PHONY: down
down: ## Stop services and remove containers
	@docker compose down

.PHONY: ps
ps: ## Display service status
	@docker compose ps

.PHONY: logs
logs: ## Tail logs for all services
	@docker compose logs -f

.PHONY: restart
restart: ## Restart all services
	@$(MAKE) down
	@$(MAKE) up

.PHONY: restart-flask
restart-flask: ## Restart entire stack to reload secrets from files
	@echo "[restart-flask] Restarting stack to reload secrets..."
	@docker-compose down
	@./scripts/run_https.sh
	@echo "[restart-flask] Stack restarted with updated secrets"

.PHONY: rotate-secret-legacy
rotate-secret-legacy: ## [DEPRECATED] Old rotation method (use rotate-secret instead)
	@$(MAKE) bootstrap-service-account
	@./scripts/run_https.sh

.PHONY: doctor
doctor: ## Check az login, Key Vault access and docker compose version
	@az account show >/dev/null || (echo "[doctor] Run 'az login' first." >&2; exit 1)
	@az keyvault secret list --vault-name $${AZURE_KEY_VAULT_NAME:?Set AZURE_KEY_VAULT_NAME} >/dev/null || (echo "[doctor] Cannot list secrets; check Key Vault permissions." >&2; exit 1)
	@docker compose version >/dev/null || (echo "[doctor] docker compose not available." >&2; exit 1)
	@echo "[doctor] Environment looks good."

.PHONY: pytest
pytest: ## Run unit tests
	@python3 -m venv venv >/dev/null 2>&1 || true
	@. venv/bin/activate && pip install -r requirements.txt >/dev/null
	@. venv/bin/activate && $(WITH_ENV) python3 -m pytest

.PHONY: pytest-unit
pytest-unit: ## Run unit tests only (skip integration tests)
	@python3 -m venv venv >/dev/null 2>&1 || true
	@. venv/bin/activate && pip install -r requirements.txt >/dev/null
	@. venv/bin/activate && $(WITH_ENV) python3 -m pytest -m "not integration"

.PHONY: pytest-e2e
pytest-e2e: ## Run E2E integration tests (requires running stack)
	@echo "[pytest-e2e] Running integration tests against live stack..."
	@python3 -m venv venv >/dev/null 2>&1 || true
	@. venv/bin/activate && pip install -r requirements.txt >/dev/null
	@. venv/bin/activate && $(WITH_ENV) python3 -m pytest tests/test_integration_e2e.py -v -m integration

.PHONY: verify-audit
verify-audit: ## Verify integrity of audit log signatures
	@$(WITH_ENV) $(PYTHON) scripts/audit.py

.PHONY: rotate-secret
rotate-secret: ## Rotate Keycloak service client secret (production only)
	@./scripts/rotate_secret.sh

.PHONY: rotate-secret-dry
rotate-secret-dry: ## Dry-run of secret rotation (no changes applied)
	@./scripts/rotate_secret.sh --dry-run
