# ============================================================================
# Secrets Management
# ============================================================================

.PHONY: load-secrets require-service-secret require-admin-creds bootstrap-service-account
.PHONY: rotate-secret rotate-secret-dry clean-secrets clean-all archive-audit verify-audit
.PHONY: doctor doctor-secrets

load-secrets: ## Load secrets from Azure Key Vault into .runtime/secrets
	@bash scripts/load_secrets_from_keyvault.sh

require-service-secret:
	@$(WITH_ENV) test -n "$${KEYCLOAK_SERVICE_CLIENT_SECRET}" || (echo "KEYCLOAK_SERVICE_CLIENT_SECRET missing. Run 'make bootstrap-service-account' to rotate it in Key Vault." >&2; exit 1)

require-admin-creds:
	@$(WITH_ENV) test -n "$${KEYCLOAK_ADMIN}" -a -n "$${KEYCLOAK_ADMIN_PASSWORD}" || (echo "Admin credentials missing; ensure KEYCLOAK_ADMIN is set and the Key Vault secret exists." >&2; exit 1)

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
	echo "[bootstrap] KEYCLOAK_SERVICE_CLIENT_SECRET rotated in Azure Key Vault." ; \
	echo "Re-run ./scripts/run_https.sh to refresh containers with the new secret."

rotate-secret: ## Rotate Keycloak service client secret (production only)
	@./scripts/rotate_secret.sh

rotate-secret-dry: ## Dry-run of secret rotation (no changes applied)
	@./scripts/rotate_secret.sh --dry-run

clean-secrets: ## Remove secrets only (keep audit logs)
	@rm -rf .runtime/secrets || true
	@chmod -R u+w .runtime/azure 2>/dev/null || true
	@rm -rf .runtime/azure || true
	@echo "[clean-secrets] Removed .runtime/secrets and .runtime/azure (audit logs preserved)"

clean-all: ## Remove runtime data (secrets + audit logs)
	@rm -rf .runtime/secrets || true
	@chmod -R u+w .runtime/azure 2>/dev/null || true
	@rm -rf .runtime/azure || true
	@rm -rf .runtime/audit/*.jsonl || true
	@rm -f .runtime/audit/audit_log_signing_key || true
	@echo "[clean-all] Removed .runtime/ (secrets, azure cache, audit logs)"

archive-audit: ## Archive current audit log with timestamp
	@if [ -f .runtime/audit/jml-events.jsonl ]; then \
		timestamp=$$(date +%Y%m%d_%H%M%S); \
		mkdir -p .runtime/audit/archive; \
		cp .runtime/audit/jml-events.jsonl .runtime/audit/archive/jml-events_$$timestamp.jsonl; \
		echo "[archive] Audit log archived to .runtime/audit/archive/jml-events_$$timestamp.jsonl"; \
	else \
		echo "[archive] No audit log to archive"; \
	fi

verify-audit: ## Verify integrity of audit log signatures
	@if [ -f .runtime/audit/audit_log_signing_key ]; then \
		AUDIT_LOG_SIGNING_KEY_FILE=.runtime/audit/audit_log_signing_key AZURE_USE_KEYVAULT=false $(PYTHON) scripts/audit.py; \
	elif [ -f .runtime/secrets/audit_log_signing_key ]; then \
		AUDIT_LOG_SIGNING_KEY="$$(tr -d '\n' < .runtime/secrets/audit_log_signing_key)" AZURE_USE_KEYVAULT=false $(PYTHON) scripts/audit.py; \
	else \
		$(WITH_ENV) $(PYTHON) scripts/audit.py; \
	fi

doctor: ## Check environment health (Visual Report)
	@./scripts/doctor.sh

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
