SHELL := /bin/bash

# Use python3 explicitly so we work on systems where only python3 is installed.
PYTHON ?= python3
JML := $(PYTHON) scripts/jml.py


COMMON_FLAGS = --kc-url $${KEYCLOAK_URL} --auth-realm $${KEYCLOAK_SERVICE_REALM} --svc-client-id $${KEYCLOAK_SERVICE_CLIENT_ID} --svc-client-secret $${KEYCLOAK_SERVICE_CLIENT_SECRET}
WITH_ENV := set -a; source .env; set +a;

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?##' Makefile | sed 's/:.*##/: /'

.PHONY: require-service-secret
require-service-secret:
	@$(WITH_ENV) test -n "$${KEYCLOAK_SERVICE_CLIENT_SECRET}" || (echo "KEYCLOAK_SERVICE_CLIENT_SECRET not set. Run 'make bootstrap-service-account' and export the secret." >&2; exit 1)

.PHONY: require-admin-creds
require-admin-creds:
	@$(WITH_ENV) test -n "$${KEYCLOAK_ADMIN}" -a -n "$${KEYCLOAK_ADMIN_PASSWORD}" || (echo "Admin credentials missing; export KEYCLOAK_ADMIN and KEYCLOAK_ADMIN_PASSWORD." >&2; exit 1)

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
	secret=$$($(JML) --kc-url "$$KEYCLOAK_URL" --auth-realm master --svc-client-id "$$KEYCLOAK_SERVICE_CLIENT_ID" bootstrap-service-account --realm "$$KEYCLOAK_REALM" --admin-user "$$KEYCLOAK_ADMIN" --admin-pass "$$ADMIN_PASS"); \
	if [ -z "$$secret" ]; then \
		echo "[bootstrap] No secret returned; .env not updated." >&2; \
		exit 1; \
	fi; \
	python3 scripts/update_env.py .env KEYCLOAK_SERVICE_CLIENT_SECRET "$$secret"; \
	echo "[bootstrap] KEYCLOAK_SERVICE_CLIENT_SECRET updated in .env"; \
	echo "$$secret"; \
	echo "Export KEYCLOAK_SERVICE_CLIENT_SECRET to use JML commands."

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

.PHONY: pytest
pytest: ## Run unit tests
	@$(WITH_ENV) python3 -m pytest
