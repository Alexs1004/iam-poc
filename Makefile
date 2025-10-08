SHELL := /bin/bash

JML := python scripts/jml.py


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
	@$(WITH_ENV) test -n "$${KEYCLOAK_ADMIN_USER}" -a -n "$${KEYCLOAK_ADMIN_PASS}" || (echo "Admin credentials missing; export KEYCLOAK_ADMIN_USER and KEYCLOAK_ADMIN_PASS." >&2; exit 1)

.PHONY: bootstrap-service-account
bootstrap-service-account: require-admin-creds ## One-time bootstrap (requires master admin; rotates secret)
	@$(WITH_ENV) $(JML) --kc-url "$${KEYCLOAK_URL}" --auth-realm master --svc-client-id "$${KEYCLOAK_SERVICE_CLIENT_ID}" bootstrap-service-account --realm "$${KEYCLOAK_REALM}" --admin-user $${KEYCLOAK_ADMIN_USER} --admin-pass $${KEYCLOAK_ADMIN_PASS}

.PHONY: init
init: require-service-secret ## Provision realm, public client, roles, and required actions
	@$(WITH_ENV) $(JML) $(COMMON_FLAGS) init --realm $${KEYCLOAK_REALM} --client-id $${OIDC_CLIENT_ID} --redirect-uri $${OIDC_REDIRECT_URI}

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
demo: ## Run the scripted JML demonstration
	@$(WITH_ENV) ./demo_jml.sh

.PHONY: pytest
pytest: ## Run unit tests
	@$(WITH_ENV) python3 -m pytest