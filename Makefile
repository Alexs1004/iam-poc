SHELL := /bin/bash

JML := python scripts/jml.py

KC_URL ?= $(KEYCLOAK_URL)
SERVICE_REALM ?= $(KEYCLOAK_SERVICE_REALM)
SERVICE_CLIENT_ID ?= $(KEYCLOAK_SERVICE_CLIENT_ID)
SERVICE_CLIENT_SECRET ?= $(KEYCLOAK_SERVICE_CLIENT_SECRET)
REALM ?= $(KEYCLOAK_REALM)
CLIENT_ID ?= $(OIDC_CLIENT_ID)
REDIRECT_URI ?= $(OIDC_REDIRECT_URI)
ALICE_TEMP ?= $(ALICE_TEMP_PASSWORD)
BOB_TEMP ?= $(BOB_TEMP_PASSWORD)
ADMIN_USER ?= $(KEYCLOAK_ADMIN_USER)
ADMIN_PASS ?= $(KEYCLOAK_ADMIN_PASS)

COMMON_FLAGS := --kc-url $(KC_URL) --auth-realm $(SERVICE_REALM) --svc-client-id $(SERVICE_CLIENT_ID) --svc-client-secret $(SERVICE_CLIENT_SECRET)
BOOTSTRAP_FLAGS := --kc-url $(KC_URL) --auth-realm $(SERVICE_REALM) --svc-client-id $(SERVICE_CLIENT_ID)

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?##' Makefile | sed 's/:.*##/: /'

.PHONY: require-service-secret
require-service-secret:
	@test -n "$(SERVICE_CLIENT_SECRET)" || (echo "KEYCLOAK_SERVICE_CLIENT_SECRET not set. Run 'make bootstrap-service-account' and export the secret." >&2; exit 1)

.PHONY: require-admin-creds
require-admin-creds:
	@test -n "$(ADMIN_USER)" -a -n "$(ADMIN_PASS)" || (echo "Admin credentials missing; export KEYCLOAK_ADMIN_USER and KEYCLOAK_ADMIN_PASS." >&2; exit 1)

.PHONY: bootstrap-service-account
bootstrap-service-account: require-admin-creds ## Rotate secret and grant realm-management roles to automation client
	@$(JML) $(BOOTSTRAP_FLAGS) bootstrap-service-account --realm $(REALM) --admin-user $(ADMIN_USER) --admin-pass $(ADMIN_PASS)

.PHONY: init
init: require-service-secret ## Provision realm, public client, roles, and required actions
	@$(JML) $(COMMON_FLAGS) init --realm $(REALM) --client-id $(CLIENT_ID) --redirect-uri $(REDIRECT_URI)

.PHONY: joiner-alice
joiner-alice: require-service-secret ## Create analyst user alice with temporary password and MFA requirements
	@test -n "$(ALICE_TEMP)" || (echo "Set ALICE_TEMP_PASSWORD." >&2; exit 1)
	@$(JML) $(COMMON_FLAGS) joiner --realm $(REALM) --username alice --email alice@example.com --first Alice --last Demo --role analyst --temp-password $(ALICE_TEMP)

.PHONY: joiner-bob
joiner-bob: require-service-secret ## Create analyst user bob with temporary password and MFA requirements
	@test -n "$(BOB_TEMP)" || (echo "Set BOB_TEMP_PASSWORD." >&2; exit 1)
	@$(JML) $(COMMON_FLAGS) joiner --realm $(REALM) --username bob --email bob@example.com --first Bob --last Demo --role analyst --temp-password $(BOB_TEMP)

.PHONY: mover-alice
mover-alice: require-service-secret ## Promote alice from analyst to admin
	@$(JML) $(COMMON_FLAGS) mover --realm $(REALM) --username alice --from-role analyst --to-role admin

.PHONY: leaver-bob
leaver-bob: require-service-secret ## Disable bob account
	@$(JML) $(COMMON_FLAGS) leaver --realm $(REALM) --username bob

.PHONY: delete-realm
delete-realm: require-service-secret ## Delete realm (irreversible; skips master)
	@$(JML) $(COMMON_FLAGS) delete-realm --realm $(REALM)

.PHONY: demo
demo: ## Run the scripted JML demonstration
	@./demo_jml.sh

.PHONY: pytest
pytest: ## Run unit tests
	@python3 -m pytest
