# ============================================================================
# JML (Joiner / Mover / Leaver) Operations
# ============================================================================

COMMON_FLAGS = --kc-url $${KEYCLOAK_URL} --auth-realm $${KEYCLOAK_SERVICE_REALM} --svc-client-id $${KEYCLOAK_SERVICE_CLIENT_ID} --svc-client-secret $${KEYCLOAK_SERVICE_CLIENT_SECRET}

.PHONY: init joiner-alice joiner-bob mover-alice leaver-bob delete-realm demo

init: require-service-secret ## Provision realm, public client, roles, and required actions
	@$(WITH_ENV) $(JML) $(COMMON_FLAGS) init --realm $${KEYCLOAK_REALM} --client-id $${OIDC_CLIENT_ID} --redirect-uri $${OIDC_REDIRECT_URI} --post-logout-redirect-uri $${POST_LOGOUT_REDIRECT_URI}

joiner-alice: require-service-secret ## Create analyst user alice with temporary password and MFA requirements
	@$(WITH_ENV) test -n "$${ALICE_TEMP_PASSWORD}" || (echo "Set ALICE_TEMP_PASSWORD." >&2; exit 1)
	@$(WITH_ENV) $(JML) $(COMMON_FLAGS) joiner --realm $${KEYCLOAK_REALM} --username alice --email alice@example.com --first Alice --last Demo --role analyst --temp-password $${ALICE_TEMP_PASSWORD}

joiner-bob: require-service-secret ## Create analyst user bob with temporary password and MFA requirements
	@$(WITH_ENV) test -n "$${BOB_TEMP_PASSWORD}" || (echo "Set BOB_TEMP_PASSWORD." >&2; exit 1)
	@$(WITH_ENV) $(JML) $(COMMON_FLAGS) joiner --realm $${KEYCLOAK_REALM} --username bob --email bob@example.com --first Bob --last Demo --role analyst --temp-password $${BOB_TEMP_PASSWORD}

mover-alice: require-service-secret ## Promote alice from analyst to admin
	@$(WITH_ENV) $(JML) $(COMMON_FLAGS) mover --realm $${KEYCLOAK_REALM} --username alice --from-role analyst --to-role admin

leaver-bob: require-service-secret ## Disable bob account
	@$(WITH_ENV) $(JML) $(COMMON_FLAGS) leaver --realm $${KEYCLOAK_REALM} --username bob

delete-realm: require-service-secret ## Delete realm (irreversible; skips master)
	@$(WITH_ENV) $(JML) $(COMMON_FLAGS) delete-realm --realm $${KEYCLOAK_REALM}

demo: ## Run the scripted JML demonstration (starts stack + automation)
	@./scripts/run_https.sh
	@$(WITH_ENV) ./scripts/demo_jml.sh
