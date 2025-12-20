# ============================================================================
# Docker / Stack Management
# ============================================================================

.PHONY: up down ps logs restart restart-flask ensure-stack

up: ## Start services (requires run_https.sh for cert/secrets)
	@set -a; source .env 2>/dev/null || true; set +a; \
	use_keyvault="$${AZURE_USE_KEYVAULT:-}"; \
	shopt -s nocasematch; \
	if [[ "$$use_keyvault" == "true" ]] && [ ! -s .runtime/secrets/keycloak_service_client_secret ]; then \
		echo "[up] Local secrets missing, loading from Azure Key Vault..."; \
		$(MAKE) load-secrets; \
	fi
	@./scripts/run_https.sh

down: ## Stop services and remove containers
	@docker compose down

ps: ## Display service status
	@docker compose ps

logs: ## Tail logs (SERVICE=name to filter)
	@if [ -n "$(SERVICE)" ]; then \
		docker compose logs -f "$(SERVICE)"; \
	else \
		docker compose logs -f; \
	fi

restart: ## Restart all services
	@$(MAKE) down
	@$(MAKE) up

restart-flask: ## Restart entire stack to reload secrets from files
	@echo "[restart-flask] Restarting stack to reload secrets..."
	@docker compose down
	@./scripts/run_https.sh
	@echo "[restart-flask] Stack restarted with updated secrets"

restart-stack: ## Recreate certificates, rebuild image if needed, and restart containers
	@./scripts/run_https.sh

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
