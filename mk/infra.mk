# ============================================================================
# Terraform Infrastructure Management
# ============================================================================
# Uses Docker for reproducibility (same environment as CI/CD)
# Falls back to local terraform only if Docker is unavailable
# ============================================================================

# Prefer Docker for consistency, fallback to local
DOCKER_AVAILABLE := $(shell docker compose version >/dev/null 2>&1 && echo yes)
ifeq ($(DOCKER_AVAILABLE),yes)
  TERRAFORM_CMD = docker compose run --rm terraform
  TERRAFORM_MODE = 🐳 Docker
else
  TERRAFORM_CMD = cd infra && terraform
  TERRAFORM_MODE = 💻 Local
endif

.PHONY: infra/init infra/validate infra/plan infra/apply infra/destroy infra/fmt infra/clean infra/check infra/build

infra/check: ## Validate Terraform syntax (no Azure auth required)
	@echo "[infra/check] Validating Terraform configuration (syntax only)..."
	@# Clean any existing state that might point to Azure backend
	@sudo rm -rf infra/.terraform infra/.terraform.lock.hcl 2>/dev/null || true
	@docker run --rm -v $(PWD)/infra:/workspace -w /workspace \
		-e ARM_SKIP_PROVIDER_REGISTRATION=true \
		-e ARM_TENANT_ID=00000000-0000-0000-0000-000000000000 \
		-e ARM_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000 \
		-e ARM_CLIENT_ID=00000000-0000-0000-0000-000000000000 \
		-e ARM_CLIENT_SECRET=dummy \
		hashicorp/terraform:1.9.8 init -backend=false -input=false
	@docker run --rm -v $(PWD)/infra:/workspace -w /workspace \
		-e ARM_TENANT_ID=00000000-0000-0000-0000-000000000000 \
		-e ARM_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000 \
		-e ARM_CLIENT_ID=00000000-0000-0000-0000-000000000000 \
		-e ARM_CLIENT_SECRET=dummy \
		hashicorp/terraform:1.9.8 validate
	@echo "[infra/check] ✅ Terraform configuration is valid"
	@# Clean up after validation (avoid permission issues)
	@sudo rm -rf infra/.terraform infra/.terraform.lock.hcl 2>/dev/null || true

infra/init: ## Initialize Terraform (with Azure backend if configured)
	@echo "[infra/init] Mode: $(TERRAFORM_MODE)"
	@if [ -f infra/backend.hcl ]; then \
		echo "[infra/init] Initializing with Azure backend..."; \
		$(TERRAFORM_CMD) init -backend-config=backend.hcl; \
	else \
		echo "[infra/init] Initializing with local backend..."; \
		echo "[infra/init] ⚠️  Create infra/backend.hcl for Azure state storage"; \
		$(TERRAFORM_CMD) init -backend=false; \
	fi

infra/validate: infra/init ## Validate Terraform configuration
	@$(TERRAFORM_CMD) validate

infra/plan: infra/init ## Show Terraform execution plan
	@$(TERRAFORM_CMD) plan

infra/apply: infra/init ## Apply Terraform changes (requires confirmation)
	@$(TERRAFORM_CMD) apply

infra/destroy: infra/init ## Destroy Terraform infrastructure (requires confirmation)
	@$(TERRAFORM_CMD) destroy

infra/fmt: ## Format Terraform files
	@docker run --rm -v $(PWD)/infra:/workspace -w /workspace \
		hashicorp/terraform:1.9.8 fmt -recursive

infra/build: ## Build Terraform Docker image (with Azure CLI)
	@echo "[infra/build] Building Terraform image with Azure CLI..."
	@docker compose build terraform
	@echo "[infra/build] ✅ Image built: iam-poc-terraform"

infra/clean: ## Remove Terraform cache and lock file
	@echo "[infra/clean] Removing .terraform/ and .terraform.lock.hcl..."
	@sudo rm -rf infra/.terraform infra/.terraform.lock.hcl 2>/dev/null || \
		rm -rf infra/.terraform infra/.terraform.lock.hcl 2>/dev/null || true
	@echo "[infra/clean] ✓ Cleaned"
