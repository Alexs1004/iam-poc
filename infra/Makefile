.PHONY: help init validate plan apply destroy fmt clean

DOCKER_RUN = docker compose run --rm terraform

help:
	@echo "Terraform commands:"
	@echo "  make init      - Initialize Terraform"
	@echo "  make validate  - Validate configuration"
	@echo "  make plan      - Show execution plan"
	@echo "  make apply     - Apply changes"
	@echo "  make destroy   - Destroy infrastructure"
	@echo "  make fmt       - Format Terraform files"
	@echo "  make clean     - Remove Terraform cache"

init:
	@if [ -f backend.hcl ]; then \
		$(DOCKER_RUN) init -backend-config=backend.hcl; \
	else \
		$(DOCKER_RUN) init; \
	fi

validate: init
	@$(DOCKER_RUN) validate

plan: init
	@$(DOCKER_RUN) plan -var="tenant_id=$(ARM_TENANT_ID)"

apply: init
	@$(DOCKER_RUN) apply -var="tenant_id=$(ARM_TENANT_ID)"

destroy: init
	@$(DOCKER_RUN) destroy -var="tenant_id=$(ARM_TENANT_ID)"

fmt:
	@$(DOCKER_RUN) fmt -recursive

clean:
	@rm -rf .terraform .terraform.lock.hcl
