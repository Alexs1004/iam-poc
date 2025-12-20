# ============================================================================
# Entra ID User Provisioning (Azure AD)
# ============================================================================

.PHONY: demo-entra demo-entra-cleanup demo-entra-delete

demo-entra: ## Provision demo users in Entra ID (requires ENTRA_DOMAIN)
	@./scripts/demo_entra.sh

demo-entra-cleanup: ## Disable demo users in Entra ID (soft delete)
	@./scripts/demo_entra.sh --cleanup

demo-entra-delete: ## Permanently delete demo users in Entra ID
	@./scripts/demo_entra.sh --hard-cleanup
