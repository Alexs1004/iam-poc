# ============================================================================
# Security Scanning
# ============================================================================

.PHONY: scan-secrets scan-vulns scan-vulns-all sbom scan-sbom security-check

scan-secrets: ## Run Gitleaks to detect secrets in codebase
	@echo "[scan-secrets] 🔍 Scanning for secrets with Gitleaks..."
	@docker run --rm -v $(PWD):/path ghcr.io/gitleaks/gitleaks:latest detect \
		--source /path \
		--config /path/.gitleaks.toml \
		--no-git \
		--verbose
	@echo "[scan-secrets] ✅ No secrets found"

scan-vulns: ## Run Trivy to scan for CVE vulnerabilities
	@echo "[scan-vulns] 🛡️  Scanning for vulnerabilities with Trivy..."
	@docker run --rm -v $(PWD):/workspace aquasec/trivy:latest fs \
		--severity HIGH,CRITICAL \
		--scanners vuln \
		--exit-code 1 \
		/workspace/requirements.txt
	@echo "[scan-vulns] ✅ No HIGH/CRITICAL vulnerabilities found"

scan-vulns-all: ## Run Trivy on entire filesystem (slower, comprehensive)
	@echo "[scan-vulns-all] 🛡️  Scanning entire project with Trivy..."
	@docker run --rm -v $(PWD):/workspace aquasec/trivy:latest fs \
		--severity HIGH,CRITICAL,MEDIUM \
		--scanners vuln \
		/workspace

sbom: ## Generate Software Bill of Materials with Syft
	@echo "[sbom] 📦 Generating SBOM with Syft (scanning Docker image)..."
	@mkdir -p .runtime/sbom
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		-v $(PWD)/.runtime/sbom:/out anchore/syft:latest \
		iam-poc-flask:latest -o spdx-json=/out/sbom-spdx.json
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		-v $(PWD)/.runtime/sbom:/out anchore/syft:latest \
		iam-poc-flask:latest -o cyclonedx-json=/out/sbom-cyclonedx.json
	@echo "[sbom] ✅ SBOM generated from Docker image 'iam-poc-flask:latest':"
	@echo "    • .runtime/sbom/sbom-spdx.json (SPDX format)"
	@echo "    • .runtime/sbom/sbom-cyclonedx.json (CycloneDX format)"

scan-sbom: ## Scan SBOM for vulnerabilities with Grype
	@if [ ! -f .runtime/sbom/sbom-spdx.json ]; then \
		echo "[scan-sbom] ⚠️  SBOM not found. Generating first..."; \
		$(MAKE) sbom; \
	fi
	@echo "[scan-sbom] 🔍 Scanning SBOM with Grype..."
	@docker run --rm -v $(PWD):/workspace anchore/grype:latest \
		sbom:/workspace/.runtime/sbom/sbom-spdx.json \
		--fail-on critical \
		-o table
	@echo "[scan-sbom] ✅ No CRITICAL vulnerabilities in SBOM"

security-check: ## Run all security scans (secrets, vulns, SBOM)
	@echo "🔐 Running comprehensive security checks..."
	@echo ""
	@$(MAKE) scan-secrets
	@echo ""
	@$(MAKE) scan-vulns
	@echo ""
	@$(MAKE) sbom
	@echo ""
	@$(MAKE) scan-sbom
	@echo ""
	@echo "✅ All security checks passed!"
