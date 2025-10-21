"""Gunicorn configuration file with post-fork hook for Azure Key Vault secrets."""
import os


def post_fork(server, worker):
    """
    Called just after a worker has been forked.
    Load secrets from Azure Key Vault in each worker process.
    """
    # Enforce DEMO_MODE consistency: Demo mode must never use Azure Key Vault
    # This is a safety guard; normally validate_env.sh should correct .env before Docker starts
    demo_mode = os.environ.get("DEMO_MODE", "false").lower() == "true"
    if demo_mode and os.environ.get("AZURE_USE_KEYVAULT", "false").lower() == "true":
        worker.log.warning("DEMO_MODE=true requires AZURE_USE_KEYVAULT=false (runtime guard)")
        worker.log.info("Forcing AZURE_USE_KEYVAULT=false | Run 'make validate-env' to fix .env permanently")
        os.environ["AZURE_USE_KEYVAULT"] = "false"
    
    use_kv = os.environ.get("AZURE_USE_KEYVAULT", "false").lower() == "true"
    if not use_kv:
        worker.log.info("Skipping Azure Key Vault (AZURE_USE_KEYVAULT=false)")
        return
    
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
    except ImportError:
        worker.log.error("Azure Key Vault requested but azure-keyvault-secrets not installed")
        return
    
    vault_name = os.environ.get("AZURE_KEY_VAULT_NAME")
    if not vault_name:
        worker.log.error("AZURE_KEY_VAULT_NAME required when AZURE_USE_KEYVAULT=true")
        return
    
    vault_uri = f"https://{vault_name}.vault.azure.net"
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=vault_uri, credential=credential)
    
    # Map environment variables to Key Vault secret names
    secret_mapping = {
        "FLASK_SECRET_KEY": os.environ.get("AZURE_SECRET_FLASK_SECRET_KEY", "flask-secret-key"),
        "KEYCLOAK_SERVICE_CLIENT_SECRET": os.environ.get(
            "AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET", "keycloak-service-client-secret"
        ),
        "KEYCLOAK_ADMIN_PASSWORD": os.environ.get("AZURE_SECRET_KEYCLOAK_ADMIN_PASSWORD", "keycloak-admin-password"),
        "ALICE_TEMP_PASSWORD": os.environ.get("AZURE_SECRET_ALICE_TEMP_PASSWORD", "alice-temp-password"),
        "BOB_TEMP_PASSWORD": os.environ.get("AZURE_SECRET_BOB_TEMP_PASSWORD", "bob-temp-password"),
        "CAROL_TEMP_PASSWORD": os.environ.get("AZURE_SECRET_CAROL_TEMP_PASSWORD", "carol-temp-password"),
        "AUDIT_LOG_SIGNING_KEY": os.environ.get("AZURE_SECRET_AUDIT_LOG_SIGNING_KEY", "audit-log-signing-key"),
    }
    
    for env_name, secret_name in secret_mapping.items():
        if os.environ.get(env_name):  # Skip if already set
            continue
        secret_name = secret_name.strip()
        if not secret_name:
            continue
        try:
            secret = secret_client.get_secret(secret_name)
            os.environ[env_name] = secret.value
            worker.log.info(f"Loaded secret '{secret_name}' into {env_name}")
        except Exception as exc:
            worker.log.error(f"Failed to load secret '{secret_name}': {exc}")
    
    worker.log.info("Azure Key Vault secrets loaded successfully")
