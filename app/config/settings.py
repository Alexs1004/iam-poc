"""Settings loader with environment variable and Azure Key Vault integration."""
from __future__ import annotations
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Azure imports (optional)
try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
    from azure.keyvault.keys import KeyClient
    from azure.core.exceptions import ResourceNotFoundError
    AZURE_AVAILABLE = True
except ImportError:
    DefaultAzureCredential = None
    SecretClient = None
    KeyClient = None
    ResourceNotFoundError = Exception
    AZURE_AVAILABLE = False


def _load_secret_from_file(secret_name: str, env_var: str | None = None) -> str | None:
    """
    Load secret from /run/secrets (Docker secrets pattern).
    
    Priority:
    1. /run/secrets/{secret_name} (Docker secrets mount)
    2. Environment variable (fallback)
    
    Args:
        secret_name: Name of the secret file in /run/secrets
        env_var: Optional environment variable name to check as fallback
    
    Returns:
        Secret value or None if not found
    """
    secret_file = Path("/run/secrets") / secret_name
    
    # Priority 1: Read from /run/secrets
    if secret_file.exists() and secret_file.is_file():
        try:
            secret_value = secret_file.read_text().strip()
            if secret_value:
                print(f"[settings] ✓ Loaded {secret_name} from /run/secrets")
                return secret_value
        except Exception as e:
            print(f"[settings] ✗ Failed to read /run/secrets/{secret_name}: {e}")
    
    # Priority 2: Fallback to environment variable
    if env_var:
        secret_value = os.getenv(env_var)
        if secret_value:
            print(f"[settings] ✓ Loaded {env_var} from environment (fallback)")
            return secret_value
    
    return None


@dataclass
class AppConfig:
    """Application configuration container."""
    # Mode
    demo_mode: bool
    azure_use_keyvault: bool
    
    # Flask
    secret_key: str
    secret_key_fallbacks: list[str] = field(default_factory=list)
    session_cookie_secure: bool = True
    trusted_proxy_ips: str = "127.0.0.1/32,::1/128"
    
    # Keycloak/OIDC
    keycloak_url: str = ""
    keycloak_realm: str = "demo"
    keycloak_service_realm: str = "demo"
    keycloak_issuer: str = ""
    keycloak_server_url: str = ""
    keycloak_public_issuer: str = ""
    
    # OIDC Client
    oidc_client_id: str = "flask-app"
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""
    post_logout_redirect_uri: str = ""
    
    # Service Account
    keycloak_service_client_id: str = "automation-cli"
    keycloak_service_client_secret: str = ""
    
    # Admin credentials
    keycloak_admin: str = "admin"
    keycloak_admin_password: str = "admin"
    
    # Roles
    realm_admin_role: str = "realm-admin"
    iam_operator_role: str = "iam-operator"
    assignable_roles: list[str] = field(default_factory=lambda: ["analyst", "manager"])
    
    # Audit
    audit_log_signing_key: str = ""
    
    # Demo passwords (for reference)
    demo_passwords: dict[str, str] = field(default_factory=dict)


def _enforce_demo_mode_consistency() -> None:
    """Enforce DEMO_MODE consistency: Demo mode must never use Azure Key Vault.
    
    This is a safety guard; normally validate_env.sh should correct .env before Docker starts.
    """
    demo_mode = os.environ.get("DEMO_MODE", "false").lower() == "true"
    if demo_mode and os.environ.get("AZURE_USE_KEYVAULT", "false").lower() == "true":
        print("[settings] WARNING: DEMO_MODE=true requires AZURE_USE_KEYVAULT=false (runtime guard)")
        print("[settings] Forcing AZURE_USE_KEYVAULT=false | Run 'make validate-env' to fix .env permanently")
        os.environ["AZURE_USE_KEYVAULT"] = "false"


def _load_secrets_from_azure() -> None:
    """Load secrets from Azure Key Vault if enabled."""
    use_kv = os.environ.get("AZURE_USE_KEYVAULT", "false").lower() == "true"
    print(f"[settings._load_secrets_from_azure] AZURE_USE_KEYVAULT={os.environ.get('AZURE_USE_KEYVAULT')}, use_kv={use_kv}")
    
    if not use_kv:
        print("[settings._load_secrets_from_azure] Skipping Key Vault (AZURE_USE_KEYVAULT=false)")
        return
    
    if not AZURE_AVAILABLE:
        raise RuntimeError("Azure Key Vault integration requested but azure-keyvault-secrets is not installed.")
    
    vault_name = os.environ.get("AZURE_KEY_VAULT_NAME")
    if not vault_name:
        raise RuntimeError("AZURE_KEY_VAULT_NAME is required when AZURE_USE_KEYVAULT=true.")
    
    vault_uri = f"https://{vault_name}.vault.azure.net"
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=vault_uri, credential=credential)
    
    secret_mapping = {
        "FLASK_SECRET_KEY": os.environ.get("AZURE_SECRET_FLASK_SECRET_KEY", "flask-secret-key"),
        "FLASK_SECRET_KEY_FALLBACKS": os.environ.get("AZURE_SECRET_FLASK_SECRET_KEY_FALLBACKS", ""),
        "KEYCLOAK_SERVICE_CLIENT_SECRET": os.environ.get(
            "AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET", "keycloak-service-client-secret"
        ),
        "KEYCLOAK_ADMIN_PASSWORD": os.environ.get("AZURE_SECRET_KEYCLOAK_ADMIN_PASSWORD", "keycloak-admin-password"),
        "ALICE_TEMP_PASSWORD": os.environ.get("AZURE_SECRET_ALICE_TEMP_PASSWORD", "alice-temp-password"),
        "BOB_TEMP_PASSWORD": os.environ.get("AZURE_SECRET_BOB_TEMP_PASSWORD", "bob-temp-password"),
        "CAROL_TEMP_PASSWORD": os.environ.get("AZURE_SECRET_CAROL_TEMP_PASSWORD", "carol-temp-password"),
        "JOE_TEMP_PASSWORD": os.environ.get("AZURE_SECRET_JOE_TEMP_PASSWORD", "joe-temp-password"),
        "AUDIT_LOG_SIGNING_KEY": os.environ.get("AZURE_SECRET_AUDIT_LOG_SIGNING_KEY", "audit-log-signing-key"),
    }
    
    key_mapping = {
        "FLASK_SECRET_KEY": os.environ.get("AZURE_KEY_FLASK_SECRET_KEY", "").strip(),
    }
    
    # Load keys if configured
    key_client = None
    if any(value for value in key_mapping.values()):
        if KeyClient is None:
            raise RuntimeError("AZURE_KEY_* variables defined but azure-keyvault-keys is not installed.")
        key_client = KeyClient(vault_url=vault_uri, credential=credential)
    
    if key_client:
        for env_name, key_name in key_mapping.items():
            if os.environ.get(env_name):
                continue
            key_name = key_name.strip()
            if not key_name:
                continue
            try:
                import base64
                key_bundle = key_client.get_key(key_name)
                key_material = getattr(key_bundle, "key", None)
                key_value = getattr(key_material, "k", None) if key_material else None
                if not key_value:
                    continue
                padding = "=" * (-len(key_value) % 4)
                decoded = base64.urlsafe_b64decode(f"{key_value}{padding}".encode("ascii"))
                os.environ[env_name] = base64.urlsafe_b64encode(decoded).decode("ascii")
            except ResourceNotFoundError:
                continue
            except Exception as exc:
                raise RuntimeError(f"Failed to retrieve key '{key_name}' from Key Vault: {exc}") from exc
    
    # Load secrets
    for env_name, secret_name in secret_mapping.items():
        if os.environ.get(env_name):
            continue
        secret_name = secret_name.strip()
        if not secret_name:
            continue
        try:
            secret = secret_client.get_secret(secret_name)
            os.environ[env_name] = secret.value
        except Exception as exc:
            raise RuntimeError(f"Failed to retrieve secret '{secret_name}' from Key Vault: {exc}") from exc


def _get_or_generate(var_name: str, demo_default: Optional[str] = None, required: bool = True, demo_mode: bool = False) -> str:
    """Get environment variable or use demo default/generate."""
    value = os.environ.get(var_name)
    if value:
        return value
    
    if demo_mode and demo_default is not None:
        print(f"[demo-mode] Using default for {var_name}")
        os.environ[var_name] = demo_default
        return demo_default
    
    if not required:
        return ""
    
    raise RuntimeError(f"Environment variable {var_name} is required in production mode.")


def load_settings() -> AppConfig:
    """Load application settings from environment, /run/secrets, and Azure Key Vault."""
    # Enforce DEMO_MODE consistency first
    _enforce_demo_mode_consistency()
    
    # Determine mode
    demo_mode = os.environ.get("DEMO_MODE", "false").lower() == "true"
    azure_use_keyvault = os.environ.get("AZURE_USE_KEYVAULT", "false").lower() == "true"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Load secrets from /run/secrets (Docker secrets pattern)
    # Priority: /run/secrets > Azure Key Vault > environment variables
    # ─────────────────────────────────────────────────────────────────────────
    
    # Flask secret key
    secret_key = _load_secret_from_file("flask_secret_key", "FLASK_SECRET_KEY")
    if not secret_key:
        if demo_mode:
            secret_key = secrets.token_urlsafe(48)
            os.environ["FLASK_SECRET_KEY"] = secret_key
            print("[demo-mode] Generated temporary FLASK_SECRET_KEY")
        elif azure_use_keyvault:
            # Fallback to Azure Key Vault (legacy support)
            _load_secrets_from_azure()
            secret_key = os.environ.get("FLASK_SECRET_KEY")
        
        if not secret_key:
            raise RuntimeError("FLASK_SECRET_KEY not found in /run/secrets, Azure Key Vault, or environment")
    
    # Keycloak service client secret
    keycloak_service_client_secret = _load_secret_from_file(
        "keycloak_service_client_secret", 
        "KEYCLOAK_SERVICE_CLIENT_SECRET"
    )
    if keycloak_service_client_secret:
        os.environ["KEYCLOAK_SERVICE_CLIENT_SECRET"] = keycloak_service_client_secret
    
    # Keycloak admin password
    keycloak_admin_password = _load_secret_from_file(
        "keycloak_admin_password",
        "KEYCLOAK_ADMIN_PASSWORD"
    )
    if keycloak_admin_password:
        os.environ["KEYCLOAK_ADMIN_PASSWORD"] = keycloak_admin_password
    
    # Audit log signing key
    audit_log_signing_key = _load_secret_from_file(
        "audit_log_signing_key",
        "AUDIT_LOG_SIGNING_KEY"
    )
    if audit_log_signing_key:
        os.environ["AUDIT_LOG_SIGNING_KEY"] = audit_log_signing_key
    elif demo_mode:
        # Use demo default key (must match the key used by scripts/demo_jml.sh)
        demo_key = os.environ.get("AUDIT_LOG_SIGNING_KEY_DEMO", "demo-audit-signing-key-change-in-production")
        os.environ["AUDIT_LOG_SIGNING_KEY"] = demo_key
        print(f"[demo-mode] Using demo AUDIT_LOG_SIGNING_KEY: {demo_key[:20]}...")
    
    # User temporary passwords (optional)
    for user in ["alice", "bob", "carol", "joe"]:
        secret_name = f"{user}_temp_password"
        env_var = f"{user.upper()}_TEMP_PASSWORD"
        temp_password = _load_secret_from_file(secret_name, env_var)
        if temp_password:
            os.environ[env_var] = temp_password
    
    secret_key_fallbacks = [
        key.strip()
        for key in os.environ.get("FLASK_SECRET_KEY_FALLBACKS", "").split(",")
        if key.strip()
    ]
    
    # Session cookie secure flag
    session_secure_str = os.environ.get("FLASK_SESSION_COOKIE_SECURE")
    if session_secure_str is None and demo_mode:
        os.environ["FLASK_SESSION_COOKIE_SECURE"] = "true"
        session_secure_str = "true"
    session_cookie_secure = (session_secure_str or "true").lower() == "true"
    
    # Trusted proxies
    trusted_proxy_ips = os.environ.get("TRUSTED_PROXY_IPS")
    if not trusted_proxy_ips:
        if demo_mode:
            trusted_proxy_ips = "127.0.0.1/32,::1/128"
            os.environ["TRUSTED_PROXY_IPS"] = trusted_proxy_ips
            print("[demo-mode] Defaulted TRUSTED_PROXY_IPS to localhost ranges")
        else:
            raise RuntimeError("TRUSTED_PROXY_IPS is required when DEMO_MODE is false.")
    
    # Keycloak URLs
    keycloak_url = os.environ.get("KEYCLOAK_URL", "http://127.0.0.1:8080" if demo_mode else "")
    keycloak_realm = os.environ.get("KEYCLOAK_REALM", "demo")
    keycloak_service_realm = os.environ.get("KEYCLOAK_SERVICE_REALM", keycloak_realm)
    
    keycloak_issuer = _get_or_generate(
        "KEYCLOAK_ISSUER",
        demo_default="http://localhost:8080/realms/demo" if demo_mode else None,
        demo_mode=demo_mode
    )
    keycloak_server_url = os.environ.get("KEYCLOAK_SERVER_URL", keycloak_issuer)
    keycloak_public_issuer = os.environ.get("KEYCLOAK_PUBLIC_ISSUER", keycloak_issuer)
    
    # OIDC
    oidc_client_id = _get_or_generate("OIDC_CLIENT_ID", demo_default="flask-app", demo_mode=demo_mode)
    oidc_client_secret = os.environ.get("OIDC_CLIENT_SECRET", "")
    oidc_redirect_uri = _get_or_generate(
        "OIDC_REDIRECT_URI",
        demo_default="http://localhost:5000/callback" if demo_mode else None,
        demo_mode=demo_mode
    )
    post_logout_redirect_uri = _get_or_generate(
        "POST_LOGOUT_REDIRECT_URI",
        demo_default="http://localhost:5000/" if demo_mode else None,
        demo_mode=demo_mode
    )
    
    # Service account
    keycloak_service_client_id = _get_or_generate(
        "KEYCLOAK_SERVICE_CLIENT_ID",
        demo_default="automation-cli",
        demo_mode=demo_mode
    )
    keycloak_service_client_secret = _get_or_generate(
        "KEYCLOAK_SERVICE_CLIENT_SECRET",
        demo_default=(os.environ.get("KEYCLOAK_SERVICE_CLIENT_SECRET_DEMO") or "demo-service-secret"),
        demo_mode=demo_mode
    )
    
    # Admin credentials
    keycloak_admin = _get_or_generate(
        "KEYCLOAK_ADMIN",
        demo_default=(os.environ.get("KEYCLOAK_ADMIN_DEMO") or "admin"),
        demo_mode=demo_mode
    )
    keycloak_admin_password = _get_or_generate(
        "KEYCLOAK_ADMIN_PASSWORD",
        demo_default=(os.environ.get("KEYCLOAK_ADMIN_PASSWORD_DEMO") or "admin"),
        demo_mode=demo_mode
    )
    
    # Roles
    realm_admin_role = os.environ.get("REALM_ADMIN_ROLE", "realm-admin").strip().lower()
    iam_operator_role = os.environ.get("IAM_OPERATOR_ROLE", "iam-operator").strip().lower()
    
    default_assignable_roles = ["analyst", "manager"]
    if iam_operator_role and iam_operator_role not in default_assignable_roles:
        default_assignable_roles.append(iam_operator_role)
    
    assignable_roles = [
        role.strip().lower()
        for role in os.environ.get("KEYCLOAK_ASSIGNABLE_ROLES", ",".join(default_assignable_roles)).split(",")
        if role.strip()
    ]
    if not assignable_roles:
        assignable_roles = default_assignable_roles
    
    # Audit
    audit_log_signing_key = os.environ.get("AUDIT_LOG_SIGNING_KEY", "")
    
    # Demo passwords
    demo_passwords = {}
    if demo_mode:
        for user in ["ALICE", "BOB", "CAROL", "JOE"]:
            demo_passwords[user] = _get_or_generate(
                f"{user}_TEMP_PASSWORD",
                demo_default=(os.environ.get(f"{user}_TEMP_PASSWORD_DEMO") or "Passw0rd!"),
                required=False,
                demo_mode=demo_mode
            )
    
    mode_label = "DEMO" if demo_mode else "PRODUCTION"
    print(f"[settings] Mode={mode_label}; realm={keycloak_realm}; client_id={oidc_client_id}")
    
    if demo_mode:
        print("[settings] WARNING: Demo credentials in use. Do not deploy with these defaults.")
    
    return AppConfig(
        demo_mode=demo_mode,
        azure_use_keyvault=azure_use_keyvault,
        secret_key=secret_key,
        secret_key_fallbacks=secret_key_fallbacks,
        session_cookie_secure=session_cookie_secure,
        trusted_proxy_ips=trusted_proxy_ips,
        keycloak_url=keycloak_url,
        keycloak_realm=keycloak_realm,
        keycloak_service_realm=keycloak_service_realm,
        keycloak_issuer=keycloak_issuer,
        keycloak_server_url=keycloak_server_url,
        keycloak_public_issuer=keycloak_public_issuer,
        oidc_client_id=oidc_client_id,
        oidc_client_secret=oidc_client_secret,
        oidc_redirect_uri=oidc_redirect_uri,
        post_logout_redirect_uri=post_logout_redirect_uri,
        keycloak_service_client_id=keycloak_service_client_id,
        keycloak_service_client_secret=keycloak_service_client_secret,
        keycloak_admin=keycloak_admin,
        keycloak_admin_password=keycloak_admin_password,
        realm_admin_role=realm_admin_role,
        iam_operator_role=iam_operator_role,
        assignable_roles=assignable_roles,
        audit_log_signing_key=audit_log_signing_key,
        demo_passwords=demo_passwords,
    )
