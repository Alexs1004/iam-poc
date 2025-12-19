"""Settings loader with environment variable and Docker secrets integration."""
from __future__ import annotations
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


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
    
    # SCIM Static Token (optional, for Entra ID provisioning demo/dev)
    scim_static_token: str = ""
    scim_static_token_source: str = ""  # "keyvault" or empty (env var)
    
    # Verification page
    verify_page_enabled: bool = field(default=False)
    
    # Demo passwords (for reference)
    demo_passwords: dict[str, str] = field(default_factory=dict)
    
    @property
    def service_client_secret_resolved(self) -> str:
        """Get Keycloak service account client secret with smart fallback.
        
        Priority:
        1. Demo mode: hardcoded "demo-service-secret"
        2. Configured value in keycloak_service_client_secret
        3. Docker secrets: /run/secrets/keycloak-service-client-secret
        4. Environment variable: KEYCLOAK_SERVICE_CLIENT_SECRET
        
        Returns:
            Client secret string
            
        Raises:
            ValueError: If secret not found in production mode
        """
        # Priority 1: Demo mode always uses hardcoded secret
        if self.demo_mode:
            return "demo-service-secret"
        
        # Priority 2: Already configured value
        if self.keycloak_service_client_secret:
            return self.keycloak_service_client_secret
        
        # Priority 3: Try Docker secrets (both naming conventions)
        for secret_name in ["keycloak_service_client_secret", "keycloak-service-client-secret"]:
            secret_path = Path("/run/secrets") / secret_name
            if secret_path.exists():
                secret = secret_path.read_text().strip()
                if secret:
                    return secret
        
        # Priority 4: Environment variable
        secret = os.environ.get("KEYCLOAK_SERVICE_CLIENT_SECRET")
        if secret:
            return secret
        
        raise ValueError(
            "KEYCLOAK_SERVICE_CLIENT_SECRET not found. "
            "Set DEMO_MODE=true or provide secret via Docker secrets or environment variable."
        )


def _enforce_demo_mode_consistency() -> None:
    """Enforce DEMO_MODE consistency: Demo mode must never use Azure Key Vault.
    
    This is a safety guard; normally validate_env.sh should correct .env before Docker starts.
    """
    demo_mode = os.environ.get("DEMO_MODE", "false").lower() == "true"
    if demo_mode and os.environ.get("AZURE_USE_KEYVAULT", "false").lower() == "true":
        print("[settings] WARNING: DEMO_MODE=true requires AZURE_USE_KEYVAULT=false (runtime guard)")
        print("[settings] Forcing AZURE_USE_KEYVAULT=false | Run 'make validate-env' to fix .env permanently")
        os.environ["AZURE_USE_KEYVAULT"] = "false"


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
            # In production with Key Vault, secrets MUST be pre-loaded via make load-secrets
            # and mounted as /run/secrets. DO NOT call Azure Key Vault from container.
            raise RuntimeError(
                "FLASK_SECRET_KEY not found in /run/secrets. "
                "Run 'make quickstart' on the host (loads secrets and restarts services)."
            )
        
        if not secret_key:
            raise RuntimeError("FLASK_SECRET_KEY not found in /run/secrets or environment")
    
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
    
    # SCIM Static Token (optional, for Entra ID provisioning)
    scim_static_token_source = os.environ.get("SCIM_STATIC_TOKEN_SOURCE", "").strip().lower()
    scim_static_token = ""
    
    if scim_static_token_source == "keyvault":
        # Load from Azure Key Vault (via /run/secrets if pre-loaded)
        scim_static_token = _load_secret_from_file("scim_static_token", "SCIM_STATIC_TOKEN")
        if scim_static_token:
            print("[settings] ✓ Loaded SCIM static token from Key Vault")
        elif not demo_mode:
            print("[settings] ⚠️ SCIM_STATIC_TOKEN_SOURCE=keyvault but secret not found in /run/secrets")
    else:
        # Load from environment variable (fallback or demo mode)
        scim_static_token = os.environ.get("SCIM_STATIC_TOKEN", "")
        if scim_static_token:
            print(f"[settings] ✓ Loaded SCIM static token from environment (length: {len(scim_static_token)})")
    
    # Store in environment for runtime access
    if scim_static_token:
        os.environ["SCIM_STATIC_TOKEN"] = scim_static_token
    
    # Entra ID client secret (optional, for Multi-IdP)
    entra_client_secret = _load_secret_from_file("entra_client_secret", "ENTRA_CLIENT_SECRET")
    if entra_client_secret:
        os.environ["ENTRA_CLIENT_SECRET"] = entra_client_secret
        print("[settings] ✓ Loaded ENTRA_CLIENT_SECRET from /run/secrets")
    
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
        # Default to localhost in demo mode or test environment
        is_testing = os.environ.get("PYTEST_CURRENT_TEST") is not None
        if demo_mode or is_testing:
            trusted_proxy_ips = "127.0.0.1/32,::1/128"
            os.environ["TRUSTED_PROXY_IPS"] = trusted_proxy_ips
            if demo_mode:
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
    
    # SCIM Static Token
    scim_static_token = os.environ.get("SCIM_STATIC_TOKEN", "")
    scim_static_token_source = os.environ.get("SCIM_STATIC_TOKEN_SOURCE", "")
    
    # Verification page (enabled by default in demo mode, disabled in production)
    verify_page_enabled = os.environ.get("VERIFY_PAGE_ENABLED", str(demo_mode)).lower() == "true"
    
    # Demo passwords
    demo_passwords = {}
    if demo_mode:
        for user in ["ALICE", "BOB", "CAROL", "JOE"]:
            demo_passwords[user] = _get_or_generate(
                f"{user}_TEMP_PASSWORD",
                demo_default=(os.environ.get(f"{user}_TEMP_PASSWORD_DEMO") or "Temp123!"),
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
        scim_static_token=scim_static_token,
        scim_static_token_source=scim_static_token_source,
        verify_page_enabled=verify_page_enabled,
        demo_passwords=demo_passwords,
    )


# Global settings instance (loaded lazily on first import)
settings: AppConfig = load_settings()
