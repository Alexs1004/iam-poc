"""Authentication routes and OIDC helpers.

Multi-IdP Support:
- Default provider: OIDC_PROVIDER env var (keycloak|entra)
- Runtime override: GET /login?provider=keycloak|entra (dev/demo only)
- Claim normalization: realm_access.roles (Keycloak) → roles, roles (Entra) → roles
"""
from __future__ import annotations
import hashlib
import base64
import os
import secrets
import string
from urllib.parse import urlencode

from flask import Blueprint, session, redirect, url_for, request, current_app
from authlib.integrations.flask_client import OAuth

bp = Blueprint("auth", __name__)

# Module-level OAuth instance (will be initialized by create_app)
oauth: OAuth = None
_providers: dict = {}  # Registered OIDC providers

# Supported providers
SUPPORTED_PROVIDERS = {"keycloak", "entra"}


def init_oauth(app, cfg):
    """Initialize OAuth client with multi-IdP support."""
    global oauth, _providers
    
    oauth = OAuth(app)
    _providers = {}
    
    # Register Keycloak (always available)
    _providers["keycloak"] = oauth.register(
        name="keycloak",
        server_metadata_url=f"{cfg.keycloak_server_url}/.well-known/openid-configuration",
        client_id=cfg.oidc_client_id,
        client_secret=cfg.oidc_client_secret or None,
        client_kwargs={"scope": "openid profile email roles"},
        fetch_token=lambda: session.get("token"),
    )
    
    # Register Entra ID (if configured)
    entra_issuer = os.environ.get("ENTRA_ISSUER")
    entra_client_id = os.environ.get("ENTRA_CLIENT_ID")
    if entra_issuer and entra_client_id:
        entra_client_secret = os.environ.get("ENTRA_CLIENT_SECRET") or None
        _providers["entra"] = oauth.register(
            name="entra",
            server_metadata_url=f"{entra_issuer}/.well-known/openid-configuration",
            client_id=entra_client_id,
            client_secret=entra_client_secret,
            # response_mode=query required for authorization code flow with Entra ID
            # Without it, Entra may try form_post which causes AADSTS900561
            client_kwargs={
                "scope": "openid profile email",
                "response_mode": "query",
            },
            fetch_token=lambda: session.get("token"),
        )
    
    return oauth, _providers


def get_current_provider() -> str:
    """Get current OIDC provider name from session or env default."""
    # Session override (set via /login?provider=)
    session_provider = session.get("oidc_provider")
    if session_provider and session_provider in _providers:
        return session_provider
    
    # Environment default
    default_provider = os.environ.get("OIDC_PROVIDER", "keycloak").lower()
    if default_provider in _providers:
        return default_provider
    
    return "keycloak"


def get_oidc_client(provider: str = None):
    """Get the OIDC client instance for specified or current provider."""
    if not _providers:
        raise RuntimeError("OIDC providers not initialized. Call init_oauth first.")
    
    provider = provider or get_current_provider()
    client = _providers.get(provider)
    
    if client is None:
        # Fallback to keycloak if requested provider not available
        client = _providers.get("keycloak")
    
    if client is None:
        raise RuntimeError(f"No OIDC provider available (requested: {provider})")
    
    return client


def normalize_claims(id_claims: dict, userinfo: dict, access_claims: dict, provider: str) -> list[str]:
    """
    Normalize roles from different IdP claim formats to unified list.
    
    Keycloak: realm_access.roles, resource_access.*.roles
    Entra ID: roles (top-level array), groups (mapped to app roles)
    
    Entra ID Group → App Role Mapping:
    - IAM-Operators → iam-operator
    - Security-Managers → manager
    - Security-Analysts → analyst
    - Administrators → admin (equivalent to realm-admin)
    """
    roles = []
    
    # Entra ID group name/ID → app role mapping
    # Groups can appear as names or GUIDs in the token depending on config
    ENTRA_GROUP_TO_ROLE = {
        # By name (lowercase)
        "iam-operators": "iam-operator",
        "security-managers": "manager",
        "security-analysts": "analyst",
        "administrators": "admin",  # Equivalent to realm-admin
        # By GUID (for when groupMembershipClaims returns IDs)
        "5f3494a3-1246-4df1-b754-535ee1d017ae": "iam-operator",  # IAM-Operators
        "1bd4a7d1-e1bf-4d18-96af-159728b6fa6d": "manager",        # Security-Managers
        "bbbd2841-f1e1-42f3-b142-7c206b7949ee": "analyst",        # Security-Analysts
        "2c9c17ee-e8ec-4d24-bb42-7d1d343a9d88": "admin",          # Administrators
    }
    
    # Collect from all sources
    for source in (id_claims, userinfo, access_claims):
        if not isinstance(source, dict):
            continue
        
        # Keycloak: realm_access.roles
        realm_access = source.get("realm_access")
        if isinstance(realm_access, dict):
            roles.extend(r for r in realm_access.get("roles", []) if r not in roles)
        
        # Keycloak: resource_access.*.roles
        resource_access = source.get("resource_access")
        if isinstance(resource_access, dict):
            for client_access in resource_access.values():
                if isinstance(client_access, dict):
                    roles.extend(r for r in client_access.get("roles", []) if r not in roles)
        
        # Entra ID: roles (top-level App Roles)
        entra_roles = source.get("roles")
        if isinstance(entra_roles, list):
            roles.extend(r for r in entra_roles if r not in roles)
        
        # Entra ID: groups claim (if configured in App Registration)
        # Map group names/IDs to app roles
        groups = source.get("groups")
        if isinstance(groups, list) and provider == "entra":
            for group in groups:
                group_lower = str(group).lower()
                mapped_role = ENTRA_GROUP_TO_ROLE.get(group_lower)
                if mapped_role and mapped_role not in roles:
                    roles.append(mapped_role)
    
    return roles


def _is_provider_override_allowed() -> bool:
    """Check if ?provider= query param override is allowed (dev/demo only)."""
    # Allow in demo mode
    if os.environ.get("DEMO_MODE", "false").lower() == "true":
        return True
    # Allow in debug mode
    if os.environ.get("FLASK_DEBUG", "false").lower() in ("true", "1"):
        return True
    # Allow in development environment
    if os.environ.get("FLASK_ENV", "").lower() == "development":
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# PKCE Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _generate_code_verifier(length: int = 64) -> str:
    """Generate PKCE code verifier."""
    alphabet = string.ascii_letters + string.digits + "-._~"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _build_code_challenge(code_verifier: str) -> str:
    """Build PKCE code challenge from verifier."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────
@bp.route("/login")
def login():
    """Initiate OIDC login flow with PKCE.
    
    Query params:
        provider: Override IdP (keycloak|entra) - only in dev/demo mode
    """
    cfg = current_app.config["APP_CONFIG"]
    
    # Handle provider override (dev/demo only)
    requested_provider = request.args.get("provider", "").lower()
    if requested_provider and requested_provider in SUPPORTED_PROVIDERS:
        if _is_provider_override_allowed():
            session["oidc_provider"] = requested_provider
        else:
            current_app.logger.warning(
                f"Provider override rejected (production mode): {requested_provider}"
            )
    
    provider = get_current_provider()
    client = get_oidc_client(provider)
    
    # Store provider in session for callback
    session["oidc_provider"] = provider
    
    code_verifier = _generate_code_verifier()
    session["pkce_code_verifier"] = code_verifier
    code_challenge = _build_code_challenge(code_verifier)
    
    # Determine redirect URI based on provider
    redirect_uri = cfg.oidc_redirect_uri
    if provider == "entra":
        entra_redirect_uri = os.environ.get("ENTRA_REDIRECT_URI")
        if entra_redirect_uri:
            redirect_uri = entra_redirect_uri
    
    # Build authorization parameters
    auth_params = {
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    
    # Force account selection for Entra ID (prevents SSO auto-login)
    if provider == "entra":
        auth_params["prompt"] = "select_account"
    
    return client.authorize_redirect(**auth_params)


@bp.route("/callback")
def callback():
    """Handle OIDC callback after successful authentication."""
    cfg = current_app.config["APP_CONFIG"]
    provider = get_current_provider()
    client = get_oidc_client(provider)
    
    code_verifier = session.pop("pkce_code_verifier", None)
    if not code_verifier:
        return redirect(url_for("auth.login"))
    
    token = client.authorize_access_token(code_verifier=code_verifier)
    session["token"] = token
    
    try:
        session["id_claims"] = client.parse_id_token(token)
    except Exception:
        session["id_claims"] = {}
    
    # Store ID token claims for MFA guard
    session["id_token_claims"] = session.get("id_claims", {})
    
    # Fetch userinfo
    try:
        if provider == "entra":
            # Entra uses Microsoft Graph for userinfo
            userinfo_url = "https://graph.microsoft.com/oidc/userinfo"
        else:
            userinfo_url = f"{cfg.keycloak_server_url}/protocol/openid-connect/userinfo"
        session["userinfo"] = client.get(userinfo_url, token=token).json()
    except Exception:
        session["userinfo"] = {}
    
    # Normalize roles from provider-specific claims
    from app.core.rbac import decode_access_token, has_admin_role
    
    id_claims = session.get("id_claims") or {}
    userinfo = session.get("userinfo") or {}
    access_token = token.get("access_token")
    
    # Decode JWT access token
    issuer = cfg.keycloak_issuer if provider == "keycloak" else os.environ.get("ENTRA_ISSUER", "")
    access_claims = decode_access_token(access_token, issuer)
    
    # Debug logging for Entra ID claims
    if provider == "entra":
        current_app.logger.info(f"[Entra] id_claims groups: {id_claims.get('groups')}")
        current_app.logger.info(f"[Entra] id_claims roles: {id_claims.get('roles')}")
        current_app.logger.info(f"[Entra] userinfo groups: {userinfo.get('groups')}")
        current_app.logger.info(f"[Entra] access_claims groups: {access_claims.get('groups')}")
    
    # Normalize roles to unified format
    roles = normalize_claims(id_claims, userinfo, access_claims, provider)
    session["normalized_roles"] = roles
    
    current_app.logger.info(f"[Auth] Provider: {provider}, Normalized roles: {roles}")
    
    if has_admin_role(roles, cfg.realm_admin_role, cfg.iam_operator_role):
        return redirect(url_for("admin.admin_dashboard"))
    else:
        return redirect(url_for("admin.me"))


@bp.route("/logout", methods=["GET", "POST"])
def logout():
    """Logout user with provider-specific redirect."""
    cfg = current_app.config["APP_CONFIG"]
    provider = get_current_provider()
    
    token = session.get("token") or {}
    id_token = token.get("id_token")
    
    # Check if we should re-authenticate after logout
    reauth = request.args.get("reauth", "0") == "1"
    
    # Store reauth intent in a cookie before clearing session
    from flask import make_response
    session.clear()
    
    # Provider-specific logout endpoints
    if provider == "entra":
        entra_issuer = os.environ.get("ENTRA_ISSUER", "")
        entra_post_logout = os.environ.get("ENTRA_POST_LOGOUT_REDIRECT_URI", cfg.post_logout_redirect_uri)
        # ENTRA_ISSUER ends with /v2.0, but logout endpoint is /oauth2/v2.0/logout
        # We need to strip /v2.0 to avoid duplication
        base_url = entra_issuer.rstrip("/").removesuffix("/v2.0")
        end_session_endpoint = f"{base_url}/oauth2/v2.0/logout"
        params = {"post_logout_redirect_uri": entra_post_logout}
    else:
        # Keycloak logout endpoint
        end_session_endpoint = f"{cfg.keycloak_public_issuer.rstrip('/')}/protocol/openid-connect/logout"
        params = {"post_logout_redirect_uri": cfg.post_logout_redirect_uri}
        if id_token:
            params["id_token_hint"] = id_token
        else:
            params["client_id"] = cfg.oidc_client_id
    
    logout_url = f"{end_session_endpoint}?{urlencode(params)}"
    
    # If reauth requested, set a temporary cookie to trigger login on home page
    if reauth:
        response = make_response(redirect(logout_url))
        response.set_cookie("reauth_requested", "1", max_age=30, httponly=True, secure=True, samesite="Strict")
        return response
    
    return redirect(logout_url)


@bp.route("/")
def index():
    """Home page."""
    from flask import render_template, make_response
    from app.core.rbac import is_authenticated, current_user_context, has_admin_role
    from app.config.settings import settings
    
    # Check if reauth was requested (via cookie set during logout)
    reauth_requested = request.cookies.get("reauth_requested") == "1"
    if reauth_requested and not is_authenticated():
        # Clear the cookie and redirect to login
        response = make_response(redirect(url_for("auth.login")))
        response.set_cookie("reauth_requested", "", max_age=0)
        return response
    
    is_admin = False
    if is_authenticated():
        try:
            _, _, _, roles = current_user_context()
            is_admin = has_admin_role(roles, settings.realm_admin_role, settings.iam_operator_role)
        except Exception:
            pass
    
    return render_template(
        "index.html",
        title="Welcome",
        is_authenticated=is_authenticated(),
        is_admin=is_admin,
        demo_mode=settings.demo_mode,
    )
