"""Role-Based Access Control helpers."""
from __future__ import annotations
import time
from typing import Optional

from flask import session, current_app
from authlib.jose import JsonWebKey, jwt
import requests


# JWKS Cache
_JWKS_CACHE: Optional[JsonWebKey] = None


def collect_roles(*sources) -> list[str]:
    """Collect all roles from ID claims, userinfo, and access token claims."""
    roles = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        realm_access = source.get("realm_access")
        if isinstance(realm_access, dict):
            roles.extend(r for r in realm_access.get("roles", []) if r not in roles)
        resource_access = source.get("resource_access")
        if isinstance(resource_access, dict):
            for client_access in resource_access.values():
                if not isinstance(client_access, dict):
                    continue
                roles.extend(r for r in client_access.get("roles", []) if r not in roles)
    return roles


def decode_access_token(access_token: str, issuer: str) -> dict:
    """Decode and validate access token JWT."""
    global _JWKS_CACHE
    
    if not access_token:
        return {}
    
    try:
        # Load JWKS if not cached
        if _JWKS_CACHE is None:
            from app.api.auth import get_oidc_client
            client = get_oidc_client()
            metadata = client.load_server_metadata()
            jwks_uri = metadata.get("jwks_uri")
            if not jwks_uri:
                raise RuntimeError("jwks_uri missing from Keycloak metadata")
            resp = requests.get(jwks_uri, timeout=5)
            resp.raise_for_status()
            _JWKS_CACHE = JsonWebKey.import_key_set(resp.json())
        
        claims = jwt.decode(
            access_token,
            key=_JWKS_CACHE,
            claims_options={"iss": {"values": [issuer]}},
        )
        claims.validate()
        return dict(claims)
    except Exception:
        return {}


def has_admin_role(roles: list[str], realm_admin_role: str, iam_operator_role: str) -> bool:
    """Check if user has admin-level role."""
    admin_roles = {"admin", realm_admin_role.lower(), iam_operator_role.lower()}
    roles_lower = [role.lower() for role in roles]
    return any(role in admin_roles for role in roles_lower)


def is_authenticated() -> bool:
    """Check if user is authenticated."""
    return bool(session.get("token"))


def user_has_role(role: str) -> bool:
    """Check if current user has specific role."""
    if not is_authenticated():
        return False
    
    _, _, _, roles = current_user_context()
    return role.lower() in [r.lower() for r in roles]


def current_username() -> str:
    """Get current user's username."""
    _, id_claims, userinfo, _ = current_user_context()
    for source in (userinfo or {}, id_claims or {}):
        if not isinstance(source, dict):
            continue
        for key in ("preferred_username", "email", "name"):
            value = source.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def current_user_context() -> tuple[Optional[dict], dict, dict, list[str]]:
    """Get current user's token, claims, userinfo, and roles."""
    cfg = current_app.config["APP_CONFIG"]
    from app.api.auth import get_oidc_client
    
    token = session.get("token")
    if not token:
        return None, {}, {}, []
    
    userinfo = session.get("userinfo")
    if not userinfo:
        client = get_oidc_client()
        userinfo_url = f"{cfg.keycloak_server_url}/protocol/openid-connect/userinfo"
        userinfo = client.get(userinfo_url, token=token).json()
        session["userinfo"] = userinfo
    
    id_claims = session.get("id_claims") or {}
    access_claims = decode_access_token(token.get("access_token"), cfg.keycloak_issuer)
    roles = collect_roles(id_claims, userinfo, access_claims)
    
    return token, id_claims, userinfo, roles


def refresh_session_token() -> Optional[bool]:
    """Refresh user's session token if needed.
    
    Returns:
        None if no token or not expired
        True if refresh successful
        False if refresh failed
    """
    cfg = current_app.config["APP_CONFIG"]
    from app.api.auth import get_oidc_client
    
    token = session.get("token") or {}
    if not token:
        return None
    
    now = time.time()
    expires_at = token.get("expires_at")
    
    if expires_at is None:
        expires_in = token.get("expires_in")
        if expires_in is not None:
            try:
                expires_at = now + int(expires_in)
                token["expires_at"] = expires_at
                session["token"] = token
            except (TypeError, ValueError):
                pass
    
    if expires_at is None:
        return None
    
    # Check if token needs refresh (60s leeway)
    token_refresh_leeway = int(current_app.config.get("OIDC_TOKEN_REFRESH_LEEWAY", 60))
    if expires_at - token_refresh_leeway > now:
        return None
    
    refresh_token = token.get("refresh_token")
    if not refresh_token:
        current_app.logger.warning("Session access token expired without refresh token; clearing session.")
        clear_session_tokens()
        return False
    
    try:
        client = get_oidc_client()
        token_endpoint = f"{cfg.keycloak_server_url}/protocol/openid-connect/token"
        
        # Use requests directly for refresh_token grant (Authlib FlaskOAuth2App limitation)
        import requests
        response = requests.post(
            token_endpoint,
            data={
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': cfg.oidc_client_id,
                'client_secret': cfg.oidc_client_secret
            },
            timeout=10
        )
        response.raise_for_status()
        new_token = response.json()
    except Exception as exc:
        current_app.logger.warning("Token refresh failed: %s", exc, exc_info=False)
        clear_session_tokens()
        return False
    
    if not new_token:
        clear_session_tokens()
        return False
    
    if "refresh_token" not in new_token:
        new_token["refresh_token"] = refresh_token
    
    expires_in = new_token.get("expires_in")
    if expires_in is not None:
        try:
            new_token["expires_at"] = time.time() + int(expires_in)
        except (TypeError, ValueError):
            new_token.pop("expires_at", None)
    elif "expires_at" not in new_token and expires_at is not None:
        new_token["expires_at"] = expires_at
    
    session["token"] = new_token
    
    try:
        client = get_oidc_client()
        session["id_claims"] = client.parse_id_token(new_token)
    except Exception:
        session.pop("id_claims", None)
    
    session.pop("userinfo", None)
    return True


def clear_session_tokens() -> None:
    """Clear all session tokens."""
    session.pop("token", None)
    session.pop("userinfo", None)
    session.pop("id_claims", None)


def filter_display_roles(roles: list[str], realm: str) -> list[str]:
    """Filter out internal/default roles from display."""
    default_role_name = f"default-roles-{realm.lower()}" if realm else ""
    hidden = {default_role_name} if default_role_name else set()
    return [role for role in roles if role.lower() not in hidden]


def requires_operator_for_roles(roles: list[str], realm_admin_role: str, iam_operator_role: str) -> bool:
    """Check if any role requires operator privileges."""
    sensitive_roles = {realm_admin_role.lower(), iam_operator_role.lower()}
    return any(role and role.lower() in sensitive_roles for role in roles)
