"""
Admin UI Helper Functions — DOGFOOD SCIM Mode Support

This module provides helpers for the admin UI routes to either:
1. Call provisioning_service directly (default)
2. Call the SCIM API via HTTP (DOGFOOD_SCIM=true mode)
"""

import os
import requests
from flask import session
from app.core import provisioning_service
from app.core.provisioning_service import ScimError

# Configuration
DOGFOOD_SCIM = os.environ.get("DOGFOOD_SCIM", "false").lower() == "true"
APP_BASE_URL = os.environ.get("APP_BASE_URL", "https://localhost")
SCIM_API_URL = f"{APP_BASE_URL}/scim/v2"
REQUEST_TIMEOUT = 30  # seconds


def get_service_token_for_ui() -> str:
    """Get service account token for UI operations."""
    return provisioning_service.get_service_token()


def ui_create_user(username: str, email: str, first_name: str, last_name: str, 
                   role: str, temp_password: str = None, require_totp: bool = True,
                   require_password_update: bool = True) -> tuple[str, str]:
    """Create user via service layer or SCIM API (DOGFOOD mode).
    
    Args:
        username: Username
        email: Email address
        first_name: First name
        last_name: Last name
        role: Role to assign
        temp_password: Optional temp password (auto-generated if None)
        require_totp: Require TOTP enrollment
        require_password_update: Require password update
    
    Returns:
        Tuple of (user_id, temp_password)
    
    Raises:
        ScimError: On validation or creation failure
    """
    if DOGFOOD_SCIM:
        # Call SCIM API via HTTP
        return _dogfood_create_user(username, email, first_name, last_name, role)
    else:
        # Call service layer directly
        payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": username,
            "emails": [{"value": email, "primary": True}],
            "name": {
                "givenName": first_name,
                "familyName": last_name
            },
            "active": True,
            "role": role  # Custom extension
        }
        
        result = provisioning_service.create_user_scim_like(payload)
        user_id = result.get("id", "")
        temp_pwd = result.get("_tempPassword", temp_password or "N/A")
        
        return user_id, temp_pwd


def ui_change_role(username: str, source_role: str, target_role: str) -> None:
    """Change user role via service layer or SCIM API (DOGFOOD mode).
    
    Args:
        username: Username to update
        source_role: Current role
        target_role: New role
    
    Raises:
        ScimError: On validation or update failure
    """
    if DOGFOOD_SCIM:
        # Call SCIM API via HTTP
        _dogfood_change_role(username, source_role, target_role)
    else:
        # Call service layer directly
        provisioning_service.change_user_role(username, source_role, target_role)


def ui_disable_user(username: str) -> None:
    """Disable user via service layer or SCIM API (DOGFOOD mode).
    
    Args:
        username: Username to disable
    
    Raises:
        ScimError: On validation or disable failure
    """
    if DOGFOOD_SCIM:
        # Call SCIM API via HTTP
        _dogfood_disable_user(username)
    else:
        # Call service layer directly - need to get user ID first
        from app.core.keycloak import get_user_by_username
        
        # Get service token
        token = provisioning_service.get_service_token()
        
        # Get user by username
        user = get_user_by_username(
            provisioning_service.KEYCLOAK_BASE_URL,
            token,
            provisioning_service.KEYCLOAK_REALM,
            username
        )
        if not user:
            raise ScimError(404, f"User '{username}' not found")
        
        user_id = user.get("id")
        
        # Use PUT with active=false
        payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": username,
            "active": False
        }
        
        provisioning_service.replace_user_scim(user_id, payload)


# ─────────────────────────────────────────────────────────────────────────────
# DOGFOOD Mode — HTTP calls to SCIM API
# ─────────────────────────────────────────────────────────────────────────────

def _get_dogfood_headers() -> dict:
    """Get headers for DOGFOOD SCIM HTTP requests."""
    token = get_service_token_for_ui()
    
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/scim+json",
        "Accept": "application/scim+json",
        "X-Correlation-Id": session.get("correlation_id", "ui-request")
    }


def _dogfood_create_user(username: str, email: str, first_name: str, last_name: str, 
                         role: str) -> tuple[str, str]:
    """Create user via SCIM API HTTP call (DOGFOOD mode)."""
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": username,
        "emails": [{"value": email, "primary": True}],
        "name": {
            "givenName": first_name,
            "familyName": last_name
        },
        "active": True,
        "role": role
    }
    
    try:
        response = requests.post(
            f"{SCIM_API_URL}/Users",
            json=payload,
            headers=_get_dogfood_headers(),
            timeout=REQUEST_TIMEOUT,
            verify=False  # Self-signed certs in dev
        )
        
        if response.status_code == 201:
            result = response.json()
            user_id = result.get("id", "")
            temp_pwd = result.get("_tempPassword", "N/A")
            print(f"[dogfood] Created user via SCIM API: {username}")
            return user_id, temp_pwd
        else:
            error_data = response.json()
            detail = error_data.get("detail", "Unknown error")
            scim_type = error_data.get("scimType")
            raise ScimError(response.status_code, detail, scim_type)
            
    except requests.RequestException as exc:
        raise ScimError(500, f"DOGFOOD SCIM request failed: {exc}")


def _dogfood_change_role(username: str, source_role: str, target_role: str) -> None:
    """Change role via direct service call (SCIM doesn't have role operations)."""
    # SCIM doesn't have standard role operations, so we call service layer directly
    # even in DOGFOOD mode
    provisioning_service.change_user_role(username, source_role, target_role)
    print(f"[dogfood] Changed role via service layer: {username} ({source_role} -> {target_role})")


def _dogfood_disable_user(username: str) -> None:
    """Disable user via SCIM API HTTP call (DOGFOOD mode)."""
    from app.core.keycloak import get_user_by_username
    
    # Get service token
    token = provisioning_service.get_service_token()
    
    # Get user ID first
    user = get_user_by_username(
        provisioning_service.KEYCLOAK_BASE_URL,
        token,
        provisioning_service.KEYCLOAK_REALM,
        username
    )
    if not user:
        raise ScimError(404, f"User '{username}' not found")
    
    user_id = user.get("id")
    
    # PUT with active=false
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": username,
        "active": False
    }
    
    try:
        response = requests.put(
            f"{SCIM_API_URL}/Users/{user_id}",
            json=payload,
            headers=_get_dogfood_headers(),
            timeout=REQUEST_TIMEOUT,
            verify=False
        )
        
        if response.status_code == 200:
            print(f"[dogfood] Disabled user via SCIM API: {username}")
            return
        else:
            error_data = response.json()
            detail = error_data.get("detail", "Unknown error")
            scim_type = error_data.get("scimType")
            raise ScimError(response.status_code, detail, scim_type)
            
    except requests.RequestException as exc:
        raise ScimError(500, f"DOGFOOD SCIM request failed: {exc}")
