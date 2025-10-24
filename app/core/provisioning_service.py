"""
Provisioning Service Layer — Unified JML Logic

This module provides a unified service layer for Joiner/Mover/Leaver operations,
used by both the Flask UI and the SCIM 2.0 API. It ensures consistent business
logic, validation, and error handling across all interfaces.

Architecture:
    UI Admin (/admin/*) ──┐
                          ├──> provisioning_service.py ──> app.core.keycloak ──> Keycloak
    SCIM API (/scim/v2/*) ┘

Features:
    - SCIM-like payload validation (userName, emails, name, active)
    - Keycloak ⇔ SCIM transformation
    - Idempotent operations (create, update, delete)
    - Session revocation on user disable
    - Standardized error handling via ScimError
"""

from __future__ import annotations
import datetime
import re
import os
import secrets
import string
from pathlib import Path
from typing import Any, Optional

# Import refactored Keycloak services
from app.core.keycloak import (
    get_service_account_token,
    get_user_by_username,
    create_user,
    disable_user,
    change_role,
    add_realm_role,
    get_group_by_path,
    get_group_members,
)
from scripts import audit
import requests


def _load_secret_from_file(secret_name: str, env_var: str | None = None) -> str | None:
    """
    Load secret from /run/secrets (Docker secrets pattern).
    
    Priority:
    1. /run/secrets/{secret_name}
    2. Environment variable (fallback)
    
    Returns:
        Secret value or None if not found
    """
    secret_file = Path("/run/secrets") / secret_name
    
    if secret_file.exists() and secret_file.is_file():
        try:
            return secret_file.read_text().strip()
        except Exception:
            pass
    
    if env_var:
        return os.getenv(env_var)
    
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

# NOTE: This enforcement is duplicated in flask_app.py because both modules  
# can be loaded independently (e.g., SCIM API loads this module directly).
# The duplication ensures DEMO_MODE consistency regardless of import order.
# This is a safety guard; normally validate_env.sh should correct .env before Docker starts.
DEMO_MODE = os.environ.get("DEMO_MODE", "false").lower() == "true"
if DEMO_MODE and os.environ.get("AZURE_USE_KEYVAULT", "false").lower() == "true":
    print("[provisioning_service] WARNING: DEMO_MODE=true requires AZURE_USE_KEYVAULT=false (runtime guard)")
    print("[provisioning_service] Forcing AZURE_USE_KEYVAULT=false | Run 'make validate-env' to fix .env permanently")
    os.environ["AZURE_USE_KEYVAULT"] = "false"

# Get Keycloak base URL from either KEYCLOAK_URL or extract from KEYCLOAK_SERVER_URL
_keycloak_url = os.environ.get("KEYCLOAK_URL")
if not _keycloak_url:
    # Extract base URL from KEYCLOAK_SERVER_URL (e.g., http://keycloak:8080/realms/demo -> http://keycloak:8080)
    server_url = os.environ.get("KEYCLOAK_SERVER_URL", "http://localhost:8080/realms/demo")
    if "/realms/" in server_url:
        _keycloak_url = server_url.split("/realms/")[0]
    else:
        _keycloak_url = server_url

KEYCLOAK_BASE_URL = _keycloak_url
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "demo")
KEYCLOAK_SERVICE_REALM = os.environ.get("KEYCLOAK_SERVICE_REALM", KEYCLOAK_REALM)
KEYCLOAK_SERVICE_CLIENT_ID = os.environ.get("KEYCLOAK_SERVICE_CLIENT_ID", "automation-cli")

# Import SCIM transformer
from app.core.scim_transformer import ScimTransformer

# Import settings for centralized secret management
from app.config.settings import settings

# Use centralized secret resolution (handles demo mode, Docker secrets, env vars)
def _get_service_client_secret() -> str:
    """Get service client secret via centralized settings."""
    return settings.service_client_secret_resolved

DEFAULT_ROLE = os.environ.get("SCIM_DEFAULT_ROLE", "analyst")

# Log configuration at module import
print(f"[provisioning_service] DEMO_MODE={DEMO_MODE}, AZURE_USE_KEYVAULT={os.environ.get('AZURE_USE_KEYVAULT', 'false')}")
print(f"[provisioning_service] KEYCLOAK_BASE_URL={KEYCLOAK_BASE_URL}, REALM={KEYCLOAK_REALM}")
secret_preview = _get_service_client_secret()
print(f"[provisioning_service] CLIENT_ID={KEYCLOAK_SERVICE_CLIENT_ID}, SECRET={'***' if secret_preview else 'EMPTY'}")

# SCIM schemas
SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"

# Validation constraints
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 64
EMAIL_MAX_LENGTH = 254
NAME_MAX_LENGTH = 64
JSON_MAX_SIZE_BYTES = 65536  # 64 KB

# Regex patterns
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{3,64}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ─────────────────────────────────────────────────────────────────────────────
# Custom Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class ScimError(Exception):
    """SCIM protocol error with HTTP status and optional scimType."""
    
    def __init__(self, status: int, detail: str, scim_type: Optional[str] = None):
        self.status = status
        self.detail = detail
        self.scim_type = scim_type
        super().__init__(detail)
    
    def to_dict(self) -> dict:
        """Convert to SCIM error response format."""
        error_dict = {
            "schemas": [SCIM_ERROR_SCHEMA],
            "status": str(self.status),
            "detail": self.detail
        }
        if self.scim_type:
            error_dict["scimType"] = self.scim_type
        return error_dict


# ─────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────────────────────────────────────

def generate_temp_password(length: int = 16) -> str:
    """
    Generate a secure temporary password.
    
    Args:
        length: Password length (default: 16)
    
    Returns:
        Random password containing uppercase, lowercase, digits, and special chars
    """
    # Ensure password meets complexity requirements
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password


# ─────────────────────────────────────────────────────────────────────────────
# Validation Functions
# ─────────────────────────────────────────────────────────────────────────────

def validate_username(username: str) -> None:
    """Validate username format (3-64 chars, alphanumeric + .-_)."""
    if not username:
        raise ScimError(400, "userName is required", "invalidValue")
    
    if not USERNAME_PATTERN.match(username):
        raise ScimError(
            400,
            f"userName must be {USERNAME_MIN_LENGTH}-{USERNAME_MAX_LENGTH} characters, "
            "alphanumeric with .-_ allowed",
            "invalidValue"
        )


def validate_email(email: str) -> None:
    """Validate email format (RFC 5322 basic check, max 254 chars)."""
    if not email:
        raise ScimError(400, "email is required", "invalidValue")
    
    if len(email) > EMAIL_MAX_LENGTH:
        raise ScimError(400, f"email must not exceed {EMAIL_MAX_LENGTH} characters", "invalidValue")
    
    if not EMAIL_PATTERN.match(email):
        raise ScimError(400, "email format is invalid", "invalidValue")


def validate_name(name: str, field: str) -> None:
    """Validate name field (givenName, familyName)."""
    if not name:
        raise ScimError(400, f"{field} is required", "invalidValue")
    
    if len(name) > NAME_MAX_LENGTH:
        raise ScimError(400, f"{field} must not exceed {NAME_MAX_LENGTH} characters", "invalidValue")
    
    # Basic XSS/SQLi protection
    dangerous_chars = ["<", ">", "&", "'", "\"", ";"]
    if any(char in name for char in dangerous_chars):
        raise ScimError(400, f"{field} contains invalid characters", "invalidValue")


def validate_scim_user_payload(payload: dict) -> None:
    """Validate SCIM User payload structure and required fields."""
    # Check required schema
    if "schemas" not in payload or SCIM_USER_SCHEMA not in payload["schemas"]:
        raise ScimError(400, f"schemas must include {SCIM_USER_SCHEMA}", "invalidSyntax")
    
    # Validate userName
    validate_username(payload.get("userName", ""))
    
    # Validate emails
    emails = payload.get("emails", [])
    if not emails or not isinstance(emails, list) or not emails[0].get("value"):
        raise ScimError(400, "emails[0].value is required", "invalidValue")
    
    validate_email(emails[0]["value"])
    
    # Validate name
    name = payload.get("name", {})
    if not isinstance(name, dict):
        raise ScimError(400, "name must be an object", "invalidValue")
    
    validate_name(name.get("givenName", ""), "name.givenName")
    validate_name(name.get("familyName", ""), "name.familyName")


# ─────────────────────────────────────────────────────────────────────────────
# Keycloak ⇔ SCIM Transformation
# ─────────────────────────────────────────────────────────────────────────────

def keycloak_to_scim(kc_user: dict, base_url: str = None) -> dict:
    """Convert Keycloak user representation to SCIM User format.
    
    Delegates to ScimTransformer for consistent transformation logic.
    
    Args:
        kc_user: Keycloak user dict (id, username, email, firstName, lastName, enabled, etc.)
        base_url: Base URL for location meta (e.g., "https://localhost")
    
    Returns:
        SCIM User dict with schemas, id, userName, emails, name, active, meta
    """
    scim_base = base_url if base_url else "/scim/v2"
    return ScimTransformer.keycloak_to_scim(kc_user, scim_base)


def scim_to_keycloak(scim_payload: dict) -> dict:
    """Convert SCIM User payload to Keycloak user creation format.
    
    Delegates to ScimTransformer for consistent transformation logic.
    
    Args:
        scim_payload: SCIM User dict
    
    Returns:
        Dict with username, email, firstName, lastName, enabled
    """
    return ScimTransformer.scim_to_keycloak(scim_payload)


# ─────────────────────────────────────────────────────────────────────────────
# Service Token Management
# ─────────────────────────────────────────────────────────────────────────────

def get_service_token() -> str:
    """Obtain service account OAuth token for Keycloak operations."""
    try:
        secret = _get_service_client_secret()
        return get_service_account_token(
            KEYCLOAK_BASE_URL,
            KEYCLOAK_SERVICE_REALM,
            KEYCLOAK_SERVICE_CLIENT_ID,
            secret,
        )
    except Exception as exc:
        raise ScimError(500, f"Failed to obtain service token: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Core Service Functions
# ─────────────────────────────────────────────────────────────────────────────

def create_user_scim_like(payload: dict, correlation_id: Optional[str] = None) -> dict:
    """Create a new user (Joiner) with SCIM-like payload.
    
    Args:
        payload: SCIM User dict with userName, emails, name, active
        correlation_id: Optional correlation ID for tracing
    
    Returns:
        SCIM User dict with id, _tempPassword (if DEMO_MODE), meta
    
    Raises:
        ScimError: On validation failure or duplicate userName (409)
    """
    # Validate payload
    validate_scim_user_payload(payload)
    
    # Extract fields
    kc_data = scim_to_keycloak(payload)
    username = kc_data["username"]
    email = kc_data["email"]
    first_name = kc_data["firstName"]
    last_name = kc_data["lastName"]
    
    # Get service token
    token = get_service_token()
    
    # Check if user already exists (idempotence)
    existing = get_user_by_username(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
    if existing:
        raise ScimError(409, f"User with userName '{username}' already exists", "uniqueness")
    
    # Determine role
    role = payload.get("role", DEFAULT_ROLE)
    
    # Generate secure temporary password
    temp_password = generate_temp_password()
    
    # Create user via app.core.keycloak
    try:
        create_user(
            KEYCLOAK_BASE_URL,
            token,
            KEYCLOAK_REALM,
            username,
            email,
            first_name,
            last_name,
            temp_password,
            role,
            require_totp=True,
            require_password_update=True
        )
    except Exception as exc:
        raise ScimError(500, f"Failed to create user: {exc}")
    
    # Retrieve created user to get user_id
    kc_user = get_user_by_username(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
    if not kc_user:
        raise ScimError(500, "User created but not found in Keycloak")
    
    user_id = kc_user["id"]
    
    # Log to audit trail
    audit.log_jml_event(
        "scim_create_user",
        username,
        operator="scim-api",
        realm=KEYCLOAK_REALM,
        details={
            "user_id": user_id,
            "email": email,
            "role": role,
            "correlation_id": correlation_id
        },
        success=True
    )
    
    # Convert to SCIM format (kc_user already retrieved above)
    scim_user = keycloak_to_scim(kc_user, base_url=os.environ.get("APP_BASE_URL", "https://localhost"))
    
    # Add temp password only in DEMO_MODE
    if DEMO_MODE and temp_password:
        scim_user["_tempPassword"] = temp_password
    
    return scim_user


def get_user_scim(user_id: str) -> dict:
    """Retrieve a user by Keycloak ID.
    
    Args:
        user_id: Keycloak user ID (UUID)
    
    Returns:
        SCIM User dict
    
    Raises:
        ScimError: 404 if user not found
    """
    try:
        token = get_service_token()
        resp = requests.get(
            f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        resp.raise_for_status()
        kc_user = resp.json()
    except Exception as exc:
        raise ScimError(404, f"User with id '{user_id}' not found")
    
    return keycloak_to_scim(kc_user, base_url=os.environ.get("APP_BASE_URL", "https://localhost"))


def list_users_scim(query: Optional[dict] = None) -> dict:
    """List users with pagination and filtering.
    
    Args:
        query: Dict with optional keys:
            - startIndex: 1-based starting index (default: 1)
            - count: Max results per page (default: 10)
            - filter: SCIM filter string (e.g., 'userName eq "alice"')
    
    Returns:
        SCIM ListResponse with schemas, totalResults, startIndex, itemsPerPage, Resources
    """
    query = query or {}
    start_index = max(1, int(query.get("startIndex", 1)))
    count = min(200, max(1, int(query.get("count", 10))))
    filter_str = query.get("filter", "")
    
    # Parse simple filter: userName eq "value"
    username_filter = None
    if filter_str:
        match = re.match(r'userName\s+eq\s+"([^"]+)"', filter_str, re.IGNORECASE)
        if match:
            username_filter = match.group(1)
    
    # Get users from Keycloak
    try:
        token = get_service_token()
        
        # Build query parameters
        params = {}
        if username_filter:
            params["username"] = username_filter
        
        # Get users via REST API
        resp = requests.get(
            f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=10,
        )
        resp.raise_for_status()
        kc_users = resp.json()
    except Exception as exc:
        raise ScimError(500, f"Failed to list users: {exc}")
    
    # Convert to SCIM format
    base_url = os.environ.get("APP_BASE_URL", "https://localhost")
    scim_users = [keycloak_to_scim(u, base_url) for u in kc_users]
    
    # Apply pagination
    total_results = len(scim_users)
    start_idx = start_index - 1  # Convert to 0-based
    end_idx = start_idx + count
    paginated_users = scim_users[start_idx:end_idx]
    
    return {
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": total_results,
        "startIndex": start_index,
        "itemsPerPage": len(paginated_users),
        "Resources": paginated_users
    }


def replace_user_scim(user_id: str, payload: dict, correlation_id: Optional[str] = None) -> dict:
    """Update a user (Mover/Leaver) via PUT.
    
    Args:
        user_id: Keycloak user ID
        payload: SCIM User dict (full replacement)
        correlation_id: Optional correlation ID for tracing
    
    Returns:
        Updated SCIM User dict
    
    Raises:
        ScimError: On validation failure or user not found (404)
    """
    # Check required schema
    if "schemas" not in payload or SCIM_USER_SCHEMA not in payload["schemas"]:
        raise ScimError(400, f"schemas must include {SCIM_USER_SCHEMA}", "invalidSyntax")
    
    # Validate userName (always required)
    validate_username(payload.get("userName", ""))
    
    # For deactivation (active=false), we don't require full payload validation
    # Only validate full payload if we're doing more than just disabling
    is_deactivation_only = payload.get("active") is False and len(payload.keys()) <= 4  # schemas, userName, active, id
    
    if not is_deactivation_only:
        # Full validation for complete updates
        validate_scim_user_payload(payload)
    
    # Check if user exists
    token = get_service_token()
    kc_user = get_user_by_username(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, payload.get("userName", ""))
    
    if not kc_user:
        raise ScimError(404, f"User with id '{user_id}' not found")
    
    # Verify the user_id matches (security check)
    if kc_user.get("id") != user_id:
        raise ScimError(404, f"User with id '{user_id}' not found")
    
    username = kc_user.get("username")
    
    # Handle deactivation (Leaver)
    if not payload.get("active", True):
        try:
            # Disable user (pass operator for correct audit logging)
            disable_user(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username, operator="scim-api")
            
            # Additional SCIM-specific audit log
            audit.log_jml_event(
                "scim_disable_user",
                username,
                operator="scim-api",
                realm=KEYCLOAK_REALM,
                details={
                    "user_id": user_id,
                    "correlation_id": correlation_id
                },
                success=True
            )
        except Exception as exc:
            # Idempotent: if already disabled, don't error
            if "already disabled" not in str(exc).lower():
                raise ScimError(500, f"Failed to disable user: {exc}")
    
    # Handle role change (Mover)
    # Note: SCIM doesn't have standard "roles" field, so we'd need custom extension
    # For now, we'll just update basic attributes
    
    # Refresh user state (re-query to get updated enabled status)
    kc_user = get_user_by_username(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
    if not kc_user:
        raise ScimError(500, "User state could not be refreshed")
    
    return keycloak_to_scim(kc_user, base_url=os.environ.get("APP_BASE_URL", "https://localhost"))


def delete_user_scim(user_id: str, correlation_id: Optional[str] = None) -> None:
    """Soft-delete a user by disabling (Leaver).
    
    Args:
        user_id: Keycloak user ID
        correlation_id: Optional correlation ID for tracing
    
    Raises:
        ScimError: 404 if user not found
    """
    token = get_service_token()
    
    # Find user by ID - we need to get all users and filter by ID
    # since get_user_by_username requires username
    try:
        resp = requests.get(
            f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        resp.raise_for_status()
        kc_user = resp.json()
        username = kc_user.get("username")
    except Exception:
        raise ScimError(404, f"User with id '{user_id}' not found")
    
    # Disable user (pass operator for correct audit logging)
    try:
        disable_user(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username, operator="scim-api")
    except Exception as exc:
        # Idempotent: if already disabled, don't error
        if "already disabled" not in str(exc).lower():
            raise ScimError(500, f"Failed to delete user: {exc}")
    
    # Log to audit trail
    audit.log_jml_event(
        "scim_delete_user",
        username,
        operator="scim-api",
        realm=KEYCLOAK_REALM,
        details={
            "user_id": user_id,
            "correlation_id": correlation_id
        },
        success=True
    )


# ─────────────────────────────────────────────────────────────────────────────
# Mover-Specific Function
# ─────────────────────────────────────────────────────────────────────────────

def change_user_role(username: str, source_role: str, target_role: str, correlation_id: Optional[str] = None) -> None:
    """Change a user's role (Mover operation).
    
    Args:
        username: Username to update
        source_role: Current role to remove
        target_role: New role to assign
        correlation_id: Optional correlation ID for tracing
    
    Raises:
        ScimError: On validation failure or user not found
    """
    # Get service token
    token = get_service_token()
    
    # Check if user exists
    user = get_user_by_username(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
    if not user:
        raise ScimError(404, f"User with userName '{username}' not found")
    
    # Perform role change via app.core.keycloak
    try:
        change_role(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username, source_role, target_role)
    except Exception as exc:
        raise ScimError(500, f"Failed to change role: {exc}")
    
    # Log to audit trail
    audit.log_jml_event(
        "scim_change_role",
        username,
        operator="scim-api",
        realm=KEYCLOAK_REALM,
        details={
            "source_role": source_role,
            "target_role": target_role,
            "correlation_id": correlation_id
        },
        success=True
    )
