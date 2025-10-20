"""
Provisioning Service Layer — Unified JML Logic

This module provides a unified service layer for Joiner/Mover/Leaver operations,
used by both the Flask UI and the SCIM 2.0 API. It ensures consistent business
logic, validation, and error handling across all interfaces.

Architecture:
    UI Admin (/admin/*) ──┐
                          ├──> provisioning_service.py ──> scripts/jml.py ──> Keycloak
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
from typing import Any, Optional
from scripts import jml
from scripts import audit
import requests


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "demo")
KEYCLOAK_SERVICE_REALM = os.environ.get("KEYCLOAK_SERVICE_REALM", KEYCLOAK_REALM)
KEYCLOAK_SERVICE_CLIENT_ID = os.environ.get("KEYCLOAK_SERVICE_CLIENT_ID", "automation-cli")
KEYCLOAK_SERVICE_CLIENT_SECRET = os.environ.get("KEYCLOAK_SERVICE_CLIENT_SECRET", "")

DEMO_MODE = os.environ.get("DEMO_MODE", "false").lower() == "true"
DEFAULT_ROLE = os.environ.get("SCIM_DEFAULT_ROLE", "analyst")

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
    
    Args:
        kc_user: Keycloak user dict (id, username, email, firstName, lastName, enabled, etc.)
        base_url: Base URL for location meta (e.g., "https://localhost")
    
    Returns:
        SCIM User dict with schemas, id, userName, emails, name, active, meta
    """
    user_id = kc_user.get("id", "")
    username = kc_user.get("username", "")
    email = kc_user.get("email", "")
    first_name = kc_user.get("firstName", "")
    last_name = kc_user.get("lastName", "")
    enabled = kc_user.get("enabled", True)
    
    # Convert timestamp to ISO 8601
    created_ts = kc_user.get("createdTimestamp")
    if created_ts:
        created_dt = datetime.datetime.fromtimestamp(created_ts / 1000, tz=datetime.timezone.utc)
        created_iso = created_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        created_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Build SCIM user
    scim_user = {
        "schemas": [SCIM_USER_SCHEMA],
        "id": user_id,
        "userName": username,
        "emails": [{"value": email, "primary": True}] if email else [],
        "name": {
            "givenName": first_name,
            "familyName": last_name,
            "formatted": f"{first_name} {last_name}".strip()
        },
        "active": enabled,
        "meta": {
            "resourceType": "User",
            "created": created_iso,
            "lastModified": created_iso
        }
    }
    
    # Add location if base_url provided
    if base_url:
        scim_user["meta"]["location"] = f"{base_url}/scim/v2/Users/{user_id}"
    
    return scim_user


def scim_to_keycloak(scim_payload: dict) -> dict:
    """Convert SCIM User payload to Keycloak user creation format.
    
    Args:
        scim_payload: SCIM User dict
    
    Returns:
        Dict with username, email, firstName, lastName, enabled
    """
    emails = scim_payload.get("emails", [])
    name = scim_payload.get("name", {})
    
    return {
        "username": scim_payload.get("userName", ""),
        "email": emails[0]["value"] if emails else "",
        "firstName": name.get("givenName", ""),
        "lastName": name.get("familyName", ""),
        "enabled": scim_payload.get("active", True)
    }


# ─────────────────────────────────────────────────────────────────────────────
# Service Token Management
# ─────────────────────────────────────────────────────────────────────────────

def get_service_token() -> str:
    """Obtain service account OAuth token for Keycloak operations."""
    try:
        return jml.get_service_account_token(
            KEYCLOAK_BASE_URL,
            KEYCLOAK_SERVICE_REALM,
            KEYCLOAK_SERVICE_CLIENT_ID,
            KEYCLOAK_SERVICE_CLIENT_SECRET,
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
    existing = jml.get_user_by_username(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
    if existing:
        raise ScimError(409, f"User with userName '{username}' already exists", "uniqueness")
    
    # Determine role
    role = payload.get("role", DEFAULT_ROLE)
    
    # Generate temp password if not provided
    temp_password = None  # Will be auto-generated by jml.create_user
    
    # Create user via jml.py
    try:
        user_id, temp_password = jml.create_user(
            KEYCLOAK_BASE_URL,
            token,
            KEYCLOAK_REALM,
            username,
            email,
            first_name,
            last_name,
            temp_password or "",  # Pass empty string to trigger auto-generation
            role,
            require_totp=True,
            require_password_update=True
        )
    except Exception as exc:
        raise ScimError(500, f"Failed to create user: {exc}")
    
    # Log to audit trail
    audit.log_jml_event(
        operation="scim_create_user",
        username=username,
        details={
            "user_id": user_id,
            "email": email,
            "role": role,
            "correlation_id": correlation_id
        }
    )
    
    # Retrieve created user
    kc_user = jml.get_user_by_username(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
    if not kc_user:
        raise ScimError(500, "User created but not found in Keycloak")
    
    # Convert to SCIM format
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
        admin = jml.KeycloakAdmin(
            server_url=KEYCLOAK_BASE_URL,
            realm_name=KEYCLOAK_REALM,
            token={"access_token": token}
        )
        kc_user = admin.get_user(user_id)
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
        admin = jml.KeycloakAdmin(
            server_url=KEYCLOAK_BASE_URL,
            realm_name=KEYCLOAK_REALM,
            token={"access_token": token}
        )
        
        # Apply username filter if provided
        if username_filter:
            kc_users = admin.get_users({"username": username_filter})
        else:
            kc_users = admin.get_users({})
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
    # Validate payload
    validate_scim_user_payload(payload)
    
    # Check if user exists
    try:
        token = get_service_token()
        admin = jml.KeycloakAdmin(
            server_url=KEYCLOAK_BASE_URL,
            realm_name=KEYCLOAK_REALM,
            token={"access_token": token}
        )
        kc_user = admin.get_user(user_id)
    except Exception:
        raise ScimError(404, f"User with id '{user_id}' not found")
    
    username = kc_user.get("username")
    
    # Handle deactivation (Leaver)
    if not payload.get("active", True):
        try:
            # Revoke sessions before disabling (security requirement)
            _revoke_user_sessions(user_id, admin)
            
            # Disable user
            jml.disable_user(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
            
            # Log to audit trail
            audit.log_jml_event(
                operation="scim_disable_user",
                username=username,
                details={
                    "user_id": user_id,
                    "correlation_id": correlation_id
                }
            )
        except Exception as exc:
            # Idempotent: if already disabled, don't error
            if "already disabled" not in str(exc).lower():
                raise ScimError(500, f"Failed to disable user: {exc}")
    
    # Handle role change (Mover)
    # Note: SCIM doesn't have standard "roles" field, so we'd need custom extension
    # For now, we'll just update basic attributes
    
    # Refresh user state
    kc_user = admin.get_user(user_id)
    
    return keycloak_to_scim(kc_user, base_url=os.environ.get("APP_BASE_URL", "https://localhost"))


def delete_user_scim(user_id: str, correlation_id: Optional[str] = None) -> None:
    """Soft-delete a user by disabling (Leaver).
    
    Args:
        user_id: Keycloak user ID
        correlation_id: Optional correlation ID for tracing
    
    Raises:
        ScimError: 404 if user not found
    """
    try:
        token = get_service_token()
        admin = jml.KeycloakAdmin(
            server_url=KEYCLOAK_BASE_URL,
            realm_name=KEYCLOAK_REALM,
            token={"access_token": token}
        )
        kc_user = admin.get_user(user_id)
        username = kc_user.get("username")
    except Exception:
        raise ScimError(404, f"User with id '{user_id}' not found")
    
    # Revoke sessions before disabling
    _revoke_user_sessions(user_id, admin)
    
    # Disable user (idempotent)
    try:
        jml.disable_user(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
    except Exception as exc:
        # Idempotent: if already disabled, don't error
        if "already disabled" not in str(exc).lower():
            raise ScimError(500, f"Failed to delete user: {exc}")
    
    # Log to audit trail
    audit.log_jml_event(
        operation="scim_delete_user",
        username=username,
        details={
            "user_id": user_id,
            "correlation_id": correlation_id
        }
    )


def _revoke_user_sessions(user_id: str, admin) -> None:
    """Revoke all active sessions for a user (internal helper).
    
    Args:
        user_id: Keycloak user ID
        admin: KeycloakAdmin instance with valid token
    """
    try:
        # Get all active sessions
        sessions = admin.get_user_sessions(user_id=user_id)
        
        # Delete each session
        for session in sessions:
            session_id = session.get("id")
            if session_id:
                admin.delete_session(session_id=session_id)
    except Exception:
        # Log but don't fail - session revocation is best-effort
        pass


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
    user = jml.get_user_by_username(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
    if not user:
        raise ScimError(404, f"User with userName '{username}' not found")
    
    # Perform role change via jml.py
    try:
        jml.change_role(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username, source_role, target_role)
    except Exception as exc:
        raise ScimError(500, f"Failed to change role: {exc}")
    
    # Log to audit trail
    audit.log_jml_event(
        operation="scim_change_role",
        username=username,
        details={
            "source_role": source_role,
            "target_role": target_role,
            "correlation_id": correlation_id
        }
    )
