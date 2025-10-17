"""SCIM 2.0 API endpoints (RFC 7644) for user provisioning.

This module provides a minimal SCIM-compliant REST API on top of the existing
JML automation layer, enabling integration with external IdP systems.
"""

from __future__ import annotations
import datetime
from typing import Any
from flask import Blueprint, request, jsonify, g
from scripts import jml
from scripts import audit
import os
import requests

# SCIM 2.0 Blueprint
scim = Blueprint('scim', __name__, url_prefix='/scim/v2')

# Configuration
KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "demo")
KEYCLOAK_SERVICE_REALM = os.environ.get("KEYCLOAK_SERVICE_REALM", KEYCLOAK_REALM)
KEYCLOAK_SERVICE_CLIENT_ID = os.environ.get("KEYCLOAK_SERVICE_CLIENT_ID", "automation-cli")
KEYCLOAK_SERVICE_CLIENT_SECRET = os.environ.get("KEYCLOAK_SERVICE_CLIENT_SECRET", "")

DEFAULT_ROLE = os.environ.get("SCIM_DEFAULT_ROLE", "analyst")
DEFAULT_PASSWORD_LENGTH = 16


# ─────────────────────────────────────────────────────────────────────────────
# SCIM Schema Definitions
# ─────────────────────────────────────────────────────────────────────────────

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"


# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

def _get_service_token() -> str:
    """Obtain service account token for Keycloak operations."""
    try:
        return jml.get_service_account_token(
            KEYCLOAK_BASE_URL,
            KEYCLOAK_SERVICE_REALM,
            KEYCLOAK_SERVICE_CLIENT_ID,
            KEYCLOAK_SERVICE_CLIENT_SECRET,
        )
    except Exception as exc:
        raise RuntimeError(f"Failed to obtain service token: {exc}") from exc


def _generate_password() -> str:
    """Generate secure temporary password."""
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + "!@#$-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(DEFAULT_PASSWORD_LENGTH))


def _keycloak_to_scim(kc_user: dict) -> dict:
    """Convert Keycloak user representation to SCIM 2.0 format.
    
    Args:
        kc_user: Keycloak user representation
        
    Returns:
        SCIM User resource
    """
    user_id = kc_user.get("id", "")
    username = kc_user.get("username", "")
    email = kc_user.get("email", "")
    first = kc_user.get("firstName", "")
    last = kc_user.get("lastName", "")
    enabled = kc_user.get("enabled", True)
    
    # Build formatted name
    formatted_name = " ".join(filter(None, [first, last])).strip() or username
    
    scim_user = {
        "schemas": [SCIM_USER_SCHEMA],
        "id": user_id,
        "userName": username,
        "active": enabled,
    }
    
    # Add email if present
    if email:
        scim_user["emails"] = [
            {
                "value": email,
                "type": "work",
                "primary": True
            }
        ]
    
    # Add name if present
    if first or last:
        scim_user["name"] = {
            "formatted": formatted_name,
            "givenName": first,
            "familyName": last
        }
    
    # Add metadata
    created_ts = kc_user.get("createdTimestamp")
    if created_ts:
        created_dt = datetime.datetime.fromtimestamp(created_ts / 1000, tz=datetime.timezone.utc)
        created_iso = created_dt.isoformat()
    else:
        created_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    scim_user["meta"] = {
        "resourceType": "User",
        "created": created_iso,
        "lastModified": created_iso,
        "location": f"{request.host_url.rstrip('/')}/scim/v2/Users/{user_id}"
    }
    
    return scim_user


def _scim_error(status: int, detail: str, scim_type: str | None = None) -> tuple[dict, int]:
    """Build SCIM error response.
    
    Args:
        status: HTTP status code
        detail: Error description
        scim_type: SCIM error type (uniqueness, invalidValue, etc.)
        
    Returns:
        Tuple of (error_dict, status_code)
    """
    error = {
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": str(status),
        "detail": detail
    }
    
    if scim_type:
        error["scimType"] = scim_type
    
    return error, status


def _require_scim_content_type():
    """Validate Content-Type header for SCIM requests."""
    content_type = request.headers.get("Content-Type", "")
    if not content_type.startswith("application/scim+json") and not content_type.startswith("application/json"):
        return _scim_error(
            400,
            "Content-Type must be application/scim+json or application/json"
        )
    return None


def _validate_scim_user_schema(payload: dict) -> str | None:
    """Validate SCIM User schema in request payload.
    
    Returns:
        Error message if invalid, None if valid
    """
    if not isinstance(payload, dict):
        return "Request body must be a JSON object"
    
    schemas = payload.get("schemas", [])
    if SCIM_USER_SCHEMA not in schemas:
        return f"Missing required schema: {SCIM_USER_SCHEMA}"
    
    if "userName" not in payload:
        return "Missing required attribute: userName"
    
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SCIM Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@scim.route('/ServiceProviderConfig', methods=['GET'])
def service_provider_config():
    """SCIM 2.0 Service Provider Configuration endpoint (RFC 7644 §5)."""
    config = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://datatracker.ietf.org/doc/html/rfc7644",
        "patch": {
            "supported": False
        },
        "bulk": {
            "supported": False,
            "maxOperations": 0,
            "maxPayloadSize": 0
        },
        "filter": {
            "supported": True,
            "maxResults": 100
        },
        "changePassword": {
            "supported": False
        },
        "sort": {
            "supported": False
        },
        "etag": {
            "supported": False
        },
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Authentication using OAuth 2.0 Bearer Token",
                "specUri": "https://datatracker.ietf.org/doc/html/rfc6750"
            }
        ]
    }
    return jsonify(config), 200


@scim.route('/ResourceTypes', methods=['GET'])
def resource_types():
    """SCIM 2.0 Resource Types endpoint (RFC 7644 §6)."""
    resources = {
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": 1,
        "Resources": [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/scim/v2/Users",
                "description": "User Account",
                "schema": SCIM_USER_SCHEMA
            }
        ]
    }
    return jsonify(resources), 200


@scim.route('/Schemas', methods=['GET'])
def schemas():
    """SCIM 2.0 Schemas endpoint (RFC 7644 §7)."""
    schema_list = {
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": 1,
        "Resources": [
            {
                "id": SCIM_USER_SCHEMA,
                "name": "User",
                "description": "User Account"
            }
        ]
    }
    return jsonify(schema_list), 200


@scim.route('/Users', methods=['POST'])
def create_user():
    """SCIM 2.0 Create User endpoint (RFC 7644 §3.3).
    
    Example request:
        POST /scim/v2/Users
        Content-Type: application/scim+json
        
        {
          "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName": "alice",
          "emails": [{"value": "alice@example.com", "primary": true}],
          "name": {"givenName": "Alice", "familyName": "Demo"},
          "active": true
        }
    """
    # Validate content type
    error = _require_scim_content_type()
    if error:
        return jsonify(error[0]), error[1]
    
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify(_scim_error(400, "Invalid JSON payload")[0]), 400
    
    # Validate SCIM schema
    validation_error = _validate_scim_user_schema(payload)
    if validation_error:
        return jsonify(_scim_error(400, validation_error)[0]), 400
    
    # Extract SCIM attributes
    username = payload.get("userName", "").strip().lower()
    emails = payload.get("emails", [])
    email = emails[0]["value"] if emails else f"{username}@example.com"
    name = payload.get("name", {})
    first = name.get("givenName", "User")
    last = name.get("familyName", "Account")
    active = payload.get("active", True)
    
    # Validate required fields
    if not username:
        return jsonify(_scim_error(400, "userName is required")[0]), 400
    
    # Generate temporary password
    temp_password = _generate_password()
    
    # Get service token
    try:
        token = _get_service_token()
    except Exception as exc:
        return jsonify(_scim_error(500, f"Authentication failed: {exc}")[0]), 500
    
    # Check if user exists
    existing = jml.get_user_by_username(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
    if existing:
        return jsonify(_scim_error(
            409,
            f"User with userName '{username}' already exists",
            scim_type="uniqueness"
        )[0]), 409
    
    # Create user via JML
    try:
        jml.create_user(
            KEYCLOAK_BASE_URL,
            token,
            KEYCLOAK_REALM,
            username,
            email,
            first,
            last,
            temp_password,
            DEFAULT_ROLE,
            require_totp=True,
            require_password_update=True,
        )
        
        # Log audit event
        audit.log_jml_event(
            "joiner",
            username,
            operator="scim-api",
            realm=KEYCLOAK_REALM,
            details={"email": email, "role": DEFAULT_ROLE, "via": "scim"},
            success=True,
        )
        
    except Exception as exc:
        audit.log_jml_event(
            "joiner",
            username,
            operator="scim-api",
            realm=KEYCLOAK_REALM,
            details={"error": str(exc), "via": "scim"},
            success=False,
        )
        return jsonify(_scim_error(500, f"User creation failed: {exc}")[0]), 500
    
    # Retrieve created user
    created_user = jml.get_user_by_username(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
    if not created_user:
        return jsonify(_scim_error(500, "User created but not found")[0]), 500
    
    # Convert to SCIM format
    scim_user = _keycloak_to_scim(created_user)
    
    # Add temporary password to response (non-standard, for demo purposes)
    scim_user["_tempPassword"] = temp_password
    
    return jsonify(scim_user), 201


@scim.route('/Users/<user_id>', methods=['GET'])
def get_user(user_id: str):
    """SCIM 2.0 Get User endpoint (RFC 7644 §3.4.1).
    
    Example request:
        GET /scim/v2/Users/2819c223-7f76-453a-919d-413861904646
    """
    try:
        token = _get_service_token()
    except Exception as exc:
        return jsonify(_scim_error(500, f"Authentication failed: {exc}")[0]), 500
    
    # Get user from Keycloak
    try:
        resp = requests.get(
            f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}",
            headers=jml._auth_headers(token),
            timeout=jml.REQUEST_TIMEOUT,
        )
        
        if resp.status_code == 404:
            return jsonify(_scim_error(404, f"User {user_id} not found")[0]), 404
        
        resp.raise_for_status()
        kc_user = resp.json()
        
    except requests.HTTPError as exc:
        return jsonify(_scim_error(500, f"Failed to retrieve user: {exc}")[0]), 500
    
    # Convert to SCIM format
    scim_user = _keycloak_to_scim(kc_user)
    return jsonify(scim_user), 200


@scim.route('/Users', methods=['GET'])
def list_users():
    """SCIM 2.0 List Users endpoint with filtering (RFC 7644 §3.4.2).
    
    Example requests:
        GET /scim/v2/Users
        GET /scim/v2/Users?filter=userName eq "alice"
        GET /scim/v2/Users?startIndex=1&count=10
    """
    try:
        token = _get_service_token()
    except Exception as exc:
        return jsonify(_scim_error(500, f"Authentication failed: {exc}")[0]), 500
    
    # Parse pagination parameters
    start_index = int(request.args.get('startIndex', 1))
    count = min(int(request.args.get('count', 100)), 100)
    filter_expr = request.args.get('filter', '')
    
    # Parse filter (simple implementation: userName eq "value")
    filter_username = None
    if filter_expr:
        parts = filter_expr.split()
        if len(parts) >= 3 and parts[0] == "userName" and parts[1] == "eq":
            filter_username = parts[2].strip('"\'').lower()
    
    # Get users from Keycloak
    try:
        params = {"max": count}
        if filter_username:
            params["username"] = filter_username
        
        resp = requests.get(
            f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users",
            params=params,
            headers=jml._auth_headers(token),
            timeout=jml.REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        kc_users = resp.json()
        
    except requests.HTTPError as exc:
        return jsonify(_scim_error(500, f"Failed to list users: {exc}")[0]), 500
    
    # Convert to SCIM format
    scim_users = [_keycloak_to_scim(user) for user in kc_users]
    
    # Apply pagination
    total = len(scim_users)
    if start_index > 1:
        scim_users = scim_users[start_index - 1:]
    
    # Build SCIM ListResponse
    response = {
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(scim_users),
        "Resources": scim_users
    }
    
    return jsonify(response), 200


@scim.route('/Users/<user_id>', methods=['PUT'])
def replace_user(user_id: str):
    """SCIM 2.0 Replace User endpoint (RFC 7644 §3.5.1).
    
    Example request:
        PUT /scim/v2/Users/2819c223-7f76-453a-919d-413861904646
        Content-Type: application/scim+json
        
        {
          "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName": "alice",
          "active": false
        }
    """
    # Validate content type
    error = _require_scim_content_type()
    if error:
        return jsonify(error[0]), error[1]
    
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify(_scim_error(400, "Invalid JSON payload")[0]), 400
    
    # Validate SCIM schema
    validation_error = _validate_scim_user_schema(payload)
    if validation_error:
        return jsonify(_scim_error(400, validation_error)[0]), 400
    
    try:
        token = _get_service_token()
    except Exception as exc:
        return jsonify(_scim_error(500, f"Authentication failed: {exc}")[0]), 500
    
    # Get existing user
    try:
        resp = requests.get(
            f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}",
            headers=jml._auth_headers(token),
            timeout=jml.REQUEST_TIMEOUT,
        )
        
        if resp.status_code == 404:
            return jsonify(_scim_error(404, f"User {user_id} not found")[0]), 404
        
        resp.raise_for_status()
        kc_user = resp.json()
        username = kc_user.get("username", "")
        
    except requests.HTTPError as exc:
        return jsonify(_scim_error(500, f"Failed to retrieve user: {exc}")[0]), 500
    
    # Handle active status change (disable user)
    active = payload.get("active", True)
    if not active and kc_user.get("enabled", True):
        try:
            jml.disable_user(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
            
            audit.log_jml_event(
                "leaver",
                username,
                operator="scim-api",
                realm=KEYCLOAK_REALM,
                details={"via": "scim", "user_id": user_id},
                success=True,
            )
        except Exception as exc:
            audit.log_jml_event(
                "leaver",
                username,
                operator="scim-api",
                realm=KEYCLOAK_REALM,
                details={"error": str(exc), "via": "scim"},
                success=False,
            )
            return jsonify(_scim_error(500, f"Failed to disable user: {exc}")[0]), 500
    
    # Retrieve updated user
    resp = requests.get(
        f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}",
        headers=jml._auth_headers(token),
        timeout=jml.REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    updated_user = resp.json()
    
    # Convert to SCIM format
    scim_user = _keycloak_to_scim(updated_user)
    return jsonify(scim_user), 200


@scim.route('/Users/<user_id>', methods=['DELETE'])
def delete_user(user_id: str):
    """SCIM 2.0 Delete User endpoint (RFC 7644 §3.6).
    
    Note: This implementation disables the user rather than deleting it.
    
    Example request:
        DELETE /scim/v2/Users/2819c223-7f76-453a-919d-413861904646
    """
    try:
        token = _get_service_token()
    except Exception as exc:
        return jsonify(_scim_error(500, f"Authentication failed: {exc}")[0]), 500
    
    # Get user to retrieve username
    try:
        resp = requests.get(
            f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}",
            headers=jml._auth_headers(token),
            timeout=jml.REQUEST_TIMEOUT,
        )
        
        if resp.status_code == 404:
            return jsonify(_scim_error(404, f"User {user_id} not found")[0]), 404
        
        resp.raise_for_status()
        username = resp.json().get("username", "")
        
    except requests.HTTPError as exc:
        return jsonify(_scim_error(500, f"Failed to retrieve user: {exc}")[0]), 500
    
    # Disable user (soft delete)
    try:
        jml.disable_user(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
        
        audit.log_jml_event(
            "leaver",
            username,
            operator="scim-api",
            realm=KEYCLOAK_REALM,
            details={"via": "scim_delete", "user_id": user_id},
            success=True,
        )
        
    except Exception as exc:
        audit.log_jml_event(
            "leaver",
            username,
            operator="scim-api",
            realm=KEYCLOAK_REALM,
            details={"error": str(exc), "via": "scim_delete"},
            success=False,
        )
        return jsonify(_scim_error(500, f"Failed to delete user: {exc}")[0]), 500
    
    # SCIM DELETE returns 204 No Content
    return '', 204
