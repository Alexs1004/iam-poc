"""SCIM 2.0 API endpoints (RFC 7644) for user provisioning.

This module provides a minimal SCIM-compliant REST API that delegates all
business logic to the unified provisioning_service layer.

Architecture:
    SCIM API (/scim/v2/*) -> app/provisioning_service.py -> scripts/jml.py -> Keycloak

Security:
    - OAuth 2.0 Bearer Token authentication (RFC 6750) via @require_oauth_token decorator
    - Optional: Static Bearer Token for Entra ID provisioning (SCIM-only, DEMO_MODE or KeyVault gated)
    - Read operations require 'scim:read' scope (OAuth mode)
    - Write operations require 'scim:write' scope (OAuth mode)
    - Discovery endpoints (ServiceProviderConfig, Schemas) are public
"""

from __future__ import annotations
import os
import hmac
import hashlib
import logging
from flask import Blueprint, request, jsonify, Response, current_app, g
from werkzeug.exceptions import BadRequest
from app.core import provisioning_service
from app.core.provisioning_service import ScimError
from app.api.decorators import validate_jwt_token, TokenValidationError
from app.api.decorators import require_oauth_token

# SCIM 2.0 Blueprint
bp = Blueprint('scim', __name__, url_prefix='/scim/v2')

# Configuration
JSON_MAX_SIZE_BYTES = 65536  # 64 KB

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Authentication Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_static_token_enabled() -> bool:
    """Check if SCIM static token authentication is enabled.
    
    Enabled when:
    - DEMO_MODE=true OR
    - SCIM_STATIC_TOKEN_SOURCE=keyvault (with AZURE_USE_KEYVAULT=true)
    
    Returns:
        bool: True if static token auth is active
    """
    cfg = current_app.config.get("APP_CONFIG")
    if not cfg:
        return False
    
    # Enable in demo mode
    if cfg.demo_mode:
        return True
    
    # Enable if explicitly configured with KeyVault
    if cfg.scim_static_token_source == "keyvault" and cfg.azure_use_keyvault:
        return True
    
    return False


def _validate_static_token(provided_token: str) -> bool:
    """Validate SCIM static token with constant-time comparison.
    
    Args:
        provided_token: Token from Authorization header
    
    Returns:
        bool: True if token matches configured secret
    
    Security:
        - Uses hmac.compare_digest for timing-attack resistance
        - Never logs the actual token value
    """
    cfg = current_app.config.get("APP_CONFIG")
    if not cfg or not cfg.scim_static_token:
        return False
    
    expected_token = cfg.scim_static_token
    
    # Constant-time comparison (timing-attack safe)
    return hmac.compare_digest(provided_token, expected_token)


def _log_auth_attempt(auth_method: str, token: str, success: bool):
    """Log authentication attempt without leaking secrets.
    
    Args:
        auth_method: "static" or "oauth"
        token: Bearer token (will be hashed for logging)
        success: Whether authentication succeeded
    
    Security:
        - Only logs SHA256 hash (truncated to 12 chars)
        - Includes correlation_id, client_ip, path
    """
    # Hash token for safe logging (SHA256 truncated)
    token_hash = hashlib.sha256(token.encode()).hexdigest()[:12]
    
    # Extract request metadata
    correlation_id = request.headers.get("X-Correlation-Id", "none")
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    path = request.path
    
    status = "✅ SUCCESS" if success else "❌ FAILED"
    logger.info(
        f"{status} SCIM auth | method={auth_method} | "
        f"token_hash={token_hash} | path={path} | "
        f"correlation_id={correlation_id} | client_ip={client_ip}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Error Handler
# ─────────────────────────────────────────────────────────────────────────────

def scim_error(status: int, detail: str, scim_type: str = None) -> tuple[Response, int]:
    """Create SCIM error response tuple for route handlers.
    
    Args:
        status: HTTP status code
        detail: Human-readable error description
        scim_type: Optional SCIM error type (uniqueness, invalidValue, etc.)
    
    Returns:
        Tuple of (JSON response, status code)
    """
    error = ScimError(status, detail, scim_type)
    return jsonify(error.to_dict()), status


def scim_error_response(status: int, detail: str, scim_type: str = None) -> Response:
    """Create SCIM error Response object for before_request handlers.
    
    Args:
        status: HTTP status code
        detail: Human-readable error description
        scim_type: Optional SCIM error type (uniqueness, invalidValue, etc.)
    
    Returns:
        Flask Response object with SCIM error body and status code
    """
    error = ScimError(status, detail, scim_type)
    response = jsonify(error.to_dict())
    response.status_code = status
    return response


@bp.errorhandler(ScimError)
def handle_scim_error(error: ScimError):
    """Global error handler for ScimError exceptions."""
    return jsonify(error.to_dict()), error.status


@bp.errorhandler(413)
def handle_request_too_large(error):
    """Handle payload too large errors."""
    return scim_error(413, "Request payload exceeds maximum allowed size (64 KB)", "invalidValue")


# ─────────────────────────────────────────────────────────────────────────────
# Request Validation Middleware
# ─────────────────────────────────────────────────────────────────────────────

@bp.before_request
def validate_request():
    """Validate OAuth/static token, request size, and content type.
    
    Authentication precedence:
    1. If Authorization: Bearer <token> present:
       a. If static token mode enabled AND token matches static secret -> AUTH OK (static)
       b. Else -> Validate as OAuth2 JWT token
    2. If no Authorization header and endpoint is discovery (public) -> ALLOW
    3. Else -> 401 Unauthorized
    
    Scope restrictions:
    - Static token: ONLY accepted on /scim/v2/* endpoints
    - Static token: REJECTED on /admin, /scim/docs, or any non-SCIM path
    """
    # Skip validation in test mode IF explicitly requested (for unit tests that mock provisioning)
    # OAuth validation tests will NOT set this variable
    if current_app.config.get('TESTING') and os.getenv('SKIP_OAUTH_FOR_TESTS') == 'true':
        return None
    
    # Skip OAuth for discovery endpoints (RFC 7644 requirement)
    discovery_endpoints = [
        "/scim/v2/ServiceProviderConfig",
        "/scim/v2/ResourceTypes",
        "/scim/v2/Schemas"
    ]
    if request.path in discovery_endpoints:
        return None  # Allow public access
    
    # 1. Check for Authorization header
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        return scim_error_response(401, "Authorization header missing. Provide 'Authorization: Bearer <token>'.", "unauthorized")
    
    if not auth_header.startswith("Bearer "):
        return scim_error_response(401, "Authorization header must use Bearer token scheme: 'Authorization: Bearer <token>'.", "unauthorized")
    
    token = auth_header[7:].strip()  # Remove "Bearer " prefix
    if not token:
        return scim_error_response(401, "Bearer token is empty.", "unauthorized")
    
    # 2. Try static token authentication first (if enabled and on SCIM endpoint)
    static_token_enabled = _is_static_token_enabled()
    
    if static_token_enabled and request.path.startswith("/scim/v2/"):
        if _validate_static_token(token):
            # ✅ Static token authentication SUCCESS
            _log_auth_attempt("static", token, success=True)
            
            # Store auth metadata in request context
            g.auth_method = "static"
            g.oauth_claims = None
            g.oauth_client_id = "entra-provisioning"
            
            # Continue to payload validation (skip OAuth checks)
            # Jump to step 3 (payload size check)
            if request.content_length and request.content_length > JSON_MAX_SIZE_BYTES:
                return scim_error_response(413, "Request payload too large", "invalidValue")
            
            if request.method in ("POST", "PUT", "PATCH"):
                content_type = request.content_type or ""
                if not content_type.startswith("application/scim+json"):
                    return scim_error_response(
                        415,
                        "Content-Type must be application/scim+json",
                        "invalidSyntax"
                    )
            
            return None  # Authentication successful, continue to route handler
        else:
            # Token doesn't match static secret -> Fall through to OAuth validation
            # (Don't log failure here, let OAuth validator handle it)
            pass
    
    # 3. OAuth 2.0 JWT Token validation
    try:
        oauth_claims = validate_jwt_token(token)
        
        # ✅ OAuth authentication SUCCESS
        _log_auth_attempt("oauth", token, success=True)
        
        # Store claims in request context for route handlers
        g.auth_method = "oauth"
        g.oauth_claims = oauth_claims
        g.oauth_client_id = oauth_claims.get("client_id") or oauth_claims.get("sub")
        
        # 4. Validate scope based on HTTP method
        token_scopes = oauth_claims.get("scope", "").split()
        
        # TEMPORARY: Allow service accounts (client_credentials) without explicit SCIM scopes
        # TODO: Configure automation-cli client in Keycloak with proper SCIM client scopes
        is_service_account = oauth_claims.get("azp") == "automation-cli" or oauth_claims.get("client_id") == "automation-cli"
        
        if not is_service_account:
            # Write operations require scim:write
            if request.method in ("POST", "PUT", "DELETE", "PATCH"):
                if "scim:write" not in token_scopes:
                    return scim_error_response(
                        403,
                        "Insufficient scope. Required: 'scim:write' for write operations.",
                        "forbidden"
                    )
            # Read operations require scim:read
            elif request.method in ("GET"):
                if "scim:read" not in token_scopes and "scim:write" not in token_scopes:
                    return scim_error_response(
                        403,
                        "Insufficient scope. Required: 'scim:read' or 'scim:write' for read operations.",
                        "forbidden"
                    )
        
    except TokenValidationError as e:
        _log_auth_attempt("oauth", token, success=False)
        return scim_error_response(401, str(e), "unauthorized")
    except Exception as e:
        _log_auth_attempt("oauth", token, success=False)
        return scim_error_response(401, f"Token validation failed: {e}", "unauthorized")
    
    # 5. Check payload size
    if request.content_length and request.content_length > JSON_MAX_SIZE_BYTES:
        return scim_error_response(413, "Request payload too large", "invalidValue")
    
    # 6. Validate Content-Type for payload-bearing methods
    if request.method in ("POST", "PUT", "PATCH"):
        content_type = request.content_type or ""
        if not content_type.startswith("application/scim+json"):
            return scim_error_response(
                415,
                "Content-Type must be application/scim+json",
                "invalidSyntax"
            )


@bp.after_request
def add_correlation_id(response):
    """Add correlation ID and auth method to response headers for tracing."""
    correlation_id = request.headers.get("X-Correlation-Id")
    if correlation_id:
        response.headers["X-Correlation-Id"] = correlation_id
    
    # Add auth method header for transparency
    auth_method = getattr(g, 'auth_method', None)
    if auth_method:
        response.headers["X-Auth-Method"] = auth_method
    
    return response


# ─────────────────────────────────────────────────────────────────────────────
# SCIM Schema Discovery Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/ServiceProviderConfig', methods=['GET'])
def service_provider_config():
    """Return SCIM ServiceProviderConfig (RFC 7643 Section 5)."""
    config = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://github.com/Alexs1004/iam-poc",
        "patch": {
            "supported": True
        },
        "bulk": {
            "supported": False,
            "maxOperations": 0,
            "maxPayloadSize": 0
        },
        "filter": {
            "supported": True,
            "maxResults": 200
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
                "name": "OAuth 2.0 Bearer Token",
                "description": "OAuth 2.0 client credentials flow",
                "specUri": "https://tools.ietf.org/html/rfc6750",
                "type": "oauthbearertoken",
                "primary": True
            }
        ]
    }
    return jsonify(config), 200


@bp.route('/ResourceTypes', methods=['GET'])
def resource_types():
    """Return supported SCIM resource types."""
    resources = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 1,
        "Resources": [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/scim/v2/Users",
                "description": "SCIM User resource for Keycloak provisioning",
                "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
                "meta": {
                    "location": f"{request.host_url.rstrip('/')}/scim/v2/ResourceTypes/User",
                    "resourceType": "ResourceType"
                }
            }
        ]
    }
    return jsonify(resources), 200


@bp.route('/Schemas', methods=['GET'])
def schemas():
    """Return SCIM schema definitions."""
    schema_list = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 1,
        "Resources": [
            {
                "id": "urn:ietf:params:scim:schemas:core:2.0:User",
                "name": "User",
                "description": "User Account",
                "attributes": [
                    {
                        "name": "userName",
                        "type": "string",
                        "multiValued": False,
                        "required": True,
                        "caseExact": False,
                        "mutability": "readWrite",
                        "returned": "default",
                        "uniqueness": "server"
                    },
                    {
                        "name": "emails",
                        "type": "complex",
                        "multiValued": True,
                        "required": False,
                        "mutability": "readWrite",
                        "returned": "default"
                    },
                    {
                        "name": "active",
                        "type": "boolean",
                        "multiValued": False,
                        "required": False,
                        "mutability": "readWrite",
                        "returned": "default"
                    }
                ],
                "meta": {
                    "resourceType": "Schema",
                    "location": f"{request.host_url.rstrip('/')}/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"
                }
            }
        ]
    }
    return jsonify(schema_list), 200


# ─────────────────────────────────────────────────────────────────────────────
# SCIM User CRUD Operations
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/Users', methods=['POST'])
def create_user():
    """Create a new user (Joiner).
    
    RFC 7644 Section 3.3: Creating Resources
    
    Security:
        Requires OAuth 2.0 Bearer Token with 'scim:write' scope (validated in before_request)
    
    Returns:
        201 Created with Location header and User resource
    """
    try:
        payload = request.get_json()
        correlation_id = request.headers.get("X-Correlation-Id")
        
        # Create user via service layer
        scim_user = provisioning_service.create_user_scim_like(payload, correlation_id)
        
        # Build Location header
        location = f"{request.host_url.rstrip('/')}/scim/v2/Users/{scim_user['id']}"
        
        response = jsonify(scim_user)
        response.status_code = 201
        response.headers["Location"] = location
        
        return response
        
    except ScimError:
        raise  # Let error handler deal with it
    except Exception as exc:
        return scim_error(500, f"Internal server error: {exc}")


@bp.route('/Users/<user_id>', methods=['GET'])
def get_user(user_id: str):
    """Retrieve a specific user by ID.
    
    RFC 7644 Section 3.4.1: Retrieving a Known Resource
    
    Security:
        Requires OAuth 2.0 Bearer Token with 'scim:read' scope (validated in before_request)
    
    Args:
        user_id: Keycloak user UUID
    
    Returns:
        200 OK with User resource
    """
    try:
        scim_user = provisioning_service.get_user_scim(user_id)
        return jsonify(scim_user), 200
        
    except ScimError:
        raise
    except Exception as exc:
        return scim_error(500, f"Internal server error: {exc}")


@bp.route('/Users', methods=['GET'])
def list_users():
    """List users with pagination and filtering.
    
    RFC 7644 Section 3.4.2: Listing Resources
    
    Security:
        Requires OAuth 2.0 Bearer Token with 'scim:read' scope (validated in before_request)
    
    Query parameters:
        - startIndex: 1-based starting index (default: 1)
        - count: Max results per page (default: 10)
        - filter: SCIM filter string (e.g., 'userName eq "alice"')
    
    Returns:
        200 OK with ListResponse
    """
    try:
        query = {
            "startIndex": request.args.get("startIndex", 1),
            "count": request.args.get("count", 10),
            "filter": request.args.get("filter", "")
        }
        
        list_response = provisioning_service.list_users_scim(query)
        return jsonify(list_response), 200
        
    except ScimError:
        raise
    except Exception as exc:
        return scim_error(500, f"Internal server error: {exc}")


@bp.route('/Users/<user_id>', methods=['PUT'])
def replace_user(user_id: str):
    """Update a user via full replacement (Mover/Leaver).
    
    RFC 7644 Section 3.5.1: Replacing with PUT
    
    Security:
        Requires OAuth 2.0 Bearer Token with 'scim:write' scope (validated in before_request)
    
    Args:
        user_id: Keycloak user UUID
    
    Returns:
        200 OK with updated User resource
    """
    return scim_error(
        501,
        "Full replace is not supported. Use PATCH (active) or DELETE.",
        "notImplemented"
    )


@bp.route('/Users/<user_id>', methods=['PATCH'])
def patch_user(user_id: str):
    """Partially update a user (active flag only).
    
    Implements minimal SCIM PatchOp (RFC 7644 Section 3.5.2) restricted to
    toggling the `active` attribute.
    """
    try:
        try:
            payload = request.get_json()
        except BadRequest:
            return scim_error(400, "Request body is not valid JSON", "invalidSyntax")
        
        if not isinstance(payload, dict):
            return scim_error(400, "Request body must be a JSON object", "invalidSyntax")
        
        schemas = payload.get("schemas")
        if schemas != ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]:
            return scim_error(400, "schemas must equal ['urn:ietf:params:scim:api:messages:2.0:PatchOp']", "invalidSyntax")
        
        operations = payload.get("Operations")
        if not isinstance(operations, list) or len(operations) != 1:
            return scim_error(400, "Exactly one operation is required", "invalidSyntax")
        
        operation = operations[0]
        if not isinstance(operation, dict):
            return scim_error(400, "Operation must be an object", "invalidSyntax")
        
        if operation.get("op") != "replace":
            return scim_error(501, "Only 'replace' operations are supported", "notImplemented")
        
        if operation.get("path") != "active":
            return scim_error(501, "Only path 'active' is supported", "notImplemented")
        
        if "value" not in operation or not isinstance(operation.get("value"), bool):
            return scim_error(400, "Operation value must be a boolean", "invalidValue")
        
        correlation_id = request.headers.get("X-Correlation-Id")
        scim_user = provisioning_service.patch_user_scim(
            user_id,
            operation["value"],
            correlation_id
        )
        return jsonify(scim_user), 200
        
    except ScimError:
        raise
    except Exception as exc:
        return scim_error(500, f"Internal server error: {exc}")


@bp.route('/Users/<user_id>', methods=['DELETE'])
def delete_user(user_id: str):
    """Soft-delete a user by disabling (Leaver).
    
    RFC 7644 Section 3.6: Deleting Resources
    
    Security:
        Requires OAuth 2.0 Bearer Token with 'scim:write' scope (validated in before_request)
    
    Args:
        user_id: Keycloak user UUID
    
    Returns:
        204 No Content
    """
    try:
        correlation_id = request.headers.get("X-Correlation-Id")
        
        provisioning_service.delete_user_scim(user_id, correlation_id)
        return '', 204
        
    except ScimError:
        raise
    except Exception as exc:
        return scim_error(500, f"Internal server error: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Optional: POST /Users/.search for Azure AD/Okta compatibility
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/Users/.search', methods=['POST'])
def search_users():
    """Search users via POST (Azure AD/Okta compatibility).
    
    This endpoint accepts the same query parameters as GET /Users but via POST body,
    which some IdPs prefer for complex filter expressions.
    
    Security:
        Requires OAuth 2.0 Bearer Token with 'scim:write' scope for POST (validated in before_request)
        Note: POST is treated as write operation for scope validation
    
    Returns:
        200 OK with ListResponse
    """
    try:
        payload = request.get_json() or {}
        
        query = {
            "startIndex": payload.get("startIndex", 1),
            "count": payload.get("count", 10),
            "filter": payload.get("filter", "")
        }
        
        list_response = provisioning_service.list_users_scim(query)
        return jsonify(list_response), 200
        
    except ScimError:
        raise
    except Exception as exc:
        return scim_error(500, f"Internal server error: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Startup Message (logged when blueprint is registered in flask_app.py)
# ─────────────────────────────────────────────────────────────────────────────
# Note: Blueprint startup logging moved to flask_app.py @app.before_first_request
