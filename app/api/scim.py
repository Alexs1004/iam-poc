"""SCIM 2.0 API endpoints (RFC 7644) for user provisioning.

This module provides a minimal SCIM-compliant REST API that delegates all
business logic to the unified provisioning_service layer.

Architecture:
    SCIM API (/scim/v2/*) -> app/provisioning_service.py -> scripts/jml.py -> Keycloak

Security:
    - OAuth 2.0 Bearer Token authentication (RFC 6750) via @require_oauth_token decorator
    - Read operations require 'scim:read' scope
    - Write operations require 'scim:write' scope
    - Discovery endpoints (ServiceProviderConfig, Schemas) are public
"""

from __future__ import annotations
import os
from flask import Blueprint, request, jsonify, Response
from werkzeug.exceptions import BadRequest
from app.core import provisioning_service
from app.core.provisioning_service import ScimError
from app.api.decorators import validate_jwt_token, TokenValidationError
from app.api.decorators import require_oauth_token

# SCIM 2.0 Blueprint
bp = Blueprint('scim', __name__, url_prefix='/scim/v2')

# Configuration
JSON_MAX_SIZE_BYTES = 65536  # 64 KB


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
    """Validate OAuth, request size, and content type."""
    # Skip validation in test mode IF explicitly requested (for unit tests that mock provisioning)
    # OAuth validation tests will NOT set this variable
    from flask import current_app
    import os
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
    
    # 1. Validate OAuth Bearer Token (RFC 6750)
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        return scim_error_response(401, "Authorization header missing. Provide 'Authorization: Bearer <token>'.", "unauthorized")
    
    if not auth_header.startswith("Bearer "):
        return scim_error_response(401, "Authorization header must use Bearer token scheme: 'Authorization: Bearer <token>'.", "unauthorized")
    
    token = auth_header[7:].strip()  # Remove "Bearer " prefix
    if not token:
        return scim_error_response(401, "Bearer token is empty.", "unauthorized")
    
    try:
        oauth_claims = validate_jwt_token(token)
        
        # Store claims in request context for route handlers
        from flask import g
        g.oauth_claims = oauth_claims
        g.oauth_client_id = oauth_claims.get("client_id") or oauth_claims.get("sub")
        
        # 2. Validate scope based on HTTP method
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
        return scim_error_response(401, str(e), "unauthorized")
    except Exception as e:
        return scim_error_response(401, f"Token validation failed: {e}", "unauthorized")
    
    # 3. Check payload size
    if request.content_length and request.content_length > JSON_MAX_SIZE_BYTES:
        return scim_error_response(413, "Request payload too large", "invalidValue")
    
    # 4. Validate Content-Type for payload-bearing methods
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
    """Add correlation ID to response headers for tracing."""
    correlation_id = request.headers.get("X-Correlation-Id")
    if correlation_id:
        response.headers["X-Correlation-Id"] = correlation_id
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
