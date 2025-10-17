"""SCIM 2.0 API endpoints (RFC 7644) for user provisioning.

This module provides a minimal SCIM-compliant REST API that delegates all
business logic to the unified provisioning_service layer.

Architecture:
    SCIM API (/scim/v2/*) -> app/provisioning_service.py -> scripts/jml.py -> Keycloak
"""

from __future__ import annotations
import os
from flask import Blueprint, request, jsonify, Response
from app import provisioning_service
from app.provisioning_service import ScimError

# SCIM 2.0 Blueprint
scim = Blueprint('scim', __name__, url_prefix='/scim/v2')

# Configuration
JSON_MAX_SIZE_BYTES = 65536  # 64 KB


# ─────────────────────────────────────────────────────────────────────────────
# Error Handler
# ─────────────────────────────────────────────────────────────────────────────

def scim_error(status: int, detail: str, scim_type: str = None) -> tuple[Response, int]:
    """Create SCIM error response.
    
    Args:
        status: HTTP status code
        detail: Human-readable error description
        scim_type: Optional SCIM error type (uniqueness, invalidValue, etc.)
    
    Returns:
        Tuple of (JSON response, status code)
    """
    error = ScimError(status, detail, scim_type)
    return jsonify(error.to_dict()), status


@scim.errorhandler(ScimError)
def handle_scim_error(error: ScimError):
    """Global error handler for ScimError exceptions."""
    return jsonify(error.to_dict()), error.status


@scim.errorhandler(413)
def handle_request_too_large(error):
    """Handle payload too large errors."""
    return scim_error(413, "Request payload exceeds maximum allowed size (64 KB)", "invalidValue")


# ─────────────────────────────────────────────────────────────────────────────
# Request Validation Middleware
# ─────────────────────────────────────────────────────────────────────────────

@scim.before_request
def validate_request():
    """Validate request size and content type for mutating operations."""
    # Check payload size
    if request.content_length and request.content_length > JSON_MAX_SIZE_BYTES:
        return scim_error(413, "Request payload too large", "invalidValue")
    
    # Validate Content-Type for POST/PUT
    if request.method in ("POST", "PUT"):
        content_type = request.content_type or ""
        if not content_type.startswith("application/scim+json"):
            return scim_error(
                400,
                "Content-Type must be application/scim+json",
                "invalidSyntax"
            )


@scim.after_request
def add_correlation_id(response):
    """Add correlation ID to response headers for tracing."""
    correlation_id = request.headers.get("X-Correlation-Id")
    if correlation_id:
        response.headers["X-Correlation-Id"] = correlation_id
    return response


# ─────────────────────────────────────────────────────────────────────────────
# SCIM Schema Discovery Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@scim.route('/ServiceProviderConfig', methods=['GET'])
def service_provider_config():
    """Return SCIM ServiceProviderConfig (RFC 7643 Section 5)."""
    config = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://github.com/Alexs1004/iam-poc",
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


@scim.route('/ResourceTypes', methods=['GET'])
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


@scim.route('/Schemas', methods=['GET'])
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

@scim.route('/Users', methods=['POST'])
def create_user():
    """Create a new user (Joiner).
    
    RFC 7644 Section 3.3: Creating Resources
    
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


@scim.route('/Users/<user_id>', methods=['GET'])
def get_user(user_id: str):
    """Retrieve a specific user by ID.
    
    RFC 7644 Section 3.4.1: Retrieving a Known Resource
    
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


@scim.route('/Users', methods=['GET'])
def list_users():
    """List users with pagination and filtering.
    
    RFC 7644 Section 3.4.2: Listing Resources
    
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


@scim.route('/Users/<user_id>', methods=['PUT'])
def replace_user(user_id: str):
    """Update a user via full replacement (Mover/Leaver).
    
    RFC 7644 Section 3.5.1: Replacing with PUT
    
    Args:
        user_id: Keycloak user UUID
    
    Returns:
        200 OK with updated User resource
    """
    try:
        payload = request.get_json()
        correlation_id = request.headers.get("X-Correlation-Id")
        
        scim_user = provisioning_service.replace_user_scim(user_id, payload, correlation_id)
        return jsonify(scim_user), 200
        
    except ScimError:
        raise
    except Exception as exc:
        return scim_error(500, f"Internal server error: {exc}")


@scim.route('/Users/<user_id>', methods=['DELETE'])
def delete_user(user_id: str):
    """Soft-delete a user by disabling (Leaver).
    
    RFC 7644 Section 3.6: Deleting Resources
    
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

@scim.route('/Users/.search', methods=['POST'])
def search_users():
    """Search users via POST (Azure AD/Okta compatibility).
    
    This endpoint accepts the same query parameters as GET /Users but via POST body,
    which some IdPs prefer for complex filter expressions.
    
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
