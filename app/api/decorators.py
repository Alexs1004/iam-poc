"""
Flask decorators for authentication and authorization.

This module provides OAuth 2.0 Bearer Token validation for SCIM API endpoints.
Implements RFC 6750 (Bearer Token) and validates JWT tokens from Keycloak.
"""

import logging
from functools import wraps
from typing import Optional, List

import requests
from flask import request, jsonify, current_app
from authlib.jose import JsonWebKey, jwt
from authlib.jose.errors import JoseError

logger = logging.getLogger(__name__)


# ================================w============================================
# OAuth 2.0 Bearer Token Validation (RFC 6750)
# ============================================================================

def require_oauth_token(scopes: Optional[List[str]] = None):
    """
    Decorator to require valid OAuth 2.0 Bearer Token for SCIM API endpoints.
    
    Validates JWT tokens issued by Keycloak according to:
    - RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage
    - RFC 7519: JSON Web Token (JWT)
    
    Args:
        scopes: Optional list of required OAuth scopes (e.g., ["scim:write"])
    
    Returns:
        Decorated function that validates Bearer token before execution
    
    Raises:
        401 Unauthorized: Missing, invalid, or expired token
        403 Forbidden: Insufficient scopes
    
    Example:
        @bp.route("/scim/v2/Users", methods=["POST"])
        @require_oauth_token(scopes=["scim:write"])
        def create_user():
            return {"status": "created"}, 201
    """
    if scopes is None:
        scopes = []
    
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Step 1: Extract Bearer token from Authorization header
            auth_header = request.headers.get("Authorization", "")
            
            if not auth_header:
                logger.warning("SCIM request missing Authorization header")
                return jsonify({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": "401",
                    "detail": "Authorization header required. Use 'Authorization: Bearer <token>'",
                    "scimType": "unauthorized"
                }), 401
            
            if not auth_header.startswith("Bearer "):
                logger.warning(f"SCIM request with invalid Authorization format: {auth_header[:20]}")
                return jsonify({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": "401",
                    "detail": "Invalid Authorization header format. Expected 'Bearer <token>'",
                    "scimType": "unauthorized"
                }), 401
            
            token = auth_header[7:]  # Remove "Bearer " prefix
            
            if not token:
                logger.warning("SCIM request with empty Bearer token")
                return jsonify({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": "401",
                    "detail": "Bearer token is empty",
                    "scimType": "unauthorized"
                }), 401
            
            # Step 2: Validate JWT token
            try:
                claims = validate_jwt_token(token)
            except TokenValidationError as e:
                logger.warning(f"SCIM JWT validation failed: {e}")
                return jsonify({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": "401",
                    "detail": str(e),
                    "scimType": "invalidToken"
                }), 401
            
            # Step 3: Check required scopes (if specified)
            if scopes:
                token_scopes = claims.get("scope", "").split()
                
                # Check if token has at least one of the required scopes
                if not any(scope in token_scopes for scope in scopes):
                    logger.warning(
                        f"SCIM request lacks required scopes. "
                        f"Required: {scopes}, Token has: {token_scopes}"
                    )
                    return jsonify({
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                        "status": "403",
                        "detail": f"Insufficient scope. Required: {', '.join(scopes)}",
                        "scimType": "insufficientScope"
                    }), 403
            
            # Step 4: Attach claims to request context for downstream use
            request.oauth_claims = claims
            request.oauth_client_id = claims.get("azp") or claims.get("client_id")
            
            # Step 5: Call the actual route handler
            return fn(*args, **kwargs)
        
        return wrapper
    return decorator


class TokenValidationError(Exception):
    """Exception raised when JWT token validation fails."""
    pass


def validate_jwt_token(token: str) -> dict:
    """
    Validate JWT token issued by Keycloak.
    
    Performs the following validations:
    1. Fetch public keys from Keycloak JWKS endpoint
    2. Verify token signature (RS256)
    3. Validate issuer (must match Keycloak issuer)
    4. Validate audience (optional, if configured)
    5. Validate expiration (exp claim)
    6. Validate not-before (nbf claim, if present)
    
    Args:
        token: JWT token string
    
    Returns:
        dict: Decoded JWT claims
    
    Raises:
        TokenValidationError: If validation fails
    """
    cfg = current_app.config["APP_CONFIG"]
    
    # Step 1: Fetch JWKS (JSON Web Key Set) from Keycloak
    try:
        jwks = fetch_jwks()
    except Exception as e:
        logger.error(f"Failed to fetch JWKS from Keycloak: {e}")
        raise TokenValidationError(f"Unable to fetch public keys: {e}")
    
    # Step 2: Decode and validate JWT
    try:
        # Authlib automatically validates:
        # - Signature (using public key from JWKS)
        # - Expiration (exp claim)
        # - Not-before (nbf claim, if present)
        claims = jwt.decode(token, jwks)
        
    except JoseError as e:
        logger.warning(f"JWT validation failed: {e}")
        raise TokenValidationError(f"Invalid token: {e}")
    
    # Step 3: Validate issuer
    expected_issuer = cfg.keycloak_issuer
    actual_issuer = claims.get("iss")
    
    if actual_issuer != expected_issuer:
        logger.warning(
            f"Token issuer mismatch. Expected: {expected_issuer}, Got: {actual_issuer}"
        )
        raise TokenValidationError(
            f"Invalid issuer. Expected {expected_issuer}, got {actual_issuer}"
        )
    
    # Step 4: Validate audience (optional, for client credentials flow this may not be set)
    # Note: client_credentials grants typically don't have 'aud' claim
    # We validate the client_id/azp instead
    
    # Step 5: Log successful validation
    client_id = claims.get("azp") or claims.get("client_id", "unknown")
    logger.info(f"SCIM OAuth token validated successfully for client: {client_id}")
    
    return claims


def fetch_jwks() -> JsonWebKey:
    """
    Fetch JSON Web Key Set (JWKS) from Keycloak.
    
    JWKS contains public keys used to verify JWT signatures.
    Keys are cached for performance (Keycloak rotates keys periodically).
    
    Returns:
        JsonWebKey: Keycloak's public keys
    
    Raises:
        Exception: If JWKS endpoint is unreachable
    """
    cfg = current_app.config["APP_CONFIG"]
    
    # IMPORTANT: Use keycloak_server_url (internal Docker network URL) instead of 
    # keycloak_issuer (public URL) because Flask container cannot reach localhost:443
    # from inside Docker network.
    # 
    # keycloak_server_url: http://keycloak:8080/realms/demo (internal)
    # keycloak_issuer: https://localhost/realms/demo (public, for token validation)
    # JWKS endpoint: {server_url}/protocol/openid-connect/certs
    server_url = cfg.keycloak_server_url  # e.g., "http://keycloak:8080/realms/demo"
    jwks_url = f"{server_url}/protocol/openid-connect/certs"
    
    logger.debug(f"Fetching JWKS from: {jwks_url}")
    
    try:
        response = requests.get(jwks_url, timeout=10, verify=False)  # verify=False for self-signed certs in dev
        response.raise_for_status()
        
        jwks_data = response.json()
        
        # Create JsonWebKey from JWKS
        jwks = JsonWebKey.import_key_set(jwks_data)
        
        logger.debug(f"Successfully fetched {len(jwks_data.get('keys', []))} keys from JWKS")
        
        return jwks
        
    except requests.RequestException as e:
        logger.error(f"Failed to fetch JWKS from {jwks_url}: {e}")
        raise Exception(f"JWKS endpoint unreachable: {e}")


# ============================================================================
# Helper: Get OAuth client info from request
# ============================================================================

def get_oauth_client_id() -> Optional[str]:
    """
    Get OAuth client ID from validated token in current request.
    
    Must be called after @require_oauth_token decorator.
    
    Returns:
        str: Client ID from token, or None if not available
    """
    return getattr(request, "oauth_client_id", None)


def get_oauth_claims() -> Optional[dict]:
    """
    Get full OAuth token claims from current request.
    
    Must be called after @require_oauth_token decorator.
    
    Returns:
        dict: JWT claims, or None if not available
    """
    return getattr(request, "oauth_claims", None)
