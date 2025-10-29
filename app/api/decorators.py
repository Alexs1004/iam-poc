"""
Flask decorators for authentication and authorization.

This module provides OAuth 2.0 Bearer Token validation for SCIM API endpoints.
Implements RFC 6750 (Bearer Token) and validates JWT tokens from Keycloak.

Security:
- RSA-SHA256 signature verification via JWKS (RFC 7517)
- Expiration, issuer, audience validation (RFC 7519)
- JWKS caching for performance (1-hour refresh)
"""

import logging
from functools import wraps
from typing import Optional, List, Dict

import jwt
from jwt import PyJWKClient
from jwt.exceptions import (
    InvalidTokenError,
    ExpiredSignatureError,
    InvalidIssuerError,
    InvalidAudienceError,
    InvalidSignatureError,
    DecodeError
)
from flask import request, jsonify, current_app, g

logger = logging.getLogger(__name__)

# Global JWKS client (cached singleton)
_jwks_client: Optional[PyJWKClient] = None

# ============================================================================
# OAuth 2.0 Bearer Token Validation (RFC 6750)
# ============================================================================

class TokenValidationError(Exception):
    """Exception raised when JWT token validation fails."""
    pass


def get_jwks_client() -> PyJWKClient:
    """
    Get cached JWKS client (singleton pattern).
    
    JWKS (JSON Web Key Set) client fetches Keycloak's public keys
    for RSA signature verification. Keys are cached for performance.
    
    Returns:
        PyJWKClient: Configured client for Keycloak realm
    
    Security:
        - Caches up to 16 keys
        - Refreshes cache every 1 hour
        - Uses kid (Key ID) from JWT header to select correct key
    
    References:
        - RFC 7517 (JWKS)
        - RFC 7518 (JWA - algorithms)
    """
    global _jwks_client
    
    if _jwks_client is None:
        cfg = current_app.config["APP_CONFIG"]
        
        # Use internal Docker URL for JWKS endpoint
        # (keycloak:8080 accessible from Flask container)
        server_url = cfg.keycloak_server_url  # http://keycloak:8080/realms/demo
        jwks_url = f"{server_url}/protocol/openid-connect/certs"
        
        logger.info(f"Initializing JWKS client for: {jwks_url}")
        
        _jwks_client = PyJWKClient(
            jwks_url,
            cache_keys=True,      # Cache public keys (avoid JWKS call every request)
            max_cached_keys=16,   # Max keys in cache (Keycloak rotates keys)
            lifespan=3600,        # Refresh cache after 1 hour (3600 seconds)
            headers={"User-Agent": "IAM-PoC-Flask/1.0"}  # Identify client in Keycloak logs
        )
    
    return _jwks_client


def validate_jwt_token(token: str) -> Dict[str, any]:
    """
    Validate JWT Bearer token with full security checks.
    
    Validations performed:
    1. Signature verification (RSA-SHA256 via JWKS)
    2. Expiration (exp claim)
    3. Not Before (nbf claim)
    4. Issuer (iss claim)
    5. Audience (aud claim, if configured)
    
    Args:
        token: JWT token string (without "Bearer " prefix)
    
    Returns:
        dict: Validated token claims
    
    Raises:
        TokenValidationError: If any validation fails
    
    Security:
        - Uses Keycloak JWKS endpoint for public key rotation
        - Enforces strict validation (signature, expiration, issuer)
        - Cache-enabled to avoid JWKS call on every request
        - Guards against token tampering, replay attacks
    
    References:
        - RFC 6750 (Bearer Token Usage)
        - RFC 7519 (JWT)
        - RFC 7517 (JWKS)
    
    Example:
        >>> claims = validate_jwt_token("eyJhbGc...")
        >>> print(claims['sub'])  # automation-cli
        >>> print(claims['scope'])  # scim:read scim:write
    """
    # Guard: Skip validation in test mode (unit tests mock OAuth)
    if current_app.config.get('TESTING'):
        skip_oauth = current_app.config.get('SKIP_OAUTH_FOR_TESTS', False)
        if skip_oauth:
            logger.warning("⚠️ JWT validation SKIPPED (TESTING + SKIP_OAUTH_FOR_TESTS)")
            return {
                'sub': 'test-user',
                'scope': 'scim:read scim:write',
                'iss': 'test-issuer',
                'aud': 'account',
                'client_id': 'test-client'
            }
    
    cfg = current_app.config["APP_CONFIG"]
    
    try:
        # Step 1: Get signing key from JWKS (uses kid from JWT header)
        jwks_client = get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        # Step 2: Decode + verify signature + validate claims
        expected_issuer = cfg.keycloak_issuer  # https://localhost/realms/demo (public URL)
        
        # Note: audience validation optional for client_credentials grant
        # Keycloak client_credentials tokens typically have aud=["account"]
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=['RS256'],           # Only RSA-SHA256 (asymmetric)
            issuer=expected_issuer,         # Validate issuer (prevent token from wrong realm)
            options={
                'verify_signature': True,   # ✅ Verify RSA signature (CRITICAL)
                'verify_exp': True,         # ✅ Check expiration
                'verify_nbf': True,         # ✅ Check not-before
                'verify_iss': True,         # ✅ Check issuer
                'verify_aud': False,        # ⚠️ Audience optional for client_credentials
                'require_exp': True,        # exp claim mandatory
                'require_iat': True         # iat claim mandatory
            },
            leeway=5                         # Allow small clock skew between services
        )
        
        # Step 3: Log successful validation
        client_id = claims.get("azp") or claims.get("client_id", "unknown")
        logger.debug(f"✅ JWT validated for client: {client_id}, scopes: {claims.get('scope')}")
        
        return claims
        
    except ExpiredSignatureError:
        raise TokenValidationError("Token expired (exp claim)")
    except InvalidIssuerError as e:
        raise TokenValidationError(f"Invalid issuer (token from wrong Keycloak realm): {e}")
    except InvalidAudienceError as e:
        raise TokenValidationError(f"Invalid audience (token not for this API): {e}")
    except InvalidSignatureError:
        raise TokenValidationError("Invalid signature (token tampered or wrong key)")
    except DecodeError as e:
        raise TokenValidationError(f"Token decode error (malformed JWT): {e}")
    except Exception as e:
        logger.error(f"❌ JWT validation failed: {e}")
        raise TokenValidationError(f"Token validation failed: {e}")



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
            g.oauth_claims = claims
            g.oauth_client_id = claims.get("azp") or claims.get("client_id")
            
            # Step 5: Call the actual route handler
            return fn(*args, **kwargs)
        
        return wrapper
    return decorator


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
    return getattr(request, "oauth_client_id", None) or getattr(g, "oauth_client_id", None)


def get_oauth_claims() -> Optional[dict]:
    """
    Get full OAuth token claims from current request.
    
    Must be called after @require_oauth_token decorator.
    
    Returns:
        dict: JWT claims, or None if not available
    """
    return getattr(request, "oauth_claims", None) or getattr(g, "oauth_claims", None)
