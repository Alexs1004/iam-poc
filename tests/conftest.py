"""Pytest shared fixtures for security tests."""
import os
import pathlib
import sys
import json
import base64
import time
from typing import Optional
from unittest.mock import Mock

# Add project root to Python path
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Configure test environment BEFORE any app imports
# Priority: 1) Explicit DEMO_MODE env var, 2) Use cached Azure secrets, 3) Fall back to DEMO_MODE
if "DEMO_MODE" not in os.environ:
    # Only auto-detect mode if not explicitly set
    secrets_dir = ROOT / ".runtime" / "secrets"
    if secrets_dir.exists() and secrets_dir.is_dir():
        # Production mode: Load secrets from Azure Key Vault cache (host path)
        os.environ.setdefault("DEMO_MODE", "false")
        os.environ.setdefault("AZURE_USE_KEYVAULT", "false")  # Use cached secrets, not live KV
        
        # Set required production config (tests run on localhost)
        os.environ.setdefault("TRUSTED_PROXY_IPS", "127.0.0.1/32,::1/128")
        os.environ.setdefault("KEYCLOAK_URL", "https://localhost")  # Public base URL
        os.environ.setdefault("KEYCLOAK_ISSUER", "https://localhost/realms/demo")
        os.environ.setdefault("OIDC_CLIENT_ID", "flask-app")
        os.environ.setdefault("OIDC_REDIRECT_URI", "https://localhost/callback")
        os.environ.setdefault("POST_LOGOUT_REDIRECT_URI", "https://localhost")
        os.environ.setdefault("KEYCLOAK_SERVICE_REALM", "demo")
        os.environ.setdefault("KEYCLOAK_SERVICE_CLIENT_ID", "automation-cli")
        os.environ.setdefault("KEYCLOAK_ADMIN", "admin")  # Non-sensitive username
        
        # Load all secret files into environment variables
        for secret_file in secrets_dir.iterdir():
            if secret_file.is_file():
                secret_value = secret_file.read_text().strip()
                # Map file names to env vars: keycloak-admin-password → KEYCLOAK_ADMIN_PASSWORD
                env_var = secret_file.name.replace('-', '_').upper()
                if env_var not in os.environ:
                    os.environ[env_var] = secret_value
    else:
        # Demo mode: App will generate temporary secrets
        os.environ.setdefault("DEMO_MODE", "true")

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from authlib.jose import JsonWebKey, jwt as authlib_jwt

from app.flask_app import create_app


# ─────────────────────────────────────────────────────────────────────────────
# Network Guard Rails
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _mock_oidc_endpoints(monkeypatch, request):
    """
    Prevent unit tests from hitting live OIDC endpoints.

    Integration tests are explicitly marked with @pytest.mark.integration and
    are allowed to perform real HTTP calls by skipping this fixture.
    """
    if request.node.get_closest_marker("integration"):
        return

    class _StubResponse:
        def __init__(self, payload: dict, status_code: int = 200):
            self._payload = payload
            self.status_code = status_code
            self.text = json.dumps(payload)

        def json(self):
            return self._payload

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.HTTPError(response=self)

    def _stub_post(url, *args, **kwargs):
        if url.endswith("/protocol/openid-connect/token"):
            return _StubResponse({"access_token": "test-token", "expires_in": 300})
        raise RuntimeError(f"Unexpected HTTP POST in unit test: {url}")

    def _stub_get(url, *args, **kwargs):
        if url.endswith("/.well-known/openid-configuration"):
            return _StubResponse({"jwks_uri": "http://localhost:8080/realms/demo/protocol/openid-connect/certs"})
        if url.endswith("/protocol/openid-connect/certs"):
            return _StubResponse({"keys": []})
        raise RuntimeError(f"Unexpected HTTP GET in unit test: {url}")

    monkeypatch.setattr(requests, "post", _stub_post)
    monkeypatch.setattr(requests, "get", _stub_get)


# ─────────────────────────────────────────────────────────────────────────────
# Flask Test Client
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture()
def client(monkeypatch):
    """Flask test client with stubbed network requests."""
    flask_app = create_app()
    flask_app.config.update(TESTING=True)

    class _StubResponse:
        def __init__(self, payload: dict, status_code: int = 200):
            self._payload = payload
            self.status_code = status_code

        def json(self):
            return self._payload

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.HTTPError(response=self)

    def _stub_get(url, *args, **kwargs):
        if url.endswith("/.well-known/openid-configuration"):
            return _StubResponse({"jwks_uri": "http://localhost:8080/realms/demo/protocol/openid-connect/certs"})
        if url.endswith("/protocol/openid-connect/certs"):
            return _StubResponse({"keys": []})
        raise RuntimeError(f"Unexpected network access in tests: {url}")

    monkeypatch.setattr(requests, "get", _stub_get)

    with flask_app.test_client() as client:
        with flask_app.app_context():
            yield client


# ─────────────────────────────────────────────────────────────────────────────
# RSA Key Pair for JWT Testing
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(scope="session")
def rsa_key_pair():
    """Generate RSA key pair for JWT signing in tests."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return {
        "private_key": private_key,
        "private_pem": private_pem,
        "public_key": public_key,
        "public_pem": public_pem,
    }


@pytest.fixture()
def mock_jwks_endpoint(monkeypatch, rsa_key_pair):
    """Mock JWKS endpoint with RSA public key."""
    
    class JWKSEndpoint:
        def __init__(self):
            self.keys = []
            self.fetch_count = 0
            # Import public key as JWK
            jwk = JsonWebKey.import_key(rsa_key_pair["public_pem"], {"kty": "RSA"})
            # Convert to dict and add kid/use/alg
            jwk_dict = jwk.as_dict()
            jwk_dict["kid"] = "default-key-id"
            jwk_dict["use"] = "sig"
            jwk_dict["alg"] = "RS256"
            self.keys = [jwk_dict]
        
        def set_keys(self, keys: list[dict]):
            """Set custom JWKS keys."""
            self.keys = keys
        
        def get_jwks(self):
            """Return current JWKS."""
            self.fetch_count += 1
            return {"keys": self.keys}
    
    endpoint = JWKSEndpoint()
    
    def _mock_requests_get(url, *args, **kwargs):
        if url.endswith("/protocol/openid-connect/certs"):
            endpoint.fetch_count += 1
            return Mock(
                status_code=200,
                json=lambda: endpoint.get_jwks(),
                raise_for_status=lambda: None
            )
        if url.endswith("/.well-known/openid-configuration"):
            return Mock(
                status_code=200,
                json=lambda: {"jwks_uri": "http://localhost:8080/realms/demo/protocol/openid-connect/certs"},
                raise_for_status=lambda: None
            )
        raise RuntimeError(f"Unexpected URL in test: {url}")
    
    monkeypatch.setattr(requests, "get", _mock_requests_get)
    
    return endpoint


# ─────────────────────────────────────────────────────────────────────────────
# JWT Token Helpers
# ─────────────────────────────────────────────────────────────────────────────
def create_valid_jwt(
    rsa_key_pair: dict,
    issuer: str = "https://localhost/realms/demo",
    audience: str = "iam-poc-ui",
    sub: str = "user-123",
    username: str = "alice",
    roles: Optional[list[str]] = None,
    exp_offset: int = 3600,
    nbf_offset: int = 0,
    kid: str = "default-key-id",
) -> str:
    """Create a valid RS256-signed JWT for testing."""
    if roles is None:
        roles = ["analyst"]
    
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "exp": now + exp_offset,
        "nbf": now + nbf_offset,
        "iat": now,
        "preferred_username": username,
        "realm_access": {"roles": roles},
    }
    
    private_key = rsa_key_pair["private_key"]
    token = authlib_jwt.encode(header, payload, private_key)
    return token.decode("utf-8") if isinstance(token, bytes) else token


def create_unsigned_jwt(
    issuer: str = "https://localhost/realms/demo",
    audience: str = "iam-poc-ui",
    roles: Optional[list[str]] = None,
) -> str:
    """Create unsigned JWT with alg:none (security vulnerability test)."""
    if roles is None:
        roles = ["realm-admin"]  # Attempt privilege escalation
    
    now = int(time.time())
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": "attacker",
        "exp": now + 3600,
        "preferred_username": "attacker",
        "realm_access": {"roles": roles},
    }
    
    # Manually construct unsigned JWT
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}."


# ─────────────────────────────────────────────────────────────────────────────
# Authentication Helpers
# ─────────────────────────────────────────────────────────────────────────────
def authenticate_with_roles(client, roles: list[str], username: str = "alice"):
    """Authenticate test client with specific roles."""
    with client.session_transaction() as session:
        session["token"] = {"access_token": "stub", "id_token": "stub"}
        session["userinfo"] = {
            "preferred_username": username,
            "realm_access": {"roles": roles},
        }
        session["id_claims"] = {
            "preferred_username": username,
            "realm_access": {"roles": roles},
        }


def get_csrf_token(client) -> str:
    """Get CSRF token from session."""
    client.get("/admin")
    with client.session_transaction() as session:
        return session.get("_csrf_token", "")


# ─────────────────────────────────────────────────────────────────────────────
# Pytest Configuration
# ─────────────────────────────────────────────────────────────────────────────
def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (requires running stack)"
    )
    config.addinivalue_line(
        "markers", "critical: marks tests as critical security tests (P0 priority)"
    )
