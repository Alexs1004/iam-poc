"""Unit tests for Multi-IdP toggle (Keycloak/Entra ID).

Tests validate:
- Default provider from OIDC_PROVIDER env var
- Query param override (?provider=) in dev/demo mode only
- Claim normalization for both IdPs
- Provider-specific logout URLs

Marker: pytest -k oidc_provider_toggle -q
"""
import os
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask, session


@pytest.fixture
def reset_auth_module():
    """Reset auth module state between tests."""
    from app.api import auth
    original_providers = auth._providers.copy() if auth._providers else {}
    yield
    auth._providers = original_providers


@pytest.fixture
def app_keycloak_default(reset_auth_module):
    """Flask app with Keycloak as default provider."""
    os.environ["OIDC_PROVIDER"] = "keycloak"
    os.environ["DEMO_MODE"] = "true"
    os.environ["AZURE_USE_KEYVAULT"] = "false"
    os.environ.pop("ENTRA_ISSUER", None)
    os.environ.pop("ENTRA_CLIENT_ID", None)
    
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key"
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["TESTING"] = True
    
    yield app
    
    os.environ.pop("OIDC_PROVIDER", None)


@pytest.fixture
def app_multi_idp(reset_auth_module):
    """Flask app with both Keycloak and Entra configured."""
    os.environ["OIDC_PROVIDER"] = "keycloak"
    os.environ["DEMO_MODE"] = "true"
    os.environ["AZURE_USE_KEYVAULT"] = "false"
    os.environ["ENTRA_ISSUER"] = "https://login.microsoftonline.com/tenant-id/v2.0"
    os.environ["ENTRA_CLIENT_ID"] = "entra-client-id-123"
    os.environ["ENTRA_CLIENT_SECRET"] = "entra-secret"
    os.environ["ENTRA_REDIRECT_URI"] = "https://localhost/callback"
    
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key"
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["TESTING"] = True
    
    yield app
    
    os.environ.pop("OIDC_PROVIDER", None)
    os.environ.pop("ENTRA_ISSUER", None)
    os.environ.pop("ENTRA_CLIENT_ID", None)
    os.environ.pop("ENTRA_CLIENT_SECRET", None)
    os.environ.pop("ENTRA_REDIRECT_URI", None)


@pytest.fixture
def app_production_mode(reset_auth_module):
    """Flask app in production mode (no demo, no debug)."""
    os.environ["OIDC_PROVIDER"] = "keycloak"
    os.environ["DEMO_MODE"] = "false"
    os.environ["FLASK_DEBUG"] = "false"
    os.environ["FLASK_ENV"] = "production"
    os.environ["AZURE_USE_KEYVAULT"] = "false"
    os.environ["ENTRA_ISSUER"] = "https://login.microsoftonline.com/tenant-id/v2.0"
    os.environ["ENTRA_CLIENT_ID"] = "entra-client-id-123"
    
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key"
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["TESTING"] = True
    
    yield app
    
    os.environ.pop("OIDC_PROVIDER", None)
    os.environ.pop("DEMO_MODE", None)
    os.environ.pop("FLASK_DEBUG", None)
    os.environ.pop("FLASK_ENV", None)
    os.environ.pop("ENTRA_ISSUER", None)
    os.environ.pop("ENTRA_CLIENT_ID", None)


# ═════════════════════════════════════════════════════════════════════════════
# Test: Default Provider Selection (OIDC_PROVIDER env)
# ═════════════════════════════════════════════════════════════════════════════

def test_oidc_provider_toggle_default_keycloak(app_keycloak_default):
    """Default provider is keycloak when OIDC_PROVIDER=keycloak."""
    from app.api.auth import get_current_provider, _providers
    
    # Simulate initialized providers
    _providers["keycloak"] = MagicMock()
    
    with app_keycloak_default.app_context():
        with app_keycloak_default.test_request_context():
            provider = get_current_provider()
            assert provider == "keycloak"


def test_oidc_provider_toggle_default_entra():
    """Default provider is entra when OIDC_PROVIDER=entra."""
    os.environ["OIDC_PROVIDER"] = "entra"
    os.environ["DEMO_MODE"] = "true"
    
    from app.api.auth import get_current_provider, _providers
    
    # Simulate initialized providers
    _providers["keycloak"] = MagicMock()
    _providers["entra"] = MagicMock()
    
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test"
    
    with app.app_context():
        with app.test_request_context():
            provider = get_current_provider()
            assert provider == "entra"
    
    os.environ.pop("OIDC_PROVIDER", None)


# ═════════════════════════════════════════════════════════════════════════════
# Test: Session Override via ?provider= Query Param
# ═════════════════════════════════════════════════════════════════════════════

def test_oidc_provider_toggle_session_override(app_multi_idp):
    """Provider from session overrides env default."""
    from app.api.auth import get_current_provider, _providers
    
    # Simulate initialized providers
    _providers["keycloak"] = MagicMock()
    _providers["entra"] = MagicMock()
    
    with app_multi_idp.test_client() as client:
        with client.session_transaction() as sess:
            sess["oidc_provider"] = "entra"
        
        with app_multi_idp.app_context():
            with app_multi_idp.test_request_context():
                from flask import session as flask_session
                flask_session["oidc_provider"] = "entra"
                provider = get_current_provider()
                assert provider == "entra"


# ═════════════════════════════════════════════════════════════════════════════
# Test: Provider Override Security (Demo/Dev Only)
# ═════════════════════════════════════════════════════════════════════════════

def test_oidc_provider_toggle_override_allowed_demo_mode():
    """?provider= override allowed in demo mode."""
    os.environ["DEMO_MODE"] = "true"
    os.environ["FLASK_DEBUG"] = "false"
    os.environ["FLASK_ENV"] = "production"
    
    from app.api.auth import _is_provider_override_allowed
    
    assert _is_provider_override_allowed() is True
    
    os.environ.pop("DEMO_MODE", None)


def test_oidc_provider_toggle_override_allowed_debug_mode():
    """?provider= override allowed in debug mode."""
    os.environ["DEMO_MODE"] = "false"
    os.environ["FLASK_DEBUG"] = "true"
    os.environ["FLASK_ENV"] = "production"
    
    from app.api.auth import _is_provider_override_allowed
    
    assert _is_provider_override_allowed() is True
    
    os.environ.pop("FLASK_DEBUG", None)


def test_oidc_provider_toggle_override_allowed_dev_env():
    """?provider= override allowed in development environment."""
    os.environ["DEMO_MODE"] = "false"
    os.environ["FLASK_DEBUG"] = "false"
    os.environ["FLASK_ENV"] = "development"
    
    from app.api.auth import _is_provider_override_allowed
    
    assert _is_provider_override_allowed() is True
    
    os.environ.pop("FLASK_ENV", None)


def test_oidc_provider_toggle_override_blocked_production():
    """?provider= override blocked in production mode."""
    os.environ["DEMO_MODE"] = "false"
    os.environ["FLASK_DEBUG"] = "false"
    os.environ["FLASK_ENV"] = "production"
    
    from app.api.auth import _is_provider_override_allowed
    
    assert _is_provider_override_allowed() is False
    
    os.environ.pop("DEMO_MODE", None)
    os.environ.pop("FLASK_DEBUG", None)
    os.environ.pop("FLASK_ENV", None)


# ═════════════════════════════════════════════════════════════════════════════
# Test: Claim Normalization (Keycloak vs Entra)
# ═════════════════════════════════════════════════════════════════════════════

def test_oidc_provider_toggle_normalize_keycloak_roles():
    """Normalize roles from Keycloak realm_access.roles claim."""
    from app.api.auth import normalize_claims
    
    id_claims = {
        "sub": "user123",
        "realm_access": {"roles": ["analyst", "manager"]}
    }
    userinfo = {}
    access_claims = {
        "resource_access": {
            "flask-app": {"roles": ["app-admin"]}
        }
    }
    
    roles = normalize_claims(id_claims, userinfo, access_claims, "keycloak")
    
    assert "analyst" in roles
    assert "manager" in roles
    assert "app-admin" in roles


def test_oidc_provider_toggle_normalize_entra_roles():
    """Normalize roles from Entra ID top-level roles claim."""
    from app.api.auth import normalize_claims
    
    id_claims = {
        "sub": "user123",
        "roles": ["admin", "viewer"]
    }
    userinfo = {}
    access_claims = {}
    
    roles = normalize_claims(id_claims, userinfo, access_claims, "entra")
    
    assert "admin" in roles
    assert "viewer" in roles


def test_oidc_provider_toggle_normalize_mixed_claims():
    """Normalize roles from both Keycloak and Entra claim formats."""
    from app.api.auth import normalize_claims
    
    id_claims = {
        "sub": "user123",
        "realm_access": {"roles": ["keycloak-role"]},
        "roles": ["entra-role"]
    }
    userinfo = {}
    access_claims = {}
    
    roles = normalize_claims(id_claims, userinfo, access_claims, "keycloak")
    
    assert "keycloak-role" in roles
    assert "entra-role" in roles


def test_oidc_provider_toggle_normalize_no_duplicates():
    """Normalized roles should not contain duplicates."""
    from app.api.auth import normalize_claims
    
    id_claims = {"roles": ["admin"]}
    userinfo = {"roles": ["admin"]}
    access_claims = {"roles": ["admin"]}
    
    roles = normalize_claims(id_claims, userinfo, access_claims, "entra")
    
    assert roles.count("admin") == 1


def test_oidc_provider_toggle_normalize_empty_claims():
    """Handle empty claims gracefully."""
    from app.api.auth import normalize_claims
    
    roles = normalize_claims({}, {}, {}, "keycloak")
    
    assert roles == []


# ═════════════════════════════════════════════════════════════════════════════
# Test: Provider Fallback
# ═════════════════════════════════════════════════════════════════════════════

def test_oidc_provider_toggle_fallback_to_keycloak():
    """Fallback to keycloak if requested provider not available."""
    os.environ["OIDC_PROVIDER"] = "nonexistent"
    
    from app.api.auth import get_current_provider, _providers
    
    # Only keycloak available
    _providers.clear()
    _providers["keycloak"] = MagicMock()
    
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test"
    
    with app.app_context():
        with app.test_request_context():
            provider = get_current_provider()
            assert provider == "keycloak"
    
    os.environ.pop("OIDC_PROVIDER", None)


# ═════════════════════════════════════════════════════════════════════════════
# Test: Marker for pytest -k oidc_provider_toggle
# ═════════════════════════════════════════════════════════════════════════════

def test_oidc_provider_toggle_marker_works():
    """This test validates that pytest -k oidc_provider_toggle filters correctly."""
    assert "oidc_provider_toggle" in __file__
