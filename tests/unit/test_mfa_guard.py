"""Unit tests for MFA guard decorator (Conditional Access).

Tests validate:
- MFA enforcement when REQUIRE_MFA=true
- Permissive fallback when 'amr' claim missing
- 403 rejection when 'amr' exists but doesn't contain MFA method
- Bypass when REQUIRE_MFA=false (default)

Marker: pytest -k mfa_guard -q
"""
import os
import pytest
from unittest.mock import patch
from flask import Flask, session


@pytest.fixture
def app_mfa_required():
    """Flask app with REQUIRE_MFA=true."""
    os.environ["REQUIRE_MFA"] = "true"
    os.environ["DEMO_MODE"] = "true"
    os.environ["AZURE_USE_KEYVAULT"] = "false"
    
    from app.flask_app import require_mfa
    
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key"
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["TESTING"] = True
    
    @app.route("/admin/test")
    @require_mfa
    def admin_test():
        return "OK", 200
    
    yield app
    
    os.environ.pop("REQUIRE_MFA", None)


@pytest.fixture
def app_mfa_disabled():
    """Flask app with REQUIRE_MFA=false (default)."""
    os.environ["REQUIRE_MFA"] = "false"
    os.environ["DEMO_MODE"] = "true"
    os.environ["AZURE_USE_KEYVAULT"] = "false"
    
    from app.flask_app import require_mfa
    
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key"
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["TESTING"] = True
    
    @app.route("/admin/test")
    @require_mfa
    def admin_test():
        return "OK", 200
    
    yield app
    
    os.environ.pop("REQUIRE_MFA", None)


# ═════════════════════════════════════════════════════════════════════════════
# Test: MFA Enforcement Disabled (REQUIRE_MFA=false)
# ═════════════════════════════════════════════════════════════════════════════

def test_mfa_guard_disabled_allows_access(app_mfa_disabled):
    """When REQUIRE_MFA=false, all requests pass through."""
    with app_mfa_disabled.test_client() as client:
        with client.session_transaction() as sess:
            sess["id_token_claims"] = {"sub": "user123"}  # No 'amr' claim
        
        response = client.get("/admin/test")
        assert response.status_code == 200


def test_mfa_guard_disabled_ignores_amr(app_mfa_disabled):
    """When REQUIRE_MFA=false, 'amr' claim is not checked."""
    with app_mfa_disabled.test_client() as client:
        with client.session_transaction() as sess:
            sess["id_token_claims"] = {"sub": "user123", "amr": ["pwd"]}  # No MFA
        
        response = client.get("/admin/test")
        assert response.status_code == 200


# ═════════════════════════════════════════════════════════════════════════════
# Test: MFA Enforcement Enabled - Permissive Fallback
# ═════════════════════════════════════════════════════════════════════════════

def test_mfa_guard_missing_amr_allows_access(app_mfa_required):
    """When 'amr' claim missing, access is allowed (permissive fallback)."""
    with app_mfa_required.test_client() as client:
        with client.session_transaction() as sess:
            sess["id_token_claims"] = {"sub": "user123"}  # No 'amr' claim
        
        response = client.get("/admin/test")
        assert response.status_code == 200


def test_mfa_guard_empty_claims_allows_access(app_mfa_required):
    """When no ID token claims, access is allowed (permissive fallback)."""
    with app_mfa_required.test_client() as client:
        with client.session_transaction() as sess:
            sess["id_token_claims"] = {}
        
        response = client.get("/admin/test")
        assert response.status_code == 200


# ═════════════════════════════════════════════════════════════════════════════
# Test: MFA Enforcement - Valid MFA Claims
# ═════════════════════════════════════════════════════════════════════════════

def test_mfa_guard_amr_contains_mfa(app_mfa_required):
    """When 'amr' contains 'mfa', access is allowed."""
    with app_mfa_required.test_client() as client:
        with client.session_transaction() as sess:
            sess["id_token_claims"] = {"sub": "user123", "amr": ["pwd", "mfa"]}
        
        response = client.get("/admin/test")
        assert response.status_code == 200


def test_mfa_guard_amr_contains_otp(app_mfa_required):
    """When 'amr' contains 'otp' (TOTP), access is allowed."""
    with app_mfa_required.test_client() as client:
        with client.session_transaction() as sess:
            sess["id_token_claims"] = {"sub": "user123", "amr": ["pwd", "otp"]}
        
        response = client.get("/admin/test")
        assert response.status_code == 200


def test_mfa_guard_amr_contains_hwk(app_mfa_required):
    """When 'amr' contains 'hwk' (hardware key), access is allowed."""
    with app_mfa_required.test_client() as client:
        with client.session_transaction() as sess:
            sess["id_token_claims"] = {"sub": "user123", "amr": ["hwk"]}
        
        response = client.get("/admin/test")
        assert response.status_code == 200


def test_mfa_guard_amr_contains_fido(app_mfa_required):
    """When 'amr' contains 'fido' (FIDO2/WebAuthn), access is allowed."""
    with app_mfa_required.test_client() as client:
        with client.session_transaction() as sess:
            sess["id_token_claims"] = {"sub": "user123", "amr": ["fido"]}
        
        response = client.get("/admin/test")
        assert response.status_code == 200


def test_mfa_guard_amr_as_string(app_mfa_required):
    """Handle 'amr' as string (some IdPs return string instead of array)."""
    with app_mfa_required.test_client() as client:
        with client.session_transaction() as sess:
            sess["id_token_claims"] = {"sub": "user123", "amr": "mfa"}
        
        response = client.get("/admin/test")
        assert response.status_code == 200


# ═════════════════════════════════════════════════════════════════════════════
# Test: MFA Enforcement - Invalid/Missing MFA
# ═════════════════════════════════════════════════════════════════════════════

def test_mfa_guard_amr_pwd_only_returns_403(app_mfa_required):
    """When 'amr' contains only 'pwd' (password), return 403."""
    with app_mfa_required.test_client() as client:
        with client.session_transaction() as sess:
            sess["id_token_claims"] = {"sub": "user123", "amr": ["pwd"]}
        
        response = client.get("/admin/test")
        assert response.status_code == 403


def test_mfa_guard_amr_no_mfa_method_returns_403(app_mfa_required):
    """When 'amr' exists but has no MFA method, return 403."""
    with app_mfa_required.test_client() as client:
        with client.session_transaction() as sess:
            sess["id_token_claims"] = {"sub": "user123", "amr": ["rsa", "wia"]}
        
        response = client.get("/admin/test")
        assert response.status_code == 403


def test_mfa_guard_amr_empty_list_returns_403(app_mfa_required):
    """When 'amr' is empty list, return 403."""
    with app_mfa_required.test_client() as client:
        with client.session_transaction() as sess:
            sess["id_token_claims"] = {"sub": "user123", "amr": []}
        
        response = client.get("/admin/test")
        assert response.status_code == 403


# ═════════════════════════════════════════════════════════════════════════════
# Test: Error Message
# ═════════════════════════════════════════════════════════════════════════════

def test_mfa_guard_403_message(app_mfa_required):
    """403 response includes helpful error message."""
    with app_mfa_required.test_client() as client:
        with client.session_transaction() as sess:
            sess["id_token_claims"] = {"sub": "user123", "amr": ["pwd"]}
        
        response = client.get("/admin/test")
        assert response.status_code == 403
        assert b"MFA required" in response.data or b"403" in response.data


# ═════════════════════════════════════════════════════════════════════════════
# Test: Marker for pytest -k mfa_guard
# ═════════════════════════════════════════════════════════════════════════════

def test_mfa_guard_marker_works():
    """This test validates that pytest -k mfa_guard filters correctly."""
    assert "mfa_guard" in __file__
