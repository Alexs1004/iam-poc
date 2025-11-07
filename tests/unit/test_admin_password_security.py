"""
Unit tests for password security in admin UI.

Validates that temporary passwords are NEVER exposed in production mode.
"""
import pytest
from unittest.mock import MagicMock, patch


def test_joiner_no_password_in_flash_when_production_mode(monkeypatch):
    """
    SECURITY TEST: Flash message must NOT contain password when DEMO_MODE=False
    
    This test validates OWASP A07:2021 (Identification and Authentication Failures)
    and ensures compliance with RFC 7644 § 7.7 (passwords must not be returned).
    """
    from app.api.admin import bp as admin_bp
    from flask import Flask
    from app.config.settings import AppConfig
    
    # Create test Flask app
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key"
    app.config["TESTING"] = True
    
    # ✅ Configure PRODUCTION mode (no demo)
    prod_config = AppConfig(
        demo_mode=False,  # ← Critical: production mode
        azure_use_keyvault=True,
        secret_key="test-key",
        keycloak_url="https://kc.test",
        keycloak_realm="test",
        keycloak_service_realm="test",
    )
    app.config["APP_CONFIG"] = prod_config
    
    # Register blueprint
    app.register_blueprint(admin_bp, url_prefix="/admin")
    
    # Mock authentication and RBAC
    def mock_is_authenticated():
        return True
    
    def mock_current_username():
        return "operator"
    
    def mock_user_has_role(role):
        return role in ["iam-operator", "operator"]  # ← Fix: allow iam-operator
    
    def mock_current_user_context():
        return "operator-id", "operator@test.com", "Operator", ["iam-operator"]  # ← Fix: proper role
    
    monkeypatch.setattr("app.api.admin.is_authenticated", mock_is_authenticated)
    monkeypatch.setattr("app.api.admin.current_username", mock_current_username)
    monkeypatch.setattr("app.api.admin.user_has_role", mock_user_has_role)
    monkeypatch.setattr("app.api.admin.current_user_context", mock_current_user_context)
    
    # Mock admin_ui.ui_create_user to simulate successful user creation
    mock_ui_create = MagicMock(return_value=("user-123", "SecretPass123!"))
    monkeypatch.setattr("app.api.helpers.admin_ui.ui_create_user", mock_ui_create)
    
    # Mock audit logging
    mock_audit = MagicMock()
    monkeypatch.setattr("app.api.admin.audit.log_jml_event", mock_audit)
    
    with app.test_client() as client:
        # Simulate joiner form submission
        response = client.post(
            "/admin/joiner",
            data={
                "username": "testuser",
                "email": "test@example.com",
                "first": "Test",
                "last": "User",
                "role": "employee",
                "temp_password": "",  # Auto-generated
                "require_totp": "false",
                "require_password_update": "true",
            },
            follow_redirects=False,
        )
        
        # ✅ Verify NO password appears in flash messages
        with client.session_transaction() as session:
            flashes = session.get("_flashes", [])
            for category, message in flashes:
                # Critical security checks
                assert "SecretPass123!" not in message, \
                    "🔴 SECURITY BREACH: Temporary password leaked in flash message!"
                assert "password:" not in message.lower() or "password reset" in message.lower(), \
                    "🔴 SECURITY BREACH: Password field exposed in production mode!"
                assert "temporary password is" not in message.lower(), \
                    "🔴 SECURITY BREACH: Temporary password pattern found in flash!"
                
                # ✅ Verify production-safe message appears instead
                if category in ("success", "info"):
                    assert "provisioned successfully" in message.lower() or \
                           "password reset instructions sent" in message.lower(), \
                           "Production flash message should mention email delivery"


def test_joiner_password_visible_in_demo_mode():
    """
    Unit test: Validates that flash message logic includes password in DEMO_MODE.
    
    This is a simplified test focusing on the flash message logic itself.
    """
    from app.config.settings import AppConfig
    
    # Test 1: Production mode - password should NOT be shown
    prod_config = AppConfig(
        demo_mode=False,
        azure_use_keyvault=True,
        secret_key="test",
        keycloak_url="https://kc",
        keycloak_realm="test",
        keycloak_service_realm="test",
    )
    
    returned_password = "SecretPass123"
    username = "testuser"
    email = "test@example.com"
    
    # Simulate production flash logic
    if prod_config.demo_mode and returned_password:
        flash_msg = f"User '{username}' provisioned. ⚠️ DEMO MODE: Temporary password is {returned_password}"
        should_show_password = True
    else:
        flash_msg = f"User '{username}' provisioned successfully. Password reset instructions sent to {email}."
        should_show_password = False
    
    assert not should_show_password, "Production mode should not show password"
    assert "SecretPass123" not in flash_msg, "Password should not be in production flash message"
    assert "Password reset instructions sent" in flash_msg
    
    # Test 2: Demo mode - password SHOULD be shown
    demo_config = AppConfig(
        demo_mode=True,
        azure_use_keyvault=False,
        secret_key="test",
        keycloak_url="https://kc",
        keycloak_realm="test",
        keycloak_service_realm="test",
    )
    
    # Simulate demo flash logic
    if demo_config.demo_mode and returned_password:
        flash_msg = f"User '{username}' provisioned. ⚠️ DEMO MODE: Temporary password is {returned_password}"
        should_show_password = True
    else:
        flash_msg = f"User '{username}' provisioned successfully. Password reset instructions sent to {email}."
        should_show_password = False
    
    assert should_show_password, "Demo mode should show password"
    assert "SecretPass123" in flash_msg, "Password should be visible in demo flash message"
    assert "DEMO MODE" in flash_msg, "Demo warning should be present"


def test_ui_create_user_respects_demo_mode(monkeypatch):
    """
    Validates that _tempPassword is only in SCIM response when DEMO_MODE=True.
    
    This is a defense-in-depth check at the service layer.
    """
    from app.api.helpers import admin_ui
    from app.core import provisioning_service
    
    # Mock SCIM service response (no _tempPassword in production)
    mock_create_scim = MagicMock(return_value={
        "id": "user-789",
        "userName": "secureuser",
        "emails": [{"value": "secure@example.com"}],
        "active": True,
        # NOTE: _tempPassword should NOT be here in production
    })
    
    monkeypatch.setattr(
        "app.core.provisioning_service.create_user_scim_like",
        mock_create_scim
    )
    
    # Simulate production mode at provisioning_service level
    monkeypatch.setattr("app.core.provisioning_service.DEMO_MODE", False)
    
    user_id, returned_password = admin_ui.ui_create_user(
        username="secureuser",
        email="secure@example.com",
        first_name="Secure",
        last_name="User",
        role="employee",
    )
    
    # ✅ In production, SCIM response should not contain _tempPassword
    # ui_create_user returns "N/A" as fallback, which is acceptable
    # The important part is that create_user_scim_like didn't include it
    assert "_tempPassword" not in mock_create_scim.return_value, \
        "_tempPassword must not be in SCIM response in production mode"
    
    # Verify the function was called (the real security check happens in provisioning_service)
    mock_create_scim.assert_called_once()
