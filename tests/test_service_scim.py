"""
Unit tests for app/provisioning_service.py

Tests the unified service layer that provides SCIM-like provisioning
operations (create, get, list, replace, delete, change_role).
"""

import os
import pathlib
import sys
from unittest.mock import MagicMock, patch, call
import pytest

# Add project root to Python path
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("DEMO_MODE", "true")
os.environ.setdefault("APP_BASE_URL", "https://localhost")

from app.core import provisioning_service
from app.core.provisioning_service import (
    ScimError,
    create_user_scim_like,
    get_user_scim,
    list_users_scim,
    replace_user_scim,
    delete_user_scim,
    change_user_role,
    validate_username,
    validate_email,
    validate_name,
    keycloak_to_scim,
    scim_to_keycloak,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_jml(monkeypatch):
    """Mock scripts.jml module"""
    mock = MagicMock()
    mock.create_user.return_value = ("test-uuid-123", "TempPass123!")
    mock.get_user_by_id.return_value = {
        "id": "test-uuid-123",
        "username": "alice",
        "firstName": "Alice",
        "lastName": "Wonder",
        "email": "alice@example.com",
        "enabled": True,
    }
    mock.get_user_by_username.return_value = {
        "id": "test-uuid-123",
        "username": "alice",
        "firstName": "Alice",
        "lastName": "Wonder",
        "email": "alice@example.com",
        "enabled": True,
    }
    mock.list_users.return_value = [
        {
            "id": "test-uuid-123",
            "username": "alice",
            "firstName": "Alice",
            "lastName": "Wonder",
            "email": "alice@example.com",
            "enabled": True,
        }
    ]
    mock.disable_user.return_value = None
    mock.change_role.return_value = None
    
    monkeypatch.setattr("app.provisioning_service.jml", mock)
    return mock


@pytest.fixture
def mock_audit(monkeypatch):
    """Mock scripts.audit module"""
    mock = MagicMock()
    monkeypatch.setattr("app.provisioning_service.audit", mock)
    return mock


@pytest.fixture
def mock_keycloak_admin(monkeypatch):
    """Mock KeycloakAdmin instance"""
    mock_admin = MagicMock()
    mock_admin.get_user_sessions.return_value = [
        {"id": "session-123"},
        {"id": "session-456"},
    ]
    
    def mock_get_admin(*args, **kwargs):
        return mock_admin
    
    monkeypatch.setattr("app.provisioning_service.get_keycloak_admin", mock_get_admin)
    return mock_admin


@pytest.fixture
def valid_create_payload():
    """Valid SCIM User payload for create operations"""
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice",
        "emails": [{"value": "alice@example.com", "primary": True}],
        "name": {"givenName": "Alice", "familyName": "Wonder"},
        "active": True,
        "role": "analyst",
    }


# ============================================================================
# Validation Tests
# ============================================================================

def test_validate_username_success():
    """Valid usernames pass validation"""
    # Should not raise
    validate_username("alice")
    validate_username("bob123")
    validate_username("test_user")


def test_validate_username_too_short():
    """Usernames < 3 chars raise ScimError"""
    with pytest.raises(ScimError) as exc:
        validate_username("ab")
    assert exc.value.status == 400
    assert "too short" in exc.value.detail.lower()
    assert exc.value.scim_type == "invalidValue"


def test_validate_username_too_long():
    """Usernames > 64 chars raise ScimError"""
    with pytest.raises(ScimError) as exc:
        validate_username("a" * 65)
    assert exc.value.status == 400
    assert "too long" in exc.value.detail.lower()


def test_validate_username_invalid_chars():
    """Usernames with special chars raise ScimError"""
    with pytest.raises(ScimError) as exc:
        validate_username("alice@example.com")
    assert exc.value.status == 400
    assert "invalid characters" in exc.value.detail.lower()


def test_validate_email_success():
    """Valid emails pass validation"""
    # Should not raise
    validate_email("test@example.com")
    validate_email("user+tag@subdomain.example.org")


def test_validate_email_invalid():
    """Invalid emails raise ScimError"""
    with pytest.raises(ScimError) as exc:
        validate_email("not-an-email")
    assert exc.value.status == 400
    assert "invalid email" in exc.value.detail.lower()


def test_validate_email_too_long():
    """Emails > 254 chars raise ScimError"""
    long_email = "a" * 250 + "@example.com"
    with pytest.raises(ScimError) as exc:
        validate_email(long_email)
    assert exc.value.status == 400


def test_validate_name_success():
    """Valid names pass validation"""
    # Should not raise
    validate_name("Alice", "givenName")
    validate_name("O'Connor", "familyName")


def test_validate_name_too_long():
    """Names > 64 chars raise ScimError"""
    with pytest.raises(ScimError) as exc:
        validate_name("a" * 65, "givenName")
    assert exc.value.status == 400
    assert "too long" in exc.value.detail.lower()


def test_validate_name_invalid_chars():
    """Names with HTML/JS raise ScimError"""
    with pytest.raises(ScimError) as exc:
        validate_name("<script>alert(1)</script>", "givenName")
    assert exc.value.status == 400
    assert "invalid characters" in exc.value.detail.lower()


# ============================================================================
# Conversion Tests
# ============================================================================

def test_keycloak_to_scim():
    """Keycloak user dict converts to SCIM format"""
    keycloak_user = {
        "id": "test-uuid-123",
        "username": "alice",
        "firstName": "Alice",
        "lastName": "Wonder",
        "email": "alice@example.com",
        "enabled": True,
    }
    scim_user = keycloak_to_scim(keycloak_user)
    
    assert scim_user["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
    assert scim_user["id"] == "test-uuid-123"
    assert scim_user["userName"] == "alice"
    assert scim_user["emails"][0]["value"] == "alice@example.com"
    assert scim_user["name"]["givenName"] == "Alice"
    assert scim_user["name"]["familyName"] == "Wonder"
    assert scim_user["active"] is True
    assert "meta" in scim_user
    assert scim_user["meta"]["resourceType"] == "User"


def test_scim_to_keycloak():
    """SCIM user dict converts to Keycloak format"""
    scim_user = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice",
        "emails": [{"value": "alice@example.com", "primary": True}],
        "name": {"givenName": "Alice", "familyName": "Wonder"},
        "active": True,
    }
    keycloak_user = scim_to_keycloak(scim_user)
    
    assert keycloak_user["username"] == "alice"
    assert keycloak_user["email"] == "alice@example.com"
    assert keycloak_user["firstName"] == "Alice"
    assert keycloak_user["lastName"] == "Wonder"
    assert keycloak_user["enabled"] is True


# ============================================================================
# ScimError Tests
# ============================================================================

def test_scim_error_to_dict():
    """ScimError.to_dict() returns SCIM-compliant error format"""
    error = ScimError(409, "User already exists", "uniqueness")
    error_dict = error.to_dict()
    
    assert error_dict["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert error_dict["status"] == "409"
    assert error_dict["detail"] == "User already exists"
    assert error_dict["scimType"] == "uniqueness"


def test_scim_error_without_scim_type():
    """ScimError without scimType omits the field"""
    error = ScimError(500, "Internal error", None)
    error_dict = error.to_dict()
    
    assert "scimType" not in error_dict
    assert error_dict["status"] == "500"


# ============================================================================
# create_user_scim_like Tests
# ============================================================================

def test_create_user_success(mock_jml, mock_audit, valid_create_payload):
    """create_user_scim_like returns SCIM User with id and _tempPassword"""
    result = create_user_scim_like(valid_create_payload, correlation_id="test-123")
    
    assert result["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
    assert result["id"] == "test-uuid-123"
    assert result["userName"] == "alice"
    assert result["_tempPassword"] == "TempPass123!"  # DEMO_MODE=true
    assert "meta" in result
    assert result["meta"]["location"].endswith("/scim/v2/Users/test-uuid-123")
    
    # Verify jml.create_user called
    mock_jml.create_user.assert_called_once()
    args = mock_jml.create_user.call_args[1]
    assert args["username"] == "alice"
    assert args["email"] == "alice@example.com"
    assert args["first_name"] == "Alice"
    assert args["last_name"] == "Wonder"
    assert args["role"] == "analyst"
    
    # Verify audit log
    mock_audit.log_jml_event.assert_called_once()


def test_create_user_missing_username(mock_jml, mock_audit):
    """Missing userName raises ScimError 400"""
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "emails": [{"value": "test@example.com"}],
    }
    
    with pytest.raises(ScimError) as exc:
        create_user_scim_like(payload)
    
    assert exc.value.status == 400
    assert "userName" in exc.value.detail
    assert exc.value.scim_type == "invalidValue"


def test_create_user_invalid_email(mock_jml, mock_audit, valid_create_payload):
    """Invalid email raises ScimError 400"""
    valid_create_payload["emails"][0]["value"] = "not-an-email"
    
    with pytest.raises(ScimError) as exc:
        create_user_scim_like(valid_create_payload)
    
    assert exc.value.status == 400
    assert "email" in exc.value.detail.lower()


def test_create_user_duplicate_username(mock_jml, mock_audit, valid_create_payload):
    """Duplicate userName raises ScimError 409"""
    mock_jml.create_user.side_effect = ValueError("User alice already exists")
    
    with pytest.raises(ScimError) as exc:
        create_user_scim_like(valid_create_payload)
    
    assert exc.value.status == 409
    assert exc.value.scim_type == "uniqueness"


# ============================================================================
# get_user_scim Tests
# ============================================================================

def test_get_user_success(mock_jml):
    """get_user_scim returns SCIM User"""
    result = get_user_scim("test-uuid-123")
    
    assert result["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
    assert result["id"] == "test-uuid-123"
    assert result["userName"] == "alice"
    assert "_tempPassword" not in result  # Never in GET response
    
    mock_jml.get_user_by_id.assert_called_once_with("test-uuid-123")


def test_get_user_not_found(mock_jml):
    """get_user_scim raises ScimError 404 for missing user"""
    mock_jml.get_user_by_id.return_value = None
    
    with pytest.raises(ScimError) as exc:
        get_user_scim("nonexistent-uuid")
    
    assert exc.value.status == 404
    assert "not found" in exc.value.detail.lower()


# ============================================================================
# list_users_scim Tests
# ============================================================================

def test_list_users_default_pagination(mock_jml):
    """list_users_scim returns ListResponse with default pagination"""
    result = list_users_scim()
    
    assert result["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    assert result["totalResults"] == 1
    assert result["startIndex"] == 1
    assert result["itemsPerPage"] == 1
    assert len(result["Resources"]) == 1
    assert result["Resources"][0]["userName"] == "alice"
    
    mock_jml.list_users.assert_called_once()


def test_list_users_with_pagination(mock_jml):
    """list_users_scim respects startIndex and count params"""
    query = {"startIndex": 11, "count": 50}
    result = list_users_scim(query)
    
    assert result["startIndex"] == 11
    # itemsPerPage is actual results, not requested count
    assert result["itemsPerPage"] <= 50


def test_list_users_with_filter(mock_jml):
    """list_users_scim handles filter parameter"""
    query = {"filter": 'userName eq "alice"'}
    result = list_users_scim(query)
    
    assert len(result["Resources"]) == 1
    assert result["Resources"][0]["userName"] == "alice"


def test_list_users_filter_no_match(mock_jml):
    """list_users_scim returns empty Resources for no match"""
    mock_jml.list_users.return_value = []
    query = {"filter": 'userName eq "nonexistent"'}
    result = list_users_scim(query)
    
    assert result["totalResults"] == 0
    assert result["Resources"] == []


def test_list_users_max_count_limit(mock_jml):
    """list_users_scim enforces max count of 200"""
    query = {"count": 500}
    result = list_users_scim(query)
    
    # Should cap at 200
    assert result["itemsPerPage"] <= 200


# ============================================================================
# replace_user_scim Tests
# ============================================================================

def test_replace_user_update_name(mock_jml, mock_audit):
    """replace_user_scim updates user name"""
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice",
        "emails": [{"value": "alice@example.com", "primary": True}],
        "name": {"givenName": "Alice", "familyName": "Smith"},  # Changed
        "active": True,
    }
    
    result = replace_user_scim("test-uuid-123", payload, correlation_id="test-456")
    
    assert result["name"]["familyName"] == "Smith"
    
    # Verify jml.get_user_by_id + update_user called
    mock_jml.get_user_by_id.assert_called()


def test_replace_user_disable(mock_jml, mock_audit, mock_keycloak_admin):
    """replace_user_scim with active=false disables user and revokes sessions"""
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice",
        "emails": [{"value": "alice@example.com", "primary": True}],
        "name": {"givenName": "Alice", "familyName": "Wonder"},
        "active": False,  # Disable user
    }
    
    result = replace_user_scim("test-uuid-123", payload, correlation_id="test-789")
    
    assert result["active"] is False
    
    # Verify session revocation
    mock_keycloak_admin.get_user_sessions.assert_called_once_with(user_id="test-uuid-123")
    assert mock_keycloak_admin.delete_session.call_count == 2
    mock_keycloak_admin.delete_session.assert_any_call(session_id="session-123")
    mock_keycloak_admin.delete_session.assert_any_call(session_id="session-456")


def test_replace_user_not_found(mock_jml, mock_audit):
    """replace_user_scim raises ScimError 404 for missing user"""
    mock_jml.get_user_by_id.return_value = None
    
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "ghost",
        "emails": [{"value": "ghost@example.com"}],
        "active": True,
    }
    
    with pytest.raises(ScimError) as exc:
        replace_user_scim("nonexistent-uuid", payload)
    
    assert exc.value.status == 404


# ============================================================================
# delete_user_scim Tests
# ============================================================================

def test_delete_user_success(mock_jml, mock_audit, mock_keycloak_admin):
    """delete_user_scim disables user and revokes sessions"""
    delete_user_scim("test-uuid-123", correlation_id="test-delete")
    
    # Verify disable
    mock_jml.disable_user.assert_called_once_with("test-uuid-123")
    
    # Verify session revocation
    mock_keycloak_admin.get_user_sessions.assert_called_once_with(user_id="test-uuid-123")
    assert mock_keycloak_admin.delete_session.call_count == 2
    
    # Verify audit log
    mock_audit.log_jml_event.assert_called_once()


def test_delete_user_not_found(mock_jml, mock_audit):
    """delete_user_scim raises ScimError 404 for missing user"""
    mock_jml.get_user_by_id.return_value = None
    
    with pytest.raises(ScimError) as exc:
        delete_user_scim("nonexistent-uuid")
    
    assert exc.value.status == 404


def test_delete_user_idempotent(mock_jml, mock_audit, mock_keycloak_admin):
    """delete_user_scim is idempotent (no error if already disabled)"""
    mock_jml.get_user_by_id.return_value = {
        "id": "test-uuid-123",
        "username": "alice",
        "enabled": False,  # Already disabled
    }
    
    # Should not raise error
    delete_user_scim("test-uuid-123")
    
    # Should still call disable (idempotent)
    mock_jml.disable_user.assert_called_once()


# ============================================================================
# change_user_role Tests
# ============================================================================

def test_change_role_success(mock_jml, mock_audit):
    """change_user_role calls jml.change_role"""
    change_user_role("alice", "analyst", "manager", correlation_id="test-role")
    
    mock_jml.change_role.assert_called_once_with(
        username="alice",
        source_role="analyst",
        target_role="manager"
    )
    
    # Verify audit log
    mock_audit.log_jml_event.assert_called_once()


def test_change_role_user_not_found(mock_jml, mock_audit):
    """change_user_role raises ScimError 404 for missing user"""
    mock_jml.get_user_by_username.return_value = None
    
    with pytest.raises(ScimError) as exc:
        change_user_role("ghost", "analyst", "manager")
    
    assert exc.value.status == 404
    assert "not found" in exc.value.detail.lower()


def test_change_role_invalid_source_role(mock_jml, mock_audit):
    """change_user_role raises ScimError 400 for invalid source role"""
    mock_jml.change_role.side_effect = ValueError("User does not have role analyst")
    
    with pytest.raises(ScimError) as exc:
        change_user_role("alice", "analyst", "manager")
    
    assert exc.value.status == 400


# ============================================================================
# Integration Test: Full CRUD Flow
# ============================================================================

def test_full_crud_flow(mock_jml, mock_audit, mock_keycloak_admin, valid_create_payload):
    """Integration test: create → get → list → replace → delete"""
    
    # 1. Create user
    created = create_user_scim_like(valid_create_payload, correlation_id="crud-1")
    user_id = created["id"]
    assert user_id == "test-uuid-123"
    assert "_tempPassword" in created
    
    # 2. Get user
    retrieved = get_user_scim(user_id)
    assert retrieved["userName"] == "alice"
    assert "_tempPassword" not in retrieved
    
    # 3. List users
    list_result = list_users_scim({"filter": 'userName eq "alice"'})
    assert list_result["totalResults"] == 1
    assert list_result["Resources"][0]["id"] == user_id
    
    # 4. Replace user (update name)
    update_payload = valid_create_payload.copy()
    update_payload["name"]["familyName"] = "Smith"
    updated = replace_user_scim(user_id, update_payload, correlation_id="crud-4")
    assert updated["name"]["familyName"] == "Smith"
    
    # 5. Delete user
    delete_user_scim(user_id, correlation_id="crud-5")
    
    # Verify session revocation happened
    assert mock_keycloak_admin.delete_session.call_count == 2
    
    # Verify audit logs (create + replace + delete = 3 events)
    assert mock_audit.log_jml_event.call_count == 3


# ============================================================================
# Error Handling Tests
# ============================================================================

def test_internal_error_wrapped_in_scim_error(mock_jml, valid_create_payload):
    """Unexpected exceptions are wrapped in ScimError 500"""
    mock_jml.create_user.side_effect = RuntimeError("Database connection failed")
    
    with pytest.raises(ScimError) as exc:
        create_user_scim_like(valid_create_payload)
    
    assert exc.value.status == 500
    assert "internal" in exc.value.detail.lower() or "error" in exc.value.detail.lower()


def test_keycloak_admin_error_during_session_revocation(mock_jml, mock_audit, mock_keycloak_admin):
    """Session revocation errors are logged but don't fail delete"""
    mock_keycloak_admin.get_user_sessions.side_effect = Exception("Keycloak unreachable")
    
    # Should still succeed (best effort session revocation)
    delete_user_scim("test-uuid-123")
    
    # Verify disable still called
    mock_jml.disable_user.assert_called_once()
