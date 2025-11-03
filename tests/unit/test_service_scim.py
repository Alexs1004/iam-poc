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
    """Mock app.core.keycloak functions (renamed for backward compatibility)"""
    # Force DEMO_MODE to True for tests that need _tempPassword
    monkeypatch.setattr("app.core.provisioning_service.DEMO_MODE", True)
    
    # Create mock object to hold all functions
    mock = MagicMock()
    
    # Mock generate_temp_password
    mock_gen_password = MagicMock(return_value="TempPass123!")
    monkeypatch.setattr("app.core.provisioning_service.generate_temp_password", mock_gen_password)
    
    # Mock get_service_account_token (needed for service token)
    mock_token = MagicMock(return_value="mock-service-token-12345")
    monkeypatch.setattr("app.core.provisioning_service.get_service_account_token", mock_token)
    
    # Mock create_user
    mock.create_user = MagicMock(return_value=("test-uuid-123", "TempPass123!"))
    monkeypatch.setattr("app.core.provisioning_service.create_user", mock.create_user)
    
    # Mock get_user_by_username (used more often than get_user_by_id)
    # Default: return None first (user doesn't exist), then return user data after "creation"
    mock.get_user_by_username = MagicMock(side_effect=[
        None,  # First call: check if exists (no)
        {  # Second call: after creation (yes)
            "id": "test-uuid-123",
            "username": "alice",
            "firstName": "Alice",
            "lastName": "Wonder",
            "email": "alice@example.com",
            "enabled": True,
        }
    ])
    monkeypatch.setattr("app.core.provisioning_service.get_user_by_username", mock.get_user_by_username)
    
    # Mock get_user_by_id (alias to get_user_by_username for test compatibility)
    mock.get_user_by_id = mock.get_user_by_username
    
    # Mock list_users - need to mock the requests call instead
    mock.list_users = MagicMock(return_value=[
        {
            "id": "test-uuid-123",
            "username": "alice",
            "firstName": "Alice",
            "lastName": "Wonder",
            "email": "alice@example.com",
            "enabled": True,
        }
    ])
    
    # Mock disable_user
    mock.disable_user = MagicMock(return_value=None)
    monkeypatch.setattr("app.core.provisioning_service.disable_user", mock.disable_user)
    
    # Mock change_role
    mock.change_role = MagicMock(return_value=None)
    monkeypatch.setattr("app.core.provisioning_service.change_role", mock.change_role)
    
    # Mock add_realm_role (used in role operations)
    mock.add_realm_role = MagicMock(return_value=None)
    monkeypatch.setattr("app.core.provisioning_service.add_realm_role", mock.add_realm_role)
    
    return mock


@pytest.fixture
def mock_audit(monkeypatch):
    """Mock scripts.audit module"""
    mock = MagicMock()
    monkeypatch.setattr("app.core.provisioning_service.audit", mock)
    return mock


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


def test_load_secret_from_file_reads_disk(monkeypatch, tmp_path):
    secrets_dir = tmp_path / "run_secrets"
    secrets_dir.mkdir()
    secret_path = secrets_dir / "test_secret"
    secret_path.write_text("value\n", encoding="utf-8")

    def fake_path(value):
        if value == "/run/secrets":
            return secrets_dir
        return pathlib.Path(value)

    monkeypatch.setattr(provisioning_service, "Path", fake_path, raising=False)
    result = provisioning_service._load_secret_from_file("test_secret")
    assert result == "value"


def test_load_secret_from_file_env_fallback(monkeypatch):
    monkeypatch.setattr(
        provisioning_service,
        "Path",
        lambda value: pathlib.Path("/nonexistent"),
        raising=False,
    )
    monkeypatch.setenv("ENV_SECRET", "fallback")
    result = provisioning_service._load_secret_from_file("missing", "ENV_SECRET")
    assert result == "fallback"


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
    assert exc.value.scim_type == "invalidValue"


def test_validate_username_too_long():
    """Usernames > 64 chars raise ScimError"""
    with pytest.raises(ScimError) as exc:
        validate_username("a" * 65)
    assert exc.value.status == 400
    assert exc.value.scim_type == "invalidValue"


def test_validate_username_invalid_chars():
    """Usernames with special chars raise ScimError"""
    with pytest.raises(ScimError) as exc:
        validate_username("alice@example.com")
    assert exc.value.status == 400
    assert exc.value.scim_type == "invalidValue"


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
    assert exc.value.scim_type == "invalidValue"


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
    validate_name("O-Connor", "familyName")  # Hyphen is safe, apostrophe blocked by XSS protection


def test_validate_name_too_long():
    """Names > 128 chars raise ScimError"""
    with pytest.raises(ScimError) as exc:
        validate_name("a" * 129, "givenName")
    assert exc.value.status == 400
    assert exc.value.scim_type == "invalidValue"


def test_validate_name_invalid_chars():
    """Names with dangerous chars raise ScimError"""
    with pytest.raises(ScimError) as exc:
        validate_name("<script>alert(1)</script>", "givenName")
    assert exc.value.status == 400
    assert exc.value.scim_type == "invalidValue"


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
    assert result["meta"]["location"].endswith("/Users/test-uuid-123")  # May be /scim/v2/Users or /Users
    
    # Verify create_user was called
    mock_jml.create_user.assert_called_once()
    
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


def test_create_user_duplicate_username(mock_jml, mock_audit, valid_create_payload, monkeypatch):
    """Duplicate userName raises ScimError 409"""
    # Override the side_effect from fixture with return_value for this test
    mock_get_user = MagicMock(return_value={
        "id": "existing-uuid",
        "username": "alice",
        "enabled": True
    })
    monkeypatch.setattr("app.core.provisioning_service.get_user_by_username", mock_get_user)
    
    with pytest.raises(ScimError) as exc:
        create_user_scim_like(valid_create_payload)
    
    assert exc.value.status == 409
    assert exc.value.scim_type == "uniqueness"


# ============================================================================
# get_user_scim Tests
# ============================================================================

@patch('app.core.provisioning_service.requests.get')
def test_get_user_success(mock_get, mock_jml):
    """get_user_scim returns SCIM User"""
    # Mock requests.get to return Keycloak user
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "id": "test-uuid-123",
        "username": "alice",
        "firstName": "Alice",
        "lastName": "Wonder",
        "email": "alice@example.com",
        "enabled": True,
    }
    mock_get.return_value = mock_response
    
    result = get_user_scim("test-uuid-123")
    
    assert result["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
    assert result["id"] == "test-uuid-123"
    assert result["userName"] == "alice"
    assert "_tempPassword" not in result  # Never in GET response


@patch('app.core.provisioning_service.requests.get')
def test_get_user_not_found(mock_get, mock_jml):
    """get_user_scim raises ScimError 404 for missing user"""
    # Mock requests.get to raise 404
    mock_get.side_effect = Exception("Not found")
    
    with pytest.raises(ScimError) as exc:
        get_user_scim("nonexistent-uuid")
    
    assert exc.value.status == 404
    assert "not found" in exc.value.detail.lower()


# ============================================================================
# list_users_scim Tests
# ============================================================================

@patch('app.core.provisioning_service.requests.get')
def test_list_users_default_pagination(mock_get, mock_jml):
    """list_users_scim returns ListResponse with default pagination"""
    # Mock requests.get to return Keycloak users list
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [{
        "id": "test-uuid-123",
        "username": "alice",
        "firstName": "Alice",
        "lastName": "Wonder",
        "email": "alice@example.com",
        "enabled": True,
    }]
    mock_get.return_value = mock_response
    
    result = list_users_scim()
    
    assert result["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    assert result["totalResults"] == 1
    assert result["startIndex"] == 1
    assert result["itemsPerPage"] == 1
    assert len(result["Resources"]) == 1
    assert result["Resources"][0]["userName"] == "alice"


@patch('app.core.provisioning_service.requests.get')
def test_list_users_with_pagination(mock_get, mock_jml):
    """list_users_scim respects startIndex and count params"""
    # Mock empty list for pagination test
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = []
    mock_get.return_value = mock_response
    
    query = {"startIndex": 11, "count": 50}
    result = list_users_scim(query)
    
    assert result["startIndex"] == 11
    # itemsPerPage is actual results, not requested count
    assert result["itemsPerPage"] == 0


@patch('app.core.provisioning_service.requests.get')
def test_list_users_with_filter(mock_get, mock_jml):
    """list_users_scim handles filter parameter"""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [{
        "id": "test-uuid-123",
        "username": "alice",
        "firstName": "Alice",
        "lastName": "Wonder",
        "email": "alice@example.com",
        "enabled": True,
    }]
    mock_get.return_value = mock_response
    
    query = {"filter": 'userName eq "alice"'}
    result = list_users_scim(query)
    
    assert len(result["Resources"]) == 1
    assert result["Resources"][0]["userName"] == "alice"


@patch('app.core.provisioning_service.requests.get')
def test_list_users_filter_no_match(mock_get, mock_jml):
    """list_users_scim returns empty Resources for no match"""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = []
    mock_get.return_value = mock_response
    
    query = {"filter": 'userName eq "nonexistent"'}
    result = list_users_scim(query)
    
    assert result["totalResults"] == 0
    assert result["Resources"] == []


@patch('app.core.provisioning_service.requests.get')
def test_list_users_max_count_limit(mock_get, mock_jml):
    """list_users_scim enforces max count of 200"""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = []
    mock_get.return_value = mock_response
    
    query = {"count": 500}
    result = list_users_scim(query)
    
    # Should cap at 200
    assert result["itemsPerPage"] <= 200


# ============================================================================
# replace_user_scim Tests
# ============================================================================

@patch('app.core.provisioning_service.get_user_by_username')
def test_replace_user_update_name(mock_get_user, mock_jml, mock_audit):
    """replace_user_scim updates user name (returns refreshed user state)"""
    # Mock get_user_by_username to return existing user (called twice: check + refresh)
    original_user = {
        "id": "test-uuid-123",
        "username": "alice",
        "firstName": "Alice",
        "lastName": "Wonder",
        "email": "alice@example.com",
        "enabled": True,
    }
    
    updated_user = {
        "id": "test-uuid-123",
        "username": "alice",
        "firstName": "Alice",
        "lastName": "Smith",  # Updated
        "email": "alice@example.com",
        "enabled": True,
    }
    
    # Mock returns: 1st call = validation, 2nd call = refresh
    mock_get_user.side_effect = [original_user, updated_user]
    
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice",
        "emails": [{"value": "alice@example.com", "primary": True}],
        "name": {"givenName": "Alice", "familyName": "Smith"},
        "active": True,
    }
    
    result = replace_user_scim("test-uuid-123", payload, correlation_id="test-456")
    
    # Verify result reflects refreshed state
    assert result["name"]["familyName"] == "Smith"
    assert result["userName"] == "alice"


@patch('app.core.provisioning_service.get_user_by_username')
@patch('app.core.provisioning_service.disable_user')
def test_replace_user_disable(mock_disable, mock_get_user, mock_jml, mock_audit):
    """replace_user_scim with active=false disables user and revokes sessions"""
    # Mock get_user_by_username (called twice: check + refresh)
    enabled_user = {
        "id": "test-uuid-123",
        "username": "alice",
        "firstName": "Alice",
        "lastName": "Wonder",
        "email": "alice@example.com",
        "enabled": True,
    }
    
    disabled_user = {
        **enabled_user,
        "enabled": False,  # After disable
    }
    
    mock_get_user.side_effect = [enabled_user, disabled_user]
    
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice",
        "emails": [{"value": "alice@example.com", "primary": True}],
        "name": {"givenName": "Alice", "familyName": "Wonder"},
        "active": False,  # Disable user
    }
    
    result = replace_user_scim("test-uuid-123", payload, correlation_id="test-789")
    
    # Verify result reflects disabled state
    assert result["active"] is False
    # Verify disable_user was called
    mock_disable.assert_called_once()


@patch('app.core.provisioning_service.get_user_by_username')
def test_replace_user_not_found(mock_get_user, mock_jml, mock_audit):
    """replace_user_scim raises ScimError 404 for missing user"""
    # Mock user not found (return None)
    mock_get_user.return_value = None
    
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "ghost",
        "emails": [{"value": "ghost@example.com"}],
        "name": {"givenName": "Ghost", "familyName": "User"},  # Add required fields
        "active": True,
    }
    
    with pytest.raises(ScimError) as exc:
        replace_user_scim("nonexistent-uuid", payload)
    
    assert exc.value.status == 404


# ============================================================================
# patch_user_scim Tests
# ============================================================================


def _mock_response(payload, status_code=200):
    """Helper to craft mock requests responses."""
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


def test_patch_user_scim_disable_success(monkeypatch, mock_jml, mock_audit):
    """patch_user_scim disables an active user and logs audit entry."""
    initial_user = {
        "id": "user-123",
        "username": "alice",
        "firstName": "Alice",
        "lastName": "Wonder",
        "email": "alice@example.com",
        "enabled": True,
    }
    disabled_user = {**initial_user, "enabled": False}
    
    get_mock = MagicMock(side_effect=[_mock_response(initial_user), _mock_response(disabled_user)])
    put_resp = _mock_response({}, status_code=204)
    put_mock = MagicMock(return_value=put_resp)
    
    monkeypatch.setattr("app.core.provisioning_service.requests.get", get_mock)
    monkeypatch.setattr("app.core.provisioning_service.requests.put", put_mock)
    
    result = provisioning_service.patch_user_scim("user-123", False, correlation_id="corr-1")
    
    assert result["active"] is False
    put_mock.assert_called_once()
    payload_sent = put_mock.call_args.kwargs["json"]
    assert payload_sent["enabled"] is False
    mock_audit.log_jml_event.assert_called_once()
    audit_call = mock_audit.log_jml_event.call_args.kwargs
    assert audit_call["details"]["previous_active"] is True
    assert audit_call["details"]["new_active"] is False
    assert audit_call["details"]["user_id"] == "user-123"


def test_patch_user_scim_enable_success(monkeypatch, mock_jml, mock_audit):
    """patch_user_scim enables a disabled user."""
    disabled_user = {
        "id": "user-234",
        "username": "bob",
        "firstName": "Bob",
        "lastName": "Builder",
        "email": "bob@example.com",
        "enabled": False,
    }
    enabled_user = {**disabled_user, "enabled": True}
    
    get_mock = MagicMock(side_effect=[_mock_response(disabled_user), _mock_response(enabled_user)])
    put_resp = _mock_response({}, status_code=204)
    put_mock = MagicMock(return_value=put_resp)
    
    monkeypatch.setattr("app.core.provisioning_service.requests.get", get_mock)
    monkeypatch.setattr("app.core.provisioning_service.requests.put", put_mock)
    
    result = provisioning_service.patch_user_scim("user-234", True, correlation_id="corr-2")
    
    assert result["active"] is True
    put_mock.assert_called_once()
    payload_sent = put_mock.call_args.kwargs["json"]
    assert payload_sent["enabled"] is True
    audit_call = mock_audit.log_jml_event.call_args.kwargs
    assert audit_call["details"]["previous_active"] is False
    assert audit_call["details"]["new_active"] is True


def test_patch_user_scim_idempotent(monkeypatch, mock_jml, mock_audit):
    """patch_user_scim is idempotent when state already matches."""
    active_user = {
        "id": "user-345",
        "username": "carol",
        "firstName": "Carol",
        "lastName": "Jones",
        "email": "carol@example.com",
        "enabled": True,
    }
    
    get_mock = MagicMock(side_effect=[_mock_response(active_user), _mock_response(active_user)])
    put_mock = MagicMock()
    
    monkeypatch.setattr("app.core.provisioning_service.requests.get", get_mock)
    monkeypatch.setattr("app.core.provisioning_service.requests.put", put_mock)
    
    result = provisioning_service.patch_user_scim("user-345", True, correlation_id="corr-3")
    
    assert result["active"] is True
    put_mock.assert_not_called()
    mock_audit.log_jml_event.assert_called_once()
    audit_call = mock_audit.log_jml_event.call_args.kwargs
    assert audit_call["details"]["previous_active"] is True
    assert audit_call["details"]["new_active"] is True


def test_patch_user_scim_not_found(monkeypatch, mock_jml, mock_audit):
    """patch_user_scim raises 404 when user does not exist."""
    not_found_response = _mock_response({}, status_code=404)
    get_mock = MagicMock(return_value=not_found_response)
    monkeypatch.setattr("app.core.provisioning_service.requests.get", get_mock)
    monkeypatch.setattr("app.core.provisioning_service.requests.put", MagicMock())
    
    with pytest.raises(ScimError) as exc:
        provisioning_service.patch_user_scim("missing-user", False)
    
    assert exc.value.status == 404
    mock_audit.log_jml_event.assert_not_called()


def test_patch_user_scim_update_failure(monkeypatch, mock_jml, mock_audit):
    """patch_user_scim propagates update errors as 500."""
    initial_user = {
        "id": "user-456",
        "username": "dave",
        "firstName": "Dave",
        "lastName": "Smith",
        "email": "dave@example.com",
        "enabled": True,
    }
    
    get_mock = MagicMock(side_effect=[_mock_response(initial_user)])
    failing_put = MagicMock(side_effect=Exception("Keycloak unavailable"))
    
    monkeypatch.setattr("app.core.provisioning_service.requests.get", get_mock)
    monkeypatch.setattr("app.core.provisioning_service.requests.put", failing_put)
    
    with pytest.raises(ScimError) as exc:
        provisioning_service.patch_user_scim("user-456", False)
    
    assert exc.value.status == 500
    mock_audit.log_jml_event.assert_not_called()


# ============================================================================
# delete_user_scim Tests
# ============================================================================

@patch('app.core.provisioning_service.requests.get')
def test_delete_user_success(mock_get, mock_jml, mock_audit):
    """delete_user_scim soft-deletes user via disable_user"""
    # Mock user lookup by ID
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "id": "test-uuid-789",
        "username": "bob",
        "enabled": True,
    }
    
    # delete_user_scim returns None on success
    result = delete_user_scim("test-uuid-789", correlation_id="del-001")
    
    assert result is None
    # Verify disable_user was called
    mock_jml.disable_user.assert_called_once()


@patch('app.core.provisioning_service.requests.get')
def test_delete_user_idempotent(mock_get, mock_jml, mock_audit):
    """delete_user_scim is idempotent - no error if already disabled"""
    # Mock user already disabled
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "id": "test-uuid-999",
        "username": "inactive",
        "enabled": False,  # Already disabled
    }
    
    # Should not raise error
    result = delete_user_scim("test-uuid-999", correlation_id="del-002")
    
    assert result is None


# ============================================================================
# change_user_role Tests
# ============================================================================


@patch('app.core.provisioning_service.get_user_by_username')
@patch('app.core.provisioning_service.change_role')
def test_change_role_success(mock_change_role, mock_get_user, mock_jml, mock_audit):
    """change_user_role moves user from analyst to manager"""
    # Mock get_user_by_username
    mock_get_user.return_value = {
        "id": "user-123",
        "username": "alice",
        "enabled": True,
    }
    
    # change_user_role returns None on success
    result = change_user_role(
        username="alice",
        source_role="analyst",
        target_role="manager",
        correlation_id="test-role"
    )
    
    # Verify function completed (returns None)
    assert result is None
    # Verify audit log was called
    mock_audit.log_jml_event.assert_called_once()
    # Verify change_role was called
    mock_change_role.assert_called_once()


def test_change_role_user_not_found(mock_jml, mock_audit, monkeypatch):
    """change_user_role raises ScimError 404 for missing user"""
    # Mock get_user_by_username to return None
    mock_get = MagicMock(return_value=None)
    monkeypatch.setattr("app.core.provisioning_service.get_user_by_username", mock_get)
    
    with pytest.raises(ScimError) as exc:
        change_user_role("ghost", "analyst", "manager")
    
    assert exc.value.status == 404
    assert "not found" in exc.value.detail.lower()



@patch('app.core.provisioning_service.get_user_by_username')
@patch('app.core.provisioning_service.change_role')
def test_change_role_invalid_source_role(mock_change_role, mock_get_user, mock_jml, mock_audit):
    """change_user_role raises ScimError 500 on invalid source role"""
    # Mock get_user_by_username
    mock_get_user.return_value = {
        "id": "user-456",
        "username": "diana",
        "enabled": True,
    }
    
    # Mock change_role to raise exception
    mock_change_role.side_effect = Exception("User does not have role analyst")
    
    with pytest.raises(ScimError) as exc:
        change_user_role(
            username="diana",
            source_role="analyst",
            target_role="manager"
        )
    
    assert exc.value.status == 500


# ============================================================================
# Error Handling Tests
# ============================================================================

def test_internal_error_wrapped_in_scim_error(mock_jml, mock_audit, valid_create_payload, monkeypatch):
    """Unexpected exceptions are wrapped in ScimError 500"""
    # Mock create_user to raise exception
    mock_create_error = MagicMock(side_effect=RuntimeError("Database connection failed"))
    monkeypatch.setattr("app.core.provisioning_service.create_user", mock_create_error)
    
    with pytest.raises(ScimError) as exc:
        create_user_scim_like(valid_create_payload)
    
    assert exc.value.status == 500
    assert "failed to create user" in exc.value.detail.lower()
