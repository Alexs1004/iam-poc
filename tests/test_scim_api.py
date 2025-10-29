"""
Unit tests for SCIM 2.0 API endpoints
Tests RFC 7644 compliance for user provisioning
"""

import pytest
import json
import os
from unittest.mock import MagicMock, patch

# Set environment variables before importing app
os.environ['DEMO_MODE'] = 'true'
os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-unit-tests'
os.environ['SKIP_OAUTH_FOR_TESTS'] = 'true'  # Skip OAuth validation for these unit tests

from app.api.scim import bp as scim
from app.core.provisioning_service import keycloak_to_scim, ScimError


# Cleanup fixture to prevent test pollution
@pytest.fixture(scope="module", autouse=True)
def cleanup_test_env():
    """Ensure SKIP_OAUTH_FOR_TESTS is cleaned up after this module"""
    yield
    # Cleanup after all tests in this module
    os.environ.pop('SKIP_OAUTH_FOR_TESTS', None)


@pytest.fixture
def client():
    """Create Flask test client"""
    from app.flask_app import app
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        yield client


@pytest.fixture
def mock_keycloak_user():
    """Mock Keycloak user object"""
    return {
        'id': '12345678-1234-1234-1234-123456789abc',
        'username': 'alice',
        'email': 'alice@example.com',
        'firstName': 'Alice',
        'lastName': 'Wonder',
        'enabled': True,
        'createdTimestamp': 1704067200000,  # 2024-01-01T00:00:00Z
    }


@pytest.fixture
def mock_token():
    """Mock valid OAuth token"""
    return "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token"


@pytest.fixture
def mock_oauth_validation(monkeypatch):
    """Mock OAuth token validation to always succeed"""
    def mock_validate(token, required_scope=None):
        # Return a valid decoded token payload
        return {
            'sub': 'test-user',
            'scope': 'scim:read scim:write',
            'client_id': 'test-client'
        }
    
    monkeypatch.setattr('app.api.decorators.validate_jwt_token', mock_validate)
    return mock_validate


class TestSCIMSchemaEndpoints:
    """Test SCIM schema discovery endpoints"""
    
    def test_service_provider_config(self, client):
        """Test /ServiceProviderConfig returns valid configuration"""
        response = client.get('/scim/v2/ServiceProviderConfig')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Check SCIM schema
        assert 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig' in data['schemas']
        
        # Check supported features
        assert data['filter']['supported'] is True
        assert data['patch']['supported'] is True
        assert data['bulk']['supported'] is False
        
    def test_resource_types(self, client):
        """Test /ResourceTypes returns User resource"""
        response = client.get('/scim/v2/ResourceTypes')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['totalResults'] >= 1
        
        user_resource = next(
            (r for r in data['Resources'] if r['name'] == 'User'),
            None
        )
        assert user_resource is not None
        assert user_resource['endpoint'] == '/scim/v2/Users'  # Full path including prefix
        
    def test_schemas(self, client):
        """Test /Schemas returns User schema definition"""
        response = client.get('/scim/v2/Schemas')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['totalResults'] >= 1
        
        user_schema = next(
            (s for s in data['Resources'] 
             if s['id'] == 'urn:ietf:params:scim:schemas:core:2.0:User'),
            None
        )
        assert user_schema is not None
        assert user_schema['name'] == 'User'


class TestSCIMUserCRUD:
    """Test SCIM User CRUD operations"""
    
    @patch('app.core.provisioning_service.create_user_scim_like')
    def test_create_user_success(self, mock_create, client, mock_keycloak_user, mock_token, mock_oauth_validation):
        """Test POST /Users creates user successfully"""
        # Mock the response from provisioning service
        mock_scim_user = keycloak_to_scim(mock_keycloak_user)
        mock_scim_user['_tempPassword'] = 'temp-password-xyz'
        mock_create.return_value = mock_scim_user
        
        response = client.post(
            '/scim/v2/Users',
            headers={
                'Content-Type': 'application/scim+json',
                'Authorization': mock_token
            },
            json={
                'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
                'userName': 'newuser',
                'emails': [{'value': 'newuser@example.com', 'primary': True}],
                'name': {'givenName': 'New', 'familyName': 'User'},
                'active': True
            }
        )
        
        assert response.status_code == 201
        data = json.loads(response.data)
        
        assert data['userName'] == 'alice'
        assert data['id'] == mock_keycloak_user['id']
        assert '_tempPassword' in data
        
    @patch('app.core.provisioning_service.create_user_scim_like')
    def test_create_user_conflict(self, mock_create, client, mock_keycloak_user, mock_token, mock_oauth_validation):
        """Test POST /Users returns 409 for duplicate username"""
        # Mock provisioning service raising uniqueness error
        mock_create.side_effect = ScimError(409, "User already exists", "uniqueness")
        
        response = client.post(
            '/scim/v2/Users',
            headers={
                'Content-Type': 'application/scim+json',
                'Authorization': mock_token
            },
            json={
                'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
                'userName': 'alice',
                'emails': [{'value': 'alice@example.com', 'primary': True}],
                'name': {'givenName': 'Alice', 'familyName': 'Wonder'},
                'active': True
            }
        )
        
        assert response.status_code == 409
        data = json.loads(response.data)
        assert data['scimType'] == 'uniqueness'
        
    def test_create_user_invalid_schema(self, client, mock_token):
        """Test POST /Users validates required fields"""
        response = client.post(
            '/scim/v2/Users',
            headers={
                'Content-Type': 'application/scim+json',
                'Authorization': mock_token
            },
            json={
                'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
                # Missing userName
                'emails': [{'value': 'test@example.com'}],
                'active': True
            }
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['scimType'] == 'invalidValue'
        
    @patch('app.core.provisioning_service.get_user_scim')
    def test_get_user_success(self, mock_get_user, client, mock_keycloak_user, mock_token, mock_oauth_validation):
        """Test GET /Users/{id} retrieves user"""
        mock_scim_user = keycloak_to_scim(mock_keycloak_user)
        mock_get_user.return_value = mock_scim_user
        
        response = client.get(
            f'/scim/v2/Users/{mock_keycloak_user["id"]}',
            headers={'Authorization': mock_token}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['id'] == mock_keycloak_user['id']
        assert data['userName'] == mock_keycloak_user['username']
        assert data['active'] is True
        
    @patch('app.core.provisioning_service.get_user_scim')
    def test_get_user_not_found(self, mock_get_user, client, mock_token, mock_oauth_validation):
        """Test GET /Users/{id} returns 404 for missing user"""
        mock_get_user.side_effect = ScimError(404, "User not found", "invalidValue")
        
        response = client.get(
            '/scim/v2/Users/nonexistent-id',
            headers={'Authorization': mock_token}
        )
        
        assert response.status_code == 404
        
    @patch('app.core.provisioning_service.list_users_scim')
    def test_list_users_success(self, mock_list_users, client, mock_keycloak_user, mock_token, mock_oauth_validation):
        """Test GET /Users returns paginated list"""
        scim_user1 = keycloak_to_scim(mock_keycloak_user)
        scim_user2 = keycloak_to_scim({**mock_keycloak_user, 'id': 'user-2', 'username': 'bob'})
        mock_list_users.return_value = {
            'Resources': [scim_user1, scim_user2],
            'totalResults': 2,
            'startIndex': 1,
            'itemsPerPage': 2
        }
        
        response = client.get(
            '/scim/v2/Users?startIndex=1&count=10',
            headers={'Authorization': mock_token}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['totalResults'] == 2
        assert data['startIndex'] == 1
        assert data['itemsPerPage'] == 2
        assert len(data['Resources']) == 2
        
    @patch('app.core.provisioning_service.list_users_scim')
    def test_list_users_with_filter(self, mock_list_users, client, mock_keycloak_user, mock_token, mock_oauth_validation):
        """Test GET /Users?filter=... applies filtering"""
        scim_user = keycloak_to_scim(mock_keycloak_user)
        mock_list_users.return_value = {
            'Resources': [scim_user],
            'totalResults': 1,
            'startIndex': 1,
            'itemsPerPage': 1
        }
        
        response = client.get(
            '/scim/v2/Users?filter=userName eq "alice"',
            headers={'Authorization': mock_token}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['Resources']) == 1
        
        # Verify filter was passed to provisioning service
        mock_list_users.assert_called_once()
        # list_users_scim is called with query as positional arg
        call_args = mock_list_users.call_args[0]
        assert len(call_args) > 0
        query_dict = call_args[0]
        assert query_dict.get('filter') == 'userName eq "alice"'
        
    @patch('app.core.provisioning_service.replace_user_scim')
    def test_update_user_disable(self, mock_replace, client, mock_keycloak_user, mock_token, mock_oauth_validation):
        """Test PUT /Users/{id} with active=false disables user"""
        disabled_scim_user = keycloak_to_scim({**mock_keycloak_user, 'enabled': False})
        mock_replace.return_value = disabled_scim_user
        
        response = client.put(
            f'/scim/v2/Users/{mock_keycloak_user["id"]}',
            headers={
                'Content-Type': 'application/scim+json',
                'Authorization': mock_token
            },
            json={
                'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
                'userName': 'alice',
                'active': False
            }
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['active'] is False
        
        # Verify replace_user_scim was called
        mock_replace.assert_called_once()
        
    @patch('app.core.provisioning_service.delete_user_scim')
    def test_delete_user(self, mock_delete, client, mock_keycloak_user, mock_token, mock_oauth_validation):
        """Test DELETE /Users/{id} soft-deletes user"""
        mock_delete.return_value = None  # DELETE returns no content
        
        response = client.delete(
            f'/scim/v2/Users/{mock_keycloak_user["id"]}',
            headers={'Authorization': mock_token}
        )
        
        assert response.status_code == 204
        assert response.data == b''
        
        # Verify delete was called with user_id (and correlation_id=None)
        mock_delete.assert_called_once()
        assert mock_delete.call_args[0][0] == mock_keycloak_user["id"]

    @patch('app.core.provisioning_service.patch_user_scim')
    def test_patch_user_active_success(self, mock_patch_user, client, mock_keycloak_user, mock_token, mock_oauth_validation):
        """Test PATCH /Users/{id} toggles active state"""
        updated_user = keycloak_to_scim({**mock_keycloak_user, 'enabled': False})
        mock_patch_user.return_value = updated_user
        
        response = client.patch(
            f'/scim/v2/Users/{mock_keycloak_user["id"]}',
            headers={
                'Content-Type': 'application/scim+json',
                'Authorization': mock_token
            },
            json={
                'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                'Operations': [
                    {'op': 'replace', 'path': 'active', 'value': False}
                ]
            }
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['active'] is False
        mock_patch_user.assert_called_once_with(mock_keycloak_user["id"], False, None)

    @patch('app.core.provisioning_service.patch_user_scim')
    def test_patch_user_multiple_operations_rejected(self, mock_patch_user, client, mock_keycloak_user, mock_token, mock_oauth_validation):
        """PATCH should reject multiple operations"""
        response = client.patch(
            f'/scim/v2/Users/{mock_keycloak_user["id"]}',
            headers={
                'Content-Type': 'application/scim+json',
                'Authorization': mock_token
            },
            json={
                'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                'Operations': [
                    {'op': 'replace', 'path': 'active', 'value': False},
                    {'op': 'replace', 'path': 'active', 'value': True}
                ]
            }
        )
        
        assert response.status_code == 400
        mock_patch_user.assert_not_called()

    @patch('app.core.provisioning_service.patch_user_scim')
    def test_patch_user_requires_authorization_header(self, mock_patch_user, client, mock_keycloak_user, monkeypatch):
        """PATCH should return 401 when Authorization header missing"""
        monkeypatch.setenv('SKIP_OAUTH_FOR_TESTS', 'false')
        
        response = client.patch(
            f'/scim/v2/Users/{mock_keycloak_user["id"]}',
            headers={'Content-Type': 'application/scim+json'},
            json={
                'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                'Operations': [
                    {'op': 'replace', 'path': 'active', 'value': False}
                ]
            }
        )
        
        assert response.status_code == 401
        mock_patch_user.assert_not_called()

    @patch('app.core.provisioning_service.patch_user_scim')
    def test_patch_user_insufficient_scope(self, mock_patch_user, client, mock_keycloak_user, mock_token, monkeypatch):
        """PATCH should return 403 when token lacks scim:write"""
        monkeypatch.setenv('SKIP_OAUTH_FOR_TESTS', 'false')
        
        def no_write_scope(_token):
            return {
                'sub': 'tester',
                'scope': 'scim:read',
                'client_id': 'test-client'
            }
        
        monkeypatch.setattr('app.api.scim.validate_jwt_token', no_write_scope)
        
        response = client.patch(
            f'/scim/v2/Users/{mock_keycloak_user["id"]}',
            headers={
                'Content-Type': 'application/scim+json',
                'Authorization': mock_token
            },
            json={
                'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                'Operations': [
                    {'op': 'replace', 'path': 'active', 'value': False}
                ]
            }
        )
        
        assert response.status_code == 403
        mock_patch_user.assert_not_called()

    @patch('app.core.provisioning_service.patch_user_scim')
    def test_patch_user_unsupported_media_type(self, mock_patch_user, client, mock_keycloak_user, mock_token, monkeypatch):
        """PATCH should enforce application/scim+json Content-Type"""
        monkeypatch.setenv('SKIP_OAUTH_FOR_TESTS', 'false')
        
        def full_scope(_token):
            return {
                'sub': 'tester',
                'scope': 'scim:write',
                'client_id': 'test-client'
            }
        
        monkeypatch.setattr('app.api.scim.validate_jwt_token', full_scope)
        
        response = client.patch(
            f'/scim/v2/Users/{mock_keycloak_user["id"]}',
            headers={
                'Content-Type': 'application/json',
                'Authorization': mock_token
            },
            json={
                'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                'Operations': [
                    {'op': 'replace', 'path': 'active', 'value': False}
                ]
            }
        )
        
        assert response.status_code == 415
        mock_patch_user.assert_not_called()

    @patch('app.core.provisioning_service.patch_user_scim')
    def test_patch_user_not_implemented_for_other_ops(self, mock_patch_user, client, mock_keycloak_user, mock_token, mock_oauth_validation):
        """PATCH should return 501 for unsupported operations"""
        response = client.patch(
            f'/scim/v2/Users/{mock_keycloak_user["id"]}',
            headers={
                'Content-Type': 'application/scim+json',
                'Authorization': mock_token
            },
            json={
                'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                'Operations': [
                    {'op': 'add', 'path': 'emails', 'value': []}
                ]
            }
        )
        
        assert response.status_code == 501
        mock_patch_user.assert_not_called()


class TestHelperFunctions:
    """Test helper/utility functions - DEPRECATED: moved to test_service_scim.py"""
    
    def test_keycloak_to_scim_conversion(self, mock_keycloak_user):
        """Test keycloak_to_scim transforms correctly (now in provisioning_service)"""
        scim_user = keycloak_to_scim(mock_keycloak_user)
        
        assert scim_user['id'] == mock_keycloak_user['id']
        assert scim_user['userName'] == mock_keycloak_user['username']
        assert scim_user['active'] == mock_keycloak_user['enabled']
        
        # Check name structure
        assert scim_user['name']['givenName'] == mock_keycloak_user['firstName']
        assert scim_user['name']['familyName'] == mock_keycloak_user['lastName']
        
        # Check emails
        assert len(scim_user['emails']) == 1
        assert scim_user['emails'][0]['value'] == mock_keycloak_user['email']
        assert scim_user['emails'][0]['primary'] is True
        
        # Check meta
        assert scim_user['meta']['resourceType'] == 'User'
        # Note: 'created' field now uses actual timestamps, not hardcoded
        
    def test_validate_scim_user_schema_valid(self):
        """Test validation accepts valid data (now in provisioning_service.create_user_scim_like)"""
        # This is now tested indirectly via create_user_scim_like in test_service_scim.py
        pass
        
    def test_validate_scim_user_schema_missing_username(self):
        """Test validation rejects missing userName (now in provisioning_service)"""
        # This is now tested indirectly via create_user_scim_like in test_service_scim.py
        pass
            
    def test_scim_error_format(self):
        """Test ScimError.to_dict() creates proper error response"""
        error = ScimError(400, 'Invalid input', 'invalidValue')
        error_dict = error.to_dict()
        
        assert error_dict['status'] == '400'
        assert error_dict['scimType'] == 'invalidValue'
        assert error_dict['detail'] == 'Invalid input'
        assert 'urn:ietf:params:scim:api:messages:2.0:Error' in error_dict['schemas']


class TestSCIMPaginationAndFiltering:
    """Test SCIM pagination and filtering logic"""
    
    @patch('app.core.provisioning_service.list_users_scim')
    def test_pagination_defaults(self, mock_list_users, client, mock_token, mock_oauth_validation):
        """Test default pagination values"""
        mock_list_users.return_value = {
            'Resources': [],
            'totalResults': 0,
            'startIndex': 1,
            'itemsPerPage': 0
        }
        
        response = client.get(
            '/scim/v2/Users',
            headers={'Authorization': mock_token}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # SCIM default: startIndex=1
        assert data['startIndex'] == 1
        
    @patch('app.core.provisioning_service.list_users_scim')
    def test_filter_username_eq(self, mock_list_users, client, mock_token, mock_oauth_validation):
        """Test filter parsing for 'userName eq "value"'"""
        mock_list_users.return_value = {
            'Resources': [],
            'totalResults': 0,
            'startIndex': 1,
            'itemsPerPage': 0
        }
        
        response = client.get(
            '/scim/v2/Users?filter=userName eq "alice"',
            headers={'Authorization': mock_token}
        )
        
        assert response.status_code == 200
        
        # Verify filter string was passed (as positional argument)
        call_args = mock_list_users.call_args[0]
        query_dict = call_args[0]
        assert query_dict.get('filter') == 'userName eq "alice"'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
