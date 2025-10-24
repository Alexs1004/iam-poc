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

from app.scim_api import scim
from app.core.provisioning_service import keycloak_to_scim, ScimError


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
        assert data['patch']['supported'] is False
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
    
    @patch('app.scim_api.create_user')
    @patch('app.scim_api.get_user_by_username')
    def test_create_user_success(self, mock_get_user, mock_create, client, mock_keycloak_user, mock_token):
        """Test POST /Users creates user successfully"""
        mock_get_user.return_value = None  # User doesn't exist
        mock_create.return_value = ('user-id-123', 'temp-password-xyz')
        
        with patch('app.scim_api.get_keycloak_admin') as mock_admin:
            mock_admin.return_value.get_user.return_value = mock_keycloak_user
            
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
        
    @patch('app.scim_api.get_user_by_username')
    def test_create_user_conflict(self, mock_get_user, client, mock_keycloak_user, mock_token):
        """Test POST /Users returns 409 for duplicate username"""
        mock_get_user.return_value = mock_keycloak_user  # User exists
        
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
        
    @patch('app.scim_api.get_keycloak_admin')
    def test_get_user_success(self, mock_admin, client, mock_keycloak_user, mock_token):
        """Test GET /Users/{id} retrieves user"""
        mock_admin.return_value.get_user.return_value = mock_keycloak_user
        
        response = client.get(
            f'/scim/v2/Users/{mock_keycloak_user["id"]}',
            headers={'Authorization': mock_token}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['id'] == mock_keycloak_user['id']
        assert data['userName'] == mock_keycloak_user['username']
        assert data['active'] is True
        
    @patch('app.scim_api.get_keycloak_admin')
    def test_get_user_not_found(self, mock_admin, client, mock_token):
        """Test GET /Users/{id} returns 404 for missing user"""
        mock_admin.return_value.get_user.side_effect = Exception("User not found")
        
        response = client.get(
            '/scim/v2/Users/nonexistent-id',
            headers={'Authorization': mock_token}
        )
        
        assert response.status_code == 404
        
    @patch('app.scim_api.get_keycloak_admin')
    def test_list_users_success(self, mock_admin, client, mock_keycloak_user, mock_token):
        """Test GET /Users returns paginated list"""
        mock_admin.return_value.get_users.return_value = [
            mock_keycloak_user,
            {**mock_keycloak_user, 'id': 'user-2', 'username': 'bob'},
        ]
        
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
        
    @patch('app.scim_api.get_keycloak_admin')
    def test_list_users_with_filter(self, mock_admin, client, mock_keycloak_user, mock_token):
        """Test GET /Users?filter=... applies filtering"""
        mock_admin.return_value.get_users.return_value = [mock_keycloak_user]
        
        response = client.get(
            '/scim/v2/Users?filter=userName eq "alice"',
            headers={'Authorization': mock_token}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Verify filter was applied in query
        mock_admin.return_value.get_users.assert_called_once()
        call_kwargs = mock_admin.return_value.get_users.call_args[1]
        assert 'alice' in call_kwargs.get('query', {}).get('username', '')
        
    @patch('app.scim_api.disable_user')
    @patch('app.scim_api.get_keycloak_admin')
    def test_update_user_disable(self, mock_admin, mock_disable, client, mock_keycloak_user, mock_token):
        """Test PUT /Users/{id} with active=false disables user"""
        disabled_user = {**mock_keycloak_user, 'enabled': False}
        mock_admin.return_value.get_user.return_value = disabled_user
        
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
        
        mock_disable.assert_called_once_with('alice')
        
    @patch('app.scim_api.disable_user')
    @patch('app.scim_api.get_keycloak_admin')
    def test_delete_user(self, mock_admin, mock_disable, client, mock_keycloak_user, mock_token):
        """Test DELETE /Users/{id} soft-deletes user"""
        mock_admin.return_value.get_user.return_value = mock_keycloak_user
        
        response = client.delete(
            f'/scim/v2/Users/{mock_keycloak_user["id"]}',
            headers={'Authorization': mock_token}
        )
        
        assert response.status_code == 204
        assert response.data == b''
        
        mock_disable.assert_called_once_with('alice')


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
    
    @patch('app.scim_api.get_keycloak_admin')
    def test_pagination_defaults(self, mock_admin, client, mock_token):
        """Test default pagination values"""
        mock_admin.return_value.get_users.return_value = []
        
        response = client.get(
            '/scim/v2/Users',
            headers={'Authorization': mock_token}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # SCIM default: startIndex=1
        assert data['startIndex'] == 1
        
    @patch('app.scim_api.get_keycloak_admin')
    def test_filter_username_eq(self, mock_admin, client, mock_token):
        """Test filter parsing for 'userName eq "value"'"""
        mock_admin.return_value.get_users.return_value = []
        
        response = client.get(
            '/scim/v2/Users?filter=userName eq "alice"',
            headers={'Authorization': mock_token}
        )
        
        assert response.status_code == 200
        
        # Verify username query parameter was set
        call_kwargs = mock_admin.return_value.get_users.call_args[1]
        assert 'alice' in str(call_kwargs.get('query', {}))


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
