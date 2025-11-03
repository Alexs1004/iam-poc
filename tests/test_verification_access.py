"""Tests for verification page access control."""
import pytest
from unittest.mock import patch
from app.flask_app import create_app


# Complete environment variables needed for production mode tests
PRODUCTION_ENV_VARS = {
    'DEMO_MODE': 'false',
    'FLASK_SECRET_KEY': 'test-key',
    'TRUSTED_PROXY_IPS': '127.0.0.1/32',
    'KEYCLOAK_ISSUER': 'https://localhost/realms/demo',
    'OIDC_CLIENT_ID': 'flask-app',
    'OIDC_REDIRECT_URI': 'https://localhost/callback',
    'POST_LOGOUT_REDIRECT_URI': 'https://localhost/',
    'KEYCLOAK_SERVICE_CLIENT_ID': 'automation-cli',
    'KEYCLOAK_SERVICE_CLIENT_SECRET': 'test-secret',
    'KEYCLOAK_ADMIN': 'admin',
    'KEYCLOAK_ADMIN_PASSWORD': 'admin'
}


class TestVerificationAccess:
    """Test verification page access control."""

    @patch('app.api.verification.settings.verify_page_enabled', True)
    @patch('app.api.verification.settings.demo_mode', True)
    def test_demo_mode_verify_enabled_default_allows_access(self):
        """DEMO_MODE=true, VERIFY_PAGE_ENABLED default: GET /verification → 200."""
        with patch.dict('os.environ', {
            'DEMO_MODE': 'true',
            'FLASK_SECRET_KEY': 'test-key'
        }, clear=True):
            app = create_app()
            with app.test_client() as client:
                response = client.get('/verification')
                assert response.status_code == 200

    @patch('app.api.verification.settings.verify_page_enabled', False)
    @patch('app.api.verification.settings.demo_mode', False)
    def test_production_mode_verify_disabled_default_returns_404(self):
        """DEMO_MODE=false, VERIFY_PAGE_ENABLED default: GET /verification → 404."""
        with patch.dict('os.environ', PRODUCTION_ENV_VARS, clear=True):
            app = create_app()
            with app.test_client() as client:
                response = client.get('/verification')
                assert response.status_code == 404

    @patch('app.api.verification.settings.verify_page_enabled', True)
    @patch('app.api.verification.settings.demo_mode', False)
    def test_production_mode_verify_enabled_without_auth_returns_403(self):
        """DEMO_MODE=false, VERIFY_PAGE_ENABLED=true without auth: → 403."""
        env_vars = PRODUCTION_ENV_VARS.copy()
        env_vars['VERIFY_PAGE_ENABLED'] = 'true'
        with patch.dict('os.environ', env_vars, clear=True):
            app = create_app()
            with app.test_client() as client:
                response = client.get('/verification')
                assert response.status_code in [302, 401, 403]

    @patch('app.api.verification.settings.verify_page_enabled', True)
    @patch('app.api.verification.settings.demo_mode', False)
    @patch('app.api.verification.is_authenticated')
    @patch('app.api.verification.current_user_context')
    def test_production_mode_verify_enabled_with_verifier_role_allows_access(
        self, mock_user_context, mock_is_authenticated
    ):
        """DEMO_MODE=false, VERIFY_PAGE_ENABLED=true with role "iam-verifier" → 200."""
        mock_is_authenticated.return_value = True
        mock_user_context.return_value = (None, None, None, ['iam-verifier'])
        
        env_vars = PRODUCTION_ENV_VARS.copy()
        env_vars['VERIFY_PAGE_ENABLED'] = 'true'
        with patch.dict('os.environ', env_vars, clear=True):
            app = create_app()
            with app.test_client() as client:
                response = client.get('/verification')
                assert response.status_code == 200

    @patch('app.api.verification.settings.verify_page_enabled', True)
    @patch('app.api.verification.settings.demo_mode', False)
    @patch('app.api.verification.is_authenticated')
    @patch('app.api.verification.current_user_context')
    def test_production_mode_verify_enabled_with_realm_admin_role_allows_access(
        self, mock_user_context, mock_is_authenticated
    ):
        """DEMO_MODE=false, VERIFY_PAGE_ENABLED=true with role "realm-admin" → 200."""
        mock_is_authenticated.return_value = True
        mock_user_context.return_value = (None, None, None, ['realm-admin'])
        
        env_vars = PRODUCTION_ENV_VARS.copy()
        env_vars['VERIFY_PAGE_ENABLED'] = 'true'
        with patch.dict('os.environ', env_vars, clear=True):
            app = create_app()
            with app.test_client() as client:
                response = client.get('/verification')
                assert response.status_code == 200

    @patch('app.api.verification.settings.verify_page_enabled', True)
    @patch('app.api.verification.settings.demo_mode', False)
    @patch('app.api.verification.is_authenticated')
    @patch('app.api.verification.current_user_context')
    def test_production_mode_verify_enabled_with_insufficient_role_returns_403(
        self, mock_user_context, mock_is_authenticated
    ):
        """DEMO_MODE=false, VERIFY_PAGE_ENABLED=true with insufficient role → 403."""
        mock_is_authenticated.return_value = True
        mock_user_context.return_value = (None, None, None, ['analyst'])
        
        env_vars = PRODUCTION_ENV_VARS.copy()
        env_vars['VERIFY_PAGE_ENABLED'] = 'true'
        with patch.dict('os.environ', env_vars, clear=True):
            app = create_app()
            with app.test_client() as client:
                response = client.get('/verification')
                assert response.status_code == 403