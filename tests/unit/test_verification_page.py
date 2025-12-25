"""Tests for verification page POST actions and UI flow."""
import pytest
from unittest.mock import Mock, patch, MagicMock, PropertyMock
from flask import Flask

from app.api.verification import verification_page, bp
from app.flask_app import create_app


class TestVerificationPagePOST:
    """Test verification page POST actions."""
    
    @patch('app.api.verification._check_access')
    @patch('app.api.verification.cleanup_verifier_users')
    @patch('app.api.verification.render_template')
    def test_verification_page_cleanup_action(self, mock_render, mock_cleanup, mock_check_access):
        """Test POST with cleanup action."""
        mock_cleanup.return_value = 5
        mock_render.return_value = "rendered_template"
        
        app = Flask(__name__)
        app.register_blueprint(bp)
        app.config['APP_CONFIG'] = Mock()
        app.config['APP_CONFIG'].demo_mode = True
        
        with app.test_client() as client:
            with app.test_request_context('/verification', method='POST', 
                                        data={'action': 'cleanup'}):
                from flask import request
                with patch('app.api.verification.request', request):
                    result = verification_page()
                    
                    mock_check_access.assert_called_once()
                    mock_cleanup.assert_called_once()
                    mock_render.assert_called_once()
                    
                    # Check render_template arguments
                    call_args = mock_render.call_args
                    assert call_args[0][0] == "verification.html"
                    kwargs = call_args[1]
                    assert kwargs['cleanup_count'] == 5
                    assert len(kwargs['results']) == 1
                    assert kwargs['results'][0].name == "Cleanup verifier users"
                    assert kwargs['results'][0].status == "success"

    @patch('app.api.verification._check_access')
    @patch('app.api.verification.VerificationRunner')
    @patch('app.api.verification._extract_user_access_token')
    @patch('app.api.verification.render_template')
    def test_verification_page_run_action_success(self, mock_render, mock_extract_token, 
                                                mock_runner_class, mock_check_access):
        """Test POST with run action (successful verification)."""
        from app.api.verification import CheckResult
        
        # Mock runner with proper CheckResult objects
        mock_runner = Mock()
        mock_results = [
            CheckResult("Test 1", "success", 200, "Details 1"),
            CheckResult("Test 2", "success", 200, "Details 2"),
            CheckResult("Test 3", "success", 200, "Details 3")
        ]
        mock_runner.run.return_value = mock_results
        mock_runner_class.return_value = mock_runner
        
        mock_extract_token.return_value = "user-token"
        mock_render.return_value = "rendered_template"
        
        app = Flask(__name__)
        app.register_blueprint(bp)
        app.config['APP_CONFIG'] = Mock()
        app.config['APP_CONFIG'].demo_mode = True
        
        with app.test_client() as client:
            with app.test_request_context('/verification', method='POST', 
                                        data={'action': 'run'}):
                from flask import request
                with patch('app.api.verification.request', request), \
                     patch('app.api.verification.current_app') as mock_current_app:
                    
                    mock_current_app.test_client.return_value = client
                    mock_current_app.config = {'APP_CONFIG': Mock(demo_mode=True)}
                    
                    result = verification_page()
                    
                    mock_check_access.assert_called_once()
                    # Don't check the exact client object, just that it was called
                    assert mock_runner_class.call_count == 1
                    call_args = mock_runner_class.call_args
                    assert call_args[1]['user_access_token'] == "user-token"
                    mock_runner.run.assert_called_once()
                    
                    # Check render_template arguments
                    call_args = mock_render.call_args
                    kwargs = call_args[1]
                    assert kwargs['overall_status'] == "success"
                    assert kwargs['results'] == mock_results

    @patch('app.api.verification._check_access')
    @patch('app.api.verification.VerificationRunner')
    @patch('app.api.verification._extract_user_access_token')
    @patch('app.api.verification.render_template')
    def test_verification_page_run_action_with_failures(self, mock_render, mock_extract_token, 
                                                       mock_runner_class, mock_check_access):
        """Test POST with run action (with verification failures)."""
        from app.api.verification import CheckResult
        
        # Mock runner with some failures
        mock_runner = Mock()
        mock_results = [
            CheckResult("Test 1", "success", 200, "OK"),
            CheckResult("Test 2", "failure", 401, "Unauthorized"),
            CheckResult("Test 3", "success", 200, "OK")
        ]
        mock_runner.run.return_value = mock_results
        mock_runner_class.return_value = mock_runner
        
        mock_extract_token.return_value = "user-token"
        mock_render.return_value = "rendered_template"
        
        app = Flask(__name__)
        app.register_blueprint(bp)
        app.config['APP_CONFIG'] = Mock()
        app.config['APP_CONFIG'].demo_mode = True
        
        with app.test_client() as client:
            with app.test_request_context('/verification', method='POST', 
                                        data={'action': 'run'}):
                from flask import request
                with patch('app.api.verification.request', request), \
                     patch('app.api.verification.current_app') as mock_current_app:
                    
                    # Use MagicMock to avoid async coroutine warning
                    mock_test_client = MagicMock()
                    mock_test_client.return_value = client
                    mock_current_app.test_client = mock_test_client
                    mock_current_app.config = {'APP_CONFIG': Mock(demo_mode=True)}
                    
                    result = verification_page()
                    
                    # Check render_template arguments
                    call_args = mock_render.call_args
                    kwargs = call_args[1]
                    assert kwargs['overall_status'] == "failure"

    @patch('app.api.verification._check_access')
    @patch('app.api.verification.VerificationRunner')
    @patch('app.api.verification._extract_user_access_token')
    @patch('app.api.verification.render_template')
    def test_verification_page_run_action_with_skipped(self, mock_render, mock_extract_token, 
                                                      mock_runner_class, mock_check_access):
        """Test POST with run action (with skipped tests)."""
        from app.api.verification import CheckResult
        
        # Mock runner with some skipped tests
        mock_runner = Mock()
        mock_results = [
            CheckResult("Test 1", "success", 200, "OK"),
            CheckResult("Test 2", "skipped", None, "Skipped"),
            CheckResult("Test 3", "success", 200, "OK")
        ]
        mock_runner.run.return_value = mock_results
        mock_runner_class.return_value = mock_runner
        
        mock_extract_token.return_value = "user-token"
        mock_render.return_value = "rendered_template"
        
        app = Flask(__name__)
        app.register_blueprint(bp)
        app.config['APP_CONFIG'] = Mock()
        app.config['APP_CONFIG'].demo_mode = True
        
        with app.test_client() as client:
            with app.test_request_context('/verification', method='POST', 
                                        data={'action': 'run'}):
                from flask import request
                with patch('app.api.verification.request', request), \
                     patch('app.api.verification.current_app') as mock_current_app:
                    
                    mock_current_app.test_client.return_value = client
                    mock_current_app.config = {'APP_CONFIG': Mock(demo_mode=True)}
                    
                    result = verification_page()
                    
                    # Check render_template arguments
                    call_args = mock_render.call_args
                    kwargs = call_args[1]
                    assert kwargs['overall_status'] == "partial"

    @patch('app.api.verification._check_access')
    @patch('app.api.verification.VerificationRunner')
    @patch('app.api.verification._extract_user_access_token')
    @patch('app.api.verification.render_template')
    def test_verification_page_run_action_exception(self, mock_render, mock_extract_token, 
                                                   mock_runner_class, mock_check_access):
        """Test POST with run action when runner raises exception."""
        # Mock runner that raises exception
        mock_runner = Mock()
        mock_runner.run.side_effect = Exception("Runner failed")
        mock_runner_class.return_value = mock_runner
        
        mock_extract_token.return_value = "user-token"
        mock_render.return_value = "rendered_template"
        
        app = Flask(__name__)
        app.register_blueprint(bp)
        app.config['APP_CONFIG'] = Mock()
        app.config['APP_CONFIG'].demo_mode = True
        
        with app.test_client() as client:
            with app.test_request_context('/verification', method='POST', 
                                        data={'action': 'run'}):
                from flask import request
                with patch('app.api.verification.request', request), \
                     patch('app.api.verification.current_app') as mock_current_app:
                    
                    mock_current_app.test_client.return_value = client
                    mock_current_app.config = {'APP_CONFIG': Mock(demo_mode=True)}
                    
                    result = verification_page()
                    
                    # Check that exception is handled gracefully
                    call_args = mock_render.call_args
                    kwargs = call_args[1]
                    assert len(kwargs['results']) == 1
                    assert kwargs['results'][0].name == "Verification runner"
                    assert kwargs['results'][0].status == "failure"
                    assert "Runner failed" in kwargs['results'][0].detail

    @patch('app.api.verification._check_access')
    @patch('app.api.verification.render_template')
    def test_verification_page_get_request(self, mock_render, mock_check_access):
        """Test GET request to verification page."""
        mock_render.return_value = "rendered_template"
        
        app = Flask(__name__)
        app.register_blueprint(bp)
        app.config['APP_CONFIG'] = Mock()
        app.config['APP_CONFIG'].demo_mode = True
        
        with app.test_client() as client:
            with app.test_request_context('/verification', method='GET'):
                from flask import request
                with patch('app.api.verification.request', request):
                    result = verification_page()
                    
                    mock_check_access.assert_called_once()
                    
                    # Check render_template arguments for GET
                    call_args = mock_render.call_args
                    kwargs = call_args[1]
                    assert kwargs['results'] == []
                    assert kwargs['executed_at'] is None
                    assert kwargs['overall_status'] == "success"
                    assert kwargs['cleanup_count'] == 0

    @patch('app.api.verification._check_access')
    @patch('app.api.verification.render_template')
    def test_verification_page_unknown_action(self, mock_render, mock_check_access):
        """Test POST with unknown action defaults to run."""
        with patch('app.api.verification.VerificationRunner') as mock_runner_class, \
             patch('app.api.verification._extract_user_access_token') as mock_extract_token:
            
            mock_runner = Mock()
            mock_runner.run.return_value = []
            mock_runner_class.return_value = mock_runner
            mock_extract_token.return_value = None
            mock_render.return_value = "rendered_template"
            
            app = Flask(__name__)
            app.register_blueprint(bp)
            app.config['APP_CONFIG'] = Mock()
            app.config['APP_CONFIG'].demo_mode = True
            
            with app.test_client() as client:
                with app.test_request_context('/verification', method='POST', 
                                            data={'action': 'unknown'}):
                    from flask import request
                    with patch('app.api.verification.request', request), \
                         patch('app.api.verification.current_app') as mock_current_app:
                        
                        mock_current_app.test_client.return_value = client
                        mock_current_app.config = {'APP_CONFIG': Mock(demo_mode=True)}
                        
                        result = verification_page()
                        
                        # Should default to running verification
                        mock_runner_class.assert_called_once()
                        mock_runner.run.assert_called_once()

    @patch('app.api.verification._check_access')
    @patch('app.api.verification.render_template')
    def test_verification_page_rate_limiting_context(self, mock_render, mock_check_access):
        """Test that rate limiting context is passed to template."""
        mock_render.return_value = "rendered_template"
        
        app = Flask(__name__)
        app.register_blueprint(bp)
        app.config['APP_CONFIG'] = Mock()
        app.config['APP_CONFIG'].demo_mode = True
        
        with app.test_client() as client:
            with app.test_request_context('/verification', method='GET'):
                from flask import request
                with patch('app.api.verification.request', request), \
                     patch('app.api.verification.RATE_LIMITING_AVAILABLE', True):
                    
                    result = verification_page()
                    
                    # Check that rate limiting availability is passed to template
                    call_args = mock_render.call_args
                    kwargs = call_args[1]
                    assert kwargs['rate_limiting_available'] is True


class TestVerificationPageIntegration:
    """Integration tests for verification page with real Flask app."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_verification_page_get_integration(self, monkeypatch):
        """Test GET request integration."""
        # Use monkeypatch to avoid async mock warnings with Jinja2
        from app.config import settings as settings_module
        monkeypatch.setattr(settings_module.settings, 'verify_page_enabled', True)
        monkeypatch.setattr(settings_module.settings, 'demo_mode', True)
        response = self.client.get('/verification')
        assert response.status_code == 200
        assert b'SCIM Verification' in response.data

    def test_verification_page_disabled_integration(self, monkeypatch):
        """Test verification page when disabled."""
        # Use monkeypatch to avoid async mock warnings with Jinja2
        from app.config import settings as settings_module
        monkeypatch.setattr(settings_module.settings, 'verify_page_enabled', False)
        response = self.client.get('/verification')
        assert response.status_code == 404

    def test_verification_page_cleanup_integration(self, monkeypatch):
        """Test cleanup action integration."""
        from app.config import settings as settings_module
        from app.api import verification as verification_module
        
        monkeypatch.setattr(settings_module.settings, 'verify_page_enabled', True)
        monkeypatch.setattr(settings_module.settings, 'demo_mode', True)
        
        # Use monkeypatch instead of patch to avoid async mock warnings
        cleanup_called = []
        def mock_cleanup():
            cleanup_called.append(True)
            return 3
        monkeypatch.setattr(verification_module, 'cleanup_verifier_users', mock_cleanup)
        
        response = self.client.post('/verification', data={'action': 'cleanup'})
        assert response.status_code == 200
        assert len(cleanup_called) == 1

    def test_verification_page_run_integration(self, monkeypatch):
        """Test run action integration."""
        # Mock successful verification run with proper CheckResult objects
        from app.api.verification import CheckResult
        from app.config import settings as settings_module
        
        monkeypatch.setattr(settings_module.settings, 'verify_page_enabled', True)
        monkeypatch.setattr(settings_module.settings, 'demo_mode', True)
        
        with patch('app.api.verification.VerificationRunner') as mock_runner_class, \
             patch('app.api.verification._extract_user_access_token') as mock_extract_token:
            
            mock_runner = Mock()
            mock_runner.run.return_value = [
                CheckResult(
                    name="POST /Users (create)",
                    status="success",
                    status_code=201,
                    detail="User created successfully",
                    correlation_id="test-correlation-id",
                    duration_ms=100
                ),
                CheckResult(
                    name="GET /Users/{id}",
                    status="success",
                    status_code=200,
                    detail="User retrieved successfully",
                    correlation_id="test-correlation-id-2",
                    duration_ms=50
                )
            ]
            mock_runner_class.return_value = mock_runner
            mock_extract_token.return_value = "test-token"
            
            response = self.client.post('/verification', data={'action': 'run'})
            assert response.status_code == 200
            mock_runner_class.assert_called_once()
        mock_runner.run.assert_called_once()