"""Low-level HTTP client for Keycloak Admin API.

Handles authentication, token management, and HTTP operations.
"""
from __future__ import annotations
import os
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

import requests

from .exceptions import KeycloakAPIError

REQUEST_TIMEOUT = 5


class KeycloakClient:
    """HTTP client for Keycloak Admin API with automatic token management.
    
    Features:
    - Automatic token refresh when expired
    - Centralized error handling
    - Support for both admin and service account authentication
    
    Usage:
        client = KeycloakClient("http://keycloak:8080")
        client.authenticate_admin("admin", "password")
        response = client.get("/admin/realms/demo/users")
    """
    
    def __init__(self, base_url: Optional[str] = None):
        """Initialize Keycloak client.
        
        Args:
            base_url: Keycloak base URL (defaults to KEYCLOAK_INTERNAL_URL env var)
        """
        self.base_url = (base_url or os.environ.get("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")).rstrip("/")
        self._token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None
        self._auth_method: Optional[str] = None
        self._auth_params: Dict[str, Any] = {}
    
    def authenticate_admin(self, username: str, password: str, realm: str = "master") -> str:
        """Authenticate as admin user and store credentials for auto-refresh.
        
        Args:
            username: Admin username
            password: Admin password
            realm: Authentication realm (default: master)
            
        Returns:
            Access token
        """
        self._auth_method = "admin"
        self._auth_params = {"username": username, "password": password, "realm": realm}
        token = self._get_admin_token(username, password, realm)
        self._token = token
        # Conservative expiry: assume 60 seconds for safety
        self._token_expires_at = datetime.now() + timedelta(seconds=60)
        return token
    
    def authenticate_service_account(self, auth_realm: str, client_id: str, client_secret: str) -> str:
        """Authenticate as service account and store credentials for auto-refresh.
        
        Args:
            auth_realm: Realm where service account client exists
            client_id: Service account client ID
            client_secret: Service account client secret
            
        Returns:
            Access token
        """
        self._auth_method = "service_account"
        self._auth_params = {
            "auth_realm": auth_realm,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        token = self._get_service_account_token(auth_realm, client_id, client_secret)
        self._token = token
        # Conservative expiry: assume 60 seconds for safety
        self._token_expires_at = datetime.now() + timedelta(seconds=60)
        return token
    
    def _ensure_authenticated(self) -> None:
        """Ensure we have a valid token, refreshing if necessary."""
        if not self._token or not self._token_expires_at:
            raise KeycloakAPIError(401, "Not authenticated - call authenticate_admin or authenticate_service_account first", "")
        
        # Refresh if token expired or expiring soon (within 10 seconds)
        if datetime.now() >= self._token_expires_at - timedelta(seconds=10):
            if self._auth_method == "admin":
                self._token = self._get_admin_token(
                    self._auth_params["username"],
                    self._auth_params["password"],
                    self._auth_params["realm"],
                )
            elif self._auth_method == "service_account":
                self._token = self._get_service_account_token(
                    self._auth_params["auth_realm"],
                    self._auth_params["client_id"],
                    self._auth_params["client_secret"],
                )
            self._token_expires_at = datetime.now() + timedelta(seconds=60)
    
    def get(self, path: str, params: Optional[Dict] = None, **kwargs) -> requests.Response:
        """Execute GET request with automatic authentication.
        
        Args:
            path: API endpoint path (e.g., "/admin/realms/demo/users")
            params: Query parameters
            **kwargs: Additional arguments for requests.get
            
        Returns:
            Response object
            
        Raises:
            KeycloakAPIError: On HTTP error
        """
        self._ensure_authenticated()
        url = f"{self.base_url}{path}"
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._token}"
        
        resp = requests.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs)
        self._handle_error(resp)
        return resp
    
    def post(self, path: str, json: Optional[Dict] = None, data: Optional[Dict] = None, **kwargs) -> requests.Response:
        """Execute POST request with automatic authentication.
        
        Args:
            path: API endpoint path
            json: JSON payload
            data: Form data payload
            **kwargs: Additional arguments for requests.post
            
        Returns:
            Response object
            
        Raises:
            KeycloakAPIError: On HTTP error
        """
        self._ensure_authenticated()
        url = f"{self.base_url}{path}"
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._token}"
        
        resp = requests.post(url, json=json, data=data, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs)
        self._handle_error(resp)
        return resp
    
    def put(self, path: str, json: Optional[Dict] = None, **kwargs) -> requests.Response:
        """Execute PUT request with automatic authentication.
        
        Args:
            path: API endpoint path
            json: JSON payload
            **kwargs: Additional arguments for requests.put
            
        Returns:
            Response object
            
        Raises:
            KeycloakAPIError: On HTTP error
        """
        self._ensure_authenticated()
        url = f"{self.base_url}{path}"
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._token}"
        
        resp = requests.put(url, json=json, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs)
        self._handle_error(resp)
        return resp
    
    def delete(self, path: str, **kwargs) -> requests.Response:
        """Execute DELETE request with automatic authentication.
        
        Args:
            path: API endpoint path
            **kwargs: Additional arguments for requests.delete
            
        Returns:
            Response object
            
        Raises:
            KeycloakAPIError: On HTTP error
        """
        self._ensure_authenticated()
        url = f"{self.base_url}{path}"
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._token}"
        
        resp = requests.delete(url, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs)
        self._handle_error(resp)
        return resp
    
    def _get_admin_token(self, username: str, password: str, realm: str = "master") -> str:
        """Obtain an admin token via direct access grant."""
        url = f"{self.base_url}/realms/{realm}/protocol/openid-connect/token"
        data = {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": username,
            "password": password,
        }
        resp = requests.post(url, data=data, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            raise KeycloakAPIError(resp.status_code, resp.text, url)
        return resp.json()["access_token"]
    
    def _get_service_account_token(self, auth_realm: str, client_id: str, client_secret: str) -> str:
        """Fetch a service account token using client credentials flow."""
        url = f"{self.base_url}/realms/{auth_realm}/protocol/openid-connect/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        resp = requests.post(url, data=data, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            raise KeycloakAPIError(resp.status_code, resp.text, url)
        return resp.json()["access_token"]
    
    def _handle_error(self, resp: requests.Response) -> None:
        """Centralized error handling for HTTP responses.
        
        Args:
            resp: Response object to check
            
        Raises:
            KeycloakAPIError: If response status indicates error
        """
        if resp.status_code >= 400:
            raise KeycloakAPIError(resp.status_code, resp.text, resp.url)


# ─────────────────────────────────────────────────────────────────────────────
# Standalone functions for backward compatibility
# ─────────────────────────────────────────────────────────────────────────────
def get_admin_token(kc_url: str, username: str, password: str, realm: str = "master") -> str:
    """Obtain an admin token via direct access grant on the specified realm.
    
    This is a standalone function for backward compatibility with existing code.
    New code should use KeycloakClient.authenticate_admin() instead.
    """
    client = KeycloakClient(kc_url)
    return client._get_admin_token(username, password, realm)


def get_service_account_token(kc_url: str, auth_realm: str, client_id: str, client_secret: str) -> str:
    """Fetch a service account token using client credentials flow.
    
    This is a standalone function for backward compatibility with existing code.
    New code should use KeycloakClient.authenticate_service_account() instead.
    """
    client = KeycloakClient(kc_url)
    return client._get_service_account_token(auth_realm, client_id, client_secret)


def create_client_with_token(kc_url: str, token: str, expires_in: int = 3600) -> KeycloakClient:
    """Create a pre-authenticated KeycloakClient for backward compatibility.
    
    This helper creates a client with a pre-obtained token, useful for
    standalone functions that receive (kc_url, token) parameters.
    
    Args:
        kc_url: Keycloak base URL
        token: Pre-obtained access token
        expires_in: Token validity in seconds (default: 1 hour)
        
    Returns:
        KeycloakClient instance with token pre-set
        
    Note:
        This is a compatibility helper. Prefer passing KeycloakClient
        instances directly in new code.
    """
    client = KeycloakClient(kc_url)
    client._token = token
    client._token_expires_at = datetime.now() + timedelta(seconds=expires_in)
    return client
