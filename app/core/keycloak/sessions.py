"""Keycloak session management operations."""
from __future__ import annotations
import sys
from typing import List, Dict

import requests

from .client import KeycloakClient, REQUEST_TIMEOUT, create_client_with_token


class SessionService:
    """Service for managing Keycloak user sessions."""
    
    def __init__(self, client: KeycloakClient):
        """Initialize session service.
        
        Args:
            client: Authenticated Keycloak client
        """
        self.client = client
    
    def get_user_sessions(self, realm: str, user_id: str) -> List[Dict]:
        """Get all active sessions for a user.
        
        Args:
            realm: Realm name
            user_id: User ID
            
        Returns:
            List of active session representations
        """
        try:
            resp = self.client.get(f"/admin/realms/{realm}/users/{user_id}/sessions")
            return resp.json() or []
        except Exception:
            return []
    
    def revoke_user_sessions(self, realm: str, user_id: str) -> int:
        """Revoke all active sessions for a user.
        
        Args:
            realm: Realm name
            user_id: User ID
            
        Returns:
            Number of sessions revoked
        """
        sessions_resp = self.client.get(f"/admin/realms/{realm}/users/{user_id}/sessions")
        
        if sessions_resp.status_code == 200:
            active_sessions = sessions_resp.json() or []
            if active_sessions:
                logout_resp = self.client.post(f"/admin/realms/{realm}/users/{user_id}/logout")
                if logout_resp.status_code in (204, 200):
                    print(f"[sessions] Revoked {len(active_sessions)} active session(s)", file=sys.stderr)
                    return len(active_sessions)
                else:
                    print(f"[sessions] Warning: Failed to revoke sessions (status {logout_resp.status_code})", file=sys.stderr)
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Standalone functions for backward compatibility
# ─────────────────────────────────────────────────────────────────────────────
def revoke_user_sessions(kc_url: str, token: str, realm: str, user_id: str) -> int:
    """Revoke all active sessions for a user.
    
    Args:
        kc_url: Keycloak base URL
        token: Admin token
        realm: Realm name
        user_id: User ID
        
    Returns:
        Number of sessions revoked
    """
    service = SessionService(create_client_with_token(kc_url, token))
    return service.revoke_user_sessions(realm, user_id)
