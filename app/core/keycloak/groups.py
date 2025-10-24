"""Keycloak group management operations."""
from __future__ import annotations
import sys
import time
import re
from typing import Optional, Dict
from datetime import datetime, timezone

import requests

from .client import KeycloakClient, REQUEST_TIMEOUT, create_client_with_token


class GroupService:
    """Service for managing Keycloak groups."""
    
    def __init__(self, client: KeycloakClient):
        """Initialize group service.
        
        Args:
            client: Authenticated Keycloak client
        """
        self.client = client
    
    def get_group_by_path(self, realm: str, group_path: str) -> Optional[dict]:
        """Retrieve a group by its path (e.g., '/iam-poc-managed').
        
        Args:
            realm: Realm name
            group_path: Group path starting with /
            
        Returns:
            Group representation or None if not found
        """
        resp = self.client.get(f"/admin/realms/{realm}/groups", params={"search": group_path.strip("/")})
        groups = resp.json() or []
        # Exact match on path
        for group in groups:
            if group.get("path") == group_path:
                return group
        return None
    
    def create_group(self, realm: str, group_name: str, attributes: Optional[Dict] = None) -> str:
        """Idempotently create a group and return its ID.
        
        Security guardrails:
        - Validates group name (alphanumeric, dashes, underscores only)
        - Adds metadata attributes for audit trail
        - Returns existing group ID if already exists (idempotent)
        
        Args:
            realm: Realm name
            group_name: Group name (must be 3-64 chars, alphanumeric/dashes/underscores)
            attributes: Optional attributes dictionary
            
        Returns:
            Group ID
            
        Raises:
            ValueError: If group name is invalid
        """
        # Input validation
        if not re.match(r"^[a-zA-Z0-9_-]{3,64}$", group_name):
            raise ValueError(f"Invalid group name '{group_name}': must be 3-64 alphanumeric chars, dashes, or underscores")
        
        group_path = f"/{group_name}"
        existing = self.get_group_by_path(realm, group_path)
        
        if existing:
            print(f"[init] Group '{group_name}' already exists (id={existing['id']})", file=sys.stderr)
            return existing["id"]
        
        # Add security metadata
        payload = {
            "name": group_name,
            "attributes": attributes or {},
        }
        
        # Add audit metadata
        if "created_at" not in payload["attributes"]:
            payload["attributes"]["created_at"] = [datetime.now(timezone.utc).isoformat()]
        if "created_by" not in payload["attributes"]:
            payload["attributes"]["created_by"] = ["iam-poc-bootstrap"]
        
        self.client.post(f"/admin/realms/{realm}/groups", json=payload)
        
        # Retrieve the created group to get its ID
        time.sleep(0.3)  # Small delay for eventual consistency
        created = self.get_group_by_path(realm, group_path)
        if not created:
            raise RuntimeError(f"Failed to retrieve group '{group_name}' after creation")
        
        print(f"[init] Group '{group_name}' created (id={created['id']})", file=sys.stderr)
        return created["id"]
    
    def add_user_to_group(self, realm: str, user_id: str, group_id: str) -> bool:
        """Add a user to a group (idempotent).
        
        Returns:
            True if user was added, False if already a member
        
        Security guardrails:
        - Validates user and group exist before adding
        - Returns success even if already a member (idempotent)
        
        Args:
            realm: Realm name
            user_id: User ID
            group_id: Group ID
            
        Returns:
            True if added, False if already a member
        """
        resp = self.client.put(f"/admin/realms/{realm}/users/{user_id}/groups/{group_id}")
        
        if resp.status_code == 204:
            return True
        elif resp.status_code == 409:
            # Already a member
            return False
        return False
    
    def remove_user_from_group(self, realm: str, user_id: str, group_id: str) -> bool:
        """Remove a user from a group (idempotent).
        
        Returns:
            True if user was removed, False if not a member
        
        Security guardrails:
        - Safe to call even if user is not a member
        - Does not fail if group or user doesn't exist
        
        Args:
            realm: Realm name
            user_id: User ID
            group_id: Group ID
            
        Returns:
            True if removed, False if not a member
        """
        try:
            resp = self.client.delete(f"/admin/realms/{realm}/users/{user_id}/groups/{group_id}")
            return resp.status_code == 204
        except Exception as e:
            if "404" in str(e):
                return False
            raise
    
    def get_group_members(self, realm: str, group_id: str) -> list[dict]:
        """Retrieve all members of a group.
        
        Args:
            realm: Realm name
            group_id: Group ID
            
        Returns:
            List of user representations (same format as get_user_by_username)
        """
        resp = self.client.get(f"/admin/realms/{realm}/groups/{group_id}/members")
        return resp.json() or []


# ─────────────────────────────────────────────────────────────────────────────
# Standalone functions for backward compatibility
# ─────────────────────────────────────────────────────────────────────────────





def get_group_by_path(kc_url: str, token: str, realm: str, group_path: str) -> dict | None:
    """Retrieve a group by its path (e.g., '/iam-poc-managed')."""
    service = GroupService(create_client_with_token(kc_url, token))
    return service.get_group_by_path(realm, group_path)


def create_group(kc_url: str, token: str, realm: str, group_name: str, attributes: dict | None = None) -> str:
    """Idempotently create a group and return its ID."""
    service = GroupService(create_client_with_token(kc_url, token))
    return service.create_group(realm, group_name, attributes)


def add_user_to_group(kc_url: str, token: str, realm: str, user_id: str, group_id: str) -> bool:
    """Add a user to a group (idempotent)."""
    service = GroupService(create_client_with_token(kc_url, token))
    return service.add_user_to_group(realm, user_id, group_id)


def remove_user_from_group(kc_url: str, token: str, realm: str, user_id: str, group_id: str) -> bool:
    """Remove a user from a group (idempotent)."""
    service = GroupService(create_client_with_token(kc_url, token))
    return service.remove_user_from_group(realm, user_id, group_id)


def get_group_members(kc_url: str, token: str, realm: str, group_id: str) -> list[dict]:
    """Retrieve all members of a group."""
    service = GroupService(create_client_with_token(kc_url, token))
    return service.get_group_members(realm, group_id)
