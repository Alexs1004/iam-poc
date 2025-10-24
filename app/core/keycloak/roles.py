"""Keycloak role management operations."""
from __future__ import annotations
import os
import sys
from typing import Optional

import requests

from .client import KeycloakClient, REQUEST_TIMEOUT, get_admin_token, create_client_with_token
from .exceptions import UserNotFoundError, RoleNotFoundError, GroupNotFoundError, ClientNotFoundError


class RoleService:
    """Service for managing Keycloak roles."""
    
    def __init__(self, client: KeycloakClient):
        """Initialize role service.
        
        Args:
            client: Authenticated Keycloak client
        """
        self.client = client
    
    def create_role(self, realm: str, role_name: str) -> None:
        """Idempotently create a realm-level role.
        
        Args:
            realm: Realm name
            role_name: Role name
        """
        try:
            resp = self.client.get(f"/admin/realms/{realm}/roles/{role_name}")
            if resp.status_code == 200:
                print(f"[init] Role '{role_name}' already exists", file=sys.stderr)
                return
        except Exception:
            pass
        
        payload = {"name": role_name}
        self.client.post(f"/admin/realms/{realm}/roles", json=payload)
        print(f"[init] Role '{role_name}' created", file=sys.stderr)
    
    def grant_client_role(
        self,
        realm: str,
        username: str,
        client_id: str,
        role_name: str,
        *,
        allow_admin_fallback: bool = True,
    ) -> None:
        """Assign a client-level role (e.g. realm-management/realm-admin) to a user.
        
        Args:
            realm: Realm name
            username: Username
            client_id: Client ID (e.g., realm-management)
            role_name: Role name (e.g., realm-admin)
            allow_admin_fallback: If True, retry with admin credentials on permission error
            
        Raises:
            SystemExit: If user, client, or role not found
            RuntimeError: If lacking permissions even after fallback
        """
        from .users import UserService
        from .realm import RealmService
        
        user_service = UserService(self.client)
        realm_service = RealmService(self.client)
        
        user = user_service.get_user_by_username(realm, username)
        if not user:
            raise RoleNotFoundError(f"[client-role] User '{username}' not found")
        
        client = realm_service.get_client(realm, client_id)
        if not client:
            raise RoleNotFoundError(f"[client-role] Client '{client_id}' not found in realm '{realm}'")
        
        client_uuid = client.get("id")
        if not client_uuid:
            raise RoleNotFoundError(f"[client-role] Unable to resolve client UUID for '{client_id}'")
        
        try:
            role_resp = self.client.get(f"/admin/realms/{realm}/clients/{client_uuid}/roles/{role_name}")
            role_repr = role_resp.json()
        except Exception:
            raise RoleNotFoundError(f"[client-role] Role '{role_name}' not found on client '{client_id}'")
        
        role_payload = [{"id": role_repr["id"], "name": role_repr["name"]}]

        def _assign(client_instance: KeycloakClient) -> tuple[bool, Optional[requests.Response]]:
            try:
                resp = client_instance.post(
                    f"/admin/realms/{realm}/users/{user['id']}/role-mappings/clients/{client_uuid}",
                    json=role_payload,
                )
                if resp.status_code in (204, 201, 409):
                    # 409 indicates the role was already assigned; treat as success.
                    print(
                        f"[client-role] Assigned '{role_name}' from '{client_id}' to '{username}'",
                        file=sys.stderr,
                    )
                    return True, resp
                return False, resp
            except Exception as e:
                if "401" in str(e) or "403" in str(e):
                    return False, None
                raise

        success, response = _assign(self.client)
        if success:
            return
        
        if not allow_admin_fallback:
            error_detail = response.text if response is not None else "missing privilege"
            raise RuntimeError(
                f"[client-role] Service account lacks permission to assign '{role_name}': {error_detail}"
            )
        
        # Fallback to admin credentials
        admin_user = os.environ.get("KEYCLOAK_ADMIN", "admin")
        admin_pass = os.environ.get("KEYCLOAK_ADMIN_PASSWORD")
        if not admin_pass:
            raise RuntimeError(
                "[client-role] Unable to assign client role; set KEYCLOAK_ADMIN_PASSWORD for admin fallback."
            )
        
        admin_client = KeycloakClient(self.client.base_url)
        admin_client.authenticate_admin(admin_user, admin_pass)
        success, fallback_resp = _assign(admin_client)
        if success:
            return
        
        detail = fallback_resp.text if fallback_resp is not None else "unknown error"
        raise RuntimeError(
            f"[client-role] Failed to assign '{role_name}' from '{client_id}' even with admin credentials: {detail}"
        )
    
    def change_role(self, realm: str, username: str, from_role: str, to_role: str) -> None:
        """Swap the user's role by revoking one assignment and granting another.
        
        Args:
            realm: Realm name
            username: Username
            from_role: Current role to remove
            to_role: New role to assign
            
        Raises:
            SystemExit: If user not found
        """
        from .users import UserService
        
        user_service = UserService(self.client)
        user = user_service.get_user_by_username(realm, username)
        
        if not user:
            raise RoleNotFoundError(f"[mover] User '{username}' not found")
        
        user_id = user["id"]
        
        # Remove current role
        current_role = self.client.get(f"/admin/realms/{realm}/roles/{from_role}")
        role_json = current_role.json()
        
        try:
            resp = self.client.delete(
                f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
                json=[{"id": role_json["id"], "name": role_json["name"]}],
            )
            if resp.status_code in (204, 404):
                print(f"[mover] Removed role '{from_role}' (if present)", file=sys.stderr)
        except Exception:
            print(f"[mover] Removed role '{from_role}' (if present)", file=sys.stderr)
        
        # Add new role
        target_role = self.client.get(f"/admin/realms/{realm}/roles/{to_role}")
        target_json = target_role.json()
        
        self.client.post(
            f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
            json=[{"id": target_json["id"], "name": target_json["name"]}],
        )
        print(f"[mover] Added role '{to_role}' to '{username}'", file=sys.stderr)
    
    def add_realm_role(self, realm: str, username: str, role: str) -> None:
        """Grant an additional realm-level role without removing existing ones.
        
        Args:
            realm: Realm name
            username: Username
            role: Role name to add
            
        Raises:
            SystemExit: If user not found
        """
        from .users import UserService
        
        user_service = UserService(self.client)
        user = user_service.get_user_by_username(realm, username)
        
        if not user:
            raise RoleNotFoundError(f"[role-grant] User '{username}' not found")
        
        user_id = user["id"]
        role_lookup = self.client.get(f"/admin/realms/{realm}/roles/{role}")
        role_rep = role_lookup.json()
        
        resp = self.client.post(
            f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
            json=[{"id": role_rep["id"], "name": role_rep["name"]}],
        )
        
        if resp.status_code in (204, 201, 409):
            print(f"[role-grant] Granted role '{role}' to '{username}'", file=sys.stderr)
            return


# ─────────────────────────────────────────────────────────────────────────────
# Standalone functions for backward compatibility
# ─────────────────────────────────────────────────────────────────────────────





def create_role(kc_url: str, token: str, realm: str, role_name: str) -> None:
    """Idempotently create a realm-level role."""
    service = RoleService(create_client_with_token(kc_url, token))
    service.create_role(realm, role_name)


def grant_client_role(
    kc_url: str,
    token: str,
    realm: str,
    username: str,
    client_id: str,
    role_name: str,
    *,
    allow_admin_fallback: bool = True,
) -> None:
    """Assign a client-level role (e.g. realm-management/realm-admin) to a user."""
    service = RoleService(create_client_with_token(kc_url, token))
    service.grant_client_role(realm, username, client_id, role_name, allow_admin_fallback=allow_admin_fallback)


def change_role(kc_url: str, token: str, realm: str, username: str, from_role: str, to_role: str) -> None:
    """Swap the user's role by revoking one assignment and granting another."""
    service = RoleService(create_client_with_token(kc_url, token))
    service.change_role(realm, username, from_role, to_role)


def add_realm_role(kc_url: str, token: str, realm: str, username: str, role: str) -> None:
    """Grant an additional realm-level role without removing existing ones."""
    service = RoleService(create_client_with_token(kc_url, token))
    service.add_realm_role(realm, username, role)
