"""Keycloak user management operations."""
from __future__ import annotations
import sys
import time
from typing import Optional, List
from pathlib import Path

import requests

from .client import KeycloakClient, create_client_with_token, REQUEST_TIMEOUT
from .exceptions import UserNotFoundError

# Import audit module for logging
try:
    SCRIPT_DIR = Path(__file__).parent.parent.parent.parent / "scripts"
    if str(SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPT_DIR.parent))
    from scripts import audit as audit_module
except ImportError:
    audit_module = None


class UserService:
    """Service for managing Keycloak users."""
    
    def __init__(self, client: KeycloakClient):
        """Initialize user service.
        
        Args:
            client: Authenticated Keycloak client
        """
        self.client = client
    
    def get_user_by_username(self, realm: str, username: str) -> Optional[dict]:
        """Return the user representation that exactly matches the username.
        
        Args:
            realm: Realm name
            username: Username to search for
            
        Returns:
            User representation or None if not found
        """
        resp = self.client.get(f"/admin/realms/{realm}/users", params={"username": username})
        for user in resp.json():
            if user.get("username") == username:
                return user
        return None
    
    def create_user(
        self,
        realm: str,
        username: str,
        email: str,
        first: str,
        last: str,
        temp_password: str,
        role: str,
        require_totp: bool = True,
        require_password_update: bool = True,
    ) -> None:
        """Create a new user and assign the chosen role and bootstrap password.
        
        Args:
            realm: Realm name
            username: Username
            email: Email address
            first: First name
            last: Last name
            temp_password: Temporary password
            role: Role to assign
            require_totp: Require TOTP configuration
            require_password_update: Require password change on first login
        """
        from .groups import GroupService
        from .roles import RoleService
        
        exists = self.get_user_by_username(realm, username)
        if exists:
            print(f"[joiner] User '{username}' already exists", file=sys.stderr)
            user_id = exists["id"]
        else:
            payload = {
                "username": username,
                "email": email,
                "firstName": first,
                "lastName": last,
                "enabled": True,
                "emailVerified": True,
            }
            self.client.post(f"/admin/realms/{realm}/users", json=payload)
            time.sleep(0.5)
            user_id = self.get_user_by_username(realm, username)["id"]
            print(f"[joiner] User '{username}' created (id={user_id})", file=sys.stderr)

        # Set required actions
        desired_actions = self._desired_required_actions(
            realm,
            user_id,
            require_totp=require_totp,
            require_password_update=require_password_update,
        )
        self.set_user_required_actions(realm, user_id, desired_actions)

        # Set temporary password
        self.client.put(
            f"/admin/realms/{realm}/users/{user_id}/reset-password",
            json={"type": "password", "temporary": require_password_update, "value": temp_password},
        )
        print(f"[joiner] Temp password set for '{username}'", file=sys.stderr)

        # Assign role
        role_lookup = self.client.get(f"/admin/realms/{realm}/roles/{role}")
        role_rep = role_lookup.json()
        resp = self.client.post(
            f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
            json=[{"id": role_rep["id"], "name": role_rep["name"]}],
        )
        if resp.status_code in (204, 201):
            print(f"[joiner] Assigned role '{role}' to '{username}'", file=sys.stderr)
        else:
            print(resp.text)
            resp.raise_for_status()
        
        # Security guardrail: Auto-add to managed group for visibility
        group_service = GroupService(self.client)
        managed_group = group_service.get_group_by_path(realm, "/iam-poc-managed")
        if managed_group:
            was_added = group_service.add_user_to_group(realm, user_id, managed_group["id"])
            if was_added:
                print(f"[joiner] Added '{username}' to iam-poc-managed group", file=sys.stderr)
        else:
            print(f"[joiner] Warning: iam-poc-managed group not found, user not added to group", file=sys.stderr)
    
    def ensure_required_action(self, realm: str, alias: str) -> None:
        """Enable and mark a required action as default when present.
        
        Args:
            realm: Realm name
            alias: Required action alias (e.g., CONFIGURE_TOTP)
        """
        url = f"/admin/realms/{realm}/authentication/required-actions"
        resp = self.client.get(url)
        actions = resp.json()
        target = next((act for act in actions if act.get("alias") == alias), None)
        
        if not target:
            print(f"[init] Required action '{alias}' not found; please verify Keycloak configuration", file=sys.stderr)
            return
        
        if target.get("enabled") and target.get("defaultAction"):
            print(f"[init] Required action '{alias}' already enforced", file=sys.stderr)
            return
        
        update = {
            "alias": target.get("alias"),
            "name": target.get("name"),
            "providerId": target.get("providerId"),
            "defaultAction": True,
            "enabled": True,
            "priority": target.get("priority", 0),
            "config": target.get("config", {}),
        }
        put = self.client.put(f"{url}/{alias}", json=update)
        if put.status_code in (200, 204):
            print(f"[init] Required action '{alias}' enforced (enabled + default)", file=sys.stderr)
    
    def ensure_user_required_actions(self, realm: str, user_id: str, actions: List[str]) -> None:
        """Apply required actions to a user without overwriting existing ones.
        
        Args:
            realm: Realm name
            user_id: User ID
            actions: List of required action aliases
        """
        url = f"/admin/realms/{realm}/users/{user_id}"
        resp = self.client.get(url)
        user_rep = resp.json()
        existing = set(user_rep.get("requiredActions") or [])
        desired = set(actions)
        
        if desired.issubset(existing):
            return
        
        user_rep["requiredActions"] = sorted(existing.union(desired))
        self.client.put(url, json=user_rep)
        print(f"[joiner] Required actions set to {user_rep['requiredActions']}", file=sys.stderr)
    
    def set_user_required_actions(self, realm: str, user_id: str, actions: List[str]) -> None:
        """Overwrite the user's required actions with a specific list.
        
        Args:
            realm: Realm name
            user_id: User ID
            actions: List of required action aliases
        """
        url = f"/admin/realms/{realm}/users/{user_id}"
        resp = self.client.get(url)
        user_rep = resp.json()
        desired = sorted(actions)
        current = sorted(user_rep.get("requiredActions") or [])
        
        if current == desired:
            return
        
        user_rep["requiredActions"] = desired
        self.client.put(url, json=user_rep)
        print(f"[joiner] Required actions overwritten with {desired}", file=sys.stderr)
    
    def _user_has_totp(self, realm: str, user_id: str) -> bool:
        """Return True when the user already registered a TOTP credential.
        
        Args:
            realm: Realm name
            user_id: User ID
            
        Returns:
            True if user has TOTP configured
        """
        cred_resp = self.client.get(f"/admin/realms/{realm}/users/{user_id}/credentials")
        return any(cred.get("type") == "otp" for cred in cred_resp.json() or [])
    
    def _desired_required_actions(
        self,
        realm: str,
        user_id: str,
        require_totp: bool = True,
        require_password_update: bool = True,
    ) -> List[str]:
        """Compute required actions for new joiners, prompting for TOTP if needed.
        
        Args:
            realm: Realm name
            user_id: User ID
            require_totp: Require TOTP configuration
            require_password_update: Require password update
            
        Returns:
            List of required action aliases
        """
        actions: set[str] = set()
        if require_password_update:
            actions.add("UPDATE_PASSWORD")
        if require_totp and not self._user_has_totp(realm, user_id):
            actions.add("CONFIGURE_TOTP")
        return sorted(actions)


# ─────────────────────────────────────────────────────────────────────────────
# Standalone functions for backward compatibility
# ─────────────────────────────────────────────────────────────────────────────

def get_user_by_username(kc_url: str, token: str, realm: str, username: str) -> dict | None:
    """Return the user representation that exactly matches the username."""
    service = UserService(create_client_with_token(kc_url, token))
    return service.get_user_by_username(realm, username)


def create_user(
    kc_url: str,
    token: str,
    realm: str,
    username: str,
    email: str,
    first: str,
    last: str,
    temp_password: str,
    role: str,
    require_totp: bool = True,
    require_password_update: bool = True,
) -> None:
    """Create a new user and assign the chosen role and bootstrap password."""
    service = UserService(create_client_with_token(kc_url, token))
    service.create_user(realm, username, email, first, last, temp_password, role, require_totp, require_password_update)


def disable_user(kc_url: str, token: str, realm: str, username: str, operator: str = "automation") -> None:
    """Disable (leaver) a user account in the specified realm and revoke all active sessions.
    
    Args:
        kc_url: Keycloak base URL
        token: Admin access token
        realm: Realm name
        username: Username to disable
        operator: Operator identifier for audit log (e.g., "demo-script", "cli", "scim-api", username)
        
    Raises:
        UserNotFoundError: If username doesn't exist in realm
    """
    from .sessions import revoke_user_sessions
    
    # Setup client
    client = create_client_with_token(kc_url, token)
    
    # Find user
    resp = client.get(f"/admin/realms/{realm}/users", params={"username": username})
    users = resp.json()
    user = next((u for u in users if u.get("username") == username), None)
    
    if not user:
        raise UserNotFoundError(f"User '{username}' not found in realm '{realm}'")
    
    user_id = user["id"]
    
    # Revoke all active sessions before disabling
    num_sessions = revoke_user_sessions(kc_url, token, realm, user_id)
    if num_sessions > 0:
        print(f"[leaver] Revoked {num_sessions} active session(s) for '{username}'", file=sys.stderr)
    
    # Disable the account
    user["enabled"] = False
    client.put(f"/admin/realms/{realm}/users/{user_id}", json=user)
    print(f"[leaver] User '{username}' disabled", file=sys.stderr)
    
    # ─────────────────────────────────────────────────────────────────────
    # ❌ DÉSACTIVÉ: Ne pas retirer du groupe lors de la désactivation
    # Les utilisateurs désactivés doivent rester visibles dans l'UI avec statut "Disabled"
    # Si archivage nécessaire, créer un workflow séparé avec groupe "iam-poc-archived"
    # ─────────────────────────────────────────────────────────────────────
    
    # Audit: Log user disable event (safe wrapper never raises)
    if audit_module:
        audit_module.safe_log_jml_event(
            "leaver",
            username,
            operator=operator,
            realm=realm,
            details={"user_id": user_id, "action": "disabled", "archived": False},
            success=True
        )


def ensure_required_action(kc_url: str, token: str, realm: str, alias: str) -> None:
    """Enable and mark a required action as default when present."""
    service = UserService(create_client_with_token(kc_url, token))
    service.ensure_required_action(realm, alias)


def ensure_user_required_actions(kc_url: str, token: str, realm: str, user_id: str, actions: list[str]) -> None:
    """Apply required actions to a user without overwriting existing ones."""
    service = UserService(create_client_with_token(kc_url, token))
    service.ensure_user_required_actions(realm, user_id, actions)


def set_user_required_actions(kc_url: str, token: str, realm: str, user_id: str, actions: list[str]) -> None:
    """Overwrite the user's required actions with a specific list."""
    service = UserService(create_client_with_token(kc_url, token))
    service.set_user_required_actions(realm, user_id, actions)


def _user_has_totp(kc_url: str, token: str, realm: str, user_id: str) -> bool:
    """Return True when the user already registered a TOTP credential."""
    service = UserService(create_client_with_token(kc_url, token))
    return service._user_has_totp(realm, user_id)


def _desired_required_actions(
    kc_url: str,
    token: str,
    realm: str,
    user_id: str,
    require_totp: bool = True,
    require_password_update: bool = True,
) -> list[str]:
    """Compute required actions for new joiners, prompting for TOTP if needed."""
    service = UserService(create_client_with_token(kc_url, token))
    return service._desired_required_actions(realm, user_id, require_totp, require_password_update)
