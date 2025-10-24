"""Keycloak realm management operations."""
from __future__ import annotations
import os
import sys
from typing import Optional
from urllib.parse import urlparse

import requests

from .client import KeycloakClient, REQUEST_TIMEOUT, create_client_with_token
from .exceptions import RealmNotFoundError, ClientNotFoundError


class RealmService:
    """Service for managing Keycloak realms."""
    
    def __init__(self, client: KeycloakClient):
        """Initialize realm service.
        
        Args:
            client: Authenticated Keycloak client
        """
        self.client = client
    
    def realm_exists(self, realm: str) -> bool:
        """Check whether the given realm already exists.
        
        Args:
            realm: Realm name
            
        Returns:
            True if realm exists, False otherwise
        """
        try:
            self.client.get(f"/admin/realms/{realm}")
            return True
        except Exception:
            return False
    
    def create_realm(self, realm: str) -> None:
        """Ensure the target realm exists, creating it if necessary.
        
        Args:
            realm: Realm name
            
        Raises:
            SystemExit: If lacking permissions
        """
        if self.realm_exists(realm):
            print(f"[init] Realm '{realm}' already exists", file=sys.stderr)
            return
        
        payload = {"realm": realm, "enabled": True}
        try:
            resp = self.client.post("/admin/realms", json=payload)
            if resp.status_code in (201, 409):
                print(f"[init] Realm '{realm}' created (or already existed)", file=sys.stderr)
        except Exception as e:
            if "403" in str(e):
                raise SystemExit("[init] Missing permission to create realm. Run bootstrap-service-account from master realm first.")
            raise
    
    def delete_realm(self, realm: str) -> None:
        """Delete a non-master realm, handling missing realms gracefully.
        
        Args:
            realm: Realm name
            
        Raises:
            SystemExit: If attempting to delete master realm
        """
        if realm == "master":
            print("[reset] Refusing to delete the master realm", file=sys.stderr)
            return
        
        try:
            resp = self.client.delete(f"/admin/realms/{realm}")
            if resp.status_code == 204:
                print(f"[reset] Realm '{realm}' deleted", file=sys.stderr)
                return
        except Exception as e:
            if "404" in str(e):
                print(f"[reset] Realm '{realm}' not found", file=sys.stderr)
                return
            try:
                details = str(e)
            except Exception:
                details = "unknown error"
            print(f"[reset] Failed to delete realm '{realm}': {details}", file=sys.stderr)
            raise
    
    def get_client(self, realm: str, client_id: str) -> Optional[dict]:
        """Return the client representation matching client_id, if it exists.
        
        Args:
            realm: Realm name
            client_id: Client ID to find
            
        Returns:
            Client representation or None if not found
        """
        resp = self.client.get(f"/admin/realms/{realm}/clients", params={"clientId": client_id})
        clients = resp.json()
        return clients[0] if clients else None
    
    def create_client(
        self,
        realm: str,
        client_id: str,
        redirect_uri: str,
        post_logout_redirect_uri: str,
    ) -> None:
        """Create or update the demo public client with desired configuration.
        
        Args:
            realm: Realm name
            client_id: Client ID
            redirect_uri: Redirect URI for OIDC flow
            post_logout_redirect_uri: Post-logout redirect URI
            
        Raises:
            SystemExit: If redirect URI is invalid
        """
        resp = self.client.get(f"/admin/realms/{realm}/clients", params={"clientId": client_id})
        existing = resp.json()
        
        desired_logout = post_logout_redirect_uri
        desired_redirects = [redirect_uri]
        
        try:
            desired_web_origins = [self._origin_from_url(redirect_uri)]
        except ValueError as exc:
            raise SystemExit(f"[init] {exc}") from exc
        
        if existing:
            client = existing[0]
            client_uuid = client.get("id")
            needs_update = False
            update_payload = {"clientId": client_id}

            current_redirects = sorted(client.get("redirectUris") or [])
            if sorted(desired_redirects) != current_redirects:
                needs_update = True
                update_payload["redirectUris"] = desired_redirects

            current_web_origins = sorted(client.get("webOrigins") or [])
            if sorted(desired_web_origins) != current_web_origins:
                needs_update = True
                update_payload["webOrigins"] = desired_web_origins

            current_attrs = client.get("attributes") or {}
            if current_attrs.get("post.logout.redirect.uris") != desired_logout:
                needs_update = True
                current_attrs["post.logout.redirect.uris"] = desired_logout
                update_payload["attributes"] = current_attrs

            if needs_update and client_uuid:
                self.client.put(f"/admin/realms/{realm}/clients/{client_uuid}", json=update_payload)
                print(f"[init] Client '{client_id}' updated", file=sys.stderr)
            else:
                print(f"[init] Client '{client_id}' already configured", file=sys.stderr)
            return
        
        payload = {
            "clientId": client_id,
            "publicClient": True,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "redirectUris": desired_redirects,
            "webOrigins": desired_web_origins,
            "attributes": {
                "post.logout.redirect.uris": desired_logout
            },
            "defaultClientScopes": ["profile", "email", "roles", "web-origins", "role_list"],
        }
        self.client.post(f"/admin/realms/{realm}/clients", json=payload)
        print(f"[init] Client '{client_id}' created", file=sys.stderr)
    
    def configure_security_admin_console(self, realm: str) -> None:
        """Align the built-in security-admin-console client with console requirements.
        
        Args:
            realm: Realm name
        """
        client_id = os.environ.get("SECURITY_ADMIN_CLIENT_ID", "security-admin-console")
        client = self.get_client(realm, client_id)
        
        if not client:
            print(f"[init] Client '{client_id}' not found; skipping console alignment", file=sys.stderr)
            return
        
        client_uuid = client.get("id")
        if not client_uuid:
            print(f"[init] Unable to resolve UUID for client '{client_id}'", file=sys.stderr)
            return

        root_url = os.environ.get("SECURITY_ADMIN_ROOT_URL") or self._preferred_console_root()
        base_url = self._normalize_console_base(os.environ.get("SECURITY_ADMIN_BASE_URL", ""), realm)
        
        redirect_override = os.environ.get("SECURITY_ADMIN_REDIRECT_URIS")
        if redirect_override:
            redirect_uris = [uri.strip() for uri in redirect_override.split(",") if uri.strip()]
        else:
            redirect_uris = [f"{root_url.rstrip('/')}/*"]
        
        web_origin_override = os.environ.get("SECURITY_ADMIN_WEB_ORIGINS")
        if web_origin_override:
            web_origins = [origin.strip() for origin in web_origin_override.split(",") if origin.strip()]
        else:
            web_origins = ["*"]

        detail = self.client.get(f"/admin/realms/{realm}/clients/{client_uuid}")
        representation = detail.json()

        changed = False

        def ensure(field: str, value):
            nonlocal changed
            if representation.get(field) != value:
                representation[field] = value
                changed = True

        ensure("protocol", "openid-connect")
        confidential = os.environ.get("SECURITY_ADMIN_CONFIDENTIAL", "false").lower() == "true"
        ensure("publicClient", not confidential)
        
        if confidential:
            ensure("clientAuthenticatorType", "client-secret")
        elif representation.get("clientAuthenticatorType") != "client-secret":
            ensure("clientAuthenticatorType", representation.get("clientAuthenticatorType") or "client-secret")
        
        ensure("standardFlowEnabled", True)
        ensure("directAccessGrantsEnabled", True)
        ensure("serviceAccountsEnabled", False)
        ensure("rootUrl", root_url)
        ensure("baseUrl", base_url)

        desired_redirects = sorted({uri for uri in redirect_uris if uri})
        current_redirects = sorted({uri for uri in representation.get("redirectUris") or [] if uri})
        if current_redirects != desired_redirects:
            representation["redirectUris"] = desired_redirects
            changed = True

        desired_web = sorted({origin for origin in web_origins if origin})
        current_web = sorted({origin for origin in representation.get("webOrigins") or [] if origin})
        if current_web != desired_web:
            representation["webOrigins"] = desired_web
            changed = True

        if confidential:
            desired_secret = os.environ.get("SECURITY_ADMIN_CLIENT_SECRET")
            if desired_secret and representation.get("secret") != desired_secret:
                representation["secret"] = desired_secret
                changed = True
        else:
            if representation.get("secret"):
                representation.pop("secret", None)
                changed = True

        # Remove deprecated accessType key if present to avoid conflicts.
        if "accessType" in representation:
            representation.pop("accessType", None)

        if not changed:
            print(f"[init] Client '{client_id}' already aligned for console access", file=sys.stderr)
            return

        update = self.client.put(f"/admin/realms/{realm}/clients/{client_uuid}", json=representation)
        if update.status_code in (200, 204):
            print(f"[init] Client '{client_id}' configured for admin console access", file=sys.stderr)
            return
    
    @staticmethod
    def _origin_from_url(url: str) -> str:
        """Extract the scheme+host[:port] origin from the provided URL."""
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid URL '{url}' – expected absolute URI")
        return f"{parsed.scheme}://{parsed.netloc}"
    
    @staticmethod
    def _normalize_console_base(path: str, realm: str) -> str:
        """Normalize console base path."""
        if not path:
            path = f"/admin/{realm}/console/"
        if not path.startswith("/"):
            path = "/" + path.lstrip("/")
        if not path.endswith("/"):
            path += "/"
        return path
    
    @staticmethod
    def _preferred_console_root() -> str:
        """Infer the external URL origin used to reach the Keycloak console."""
        candidates = [
            os.environ.get("SECURITY_ADMIN_ROOT_URL"),
            os.environ.get("KEYCLOAK_PUBLIC_ISSUER"),
            os.environ.get("OIDC_REDIRECT_URI"),
            os.environ.get("KEYCLOAK_PUBLIC_URL"),
            os.environ.get("KEYCLOAK_PUBLIC_BASE_URL"),
        ]
        for candidate in candidates:
            if candidate:
                parsed = urlparse(candidate)
                if parsed.scheme and parsed.netloc:
                    return f"{parsed.scheme}://{parsed.netloc}"
        return "https://localhost"


# ─────────────────────────────────────────────────────────────────────────────
# Standalone functions for backward compatibility
# ─────────────────────────────────────────────────────────────────────────────

def realm_exists(kc_url: str, token: str, realm: str) -> bool:
    """Check whether the given realm already exists."""
    client = create_client_with_token(kc_url, token)
    resp = client.get(f"/admin/realms/{realm}")
    return resp.status_code == 200


def create_realm(kc_url: str, token: str, realm: str) -> None:
    """Ensure the target realm exists, creating it if necessary."""
    service = RealmService(create_client_with_token(kc_url, token))
    service.create_realm(realm)


def delete_realm(kc_url: str, token: str, realm: str) -> None:
    """Delete a non-master realm, handling missing realms gracefully."""
    service = RealmService(create_client_with_token(kc_url, token))
    service.delete_realm(realm)


def _get_client(kc_url: str, token: str, realm: str, client_id: str) -> dict | None:
    """Return the client representation matching client_id, if it exists."""
    service = RealmService(create_client_with_token(kc_url, token))
    return service.get_client(realm, client_id)


def create_client(
    kc_url: str,
    token: str,
    realm: str,
    client_id: str,
    redirect_uri: str,
    post_logout_redirect_uri: str,
) -> None:
    """Create or update the demo public client with desired configuration."""
    service = RealmService(create_client_with_token(kc_url, token))
    service.create_client(realm, client_id, redirect_uri, post_logout_redirect_uri)


def configure_security_admin_console(kc_url: str, token: str, realm: str) -> None:
    """Align the built-in security-admin-console client with console requirements."""
    service = RealmService(create_client_with_token(kc_url, token))
    service.configure_security_admin_console(realm)


def _origin_from_url(url: str) -> str:
    """Extract the scheme+host[:port] origin from the provided URL."""
    return RealmService._origin_from_url(url)


def _preferred_console_root() -> str:
    """Infer the external URL origin used to reach the Keycloak console."""
    return RealmService._preferred_console_root()


def _normalize_console_base(path: str, realm: str) -> str:
    """Normalize console base path."""
    return RealmService._normalize_console_base(path, realm)


def _ensure_service_account_client(kc_url: str, token: str, realm: str, client_id: str) -> tuple[str, str]:
    """Create the service account client if needed and rotate its secret."""
    client_instance = create_client_with_token(kc_url, token)
    
    client = _get_client(kc_url, token, realm, client_id)
    if not client:
        payload = {
            "clientId": client_id,
            "protocol": "openid-connect",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "clientAuthenticatorType": "client-secret",
        }
        resp = client_instance.post(f"/admin/realms/{realm}/clients", json=payload)
        resp.raise_for_status()
        client = _get_client(kc_url, token, realm, client_id)
        print(f"[bootstrap] Client '{client_id}' created in realm '{realm}'", file=sys.stderr)

    client_uuid = client.get("id")
    if not client_uuid:
        raise RuntimeError("Unable to resolve client UUID for service account")

    desired_flags = {
        "serviceAccountsEnabled": True,
        "publicClient": False,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "clientAuthenticatorType": "client-secret",
        "protocol": client.get("protocol") or "openid-connect",
    }
    updated = False
    for key, desired in desired_flags.items():
        if client.get(key) != desired:
            client[key] = desired
            updated = True
    if updated:
        put = client_instance.put(f"/admin/realms/{realm}/clients/{client_uuid}", json=client)
        put.raise_for_status()
        client = _get_client(kc_url, token, realm, client_id)
        print(f"[bootstrap] Client '{client_id}' updated for service accounts", file=sys.stderr)

    from .client import get_service_account_token
    secret_resp = client_instance.post(f"/admin/realms/{realm}/clients/{client_uuid}/client-secret")
    secret_resp.raise_for_status()
    secret = secret_resp.json().get("value")
    if not secret:
        raise RuntimeError("Failed to retrieve service account secret")
    print("[bootstrap] Client secret rotated; update your environment variables.", file=sys.stderr)
    try:
        get_service_account_token(kc_url, realm, client.get("clientId", client_id), secret)
    except requests.HTTPError as exc:
        detail = exc.response.text if getattr(exc, "response", None) is not None else str(exc)
        raise RuntimeError(f"Failed to validate rotated service account secret: {detail}") from exc
    except Exception as exc:
        raise RuntimeError(f"Failed to validate rotated service account secret: {exc}") from exc
    print("[bootstrap] Verified rotated client secret by acquiring access token.", file=sys.stderr)
    return client_uuid, secret


def _assign_service_account_roles(
    kc_url: str,
    token: str,
    realm: str,
    client_uuid: str,
    role_names: list[str],
) -> None:
    """Grant the service account the required realm-management client roles."""
    client = create_client_with_token(kc_url, token)
    
    svc_user_resp = client.get(f"/admin/realms/{realm}/clients/{client_uuid}/service-account-user")
    svc_user_resp.raise_for_status()
    svc_user = svc_user_resp.json()
    svc_user_id = svc_user["id"]

    realm_mgmt_client = _get_client(kc_url, token, realm, "realm-management")
    if not realm_mgmt_client:
        print(f"[bootstrap] realm-management client missing in realm '{realm}'", file=sys.stderr)
        return
    realm_mgmt_uuid = realm_mgmt_client["id"]

    existing_resp = client.get(f"/admin/realms/{realm}/users/{svc_user_id}/role-mappings/clients/{realm_mgmt_uuid}")
    existing_resp.raise_for_status()
    existing = {role["name"] for role in existing_resp.json()}

    to_add = []
    for role_name in role_names:
        if role_name in existing:
            continue
        role_resp = client.get(f"/admin/realms/{realm}/clients/{realm_mgmt_uuid}/roles/{role_name}")
        if role_resp.status_code == 404:
            print(f"[bootstrap] Role '{role_name}' not found in realm-management", file=sys.stderr)
            continue
        role_resp.raise_for_status()
        to_add.append(role_resp.json())

    if not to_add:
        print(f"[bootstrap] Service account already holds required roles", file=sys.stderr)
        return

    assign_resp = client.post(f"/admin/realms/{realm}/users/{svc_user_id}/role-mappings/clients/{realm_mgmt_uuid}", json=to_add)
    assign_resp.raise_for_status()
    print(
        f"[bootstrap] Assigned roles {sorted(role['name'] for role in to_add)} to service account",
        file=sys.stderr,
    )


def bootstrap_service_account(
    kc_url: str,
    admin_user: str,
    admin_pass: str,
    svc_realm: str,
    svc_client_id: str,
    target_realm: str,
    role_names: list[str],
) -> str:
    """Provision the automation client and return its freshly rotated secret."""
    from .client import get_admin_token
    
    if svc_realm != "master":
        raise SystemExit("bootstrap-service-account requires --auth-realm master for admin login")
    try:
        admin_token = get_admin_token(kc_url, admin_user, admin_pass)
    except requests.HTTPError as exc:
        raise SystemExit(f"[bootstrap] Admin authentication failed: {exc}") from exc
    try:
        create_realm(kc_url, admin_token, target_realm)
        client_uuid, secret = _ensure_service_account_client(kc_url, admin_token, target_realm, svc_client_id)
        _assign_service_account_roles(kc_url, admin_token, target_realm, client_uuid, role_names)
    except requests.HTTPError as exc:
        detail = exc.response.text if exc.response is not None else str(exc)
        raise SystemExit(f"[bootstrap] Failed to configure service account: {detail}") from exc
    return secret
