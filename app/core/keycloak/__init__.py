"""Keycloak Admin API client library.

This package provides a modular, testable interface to Keycloak Admin API operations.

Architecture:
- client.py: HTTP client with authentication and auto-refresh
- realm.py: Realm and client management
- users.py: User lifecycle operations (create, disable, required actions)
- roles.py: Role assignment and management
- groups.py: Group management and membership
- sessions.py: Session management and revocation
- exceptions.py: Typed exceptions for error handling

Usage:
    # Using service classes (recommended for new code)
    from app.core.keycloak import KeycloakClient, UserService
    
    client = KeycloakClient("http://keycloak:8080")
    client.authenticate_admin("admin", "password")
    
    user_service = UserService(client)
    user = user_service.get_user_by_username("demo", "alice")
    
    # Using standalone functions (backward compatibility)
    from app.core.keycloak import get_admin_token, create_user
    
    token = get_admin_token("http://keycloak:8080", "admin", "password")
    create_user(kc_url, token, "demo", "alice", "alice@example.com", ...)
"""
from .client import (
    KeycloakClient,
    get_admin_token,
    get_service_account_token,
    create_client_with_token,
    REQUEST_TIMEOUT,
)
from .exceptions import (
    KeycloakError,
    KeycloakAPIError,
    UserNotFoundError,
    UserAlreadyExistsError,
    RealmNotFoundError,
    RoleNotFoundError,
    ClientNotFoundError,
    GroupNotFoundError,
    InsufficientPermissionsError,
)
from .realm import (
    RealmService,
    realm_exists,
    create_realm,
    delete_realm,
    create_client,
    configure_security_admin_console,
    _get_client,
    _origin_from_url,
    _preferred_console_root,
    _normalize_console_base,
    _ensure_service_account_client,
    _assign_service_account_roles,
    bootstrap_service_account,
)
from .users import (
    UserService,
    get_user_by_username,
    create_user,
    disable_user,
    ensure_required_action,
    ensure_user_required_actions,
    set_user_required_actions,
    _user_has_totp,
    _desired_required_actions,
)
from .roles import (
    RoleService,
    create_role,
    grant_client_role,
    change_role,
    add_realm_role,
)
from .groups import (
    GroupService,
    get_group_by_path,
    create_group,
    add_user_to_group,
    remove_user_from_group,
    get_group_members,
)
from .sessions import (
    SessionService,
    revoke_user_sessions,
)

__all__ = [
    # Client
    "KeycloakClient",
    "get_admin_token",
    "get_service_account_token",
    "create_client_with_token",
    "REQUEST_TIMEOUT",
    
    # Exceptions
    "KeycloakError",
    "KeycloakAPIError",
    "UserNotFoundError",
    "UserAlreadyExistsError",
    "RealmNotFoundError",
    "RoleNotFoundError",
    "ClientNotFoundError",
    "GroupNotFoundError",
    "InsufficientPermissionsError",
    
    # Services
    "RealmService",
    "UserService",
    "RoleService",
    "GroupService",
    "SessionService",
    
    # Realm functions
    "realm_exists",
    "create_realm",
    "delete_realm",
    "create_client",
    "configure_security_admin_console",
    "_get_client",
    "_origin_from_url",
    "_preferred_console_root",
    "_normalize_console_base",
    "_ensure_service_account_client",
    "_assign_service_account_roles",
    "bootstrap_service_account",
    
    # User functions
    "get_user_by_username",
    "create_user",
    "disable_user",
    "ensure_required_action",
    "ensure_user_required_actions",
    "set_user_required_actions",
    "_user_has_totp",
    "_desired_required_actions",
    
    # Role functions
    "create_role",
    "grant_client_role",
    "change_role",
    "add_realm_role",
    
    # Group functions
    "get_group_by_path",
    "create_group",
    "add_user_to_group",
    "remove_user_from_group",
    "get_group_members",
    
    # Session functions
    "revoke_user_sessions",
]
