"""Core Business Logic Module

This module provides the core business logic for IAM operations,
independent of HTTP frameworks (Flask/FastAPI).

Architecture:
    - Pure Python (no Flask dependencies in core logic)
    - Testable without HTTP mocking
    - Reusable across different interfaces (SCIM API, Admin UI, CLI)

Module Structure:
    - keycloak/         : Low-level Keycloak Admin API client
    - provisioning_service.py : High-level SCIM-like user management
    - rbac.py           : Role-Based Access Control helpers
    - scim_transformer.py : Keycloak ↔ SCIM 2.0 transformations
    - validators.py     : Input validation (SCIM payloads)

Usage Pattern:
    These modules are NOT auto-imported to avoid Flask dependencies
    when using only the Keycloak client library standalone.
    
    Import explicitly when needed:
        from app.core.provisioning_service import create_user_scim_like, ScimError
        from app.core.rbac import user_has_role, current_user_context
        from app.core.scim_transformer import ScimTransformer
        from app.core.validators import validate_scim_user_create

Public APIs:
    Provisioning (app.core.provisioning_service):
        - create_user_scim_like()
        - get_user_scim()
        - list_users_scim()
        - replace_user_scim()
        - patch_user_scim()
        - delete_user_scim()
        - get_service_token()
        - ScimError (exception)
    
    RBAC (app.core.rbac):
        - user_has_role()
        - is_authenticated()
        - current_user_context()
    
    Transformations (app.core.scim_transformer):
        - ScimTransformer.keycloak_to_scim()
        - ScimTransformer.scim_to_keycloak()
    
    Validation (app.core.validators):
        - validate_scim_user_create()
        - validate_scim_user_replace()
    
    Keycloak Client (app.core.keycloak):
        - KeycloakClient (HTTP client with auto-refresh)
        - UserService, RealmService, RoleService, etc.
        - Standalone functions for backward compatibility
"""

