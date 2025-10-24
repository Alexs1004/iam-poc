"""Core business logic modules.

Note: rbac, validators, and provisioning_service are NOT auto-imported
to avoid Flask dependencies when using only keycloak services.

To use these modules, import them explicitly:
    from app.core.provisioning_service import create_user_scim_like
    from app.core import rbac
    from app.core import validators
"""
