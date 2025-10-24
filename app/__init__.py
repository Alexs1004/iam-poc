"""IAM POC Flask Application Package.

To use the Flask app:
    from app.flask_app import app

To use Keycloak services:
    from app.core.keycloak import UserService, KeycloakClient

To use provisioning service:
    from app.core.provisioning_service import provision_user
"""
# Note: We don't import flask_app by default to avoid Flask dependency
# for CLI scripts that only use app.core.keycloak

