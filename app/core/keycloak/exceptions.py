"""Keycloak-specific exceptions for error handling."""


class KeycloakError(Exception):
    """Base exception for all Keycloak operations."""
    pass


class KeycloakAPIError(KeycloakError):
    """HTTP error from Keycloak Admin API.
    
    Attributes:
        status_code: HTTP status code
        message: Error message from response
        endpoint: API endpoint that failed
    """
    
    def __init__(self, status_code: int, message: str, endpoint: str):
        self.status_code = status_code
        self.message = message
        self.endpoint = endpoint
        super().__init__(f"[{status_code}] {endpoint}: {message}")


class UserNotFoundError(KeycloakError):
    """User lookup failed - username does not exist."""
    pass


class UserAlreadyExistsError(KeycloakError):
    """User creation failed - username or email already exists."""
    pass


class RealmNotFoundError(KeycloakError):
    """Realm does not exist."""
    pass


class RoleNotFoundError(KeycloakError):
    """Role does not exist in realm."""
    pass


class ClientNotFoundError(KeycloakError):
    """Client does not exist in realm."""
    pass


class GroupNotFoundError(KeycloakError):
    """Group does not exist in realm."""
    pass


class InsufficientPermissionsError(KeycloakError):
    """Service account or user lacks required permissions."""
    pass
