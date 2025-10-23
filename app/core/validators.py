"""Input validation helpers for user data."""
from __future__ import annotations


def normalize_username(raw: str) -> str:
    """Normalize and validate username.
    
    Args:
        raw: Raw username input
        
    Returns:
        Normalized username
        
    Raises:
        ValueError: If username is invalid
    """
    normalized = "".join(char for char in raw.lower().strip() if char.isalnum() or char in {".", "-", "_"})
    
    # SCIM-like validation: minimum length, no leading/trailing special chars
    if len(normalized) < 3:
        raise ValueError("Username must be at least 3 characters")
    if len(normalized) > 64:
        raise ValueError("Username must not exceed 64 characters")
    if normalized[0] in {".", "-", "_"} or normalized[-1] in {".", "-", "_"}:
        raise ValueError("Username cannot start or end with special characters")
    
    return normalized


def validate_email(email: str) -> str:
    """Validate email address.
    
    Args:
        email: Email address to validate
        
    Returns:
        Normalized email address
        
    Raises:
        ValueError: If email is invalid
    """
    email = email.strip().lower()
    if not email or "@" not in email:
        raise ValueError("Invalid email format")
    
    local, domain = email.rsplit("@", 1)
    if not local or not domain or "." not in domain:
        raise ValueError("Invalid email format")
    if len(email) > 254:
        raise ValueError("Email exceeds maximum length")
    
    return email


def validate_name(name: str, field: str) -> str:
    """Validate first/last name fields.
    
    Args:
        name: Name to validate
        field: Field name for error messages (e.g., "First name")
        
    Returns:
        Trimmed name
        
    Raises:
        ValueError: If name is invalid
    """
    name = name.strip()
    if not name:
        raise ValueError(f"{field} is required")
    if len(name) > 128:
        raise ValueError(f"{field} exceeds maximum length")
    
    # Prevent injection attacks
    if any(char in name for char in "<>\"'`;&|$"):
        raise ValueError(f"{field} contains invalid characters")
    
    return name
