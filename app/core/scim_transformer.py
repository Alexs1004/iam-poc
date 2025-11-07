"""SCIM 2.0 ↔ Keycloak data transformations.

This module provides bidirectional transformations between Keycloak user
representations and SCIM 2.0 User resources as defined in RFC 7644.

Usage:
    # Keycloak → SCIM
    scim_user = ScimTransformer.keycloak_to_scim(kc_user, base_url="/scim/v2")
    
    # SCIM → Keycloak
    kc_user = ScimTransformer.scim_to_keycloak(scim_user)
"""
from __future__ import annotations
from typing import Dict, Any, Optional, List
from datetime import datetime


class ScimTransformer:
    """Bidirectional transformer for SCIM/Keycloak user representations."""
    
    @staticmethod
    def keycloak_to_scim(kc_user: Dict[str, Any], base_url: str = "/scim/v2") -> Dict[str, Any]:
        """Convert Keycloak user to SCIM 2.0 User resource.
        
        Args:
            kc_user: Keycloak user representation
            base_url: SCIM API base URL for resource location
            
        Returns:
            SCIM 2.0 compliant User resource
            
        Example:
            >>> kc_user = {
            ...     "id": "abc123",
            ...     "username": "alice",
            ...     "firstName": "Alice",
            ...     "lastName": "Smith",
            ...     "email": "alice@example.com",
            ...     "enabled": True,
            ...     "createdTimestamp": 1635000000000
            ... }
            >>> scim_user = ScimTransformer.keycloak_to_scim(kc_user)
            >>> scim_user["userName"]
            'alice'
        """
        user_id = kc_user.get("id", "")
        
        scim_resource = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": user_id,
            "userName": kc_user.get("username"),
            "active": kc_user.get("enabled", True),
            "meta": {
                "resourceType": "User",
                "location": f"{base_url}/Users/{user_id}",
            }
        }
        
        # Name object (optional)
        first_name = kc_user.get("firstName")
        last_name = kc_user.get("lastName")
        if first_name or last_name:
            scim_resource["name"] = {}
            if first_name:
                scim_resource["name"]["givenName"] = first_name
            if last_name:
                scim_resource["name"]["familyName"] = last_name
        
        # Emails (optional)
        email = kc_user.get("email")
        if email:
            scim_resource["emails"] = [
                {
                    "value": email,
                    "primary": True
                }
            ]
        
        # Timestamps (convert from milliseconds to ISO8601)
        created_ts = kc_user.get("createdTimestamp")
        if created_ts:
            created_dt = datetime.fromtimestamp(created_ts / 1000.0)
            scim_resource["meta"]["created"] = created_dt.isoformat() + "Z"
            # Keycloak doesn't track lastModified, use created as fallback
            scim_resource["meta"]["lastModified"] = created_dt.isoformat() + "Z"
        
        # Security: Remove sensitive fields from response
        SENSITIVE_FIELDS = ["_tempPassword", "credentials", "password", "secret"]
        for field in SENSITIVE_FIELDS:
            scim_resource.pop(field, None)
        
        return scim_resource
    
    @staticmethod
    def scim_to_keycloak(scim_user: Dict[str, Any]) -> Dict[str, Any]:
        """Convert SCIM 2.0 User to Keycloak representation.
        
        Args:
            scim_user: SCIM 2.0 User resource
            
        Returns:
            Keycloak user representation
            
        Example:
            >>> scim_user = {
            ...     "userName": "bob",
            ...     "name": {"givenName": "Bob", "familyName": "Jones"},
            ...     "emails": [{"value": "bob@example.com", "primary": True}],
            ...     "active": True
            ... }
            >>> kc_user = ScimTransformer.scim_to_keycloak(scim_user)
            >>> kc_user["username"]
            'bob'
        """
        kc_user = {
            "username": scim_user.get("userName"),
            "enabled": scim_user.get("active", True),
        }
        
        # Handle name object
        name = scim_user.get("name", {})
        if isinstance(name, dict):
            if "givenName" in name:
                kc_user["firstName"] = name["givenName"]
            if "familyName" in name:
                kc_user["lastName"] = name["familyName"]
        
        # Handle emails (extract primary or first)
        emails = scim_user.get("emails", [])
        if emails and isinstance(emails, list):
            # Find primary email or use first one
            primary_email = next(
                (e["value"] for e in emails if e.get("primary")),
                None
            )
            if not primary_email and emails:
                primary_email = emails[0].get("value")
            
            if primary_email:
                kc_user["email"] = primary_email
        
        # Preserve existing ID if present (for updates)
        if "id" in scim_user:
            kc_user["id"] = scim_user["id"]
        
        return kc_user
    
    @staticmethod
    def extract_role_from_scim(scim_user: Dict[str, Any], default_role: str = "analyst") -> str:
        """Extract IAM role from SCIM user resource.
        
        Checks multiple SCIM extension schemas for role information:
        1. Enterprise User extension (urn:ietf:params:scim:schemas:extension:enterprise:2.0:User)
        2. Custom IAM extension (urn:ietf:params:scim:schemas:extension:iam:2.0:User)
        3. Groups (if groups represent roles)
        
        Args:
            scim_user: SCIM User resource
            default_role: Fallback role if none found
            
        Returns:
            Role name (e.g., "analyst", "manager", "iam-operator")
        """
        # Try enterprise extension
        ent_ext = scim_user.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {})
        if ent_ext.get("role"):
            return ent_ext["role"]
        
        # Try custom IAM extension
        iam_ext = scim_user.get("urn:ietf:params:scim:schemas:extension:iam:2.0:User", {})
        if iam_ext.get("role"):
            return iam_ext["role"]
        
        # Try groups (if they represent roles)
        groups = scim_user.get("groups", [])
        if groups and isinstance(groups, list):
            # Assume first group is the primary role
            first_group = groups[0]
            if isinstance(first_group, dict) and "display" in first_group:
                return first_group["display"]
            elif isinstance(first_group, str):
                return first_group
        
        return default_role
    
    @staticmethod
    def add_role_to_scim(scim_user: Dict[str, Any], role: str) -> Dict[str, Any]:
        """Add IAM role to SCIM user resource using custom extension.
        
        Args:
            scim_user: SCIM User resource
            role: Role name to add
            
        Returns:
            Modified SCIM user with role in IAM extension
        """
        # Add IAM extension schema if not present
        schemas = scim_user.get("schemas", [])
        iam_schema = "urn:ietf:params:scim:schemas:extension:iam:2.0:User"
        if iam_schema not in schemas:
            schemas.append(iam_schema)
            scim_user["schemas"] = schemas
        
        # Add role to extension
        scim_user[iam_schema] = {"role": role}
        
        return scim_user
