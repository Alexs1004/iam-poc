"""Tests for Entra ID App Roles integration.

Validates that Entra ID roles claim (top-level array) is correctly
normalized and enforced by RBAC decorators.

Security context:
- Entra ID uses `roles` claim (array of App Role values)
- Roles are defined in App Registration manifest
- Must be mapped to internal roles for consistent RBAC
"""
import pytest
from unittest.mock import patch, MagicMock
from flask import session


class TestNormalizeClaimsEntra:
    """Test normalize_claims() with Entra ID token formats."""

    def test_entra_roles_from_id_token(self, client):
        """Entra ID roles in id_token are extracted."""
        from app.api.auth import normalize_claims

        id_claims = {"roles": ["admin", "viewer"]}
        roles = normalize_claims(id_claims, {}, {}, "entra")

        assert "admin" in roles
        assert "viewer" in roles

    def test_entra_roles_from_access_token(self, client):
        """Entra ID roles in access_token are extracted."""
        from app.api.auth import normalize_claims

        access_claims = {"roles": ["iam-operator"]}
        roles = normalize_claims({}, {}, access_claims, "entra")

        assert "iam-operator" in roles

    def test_entra_no_duplicate_roles(self, client):
        """Duplicate roles across claims are deduplicated."""
        from app.api.auth import normalize_claims

        id_claims = {"roles": ["admin"]}
        access_claims = {"roles": ["admin", "viewer"]}
        roles = normalize_claims(id_claims, {}, access_claims, "entra")

        assert roles.count("admin") == 1
        assert "viewer" in roles

    def test_entra_empty_roles(self, client):
        """Empty roles array returns empty list."""
        from app.api.auth import normalize_claims

        roles = normalize_claims({"roles": []}, {}, {}, "entra")
        assert roles == []

    def test_entra_missing_roles_claim(self, client):
        """Missing roles claim returns empty list."""
        from app.api.auth import normalize_claims

        roles = normalize_claims({"sub": "user@example.com"}, {}, {}, "entra")
        assert roles == []


class TestAdminAccessWithEntraRoles:
    """Test /admin endpoint access with Entra ID roles."""

    def test_admin_role_grants_dashboard_access(self, client):
        """User with Entra 'admin' role can access /admin dashboard."""
        with client.session_transaction() as sess:
            sess["token"] = {"access_token": "mock", "id_token": "mock"}
            sess["userinfo"] = {"sub": "admin@example.com", "name": "Admin User"}
            sess["id_claims"] = {"sub": "admin@example.com"}
            sess["normalized_roles"] = ["admin"]

        response = client.get("/admin/")
        # Should not be 403 (may be 200 or redirect depending on setup)
        assert response.status_code != 403

    def test_viewer_role_denied_dashboard_access(self, client):
        """User with only 'viewer' role cannot access /admin dashboard."""
        with client.session_transaction() as sess:
            sess["token"] = {"access_token": "mock", "id_token": "mock"}
            sess["userinfo"] = {"sub": "viewer@example.com", "name": "Viewer User"}
            sess["id_claims"] = {"sub": "viewer@example.com"}
            sess["normalized_roles"] = ["viewer"]

        response = client.get("/admin/")
        assert response.status_code == 403

    def test_iam_operator_role_grants_access(self, client):
        """User with 'iam-operator' role can access /admin."""
        with client.session_transaction() as sess:
            sess["token"] = {"access_token": "mock", "id_token": "mock"}
            sess["userinfo"] = {"sub": "operator@example.com", "name": "Operator"}
            sess["id_claims"] = {"sub": "operator@example.com"}
            sess["normalized_roles"] = ["iam-operator"]

        response = client.get("/admin/")
        assert response.status_code != 403

    def test_manager_role_grants_access(self, client):
        """User with 'manager' role can access /admin."""
        with client.session_transaction() as sess:
            sess["token"] = {"access_token": "mock", "id_token": "mock"}
            sess["userinfo"] = {"sub": "manager@example.com", "name": "Manager"}
            sess["id_claims"] = {"sub": "manager@example.com"}
            sess["normalized_roles"] = ["manager"]

        response = client.get("/admin/")
        assert response.status_code != 403

    def test_no_roles_denied_access(self, client):
        """Authenticated user with no roles cannot access /admin."""
        with client.session_transaction() as sess:
            sess["token"] = {"access_token": "mock", "id_token": "mock"}
            sess["userinfo"] = {"sub": "nobody@example.com", "name": "Nobody"}
            sess["id_claims"] = {"sub": "nobody@example.com"}
            sess["normalized_roles"] = []

        response = client.get("/admin/")
        assert response.status_code == 403

    def test_realm_admin_role_grants_access(self, client):
        """User with 'realm-admin' role can access /admin."""
        with client.session_transaction() as sess:
            sess["token"] = {"access_token": "mock", "id_token": "mock"}
            sess["userinfo"] = {"sub": "realmadmin@example.com", "name": "Realm Admin"}
            sess["id_claims"] = {"sub": "realmadmin@example.com"}
            sess["normalized_roles"] = ["realm-admin"]

        response = client.get("/admin/")
        assert response.status_code != 403
