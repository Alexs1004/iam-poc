import pytest
from unittest.mock import MagicMock

from app.api.helpers import admin_ui


@pytest.fixture(autouse=True)
def reset_dogfood(monkeypatch):
    # Ensure DOGFOOD flag starts false by default
    monkeypatch.setattr(admin_ui, "DOGFOOD_SCIM", False)


def test_ui_set_user_active_direct_mode(monkeypatch):
    monkeypatch.setattr(admin_ui.provisioning_service, "get_service_token", lambda: "mock-token")
    monkeypatch.setattr(admin_ui.provisioning_service, "KEYCLOAK_BASE_URL", "https://kc")
    monkeypatch.setattr(admin_ui.provisioning_service, "KEYCLOAK_REALM", "demo")

    patch_mock = MagicMock(return_value={"id": "user-123", "active": True})
    monkeypatch.setattr(admin_ui.provisioning_service, "patch_user_scim", patch_mock)

    def fake_get_user_by_username(base_url, token, realm, username):
        assert base_url == "https://kc"
        assert token == "mock-token"
        assert realm == "demo"
        assert username == "alice"
        return {"id": "user-123"}

    monkeypatch.setattr("app.core.keycloak.get_user_by_username", fake_get_user_by_username)

    result = admin_ui.ui_set_user_active("alice", True)

    patch_mock.assert_called_once_with("user-123", True)
    assert result == {"id": "user-123", "active": True}


def test_ui_set_user_active_dogfood_mode(monkeypatch):
    monkeypatch.setattr(admin_ui.provisioning_service, "get_service_token", lambda: "mock-token")
    monkeypatch.setattr(admin_ui.provisioning_service, "KEYCLOAK_BASE_URL", "https://kc")
    monkeypatch.setattr(admin_ui.provisioning_service, "KEYCLOAK_REALM", "demo")
    monkeypatch.setattr(admin_ui, "DOGFOOD_SCIM", True)

    dogfood_mock = MagicMock(return_value={"id": "user-456", "active": False})
    monkeypatch.setattr(admin_ui, "_dogfood_set_user_active", dogfood_mock)

    def fake_get_user_by_username(base_url, token, realm, username):
        return {"id": "user-456"}

    monkeypatch.setattr("app.core.keycloak.get_user_by_username", fake_get_user_by_username)

    result = admin_ui.ui_set_user_active("bob", False)

    dogfood_mock.assert_called_once_with("user-456", "bob", False)
    assert result == {"id": "user-456", "active": False}
