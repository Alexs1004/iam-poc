import pytest
from flask import Flask
from types import SimpleNamespace

from app.api import scim
from app.core.provisioning_service import ScimError


@pytest.fixture()
def scim_app(monkeypatch):
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["APP_CONFIG"] = SimpleNamespace(
        keycloak_issuer="https://localhost/realms/demo",
        keycloak_server_url="https://localhost/realms/demo",
    )
    monkeypatch.setattr(
        scim.provisioning_service,
        "create_user_scim_like",
        lambda payload, correlation_id: {
            "id": "generated",
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        },
    )
    monkeypatch.setattr(
        scim.provisioning_service,
        "list_users_scim",
        lambda query: {"Resources": [], "totalResults": 0, "itemsPerPage": 0, "startIndex": 1},
    )
    app.register_blueprint(scim.bp)
    monkeypatch.delenv("SKIP_OAUTH_FOR_TESTS", raising=False)
    return app


@pytest.fixture()
def client(scim_app):
    with scim_app.test_client() as client:
        yield client


def auth_headers(token="token"):
    return {"Authorization": f"Bearer {token}"}


def test_missing_authorization_header_returns_401(client):
    response = client.get("/scim/v2/Users")
    body = response.get_json()
    assert response.status_code == 401
    assert body["scimType"] == "unauthorized"


def test_invalid_authorization_scheme(client):
    response = client.get("/scim/v2/Users", headers={"Authorization": "Basic abc"})
    assert response.status_code == 401


def test_write_requires_scope(client, monkeypatch):
    monkeypatch.setattr(
        scim,
        "validate_jwt_token",
        lambda token: {"scope": "scim:read", "client_id": "svc"},
    )
    monkeypatch.setattr(
        scim.provisioning_service,
        "create_user_scim_like",
        lambda payload, correlation_id: (_ for _ in ()).throw(RuntimeError("should not run")),
    )
    response = client.post(
        "/scim/v2/Users",
        headers={**auth_headers(), "Content-Type": "application/scim+json"},
        json={"userName": "alice"},
    )
    body = response.get_json()
    assert response.status_code == 403
    assert body["scimType"] == "forbidden"


def test_service_account_bypass_scope(monkeypatch, client):
    monkeypatch.setattr(
        scim,
        "validate_jwt_token",
        lambda token: {"scope": "", "client_id": "automation-cli"},
    )
    monkeypatch.setattr(
        scim.provisioning_service,
        "create_user_scim_like",
        lambda payload, correlation_id: {
            "id": "123",
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        },
    )

    response = client.post(
        "/scim/v2/Users",
        headers={**auth_headers(), "Content-Type": "application/scim+json"},
        json={"userName": "alice", "emails": [{"value": "alice@example.com"}]},
    )
    assert response.status_code == 201
    assert response.headers["Location"].endswith("/scim/v2/Users/123")


def test_content_type_validation(client, monkeypatch):
    monkeypatch.setattr(
        scim,
        "validate_jwt_token",
        lambda token: {"scope": "scim:write", "client_id": "svc"},
    )

    response = client.post(
        "/scim/v2/Users",
        headers={**auth_headers(), "Content-Type": "application/json"},
        json={"userName": "alice"},
    )
    assert response.status_code == 415
    assert response.get_json()["scimType"] == "invalidSyntax"


def test_payload_too_large_returns_413(client, monkeypatch):
    monkeypatch.setattr(
        scim,
        "validate_jwt_token",
        lambda token: {"scope": "scim:write", "client_id": "svc"},
    )
    monkeypatch.setattr(scim, "JSON_MAX_SIZE_BYTES", 10)
    monkeypatch.setattr(
        scim.provisioning_service,
        "create_user_scim_like",
        lambda payload, correlation_id: {"id": "123"},
    )
    huge_body = "{" + '"a":"' + "x" * 70000 + '"}'
    response = client.post(
        "/scim/v2/Users",
        headers={
            **auth_headers(),
            "Content-Type": "application/scim+json",
            "Content-Length": str(len(huge_body)),
        },
        data=huge_body,
    )
    assert response.status_code == 413
    assert response.get_json()["scimType"] == "invalidValue"


def test_create_user_cleartext_password_rejected(monkeypatch, client):
    monkeypatch.setattr(
        scim,
        "validate_jwt_token",
        lambda token: {"scope": "scim:write", "client_id": "svc"},
    )
    monkeypatch.setattr(
        scim.provisioning_service,
        "create_user_scim_like",
        lambda payload, correlation_id: (_ for _ in ()).throw(
            ScimError(400, "Cleartext password not allowed", "invalidValue")
        ),
    )

    response = client.post(
        "/scim/v2/Users",
        headers={**auth_headers(), "Content-Type": "application/scim+json"},
        json={"userName": "alice", "password": "secret"},
    )
    assert response.status_code == 400
    assert response.get_json()["detail"] == "Cleartext password not allowed"


def test_list_users_invalid_filter_returns_scim_error(monkeypatch, client):
    monkeypatch.setattr(
        scim,
        "validate_jwt_token",
        lambda token: {"scope": "scim:read scim:write", "client_id": "svc"},
    )
    monkeypatch.setattr(
        scim.provisioning_service,
        "list_users_scim",
        lambda query: (_ for _ in ()).throw(
            ScimError(400, "Invalid filter syntax", "invalidFilter")
        ),
    )

    response = client.get("/scim/v2/Users?filter=userName eq", headers=auth_headers())
    assert response.status_code == 400
    body = response.get_json()
    assert body["detail"] == "Invalid filter syntax"
    assert body["scimType"] == "invalidFilter"


def test_after_request_propagates_correlation_id(monkeypatch, client):
    monkeypatch.setattr(
        scim,
        "validate_jwt_token",
        lambda token: {"scope": "scim:read scim:write", "client_id": "svc"},
    )

    response = client.get(
        "/scim/v2/Users",
        headers={**auth_headers(), "X-Correlation-Id": "corr-123"},
    )
    assert response.status_code == 200
    assert response.headers["X-Correlation-Id"] == "corr-123"


def test_scim_error_helpers(client):
    with client.application.app_context():
        response, status = scim.scim_error(400, "Invalid value", "invalidValue")
        assert status == 400
        assert response.get_json()["detail"] == "Invalid value"

        resp = scim.scim_error_response(401, "Unauthorized", "unauthorized")
        assert resp.status_code == 401
        assert resp.get_json()["scimType"] == "unauthorized"


def test_create_user_handles_generic_exception(monkeypatch, client):
    monkeypatch.setattr(
        scim,
        "validate_jwt_token",
        lambda token: {"scope": "scim:write", "client_id": "svc"},
    )
    monkeypatch.setattr(
        scim.provisioning_service,
        "create_user_scim_like",
        lambda payload, correlation_id: (_ for _ in ()).throw(Exception("boom")),
    )

    response = client.post(
        "/scim/v2/Users",
        headers={**auth_headers(), "Content-Type": "application/scim+json"},
        json={"userName": "alice"},
    )
    assert response.status_code == 500
    assert "boom" in response.get_json()["detail"]


def test_get_user_handles_generic_exception(monkeypatch, client):
    monkeypatch.setattr(
        scim,
        "validate_jwt_token",
        lambda token: {"scope": "scim:read", "client_id": "svc"},
    )
    monkeypatch.setattr(
        scim.provisioning_service,
        "get_user_scim",
        lambda user_id: (_ for _ in ()).throw(Exception("boom")),
    )

    response = client.get("/scim/v2/Users/123", headers=auth_headers())
    assert response.status_code == 500


def test_list_users_handles_generic_exception(monkeypatch, client):
    monkeypatch.setattr(
        scim,
        "validate_jwt_token",
        lambda token: {"scope": "scim:read", "client_id": "svc"},
    )
    monkeypatch.setattr(
        scim.provisioning_service,
        "list_users_scim",
        lambda query: (_ for _ in ()).throw(Exception("boom")),
    )

    response = client.get("/scim/v2/Users", headers=auth_headers())
    assert response.status_code == 500


def test_replace_user_handles_generic_exception(monkeypatch, client):
    monkeypatch.setattr(
        scim,
        "validate_jwt_token",
        lambda token: {"scope": "scim:write", "client_id": "svc"},
    )
    monkeypatch.setattr(
        scim.provisioning_service,
        "replace_user_scim",
        lambda user_id, payload, correlation_id: (_ for _ in ()).throw(Exception("boom")),
    )

    response = client.put(
        "/scim/v2/Users/123",
        headers={**auth_headers(), "Content-Type": "application/scim+json"},
        json={"userName": "alice"},
    )
    assert response.status_code == 501


def test_delete_user_handles_generic_exception(monkeypatch, client):
    monkeypatch.setattr(
        scim,
        "validate_jwt_token",
        lambda token: {"scope": "scim:write", "client_id": "svc"},
    )
    monkeypatch.setattr(
        scim.provisioning_service,
        "delete_user_scim",
        lambda user_id, correlation_id: (_ for _ in ()).throw(Exception("boom")),
    )

    response = client.delete("/scim/v2/Users/123", headers=auth_headers())
    assert response.status_code == 500


def test_search_users_handles_generic_exception(monkeypatch, client):
    monkeypatch.setattr(
        scim,
        "validate_jwt_token",
        lambda token: {"scope": "scim:write", "client_id": "svc"},
    )
    monkeypatch.setattr(
        scim.provisioning_service,
        "list_users_scim",
        lambda query: (_ for _ in ()).throw(Exception("boom")),
    )

    response = client.post(
        "/scim/v2/Users/.search",
        headers={**auth_headers(), "Content-Type": "application/scim+json"},
        json={"filter": 'userName eq "alice"'},
    )
    assert response.status_code == 500
