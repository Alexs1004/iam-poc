from types import SimpleNamespace

import pytest
from flask import Flask, jsonify

from app.api import decorators
from app.api.decorators import (
    TokenValidationError,
    require_oauth_token,
    get_oauth_claims,
    get_oauth_client_id,
    validate_jwt_token,
)


@pytest.fixture(autouse=True)
def reset_jwks_cache():
    """Ensure JWKS cache does not leak between tests."""
    decorators._jwks_client = None
    yield
    decorators._jwks_client = None


@pytest.fixture()
def flask_app():
    app = Flask(__name__)
    app.config.update(TESTING=True, SKIP_OAUTH_FOR_TESTS=False)
    app.config["APP_CONFIG"] = SimpleNamespace(
        keycloak_issuer="https://localhost/realms/demo",
        keycloak_server_url="https://localhost/realms/demo",
    )

    @app.route("/protected")
    @require_oauth_token(scopes=["scim:write"])
    def protected():
        claims = get_oauth_claims() or {}
        client_id = get_oauth_client_id()
        return jsonify({"client_id": client_id, "scope": claims.get("scope", "")})

    return app


@pytest.fixture()
def client(flask_app):
    with flask_app.test_client() as client:
        yield client


def test_missing_authorization_header_returns_401(client):
    response = client.get("/protected")
    body = response.get_json()
    assert response.status_code == 401
    assert body["scimType"] == "unauthorized"


def test_invalid_authorization_scheme(client):
    response = client.get("/protected", headers={"Authorization": "Basic abc"})
    body = response.get_json()
    assert response.status_code == 401
    assert "Invalid Authorization header format" in body["detail"]


def test_empty_bearer_token(client):
    response = client.get("/protected", headers={"Authorization": "Bearer "})
    body = response.get_json()
    assert response.status_code == 401
    assert body["detail"] == "Bearer token is empty"


def test_invalid_token_returns_401(monkeypatch, client):
    monkeypatch.setattr(
        decorators,
        "validate_jwt_token",
        lambda token: (_ for _ in ()).throw(TokenValidationError("bad token")),
    )

    response = client.get("/protected", headers={"Authorization": "Bearer token"})
    body = response.get_json()
    assert response.status_code == 401
    assert body["scimType"] == "invalidToken"
    assert "bad token" in body["detail"]


def test_insufficient_scope_returns_403(monkeypatch, client):
    monkeypatch.setattr(
        decorators,
        "validate_jwt_token",
        lambda token: {"scope": "scim:read", "client_id": "automation-cli"},
    )

    response = client.get("/protected", headers={"Authorization": "Bearer token"})
    body = response.get_json()
    assert response.status_code == 403
    assert body["scimType"] == "insufficientScope"


def test_successful_request_sets_claims_context(monkeypatch, client):
    monkeypatch.setattr(
        decorators,
        "validate_jwt_token",
        lambda token: {"scope": "scim:read scim:write", "client_id": "automation-cli"},
    )

    response = client.get("/protected", headers={"Authorization": "Bearer token"})
    data = response.get_json()
    assert response.status_code == 200
    assert data == {"client_id": "automation-cli", "scope": "scim:read scim:write"}


def test_validate_jwt_token_skips_when_testing(monkeypatch, flask_app):
    flask_app.config["SKIP_OAUTH_FOR_TESTS"] = True

    with flask_app.app_context():
        claims = validate_jwt_token("ignored-token")

    assert claims["client_id"] == "test-client"
    assert claims["scope"] == "scim:read scim:write"
