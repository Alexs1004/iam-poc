from types import SimpleNamespace

import pytest
from flask import Flask
from jwt.exceptions import ExpiredSignatureError

from app.api import decorators


@pytest.fixture
def app_ctx():
    app = Flask(__name__)
    app.config["TESTING"] = False
    app.config["APP_CONFIG"] = SimpleNamespace(
        keycloak_server_url="https://issuer/realms/demo",
        keycloak_issuer="https://issuer/realms/demo",
    )
    with app.app_context():
        yield app


class DummySigningKey:
    key = "secret"


class DummyJWKS:
    def get_signing_key_from_jwt(self, token):
        return DummySigningKey()


def test_validate_jwt_token_expired_raises_token_validation_error(monkeypatch, app_ctx):
    monkeypatch.setattr(decorators, "_jwks_client", None)
    monkeypatch.setattr(decorators, "get_jwks_client", lambda: DummyJWKS())

    def raise_expired(*args, **kwargs):
        raise ExpiredSignatureError("expired")

    monkeypatch.setattr(decorators.jwt, "decode", raise_expired)

    with pytest.raises(decorators.TokenValidationError) as exc:
        decorators.validate_jwt_token("header.payload.signature")

    assert "Token expired" in str(exc.value)


def test_validate_jwt_token_unexpected_exception_wrapped(monkeypatch, app_ctx):
    monkeypatch.setattr(decorators, "_jwks_client", None)
    monkeypatch.setattr(decorators, "get_jwks_client", lambda: DummyJWKS())

    def raise_generic(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(decorators.jwt, "decode", raise_generic)

    with pytest.raises(decorators.TokenValidationError) as exc:
        decorators.validate_jwt_token("header.payload.signature")

    assert "Token validation failed" in str(exc.value)


def test_validate_jwt_token_success(monkeypatch, app_ctx):
    monkeypatch.setattr(decorators, "_jwks_client", None)
    monkeypatch.setattr(decorators, "get_jwks_client", lambda: DummyJWKS())

    claims_payload = {
        "sub": "user-123",
        "scope": "scim:read scim:write",
        "client_id": "automation-cli",
    }

    def decode_success(*args, **kwargs):
        return claims_payload

    monkeypatch.setattr(decorators.jwt, "decode", decode_success)

    claims = decorators.validate_jwt_token("header.payload.signature")
    assert claims["sub"] == "user-123"
    assert claims["scope"] == "scim:read scim:write"


def _make_protected_app(monkeypatch, validator):
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SKIP_OAUTH_FOR_TESTS"] = False
    app.config["APP_CONFIG"] = SimpleNamespace(
        keycloak_server_url="https://issuer/realms/demo",
        keycloak_issuer="https://issuer/realms/demo",
    )
    monkeypatch.setattr(decorators, "validate_jwt_token", validator)

    @app.route("/protected")
    @decorators.require_oauth_token(scopes=["scim:write"])
    def protected():
        return ("OK", 204)

    return app


def test_require_oauth_token_missing_header(monkeypatch):
    app = _make_protected_app(monkeypatch, lambda _: {})
    with app.test_client() as client:
        response = client.get("/protected")
    assert response.status_code == 401


def test_require_oauth_token_non_bearer(monkeypatch):
    app = _make_protected_app(monkeypatch, lambda _: {})
    with app.test_client() as client:
        response = client.get("/protected", headers={"Authorization": "Basic abc"})
    assert response.status_code == 401


def test_require_oauth_token_insufficient_scope(monkeypatch):
    def validator(_token):
        return {"scope": "scim:read", "client_id": "test-client"}

    app = _make_protected_app(monkeypatch, validator)
    with app.test_client() as client:
        response = client.get("/protected", headers={"Authorization": "Bearer token"})
    assert response.status_code == 403


def test_require_oauth_token_success(monkeypatch):
    def validator(_token):
        return {"scope": "scim:read scim:write", "client_id": "svc"}

    app = _make_protected_app(monkeypatch, validator)
    with app.test_client() as client:
        response = client.get("/protected", headers={"Authorization": "Bearer token"})
    assert response.status_code == 204


def test_require_oauth_token_handles_validation_error(monkeypatch):
    def validator(_token):
        raise decorators.TokenValidationError("boom")

    app = _make_protected_app(monkeypatch, validator)
    with app.test_client() as client:
        response = client.get("/protected", headers={"Authorization": "Bearer token"})
    assert response.status_code == 401
