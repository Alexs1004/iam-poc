from types import SimpleNamespace

import pytest
from flask import Flask, session

from app.core import rbac


def _raise(exc):
    raise exc


@pytest.fixture()
def app_ctx():
    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.config["APP_CONFIG"] = SimpleNamespace(
        keycloak_server_url="https://localhost",
        keycloak_issuer="https://localhost/realms/demo",
    )
    # Provide deterministic logger interface for assertions
    app.logger = SimpleNamespace(warning=lambda *args, **kwargs: None, error=lambda *args, **kwargs: None)
    with app.test_request_context():
        yield app


@pytest.fixture(autouse=True)
def reset_jwks_cache():
    rbac._JWKS_CACHE = None
    yield
    rbac._JWKS_CACHE = None


def test_collect_roles_merges_unique():
    payload = {
        "realm_access": {"roles": ["realm-admin", "iam-operator"]},
        "resource_access": {"app": {"roles": ["iam-operator", "viewer"]}},
    }
    extra = {"realm_access": {"roles": ["realm-admin"]}}
    roles = rbac.collect_roles(payload, extra)
    assert roles == ["realm-admin", "iam-operator", "viewer"]


@pytest.mark.parametrize(
    "candidate,expected",
    [
        (["user", "Admin"], True),
        (["user", "realm-admin"], True),
        (["user", "IAM-Operator"], True),
        (["user", "analyst"], False),
    ],
)
def test_has_admin_role(candidate, expected):
    assert rbac.has_admin_role(candidate, "realm-admin", "iam-operator") is expected


def test_user_has_role_true(app_ctx, monkeypatch):
    monkeypatch.setattr(rbac, "is_authenticated", lambda: True)
    monkeypatch.setattr(
        rbac,
        "current_user_context",
        lambda: (
            {"token": "x"},
            {},
            {},
            ["manager", "analyst"],
        ),
    )
    assert rbac.user_has_role("manager") is True


def test_user_has_role_false_when_not_authenticated(monkeypatch):
    monkeypatch.setattr(rbac, "is_authenticated", lambda: False)
    assert rbac.user_has_role("manager") is False


def test_current_username_prefers_userinfo(app_ctx, monkeypatch):
    monkeypatch.setattr(
        rbac,
        "current_user_context",
        lambda: (
            {"token": "x"},
            {"preferred_username": "id-claim"},
            {"preferred_username": "userinfo-name"},
            [],
        ),
    )
    assert rbac.current_username() == "userinfo-name"


def test_clear_session_tokens(app_ctx):
    session["token"] = {"access_token": "x"}
    session["userinfo"] = {"name": "alice"}
    session["id_claims"] = {"sub": "123"}

    rbac.clear_session_tokens()

    assert "token" not in session
    assert "userinfo" not in session
    assert "id_claims" not in session


def test_filter_display_roles_hides_default():
    assert rbac.filter_display_roles(["default-roles-demo", "manager"], "demo") == ["manager"]


@pytest.mark.parametrize(
    "roles,expected",
    [
        (["realm-admin"], True),
        (["iam-operator"], True),
        (["analyst"], False),
    ],
)
def test_requires_operator_for_roles(roles, expected):
    assert rbac.requires_operator_for_roles(roles, "realm-admin", "iam-operator") is expected


def test_decode_access_token_fetches_and_validates(monkeypatch):
    token_claims = {"sub": "svc-account", "realm_access": {"roles": ["analyst"]}}

    class FakeResponse:
        def json(self):
            return {"keys": []}

        def raise_for_status(self):
            return None

    class FakeClient:
        def load_server_metadata(self):
            return {"jwks_uri": "https://metadata/jwks"}

    class FakeClaims(dict):
        def validate(self):
            return None

    monkeypatch.setattr("app.api.auth.get_oidc_client", lambda: FakeClient())
    monkeypatch.setattr(rbac.requests, "get", lambda url, timeout: FakeResponse())
    monkeypatch.setattr(rbac.JsonWebKey, "import_key_set", lambda payload: "jwks-cache")
    monkeypatch.setattr(
        rbac.jwt,
        "decode",
        lambda token, key, claims_options: FakeClaims(token_claims | {"iss": claims_options["iss"]["values"][0]}),
    )

    result = rbac.decode_access_token("encoded-token", "https://localhost/realms/demo")
    assert result["sub"] == "svc-account"
    assert rbac._JWKS_CACHE == "jwks-cache"


def test_decode_access_token_returns_empty_on_error(monkeypatch):
    monkeypatch.setattr("app.api.auth.get_oidc_client", lambda: SimpleNamespace(load_server_metadata=lambda: {}))
    monkeypatch.setattr(rbac.requests, "get", lambda *args, **kwargs: (_raise(RuntimeError("boom"))))
    assert rbac.decode_access_token("token", "issuer") == {}


def test_current_user_context_fetches_userinfo(app_ctx, monkeypatch):
    session["token"] = {"access_token": "abc"}
    session["id_claims"] = {"realm_access": {"roles": ["admin"]}}

    class FakeClient:
        def get(self, url, token):
            assert "userinfo" in url
            return SimpleNamespace(json=lambda: {"preferred_username": "alice"})

    monkeypatch.setattr("app.api.auth.get_oidc_client", lambda: FakeClient())
    monkeypatch.setattr(
        rbac,
        "decode_access_token",
        lambda access_token, issuer: {"resource_access": {"svc": {"roles": ["analyst"]}}},
    )

    token, id_claims, userinfo, roles = rbac.current_user_context()
    assert token["access_token"] == "abc"
    assert userinfo["preferred_username"] == "alice"
    assert roles == ["admin", "analyst"]


def test_refresh_session_token_success(app_ctx, monkeypatch):
    session["token"] = {"access_token": "old", "refresh_token": "refresh", "expires_at": 900}
    monkeypatch.setattr(rbac.time, "time", lambda: 1000.0)

    class FakeClient:
        def refresh_token(self, endpoint, refresh_token):
            assert refresh_token == "refresh"
            return {"access_token": "new", "refresh_token": "new-refresh", "expires_in": 120}

        def parse_id_token(self, token):
            return {"sub": "svc-account"}

    monkeypatch.setattr("app.api.auth.get_oidc_client", lambda: FakeClient())

    assert rbac.refresh_session_token() is True
    assert session["token"]["access_token"] == "new"
    assert session["token"]["expires_at"] == pytest.approx(1120.0)
    assert session["id_claims"] == {"sub": "svc-account"}


def test_refresh_session_token_missing_refresh_token(app_ctx, monkeypatch):
    session["token"] = {"access_token": "a", "expires_at": 900}
    monkeypatch.setattr(rbac.time, "time", lambda: 1000.0)

    rbac.refresh_session_token()
    assert "token" not in session
    assert "userinfo" not in session
    assert "id_claims" not in session


def test_refresh_session_token_handles_refresh_failure(app_ctx, monkeypatch):
    session["token"] = {"access_token": "a", "refresh_token": "r", "expires_at": 900}
    monkeypatch.setattr(rbac.time, "time", lambda: 1000.0)

    class FakeClient:
        def refresh_token(self, endpoint, refresh_token):
            raise RuntimeError("cannot refresh")

    monkeypatch.setattr("app.api.auth.get_oidc_client", lambda: FakeClient())

    assert rbac.refresh_session_token() is False
    assert "token" not in session
