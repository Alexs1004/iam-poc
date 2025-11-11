from types import SimpleNamespace
from unittest.mock import patch, MagicMock

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
        oidc_client_id="flask-app",
        oidc_client_secret="test-secret",
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


@patch('app.core.rbac.requests.post')
@patch('app.api.auth.get_oidc_client')
def test_refresh_session_token_success(mock_get_client, mock_post, app_ctx, monkeypatch):
    """Test successful token refresh using requests.post (Authlib 1.6.5+)."""
    session["token"] = {"access_token": "old", "refresh_token": "refresh", "expires_at": 900}
    monkeypatch.setattr(rbac.time, "time", lambda: 1000.0)

    # Mock requests.post response
    mock_response = MagicMock()
    mock_response.json.return_value = {"access_token": "new", "refresh_token": "new-refresh", "expires_in": 120}
    mock_response.raise_for_status = MagicMock()  # No exception
    mock_post.return_value = mock_response

    # Mock OIDC client
    mock_client = MagicMock()
    mock_client.parse_id_token.return_value = {"sub": "svc-account"}
    mock_get_client.return_value = mock_client

    assert rbac.refresh_session_token() is True
    assert session["token"]["access_token"] == "new"
    assert session["token"]["expires_at"] == pytest.approx(1120.0)
    assert session["id_claims"] == {"sub": "svc-account"}
    
    # Verify requests.post was called with correct parameters
    assert mock_post.called
    call_data = mock_post.call_args[1]['data']
    assert call_data['grant_type'] == 'refresh_token'
    assert call_data['refresh_token'] == 'refresh'


def test_refresh_session_token_missing_refresh_token(app_ctx, monkeypatch):
    session["token"] = {"access_token": "a", "expires_at": 900}
    monkeypatch.setattr(rbac.time, "time", lambda: 1000.0)

    rbac.refresh_session_token()
    assert "token" not in session
    assert "userinfo" not in session
    assert "id_claims" not in session


@patch('app.core.rbac.requests.post')
def test_refresh_session_token_handles_refresh_failure(mock_post, app_ctx, monkeypatch):
    """Test refresh_session_token handles HTTP errors from token endpoint"""
    session["token"] = {"access_token": "a", "refresh_token": "r", "expires_at": 900}
    monkeypatch.setattr(rbac.time, "time", lambda: 1000.0)

    # Mock requests.post to raise HTTP error
    mock_post.side_effect = RuntimeError("cannot refresh")

    assert rbac.refresh_session_token() is False
    assert "token" not in session


def test_collect_roles_handles_non_dict_sources():
    """Test collect_roles with invalid source types (lines 20, 28)."""
    sources = [
        None,  # None source
        "invalid",  # String source
        {"realm_access": "not-a-dict"},  # Invalid realm_access
        {"resource_access": {"app": "not-a-dict"}},  # Invalid client access
        {"realm_access": {"roles": ["valid"]}},  # Valid for comparison
    ]
    roles = rbac.collect_roles(*sources)
    assert roles == ["valid"]


def test_decode_access_token_with_empty_token():
    """Test decode_access_token with empty token (line 38)."""
    assert rbac.decode_access_token("", "issuer") == {}
    assert rbac.decode_access_token(None, "issuer") == {}


@patch('app.core.rbac.requests.post')
@patch('app.api.auth.get_oidc_client')
def test_refresh_session_token_with_expires_in_conversion_error(mock_get_client, mock_post, app_ctx, monkeypatch):
    """Test refresh_session_token handles invalid expires_in (lines 140-147)."""
    session["token"] = {"access_token": "a", "refresh_token": "r", "expires_at": 900, "expires_in": "invalid"}
    monkeypatch.setattr(rbac.time, "time", lambda: 1000.0)

    # Mock requests.post response with invalid expires_in
    mock_response = MagicMock()
    mock_response.json.return_value = {"access_token": "new", "expires_in": "not-an-int"}
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    # Mock OIDC client that raises exception
    mock_client = MagicMock()
    mock_client.parse_id_token.side_effect = RuntimeError("parse failure")
    mock_get_client.return_value = mock_client

    result = rbac.refresh_session_token()
    assert result is True
    assert "id_claims" not in session


def test_current_user_context_without_token(app_ctx):
    """Test current_user_context with no token (line 105)."""
    token, id_claims, userinfo, roles = rbac.current_user_context()
    assert token is None
    assert id_claims == {}
    assert userinfo == {}
    assert roles == []


def test_current_username_with_no_valid_fields(app_ctx, monkeypatch):
    """Test current_username when all username fields are invalid (line 90, 95)."""
    monkeypatch.setattr(
        rbac,
        "current_user_context",
        lambda: (
            {"token": "x"},
            {"preferred_username": None, "email": "", "name": 123},  # Invalid values
            {"preferred_username": [], "email": None},  # Invalid types
            [],
        ),
    )
    assert rbac.current_username() == ""


@patch('app.core.rbac.requests.post')
def test_refresh_session_token_with_null_new_token(mock_post, app_ctx, monkeypatch):
    """Test refresh_session_token when refresh returns empty JSON (line 173-174)."""
    session["token"] = {"access_token": "a", "refresh_token": "r", "expires_at": 900}
    monkeypatch.setattr(rbac.time, "time", lambda: 1000.0)

    # Mock requests.post response returning empty/null JSON
    mock_response = MagicMock()
    mock_response.json.return_value = None  # Simulate null/empty response
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    result = rbac.refresh_session_token()
    assert result is False
    assert "token" not in session


@patch('app.core.rbac.requests.post')
@patch('app.api.auth.get_oidc_client')
def test_refresh_session_token_without_expires_at_fallback(mock_get_client, mock_post, app_ctx, monkeypatch):
    """Test refresh_session_token expires_at fallback (line 185-186)."""
    session["token"] = {"access_token": "a", "refresh_token": "r", "expires_at": 1030}  # Expires in 30s
    monkeypatch.setattr(rbac.time, "time", lambda: 1000.0)

    # Mock requests.post response without expires_in and expires_at
    mock_response = MagicMock()
    mock_response.json.return_value = {"access_token": "new", "refresh_token": "r"}
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    # Mock OIDC client
    mock_client = MagicMock()
    mock_client.parse_id_token.return_value = {"sub": "user"}
    mock_get_client.return_value = mock_client

    result = rbac.refresh_session_token()
    assert result is True

    result = rbac.refresh_session_token()
    assert result is True
    assert session["token"]["expires_at"] == 1030  # Old expires_at preserved (line 186)
