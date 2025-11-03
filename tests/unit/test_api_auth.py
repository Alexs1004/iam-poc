from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from flask import Flask

from app.api import auth


@pytest.fixture(autouse=True)
def reset_oauth_singletons():
    auth.oauth = None
    auth.oidc = None
    yield
    auth.oauth = None
    auth.oidc = None


@pytest.fixture()
def app_with_auth():
    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.config["TESTING"] = True
    app.config["APP_CONFIG"] = SimpleNamespace(
        oidc_redirect_uri="https://localhost/callback",
        keycloak_server_url="https://localhost/realms/demo",
        keycloak_public_issuer="https://localhost/realms/demo",
        post_logout_redirect_uri="https://localhost/",
        oidc_client_id="flask-app",
        keycloak_issuer="https://localhost/realms/demo",
        realm_admin_role="realm-admin",
        iam_operator_role="iam-operator",
    )
    app.register_blueprint(auth.bp)

    from flask import Blueprint

    admin_bp = Blueprint("admin", __name__)

    @admin_bp.route("/admin")
    def admin_dashboard():
        return "admin"

    @admin_bp.route("/me")
    def me():
        return "me"

    app.register_blueprint(admin_bp, url_prefix="/admin")

    return app


@pytest.fixture()
def client(app_with_auth):
    with app_with_auth.test_client() as client:
        yield client


def test_login_force_resets_session_and_sets_pkce(monkeypatch, client):
    captured = {}

    class FakeClient:
        def authorize_redirect(self, **kwargs):
            captured.update(kwargs)
            return "redirecting"

    monkeypatch.setattr(auth, "get_oidc_client", lambda: FakeClient())

    with client.session_transaction() as sess:
        sess["token"] = {"access_token": "old"}
        sess["userinfo"] = {"name": "alice"}
        sess["id_claims"] = {"sub": "123"}

    response = client.get("/login?force=1")

    assert response.data == b"redirecting"
    assert captured["redirect_uri"] == "https://localhost/callback"
    assert captured["code_challenge_method"] == "S256"
    assert "code_challenge" in captured

    with client.session_transaction() as sess:
        assert "token" not in sess
        assert "userinfo" not in sess
        assert "id_claims" not in sess
        assert "pkce_code_verifier" in sess


def test_callback_without_verifier_redirects_to_login(monkeypatch, client):
    monkeypatch.setattr(auth, "get_oidc_client", lambda: None)

    response = client.get("/callback", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_callback_admin_redirect(monkeypatch, client):
    token_data = {"access_token": "abc123"}

    class FakeClient:
        def authorize_access_token(self, code_verifier):
            assert code_verifier == "verifier"
            return token_data

        def parse_id_token(self, token):
            return {"preferred_username": "alice"}

        def get(self, url, token):
            return SimpleNamespace(json=lambda: {"email": "alice@example.com"})

    monkeypatch.setattr(auth, "get_oidc_client", lambda: FakeClient())
    monkeypatch.setattr("app.core.rbac.collect_roles", lambda *args, **kwargs: ["realm-admin"])
    monkeypatch.setattr("app.core.rbac.has_admin_role", lambda roles, realm, operator: True)

    with client.session_transaction() as sess:
        sess["pkce_code_verifier"] = "verifier"

    response = client.get("/callback", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/admin")

    with client.session_transaction() as sess:
        assert sess["token"] == token_data
        assert sess["id_claims"]["preferred_username"] == "alice"
        assert sess["userinfo"]["email"] == "alice@example.com"


def test_callback_non_admin_redirects_to_me(monkeypatch, client):
    token_data = {"access_token": "xyz"}

    class FakeClient:
        def authorize_access_token(self, code_verifier):
            return token_data

        def parse_id_token(self, token):
            raise RuntimeError("cannot parse")

        def get(self, url, token):
            raise RuntimeError("userinfo unavailable")

    monkeypatch.setattr(auth, "get_oidc_client", lambda: FakeClient())
    monkeypatch.setattr("app.core.rbac.collect_roles", lambda *args, **kwargs: ["analyst"])
    monkeypatch.setattr("app.core.rbac.has_admin_role", lambda roles, realm, operator: False)

    with client.session_transaction() as sess:
        sess["pkce_code_verifier"] = "verifier"

    response = client.get("/callback", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/me")

    with client.session_transaction() as sess:
        assert sess["token"] == token_data
        assert sess["id_claims"] == {}
        assert sess["userinfo"] == {}


def test_logout_includes_id_token_hint(client):
    logout_url = "https://localhost/realms/demo/protocol/openid-connect/logout"

    with client.session_transaction() as sess:
        sess["token"] = {"id_token": "id123"}

    response = client.get("/logout", follow_redirects=False)
    assert response.status_code == 302
    parsed = urlparse(response.headers["Location"])
    assert parsed.path == "/realms/demo/protocol/openid-connect/logout"
    params = parse_qs(parsed.query)
    assert params["post_logout_redirect_uri"] == ["https://localhost/"]
    assert params["id_token_hint"] == ["id123"]


def test_logout_without_id_token_uses_client_id(client):
    response = client.get("/logout", follow_redirects=False)
    params = parse_qs(urlparse(response.headers["Location"]).query)
    assert params["client_id"] == ["flask-app"]
