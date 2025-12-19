from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from flask import Flask

from app.api import auth


@pytest.fixture(autouse=True)
def reset_oauth_singletons():
    auth.oauth = None
    auth._providers = {}
    yield
    auth.oauth = None
    auth._providers = {}


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


def test_callback_without_verifier_redirects_to_login(monkeypatch, client):
    monkeypatch.setattr(auth, "get_oidc_client", lambda provider=None: None)
    monkeypatch.setattr(auth, "get_current_provider", lambda: "keycloak")

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

    monkeypatch.setattr(auth, "get_oidc_client", lambda provider=None: FakeClient())
    monkeypatch.setattr(auth, "get_current_provider", lambda: "keycloak")
    monkeypatch.setattr(auth, "normalize_claims", lambda id_claims, userinfo, access_claims, provider: ["realm-admin"])
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

    monkeypatch.setattr(auth, "get_oidc_client", lambda provider=None: FakeClient())
    monkeypatch.setattr(auth, "get_current_provider", lambda: "keycloak")
    monkeypatch.setattr(auth, "normalize_claims", lambda id_claims, userinfo, access_claims, provider: ["analyst"])
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


def test_logout_with_reauth_parameter(client):
    """Test that logout?reauth=1 sets cookie with proper security attributes."""
    with client.session_transaction() as sess:
        sess["token"] = {"id_token": "id123"}
    
    response = client.get("/logout?reauth=1", follow_redirects=False)
    assert response.status_code == 302
    
    # Check that cookie is set via Set-Cookie header with security attributes
    set_cookie_headers = response.headers.getlist('Set-Cookie')
    cookie_str = '; '.join(set_cookie_headers)
    assert "reauth_requested=1" in cookie_str
    assert "Max-Age=30" in cookie_str
    assert "HttpOnly" in cookie_str
    assert "Secure" in cookie_str
    assert "SameSite=Strict" in cookie_str


def test_pkce_code_verifier_generation():
    """Test PKCE code verifier is generated with correct length and characters."""
    from app.api.auth import _generate_code_verifier
    
    verifier = _generate_code_verifier(64)
    assert len(verifier) == 64
    # Should only contain allowed characters
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
    assert all(c in allowed for c in verifier)


def test_pkce_code_challenge_generation():
    """Test PKCE code challenge is properly base64url encoded SHA256 hash."""
    from app.api.auth import _build_code_challenge
    
    # Test with known verifier
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = _build_code_challenge(verifier)
    
    # Should be base64url without padding
    assert "=" not in challenge
    assert len(challenge) == 43  # SHA256 = 32 bytes = 43 base64url chars without padding
    # Should only contain base64url characters
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    assert all(c in allowed for c in challenge)


def test_login_initiates_oidc_flow(monkeypatch, client):
    """Test login route initiates OIDC flow with PKCE."""
    redirect_called = []
    
    class FakeClient:
        def authorize_redirect(self, redirect_uri, code_challenge, code_challenge_method):
            redirect_called.append({
                'redirect_uri': redirect_uri,
                'code_challenge': code_challenge,
                'code_challenge_method': code_challenge_method
            })
            from flask import redirect
            return redirect("https://keycloak/authorize?code_challenge=" + code_challenge)
    
    monkeypatch.setattr(auth, "get_oidc_client", lambda provider=None: FakeClient())
    monkeypatch.setattr(auth, "get_current_provider", lambda: "keycloak")
    monkeypatch.setattr(auth, "_is_provider_override_allowed", lambda: False)
    
    response = client.get("/login", follow_redirects=False)
    
    assert response.status_code == 302
    assert len(redirect_called) == 1
    assert redirect_called[0]['code_challenge_method'] == "S256"
    assert redirect_called[0]['redirect_uri'] == "https://localhost/callback"
    assert len(redirect_called[0]['code_challenge']) == 43  # base64url SHA256


def test_index_page_for_authenticated_user(monkeypatch, client):
    """Test index page renders for authenticated user."""
    # Mock authentication
    monkeypatch.setattr("app.core.rbac.is_authenticated", lambda: True)
    monkeypatch.setattr("app.core.rbac.current_user_context", lambda: ("alice", "alice@example.com", "sub123", ["user"]))
    monkeypatch.setattr("app.core.rbac.has_admin_role", lambda roles, r1, r2: False)
    
    # Mock settings at the config level
    from types import SimpleNamespace
    fake_settings = SimpleNamespace(
        realm_admin_role="realm-admin",
        iam_operator_role="iam-operator",
        demo_mode=False
    )
    monkeypatch.setattr("app.config.settings.settings", fake_settings)
    
    # Mock render_template to avoid loading actual template
    rendered = []
    def fake_render(template, **kwargs):
        rendered.append({'template': template, 'kwargs': kwargs})
        return f"rendered {template}"
    
    from flask import Flask
    import app.api.auth as auth_module
    
    # Patch at Flask's render_template since it's imported inside the function
    with monkeypatch.context() as m:
        m.setattr("flask.render_template", fake_render)
        
        response = client.get("/", follow_redirects=False)
        
        assert response.status_code == 200
        assert len(rendered) == 1
        assert rendered[0]['template'] == "index.html"
        assert rendered[0]['kwargs']['is_authenticated'] is True
        assert rendered[0]['kwargs']['is_admin'] is False


def test_index_page_for_authenticated_admin(monkeypatch, client):
    """Test index page renders for authenticated admin."""
    # Mock authentication as admin
    monkeypatch.setattr("app.core.rbac.is_authenticated", lambda: True)
    monkeypatch.setattr("app.core.rbac.current_user_context", lambda: ("admin", "admin@example.com", "sub456", ["realm-admin"]))
    monkeypatch.setattr("app.core.rbac.has_admin_role", lambda roles, r1, r2: True)
    
    # Mock settings
    from types import SimpleNamespace
    fake_settings = SimpleNamespace(
        realm_admin_role="realm-admin",
        iam_operator_role="iam-operator",
        demo_mode=False
    )
    monkeypatch.setattr("app.config.settings.settings", fake_settings)
    
    # Mock render_template
    rendered = []
    def fake_render(template, **kwargs):
        rendered.append({'template': template, 'kwargs': kwargs})
        return f"rendered {template}"
    
    with monkeypatch.context() as m:
        m.setattr("flask.render_template", fake_render)
        
        response = client.get("/", follow_redirects=False)
        
        assert response.status_code == 200
        assert len(rendered) == 1
        assert rendered[0]['kwargs']['is_admin'] is True


def test_index_page_with_reauth_cookie_and_not_authenticated(client):
    """Test index redirects to login when reauth cookie present and user not authenticated."""
    # Set the reauth cookie without being authenticated
    client.set_cookie('reauth_requested', '1')
    
    response = client.get("/", follow_redirects=False)
    
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    
    # Check cookie is cleared in the response
    set_cookie_headers = response.headers.getlist('Set-Cookie')
    cookie_str = '; '.join(set_cookie_headers)
    assert "reauth_requested=" in cookie_str
    assert "Max-Age=0" in cookie_str


def test_index_page_with_exception_in_has_admin_role_check(monkeypatch, client):
    """Test index handles exception during admin role check (lines 175-176)."""
    from app.config.settings import settings as real_settings
    
    def fake_is_authenticated():
        return True
    
    def fake_current_user_context():
        raise RuntimeError("JWKS fetch failed")  # Simulate error
    
    def fake_render(template_name, **kwargs):
        return f"Rendered {template_name} with is_admin={kwargs.get('is_admin')}"
    
    with monkeypatch.context() as m:
        m.setattr("app.core.rbac.is_authenticated", fake_is_authenticated)
        m.setattr("app.core.rbac.current_user_context", fake_current_user_context)
        m.setattr("app.config.settings.settings", real_settings)
        m.setattr("flask.render_template", fake_render)
        
        response = client.get("/", follow_redirects=False)
        
        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert "is_admin=False" in body  # Exception handled, is_admin defaults to False
