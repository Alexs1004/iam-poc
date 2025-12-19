import os

import pytest

from app.flask_app import create_app


@pytest.fixture()
def demo_env(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("AZURE_USE_KEYVAULT", "false")
    yield
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.delenv("AZURE_USE_KEYVAULT", raising=False)


@pytest.fixture()
def app(demo_env):
    app = create_app()

    @app.route("/test-form", methods=["POST"])
    def test_form():
        return "ok"

    return app


@pytest.fixture()
def client(app):
    with app.test_client() as client:
        yield client


def test_session_cookie_flags(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["SESSION_COOKIE_SECURE"] is True


def test_health_endpoint_success(client):
    response = client.get("/health")
    assert response.status_code == 200


def test_x_forwarded_proto_enforced(client):
    response = client.get("/health", headers={"X-Forwarded-Proto": "http"})
    assert response.status_code == 400


def test_multiple_forwarded_for_rejected(client, monkeypatch):
    """Test that multiple X-Forwarded-For is rejected when trust is restricted.
    
    Note: In DEMO_MODE with TRUSTED_PROXY_IPS=0.0.0.0/0, all proxies are trusted.
    This test validates the logic when trust is restricted.
    """
    # Skip if TRUSTED_PROXY_IPS allows all (demo mode)
    trusted_ips = os.environ.get("TRUSTED_PROXY_IPS", "")
    if "0.0.0.0/0" in trusted_ips:
        pytest.skip("TRUSTED_PROXY_IPS allows all proxies in demo mode")
    
    response = client.get("/health", headers={"X-Forwarded-For": "1.1.1.1,2.2.2.2"})
    assert response.status_code == 400


def test_csrf_missing_token_rejected(client):
    response = client.post("/test-form", data={"foo": "bar"})
    assert response.status_code == 400


def test_scim_bypass_csrf(client, monkeypatch):
    response = client.post(
        "/scim/v2/Users",
        headers={
            "Authorization": "Bearer token",
            "Content-Type": "application/scim+json",
        },
        json={},
    )
    # Without valid token the before_request will block first; ensure we see SCIM auth error not CSRF
    assert response.status_code == 401
