import os
import pathlib
import sys

import pytest
import requests
import scripts.jml as jml
import app.flask_app as flask_module

# Add project root to Python path so pytest can import the Flask app package.
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("DEMO_MODE", "true")

from app import app as flask_app
from app.flask_app import IAM_OPERATOR_ROLE, REALM_ADMIN_ROLE


def _authenticate_with_roles(client, roles, username="alice"):
    with client.session_transaction() as session:
        session["token"] = {"access_token": "", "id_token": ""}
        session["userinfo"] = {
            "preferred_username": username,
            "realm_access": {"roles": roles},
        }
        session["id_claims"] = {
            "preferred_username": username,
            "realm_access": {"roles": roles},
        }


def _authenticate_as_admin(client):
    _authenticate_with_roles(client, [REALM_ADMIN_ROLE, "analyst", IAM_OPERATOR_ROLE])


def _authenticate_as_operator(client):
    _authenticate_with_roles(client, [IAM_OPERATOR_ROLE, "analyst"])


def _get_csrf_token(client):
    client.get("/admin")
    with client.session_transaction() as session:
        return session["_csrf_token"]


# Provide a test client so each test can exercise routes without running a server.
@pytest.fixture()
def client(monkeypatch):
    flask_app.config.update(TESTING=True)

    class _StubResponse:
        def __init__(self, payload: dict, status_code: int = 200):
            self._payload = payload
            self.status_code = status_code

        def json(self):
            return self._payload

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.HTTPError(response=self)

    def _stub_get(url, *args, **kwargs):
        if url.endswith("/.well-known/openid-configuration"):
            return _StubResponse({"jwks_uri": "http://localhost:8080/realms/demo/protocol/openid-connect/certs"})
        if url.endswith("/protocol/openid-connect/certs"):
            return _StubResponse({"keys": []})
        raise RuntimeError(f"Unexpected network access in tests: {url}")

    monkeypatch.setattr(flask_module.requests, "get", _stub_get)
    monkeypatch.setattr(flask_module.oidc, "load_server_metadata", lambda: {"jwks_uri": "http://localhost:8080/realms/demo/protocol/openid-connect/certs"})

    with flask_app.test_client() as client:
        with flask_app.app_context():
            yield client


# Unauthenticated requests to /admin must be redirected to the OIDC login flow.
def test_admin_redirects_to_login_without_session(client):
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


# A signed-in user without the realm-admin role should receive a 403 and security headers.
def test_admin_requires_realm_admin_role(client):
    with client.session_transaction() as session:
        session["token"] = {"access_token": "", "id_token": ""}
        session["userinfo"] = {"realm_access": {"roles": ["analyst"]}}
        session["id_claims"] = {"realm_access": {"roles": ["analyst"]}}
    response = client.get("/admin")
    assert response.status_code == 403
    body = response.get_data(as_text=True)
    assert "403 Forbidden" in body
    assert "no-store" in response.headers["Cache-Control"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


# Realm admin role holders should gain access while the security headers stay enforced.
def test_admin_allows_realm_admin_role_and_sets_security_headers(client):
    _authenticate_as_admin(client)
    response = client.get("/admin")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Joiner / Mover / Leaver control center" in body
    assert "Provision user (Joiner)" in body
    assert "Open Keycloak Console" in body
    assert "no-store" in response.headers["Cache-Control"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_admin_allows_iam_operator_role(client):
    _authenticate_as_operator(client)
    response = client.get("/admin")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Joiner / Mover / Leaver control center" in body
    assert "Open Keycloak Console" not in body


def test_admin_joiner_invokes_create_user(monkeypatch, client):
    _authenticate_as_admin(client)
    csrf_token = _get_csrf_token(client)

    monkeypatch.setattr(flask_module, "_get_service_token", lambda: "token")

    captured = {}

    def fake_create_user(
        kc_url,
        token,
        realm,
        username,
        email,
        first,
        last,
        temp_password,
        role,
        require_totp=True,
        require_password_update=True,
    ):
        captured["args"] = {
            "kc_url": kc_url,
            "token": token,
            "realm": realm,
            "username": username,
            "email": email,
            "first": first,
            "last": last,
            "temp_password": temp_password,
            "role": role,
            "require_totp": require_totp,
            "require_password_update": require_password_update,
        }

    monkeypatch.setattr(jml, "create_user", fake_create_user)

    response = client.post(
        "/admin/joiner",
        data={
            "csrf_token": csrf_token,
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "username": "test.user",
            "role": "analyst",
            "temp_password": "Temp!123",
            "require_totp": "on",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert captured["args"]["username"] == "test.user"
    assert captured["args"]["role"] == "analyst"
    assert captured["args"]["require_totp"] is True


def test_admin_joiner_blocks_operator_from_sensitive_role(monkeypatch, client):
    _authenticate_as_operator(client)
    csrf_token = _get_csrf_token(client)

    monkeypatch.setattr(flask_module, "_get_service_token", lambda: "token")

    called = {}

    def fail_if_called(*args, **kwargs):
        called["called"] = True

    monkeypatch.setattr(jml, "create_user", fail_if_called)

    response = client.post(
        "/admin/joiner",
        data={
            "csrf_token": csrf_token,
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "username": "test.user",
            "role": REALM_ADMIN_ROLE,
            "temp_password": "Temp!123",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "called" not in called


def test_admin_mover_invokes_change_role(monkeypatch, client):
    _authenticate_as_admin(client)
    csrf_token = _get_csrf_token(client)

    monkeypatch.setattr(flask_module, "_get_service_token", lambda: "token")
    monkeypatch.setattr(jml, "get_user_by_username", lambda *args, **kwargs: {"id": "target"})
    monkeypatch.setattr(flask_module, "_user_roles", lambda token, user_id: ["analyst"])

    recorded = {}

    def fake_change_role(kc_url, token, realm, username, from_role, to_role):
        recorded["args"] = (kc_url, token, realm, username, from_role, to_role)

    monkeypatch.setattr(jml, "change_role", fake_change_role)

    assert IAM_OPERATOR_ROLE in flask_module.ASSIGNABLE_ROLES

    response = client.post(
        "/admin/mover",
        data={
            "csrf_token": csrf_token,
            "username": "bob",
            "source_role": "analyst",
            "target_role": IAM_OPERATOR_ROLE,
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    with client.session_transaction() as session:
        flashes = session.get("_flashes", [])
    assert "args" in recorded, f"change_role not invoked; flashes={flashes}"
    assert recorded["args"][3] == "bob"
    assert recorded["args"][4] == "analyst"
    assert recorded["args"][5] == IAM_OPERATOR_ROLE


def test_admin_leaver_invokes_disable_user(monkeypatch, client):
    _authenticate_as_admin(client)
    csrf_token = _get_csrf_token(client)

    monkeypatch.setattr(flask_module, "_get_service_token", lambda: "token")
    monkeypatch.setattr(jml, "get_user_by_username", lambda *args, **kwargs: {"id": "target"})
    monkeypatch.setattr(flask_module, "_user_roles", lambda token, user_id: ["analyst"])

    recorded = {}

    def fake_disable_user(kc_url, token, realm, username):
        recorded["args"] = (kc_url, token, realm, username)

    monkeypatch.setattr(jml, "disable_user", fake_disable_user)

    response = client.post(
        "/admin/leaver",
        data={
            "csrf_token": csrf_token,
            "username": "bob",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert recorded["args"][3] == "bob"


def test_admin_mover_blocks_self_change(monkeypatch, client):
    _authenticate_with_roles(client, [REALM_ADMIN_ROLE, "analyst", IAM_OPERATOR_ROLE], username="alice")
    csrf_token = _get_csrf_token(client)

    called = {}

    def fail_if_called(*args, **kwargs):
        called["called"] = True

    monkeypatch.setattr(jml, "change_role", fail_if_called)

    response = client.post(
        "/admin/mover",
        data={
            "csrf_token": csrf_token,
            "username": "alice",
            "source_role": "analyst",
            "target_role": IAM_OPERATOR_ROLE,
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "called" not in called


def test_admin_mover_requires_realm_admin_for_sensitive_roles(monkeypatch, client):
    _authenticate_as_operator(client)
    csrf_token = _get_csrf_token(client)

    monkeypatch.setattr(flask_module, "_get_service_token", lambda: "token")
    monkeypatch.setattr(jml, "get_user_by_username", lambda *args, **kwargs: {"id": "target"})
    monkeypatch.setattr(flask_module, "_user_roles", lambda token, user_id: [IAM_OPERATOR_ROLE])

    called = {}

    def fail_if_called(*args, **kwargs):
        called["called"] = True

    monkeypatch.setattr(jml, "change_role", fail_if_called)

    response = client.post(
        "/admin/mover",
        data={
            "csrf_token": csrf_token,
            "username": "bob",
            "source_role": IAM_OPERATOR_ROLE,
            "target_role": "analyst",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "called" not in called


def test_admin_leaver_blocks_self_disable(client):
    _authenticate_with_roles(client, [REALM_ADMIN_ROLE, "analyst", IAM_OPERATOR_ROLE], username="alice")
    csrf_token = _get_csrf_token(client)

    response = client.post(
        "/admin/leaver",
        data={
            "csrf_token": csrf_token,
            "username": "alice",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302


def test_admin_leaver_requires_realm_admin_for_sensitive_roles(monkeypatch, client):
    _authenticate_as_operator(client)
    csrf_token = _get_csrf_token(client)

    monkeypatch.setattr(flask_module, "_get_service_token", lambda: "token")
    monkeypatch.setattr(jml, "get_user_by_username", lambda *args, **kwargs: {"id": "target"})
    monkeypatch.setattr(flask_module, "_user_roles", lambda token, user_id: [IAM_OPERATOR_ROLE])

    called = {}

    def fail_if_called(*args, **kwargs):
        called["called"] = True

    monkeypatch.setattr(jml, "disable_user", fail_if_called)

    response = client.post(
        "/admin/leaver",
        data={
            "csrf_token": csrf_token,
            "username": "bob",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "called" not in called


# Accessing /me without a session should kick the user back to the login flow.
def test_me_requires_login(client):
    response = client.get("/me", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


# The profile view must only display the realm-admin and analyst roles to align with RBAC scope.
def test_me_filters_roles_to_realm_admin_and_analyst(client):
    with client.session_transaction() as session:
        session["token"] = {"access_token": "", "id_token": ""}
        session["userinfo"] = {"realm_access": {"roles": [REALM_ADMIN_ROLE]}}
        session["id_claims"] = {"realm_access": {"roles": ["analyst"]}}
    response = client.get("/me")
    assert response.status_code == 200
    payload = response.get_data(as_text=True)
    assert f'role-chip realm-admin">{REALM_ADMIN_ROLE}<' in payload
    assert 'role-chip">analyst<' in payload
    assert 'role-chip">custom<' not in payload


# Session cookies must be HttpOnly, Secure, and SameSite=Lax to prevent XSS and CSRF attacks.
def test_session_cookie_flags_are_hardened(client):
    with client.session_transaction() as session:
        session["token"] = {"access_token": "stub"}
        session["userinfo"] = {"realm_access": {"roles": []}}
    response = client.get("/")
    cookies = "\n".join(response.headers.getlist("Set-Cookie"))
    assert "HttpOnly" in cookies
    assert "Secure" in cookies
    assert "SameSite=Lax" in cookies


# State-changing operations without a CSRF token must be blocked with a 400 error.
def test_csrf_missing_token_blocks_state_changing_request(client):
    response = client.post("/logout")
    assert response.status_code == 400
    assert b"CSRF validation failed" in response.data


# Providing a valid CSRF token in the X-CSRF-Token header should allow the request to proceed.
def test_csrf_header_allows_state_changing_request(client):
    client.get("/")
    with client.session_transaction() as session:
        token = session["_csrf_token"]
    response = client.post("/logout", headers={"X-CSRF-Token": token})
    assert response.status_code == 405


# Requests from untrusted proxy addresses must be rejected to prevent spoofing attacks.
def test_untrusted_proxy_remote_rejected(client):
    response = client.get("/", environ_overrides={"werkzeug.proxy_fix.orig_remote_addr": "203.0.113.10"})
    assert response.status_code == 400
    assert b"Untrusted proxy" in response.data


# Non-HTTPS forwarded protocols must be rejected to enforce secure communication channels.
def test_invalid_forwarded_proto_rejected(client):
    response = client.get("/", headers={"X-Forwarded-Proto": "http"})
    assert response.status_code == 400
    assert b"Invalid forwarded protocol" in response.data
