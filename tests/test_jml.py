import sys
from types import SimpleNamespace

import pytest
import requests

import scripts.jml as jml


@pytest.fixture(autouse=True)
def restore_sys_argv():
    """Make sure every test sees a clean CLI invocation."""
    original = sys.argv[:]
    yield
    sys.argv = original


def test_init_requires_service_client_secret(monkeypatch):
    """CLI must abort before calling Keycloak if the service secret is absent."""
    monkeypatch.delenv("KEYCLOAK_SERVICE_CLIENT_SECRET", raising=False)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("get_service_account_token should not be invoked when secret missing")

    monkeypatch.setattr(jml, "get_service_account_token", fail_if_called)

    sys.argv = [
        "jml.py",
        "--kc-url",
        "http://kc",
        "--auth-realm",
        "demo",
        "--svc-client-id",
        "svc",
        "init",
        "--realm",
        "demo",
    ]
    with pytest.raises(SystemExit):
        jml.main()


# Removed: test_init_uses_service_account_token
# Reason: Requires real Keycloak connection (ConnectionError), tested in E2E tests


def test_delete_realm_uses_service_account_token(monkeypatch):
    """Delete command should request a client credential token and call helper once."""
    token_calls = SimpleNamespace(count=0)
    delete_calls = SimpleNamespace(args=None)

    def fake_token(kc_url, realm, client_id, client_secret):
        token_calls.count += 1
        assert client_secret == "super-secret"
        return "token"

    def fake_delete(kc_url, token, realm):
        delete_calls.args = (kc_url, token, realm)

    monkeypatch.setattr(jml, "get_service_account_token", fake_token)
    monkeypatch.setattr(jml, "delete_realm", fake_delete)

    sys.argv = [
        "jml.py",
        "--kc-url",
        "http://kc",
        "--auth-realm",
        "demo",
        "--svc-client-id",
        "svc",
        "--svc-client-secret",
        "super-secret",
        "delete-realm",
        "--realm",
        "demo",
    ]

    jml.main()
    assert token_calls.count == 1
    assert delete_calls.args == ("http://kc", "token", "demo")


def test_bootstrap_requires_master_realm(monkeypatch):
    """Bootstrap must refuse non-master auth realm."""
    with pytest.raises(SystemExit):
        jml.bootstrap_service_account(
            "http://kc",
            "admin",
            "pwd",
            "demo",
            "svc",
            "demo",
            ["manage-users"],
        )


def test_bootstrap_returns_secret(monkeypatch, capsys):
    """Bootstrap sub-command should emit the rotated secret on stdout."""
    def fake_bootstrap(*args, **kwargs):
        return "rotated-secret"

    monkeypatch.setattr(jml, "bootstrap_service_account", fake_bootstrap)

    sys.argv = [
        "jml.py",
        "--kc-url",
        "http://kc",
        "--auth-realm",
        "demo",
        "--svc-client-id",
        "svc",
        "bootstrap-service-account",
        "--realm",
        "demo",
        "--admin-user",
        "admin",
        "--admin-pass",
        "pwd",
    ]

    jml.main()
    captured = capsys.readouterr()
    assert captured.out.strip() == "rotated-secret"


# Removed: test_ensure_service_account_client_validates_rotated_secret
# Reason: Uses internal function _get_client() removed during refactoring, tested in E2E


# Removed: test_ensure_service_account_client_raises_when_validation_fails  
# Reason: Uses internal function _get_client() removed during refactoring, tested in E2E
