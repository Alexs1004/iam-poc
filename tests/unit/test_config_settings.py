import os
from pathlib import Path

import pytest

from app.config import settings
from app.config.settings import _get_or_generate


def make_config(**overrides):
    base = dict(
        demo_mode=False,
        azure_use_keyvault=False,
        secret_key="secret",
        secret_key_fallbacks=[],
        session_cookie_secure=True,
        trusted_proxy_ips="127.0.0.1/32",
        keycloak_url="https://localhost",
        keycloak_realm="demo",
        keycloak_service_realm="demo",
        keycloak_issuer="https://localhost/realms/demo",
        keycloak_server_url="https://localhost/realms/demo",
        keycloak_public_issuer="https://localhost/realms/demo",
        oidc_client_id="flask-app",
        oidc_client_secret="",
        oidc_redirect_uri="https://localhost/callback",
        post_logout_redirect_uri="https://localhost/",
        keycloak_service_client_id="automation-cli",
        keycloak_service_client_secret="",
        keycloak_admin="admin",
        keycloak_admin_password="admin",
        realm_admin_role="realm-admin",
        iam_operator_role="iam-operator",
        assignable_roles=["analyst", "manager"],
        audit_log_signing_key="signing-key",
        demo_passwords={},
    )
    base.update(overrides)
    return settings.AppConfig(**base)


def test_service_client_secret_demo_mode():
    cfg = make_config(demo_mode=True)
    assert cfg.service_client_secret_resolved == "demo-service-secret"


def test_service_client_secret_prefers_config_value():
    cfg = make_config(keycloak_service_client_secret="from-config")
    assert cfg.service_client_secret_resolved == "from-config"


def test_service_client_secret_reads_from_run_secrets(monkeypatch, tmp_path):
    secret_path = tmp_path / "keycloak_service_client_secret"
    secret_path.write_text("file-secret")

    real_path = settings.Path

    def fake_path(target):
        if str(target) == "/run/secrets":
            return tmp_path
        return real_path(target)

    monkeypatch.setattr(settings, "Path", fake_path)
    cfg = make_config()
    assert cfg.service_client_secret_resolved == "file-secret"


def test_service_client_secret_falls_back_to_env(monkeypatch, tmp_path):
    """Test that service client secret falls back to env when /run/secrets is empty."""
    from app.config import settings
    real_path = settings.Path

    # Mock /run/secrets to an empty temp directory
    def fake_path(target):
        if str(target) == "/run/secrets":
            return tmp_path
        return real_path(target)

    monkeypatch.setattr(settings, "Path", fake_path)
    monkeypatch.setenv("KEYCLOAK_SERVICE_CLIENT_SECRET", "env-secret")
    cfg = make_config()
    try:
        assert cfg.service_client_secret_resolved == "env-secret"
    finally:
        monkeypatch.delenv("KEYCLOAK_SERVICE_CLIENT_SECRET", raising=False)


def test_service_client_secret_raises_when_missing(monkeypatch, tmp_path):
    real_path = settings.Path

    def fake_path(target):
        if str(target) == "/run/secrets":
            return tmp_path
        return real_path(target)

    monkeypatch.setattr(settings, "Path", fake_path)
    monkeypatch.delenv("KEYCLOAK_SERVICE_CLIENT_SECRET", raising=False)

    cfg = make_config()
    with pytest.raises(ValueError):
        _ = cfg.service_client_secret_resolved


def test_enforce_demo_mode_disables_keyvault(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("AZURE_USE_KEYVAULT", "true")
    settings._enforce_demo_mode_consistency()
    assert os.getenv("AZURE_USE_KEYVAULT") == "false"


def test_get_or_generate_uses_demo_default(monkeypatch):
    monkeypatch.delenv("SAMPLE_VAR", raising=False)
    value = _get_or_generate("SAMPLE_VAR", demo_default="demo", demo_mode=True)
    assert value == "demo"
    assert os.environ["SAMPLE_VAR"] == "demo"


def test_get_or_generate_optional(monkeypatch):
    monkeypatch.delenv("OPTIONAL_VAR", raising=False)
    assert _get_or_generate("OPTIONAL_VAR", required=False) == ""


def test_get_or_generate_missing_required(monkeypatch):
    monkeypatch.delenv("REQUIRED_VAR", raising=False)
    with pytest.raises(RuntimeError):
        _get_or_generate("REQUIRED_VAR", required=True, demo_mode=False)


def test_load_settings_demo_mode_generates_defaults(monkeypatch):
    def fake_load_secret(name, env_var):
        overrides = {
            "keycloak_admin_password": "admin",
            "audit_log_signing_key": None,
        }
        return overrides.get(name)

    monkeypatch.setattr(settings, "_load_secret_from_file", fake_load_secret)
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("AZURE_USE_KEYVAULT", "false")
    monkeypatch.delenv("TRUSTED_PROXY_IPS", raising=False)

    cfg = settings.load_settings()

    assert cfg.demo_mode is True
    assert os.environ.get("TRUSTED_PROXY_IPS") == "127.0.0.1/32,::1/128"
    assert os.environ.get("AUDIT_LOG_SIGNING_KEY").startswith("demo-")
