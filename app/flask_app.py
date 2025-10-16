import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import string
import time
from functools import wraps
from tempfile import gettempdir
from urllib.parse import urlencode, urlparse

import requests
from authlib.integrations.flask_client import OAuth
from authlib.jose import JsonWebKey, jwt
from flask import (
    Flask,
    abort,
    flash,
    g,
    get_flashed_messages,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix
from scripts import jml

try:
    from azure.identity import DefaultAzureCredential  # type: ignore
    from azure.keyvault.certificates import CertificateClient  # type: ignore
    from azure.keyvault.keys import KeyClient  # type: ignore
    from azure.keyvault.secrets import SecretClient  # type: ignore
    from azure.core.exceptions import ResourceNotFoundError  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    DefaultAzureCredential = None
    SecretClient = None
    KeyClient = None
    CertificateClient = None
    ResourceNotFoundError = Exception

# ─────────────────────────────────────────────────────────────────────────────
# Flask Application & Session Configuration
# ─────────────────────────────────────────────────────────────────────────────


def _load_secrets_from_azure() -> None:
    use_kv = os.environ.get("AZURE_USE_KEYVAULT", "false").lower() == "true"
    if not use_kv:
        return
    if DefaultAzureCredential is None or SecretClient is None:
        raise RuntimeError("Azure Key Vault integration requested but azure-keyvault-secrets is not installed.")
    vault_name = os.environ.get("AZURE_KEY_VAULT_NAME")
    if not vault_name:
        raise RuntimeError("AZURE_KEY_VAULT_NAME is required when AZURE_USE_KEYVAULT=true.")
    vault_uri = f"https://{vault_name}.vault.azure.net"
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=vault_uri, credential=credential)
    secret_mapping = {
        "FLASK_SECRET_KEY": os.environ.get("AZURE_SECRET_FLASK_SECRET_KEY", "flask-secret-key"),
        "FLASK_SECRET_KEY_FALLBACKS": os.environ.get("AZURE_SECRET_FLASK_SECRET_KEY_FALLBACKS", ""),
        "KEYCLOAK_SERVICE_CLIENT_SECRET": os.environ.get(
            "AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET", "keycloak-service-client-secret"
        ),
        "KEYCLOAK_ADMIN_PASSWORD": os.environ.get("AZURE_SECRET_KEYCLOAK_ADMIN_PASSWORD", "keycloak-admin-password"),
        "ALICE_TEMP_PASSWORD": os.environ.get("AZURE_SECRET_ALICE_TEMP_PASSWORD", "alice-temp-password"),
        "BOB_TEMP_PASSWORD": os.environ.get("AZURE_SECRET_BOB_TEMP_PASSWORD", "bob-temp-password"),
    }
    key_mapping = {
        "FLASK_SECRET_KEY": os.environ.get("AZURE_KEY_FLASK_SECRET_KEY", "").strip(),
    }
    key_client = None
    if any(value for value in key_mapping.values()):
        if KeyClient is None:
            raise RuntimeError("AZURE_KEY_* variables defined but azure-keyvault-keys is not installed.")
        key_client = KeyClient(vault_url=vault_uri, credential=credential)
    if key_client:
        for env_name, key_name in key_mapping.items():
            if os.environ.get(env_name):
                continue
            key_name = key_name.strip()
            if not key_name:
                continue
            try:
                key_bundle = key_client.get_key(key_name)
            except ResourceNotFoundError:
                continue
            except Exception as exc:  # pragma: no cover - depends on Azure response
                raise RuntimeError(f"Failed to retrieve key '{key_name}' from Key Vault: {exc}") from exc
            key_material = getattr(key_bundle, "key", None)
            key_value = getattr(key_material, "k", None) if key_material else None
            if not key_value:
                continue
            padding = "=" * (-len(key_value) % 4)
            try:
                decoded = base64.urlsafe_b64decode(f"{key_value}{padding}".encode("ascii"))
            except Exception as exc:  # pragma: no cover - depends on key format
                raise RuntimeError(f"Failed to decode key '{key_name}' from Key Vault: {exc}") from exc
            os.environ[env_name] = base64.urlsafe_b64encode(decoded).decode("ascii")
    for env_name, secret_name in secret_mapping.items():
        if os.environ.get(env_name):
            continue
        secret_name = secret_name.strip()
        if not secret_name:
            continue
        try:
            secret = secret_client.get_secret(secret_name)
        except Exception as exc:  # pragma: no cover - depends on Azure response
            raise RuntimeError(f"Failed to retrieve secret '{secret_name}' from Key Vault: {exc}") from exc
        os.environ[env_name] = secret.value


_load_secrets_from_azure()

DEMO_MODE = os.environ.get("DEMO_MODE", "false").lower() == "true"


def _ensure_env(name: str, *, demo_default: str | None = None, required: bool = True) -> str:
    value = os.environ.get(name)
    if value:
        return value
    if DEMO_MODE and demo_default is not None:
        print(f"[demo-mode] Using generated default for {name}")
        os.environ[name] = demo_default
        return demo_default
    if not required:
        return ""
    raise RuntimeError(f"Environment variable {name} is required in production mode.")


def _generate_demo_secret() -> str:
    return secrets.token_urlsafe(48)


app = Flask(__name__)
secret_key = os.environ.get("FLASK_SECRET_KEY")
if not secret_key:
    if DEMO_MODE:
        secret_key = _generate_demo_secret()
        os.environ["FLASK_SECRET_KEY"] = secret_key
        print("[demo-mode] Generated temporary FLASK_SECRET_KEY")
    else:
        raise RuntimeError("FLASK_SECRET_KEY is required when DEMO_MODE is false.")
app.config["SECRET_KEY"] = secret_key
fallback_keys = [
    key.strip()
    for key in os.environ.get("FLASK_SECRET_KEY_FALLBACKS", "").split(",")
    if key.strip()
]
if fallback_keys:
    app.config["SECRET_KEY_FALLBACKS"] = fallback_keys
app.config["SESSION_TYPE"] = os.environ.get("FLASK_SESSION_TYPE", "filesystem")
if app.config["SESSION_TYPE"] == "filesystem":
    session_dir = os.environ.get("FLASK_SESSION_DIR") or os.path.join(gettempdir(), "iam_poc_flask_session")
    os.makedirs(session_dir, exist_ok=True)
    app.config["SESSION_FILE_DIR"] = session_dir
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
session_secure_flag = os.environ.get("FLASK_SESSION_COOKIE_SECURE")
if session_secure_flag is None and DEMO_MODE:
    os.environ["FLASK_SESSION_COOKIE_SECURE"] = "true"
    session_secure_flag = "true"
app.config["SESSION_COOKIE_SECURE"] = (session_secure_flag or "true").lower() == "true"
Session(app)

# Trust X-Forwarded-* headers from the first proxy (nginx) when running behind TLS termination.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[attr-defined]

TRUSTED_PROXY_CONFIG = os.environ.get("TRUSTED_PROXY_IPS")
if not TRUSTED_PROXY_CONFIG:
    if DEMO_MODE:
        TRUSTED_PROXY_CONFIG = "127.0.0.1/32,::1/128"
        os.environ["TRUSTED_PROXY_IPS"] = TRUSTED_PROXY_CONFIG
        print("[demo-mode] Defaulted TRUSTED_PROXY_IPS to localhost ranges")
    else:
        raise RuntimeError("TRUSTED_PROXY_IPS is required when DEMO_MODE is false.")
TRUSTED_PROXY_NETWORKS = []
for entry in TRUSTED_PROXY_CONFIG.split(","):
    entry = entry.strip()
    if not entry:
        continue
    try:
        TRUSTED_PROXY_NETWORKS.append(ipaddress.ip_network(entry, strict=False))
    except ValueError:
        continue

CSRF_SESSION_KEY = "_csrf_token"

# ─────────────────────────────────────────────────────────────────────────────
# OIDC Configuration (Keycloak)
# ─────────────────────────────────────────────────────────────────────────────
ISSUER = _ensure_env(
    "KEYCLOAK_ISSUER",
    demo_default="http://localhost:8080/realms/demo",
)
SERVER_URL = os.environ.get("KEYCLOAK_SERVER_URL", ISSUER)
PUBLIC_ISSUER = os.environ.get("KEYCLOAK_PUBLIC_ISSUER", ISSUER)
END_SESSION_ENDPOINT = f"{PUBLIC_ISSUER.rstrip('/')}/protocol/openid-connect/logout"
CLIENT_ID = _ensure_env("OIDC_CLIENT_ID", demo_default="flask-app")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
REDIRECT_URI = _ensure_env(
    "OIDC_REDIRECT_URI",
    demo_default="http://localhost:5000/callback",
)
POST_LOGOUT_REDIRECT_URI = _ensure_env(
    "POST_LOGOUT_REDIRECT_URI",
    demo_default="http://localhost:5000/",
)

KEYCLOAK_REALM = _ensure_env("KEYCLOAK_REALM", demo_default="demo")
KEYCLOAK_SERVICE_REALM = os.environ.get("KEYCLOAK_SERVICE_REALM", KEYCLOAK_REALM)
KEYCLOAK_SERVICE_CLIENT_ID = _ensure_env("KEYCLOAK_SERVICE_CLIENT_ID", demo_default="automation-cli")

KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_URL", "")
if not KEYCLOAK_BASE_URL:
    if "/realms/" in SERVER_URL:
        KEYCLOAK_BASE_URL = SERVER_URL.split("/realms/")[0]
    else:
        KEYCLOAK_BASE_URL = SERVER_URL.rstrip("/")

def _default_console_url(public_issuer: str) -> str:
    issuer = public_issuer.rstrip("/")
    if "/realms/" in issuer:
        base, _, _realm = issuer.partition("/realms/")
        return f"{base.rstrip('/')}/admin/master/console/"
    return f"{issuer}/admin/master/console/"

KEYCLOAK_CONSOLE_URL = os.environ.get("KEYCLOAK_CONSOLE_URL", _default_console_url(PUBLIC_ISSUER))


def _console_root_url() -> str:
    root = os.environ.get("SECURITY_ADMIN_ROOT_URL", "").strip()
    if root:
        return root.rstrip("/")
    parsed = urlparse(KEYCLOAK_CONSOLE_URL)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    parsed = urlparse(PUBLIC_ISSUER)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return "https://localhost"

SERVICE_CLIENT_SECRET = _ensure_env(
    "KEYCLOAK_SERVICE_CLIENT_SECRET",
    demo_default=os.environ.get("KEYCLOAK_SERVICE_CLIENT_SECRET_DEMO", "demo-service-secret"),
)
ADMIN_USERNAME = _ensure_env("KEYCLOAK_ADMIN", demo_default=os.environ.get("KEYCLOAK_ADMIN_DEMO", "admin"))
ADMIN_PASSWORD = _ensure_env("KEYCLOAK_ADMIN_PASSWORD", demo_default=os.environ.get("KEYCLOAK_ADMIN_PASSWORD_DEMO", "admin"))
ALICE_PASSWORD = _ensure_env(
    "ALICE_TEMP_PASSWORD",
    demo_default=os.environ.get("ALICE_TEMP_PASSWORD_DEMO", "Passw0rd!"),
)
BOB_PASSWORD = _ensure_env(
    "BOB_TEMP_PASSWORD",
    demo_default=os.environ.get("BOB_TEMP_PASSWORD_DEMO", "Passw0rd!"),
)

REALM_ADMIN_ROLE = os.environ.get("REALM_ADMIN_ROLE", "realm-admin").strip().lower()
IAM_OPERATOR_ROLE = os.environ.get("IAM_OPERATOR_ROLE", "iam-operator").strip().lower()
REALM_ADMIN_CLIENT_ID = os.environ.get("REALM_ADMIN_CLIENT_ID", "realm-management").strip()
REALM_ADMIN_CLIENT_ROLE = os.environ.get("REALM_ADMIN_CLIENT_ROLE", REALM_ADMIN_ROLE or "realm-admin").strip().lower()
JOE_PASSWORD = _ensure_env(
    "JOE_TEMP_PASSWORD",
    demo_default=os.environ.get("JOE_TEMP_PASSWORD_DEMO", "Passw0rd!"),
    required=False,
)

DEMO_WARN_VARS = {
    "KEYCLOAK_SERVICE_CLIENT_SECRET": SERVICE_CLIENT_SECRET,
    "KEYCLOAK_ADMIN_PASSWORD": ADMIN_PASSWORD,
    "ALICE_TEMP_PASSWORD": ALICE_PASSWORD,
    "BOB_TEMP_PASSWORD": BOB_PASSWORD,
}
if JOE_PASSWORD:
    DEMO_WARN_VARS["JOE_TEMP_PASSWORD"] = JOE_PASSWORD

DEMO_USER_DIRECTORY = {
    "alice": {
        "username": "alice",
        "email": os.environ.get("ALICE_EMAIL", "alice@example.com"),
        "first": "Alice",
        "last": "Demo",
        "display_name": "Alice Demo",
        "default_role": "analyst",
        "client_roles": [],
    },
    "bob": {
        "username": "bob",
        "email": os.environ.get("BOB_EMAIL", "bob@example.com"),
        "first": "Bob",
        "last": "Demo",
        "display_name": "Bob Demo",
        "default_role": "analyst",
        "client_roles": [],
    },
    "joe": {
        "username": "joe",
        "email": os.environ.get("JOE_EMAIL", "joe@example.com"),
        "first": "Joe",
        "last": "Demo",
        "display_name": "Joe Demo",
        "default_role": IAM_OPERATOR_ROLE or "iam-operator",
        "client_roles": [REALM_ADMIN_CLIENT_ROLE or REALM_ADMIN_ROLE or "realm-admin"],
    },
}

_default_assignable_roles = ["analyst"]
if IAM_OPERATOR_ROLE and IAM_OPERATOR_ROLE not in _default_assignable_roles:
    _default_assignable_roles.append(IAM_OPERATOR_ROLE)
_default_assignable_roles = list(dict.fromkeys(filter(None, _default_assignable_roles)))

ASSIGNABLE_ROLES = [
    role.strip().lower()
    for role in os.environ.get(
        "KEYCLOAK_ASSIGNABLE_ROLES",
        ",".join(_default_assignable_roles),
    ).split(",")
    if role.strip()
]
if not ASSIGNABLE_ROLES:
    ASSIGNABLE_ROLES = list(_default_assignable_roles)

SENSITIVE_ROLES = {role for role in {REALM_ADMIN_ROLE, IAM_OPERATOR_ROLE, REALM_ADMIN_CLIENT_ROLE} if role}

MODE_LABEL = "DEMO" if DEMO_MODE else "PRODUCTION"
print(
    f"[startup] Mode={MODE_LABEL}; issuer={ISSUER}; redirect_uri={REDIRECT_URI}; trusted_proxies={TRUSTED_PROXY_CONFIG}"
)
if DEMO_MODE:
    print("[startup] WARNING: Demo credentials in use. Do not deploy with these defaults.")
    for name, value in DEMO_WARN_VARS.items():
        print(f"[startup]   {name}={value}")

oauth = OAuth(app)
oidc = oauth.register(
    name="keycloak",
    server_metadata_url=f"{SERVER_URL}/.well-known/openid-configuration",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET or None,
    client_kwargs={"scope": "openid profile email roles"},
    fetch_token=lambda: session.get("token"),
)

USERINFO_URL = f"{SERVER_URL}/protocol/openid-connect/userinfo"
TOKEN_ENDPOINT = f"{SERVER_URL}/protocol/openid-connect/token"
TOKEN_REFRESH_LEEWAY = int(os.environ.get("OIDC_TOKEN_REFRESH_LEEWAY", "60"))
SKIP_TOKEN_REFRESH_ENDPOINTS = {
    "login",
    "logout",
    "callback",
    "health_check",
    "static",
}
JWKS_CACHE = None


# ─────────────────────────────────────────────────────────────────────────────
# PKCE Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _generate_code_verifier(length: int = 64) -> str:
    alphabet = string.ascii_letters + string.digits + "-._~"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _build_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ─────────────────────────────────────────────────────────────────────────────
# JWT Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _load_jwks():
    global JWKS_CACHE
    if JWKS_CACHE is None:
        metadata = oidc.load_server_metadata()
        jwks_uri = metadata.get("jwks_uri")
        if not jwks_uri:
            raise RuntimeError("jwks_uri missing from Keycloak metadata")
        resp = requests.get(jwks_uri, timeout=5)
        resp.raise_for_status()
        JWKS_CACHE = JsonWebKey.import_key_set(resp.json())
    return JWKS_CACHE


def _decode_access_token(access_token: str) -> dict:
    if not access_token:
        return {}
    try:
        key_set = _load_jwks()
        claims = jwt.decode(
            access_token,
            key=key_set,
            claims_options={"iss": {"values": [ISSUER]}},
        )
        claims.validate()
        return dict(claims)
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Rendering Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _is_authenticated() -> bool:
    return bool(session.get("token"))

def _user_has_role(role: str) -> bool:
    if not _is_authenticated():
        return False
    _, _, _, roles = _current_user_context()
    return role in roles


def _has_operator_privileges() -> bool:
    return _user_has_role(IAM_OPERATOR_ROLE)


def _current_username() -> str:
    _, id_claims, userinfo, _ = _current_user_context()
    for source in (userinfo or {}, id_claims or {}):
        if not isinstance(source, dict):
            continue
        for key in ("preferred_username", "email", "name"):
            value = source.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def _requires_operator_for_roles(roles: list[str] | tuple[str, ...]) -> bool:
    return any(role and role.lower() in SENSITIVE_ROLES for role in roles)


def _render_page(template: str, *, status: int = 200, protect: bool = False, **context):
    context.setdefault("flash_message", None)
    context.setdefault("flash_messages", [])
    messages = get_flashed_messages(with_categories=True)
    if messages:
        context["flash_messages"] = messages
    context.setdefault("csrf_token", generate_csrf_token())
    rendered = render_template(
        template,
        is_authenticated=_is_authenticated(),
        **context,
    )
    response = make_response(rendered, status)
    if protect:
        response = _security_headers(response)
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return _render_page("index.html", title="Welcome")


@app.route("/login")
def login():
    force = request.args.get("force")
    extra = {"prompt": "login", "max_age": "0"} if force else {}
    if force:
        session.pop("token", None)
        session.pop("userinfo", None)
        session.pop("id_claims", None)
    code_verifier = _generate_code_verifier()
    session["pkce_code_verifier"] = code_verifier
    code_challenge = _build_code_challenge(code_verifier)
    return oidc.authorize_redirect(
        redirect_uri=REDIRECT_URI,
        code_challenge=code_challenge,
        code_challenge_method="S256",
        **extra,
    )


@app.route("/health")
def health_check():
    return ("ok", 200, {"Content-Type": "text/plain"})


@app.route("/callback")
def callback():
    code_verifier = session.pop("pkce_code_verifier", None)
    if not code_verifier:
        return redirect(url_for("login"))
    token = oidc.authorize_access_token(code_verifier=code_verifier)
    session["token"] = token
    try:
        session["id_claims"] = oidc.parse_id_token(token)
    except Exception:
        session["id_claims"] = {}
    try:
        session["userinfo"] = oidc.get(USERINFO_URL, token=token).json()
    except Exception:
        session["userinfo"] = {}
    return redirect(url_for("me"))


@app.route("/logout")
def logout():
    token = session.get("token") or {}
    id_token = token.get("id_token")
    session.clear()
    params = {"post_logout_redirect_uri": POST_LOGOUT_REDIRECT_URI}
    if id_token:
        params["id_token_hint"] = id_token
    else:
        params["client_id"] = CLIENT_ID
    logout_url = f"{END_SESSION_ENDPOINT}?{urlencode(params)}"
    return redirect(logout_url)


# ─────────────────────────────────────────────────────────────────────────────
# Authorization Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _collect_roles(*sources):
    roles = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        realm_access = source.get("realm_access")
        if isinstance(realm_access, dict):
            roles.extend(r for r in realm_access.get("roles", []) if r not in roles)
        resource_access = source.get("resource_access")
        if isinstance(resource_access, dict):
            for client_access in resource_access.values():
                if not isinstance(client_access, dict):
                    continue
                roles.extend(r for r in client_access.get("roles", []) if r not in roles)
    return roles


def _refresh_session_token() -> bool | None:
    token = session.get("token") or {}
    if not token:
        return None
    now = time.time()
    expires_at = token.get("expires_at")
    if expires_at is None:
        expires_in = token.get("expires_in")
        if expires_in is not None:
            try:
                expires_at = now + int(expires_in)
            except (TypeError, ValueError):
                expires_at = None
            else:
                token["expires_at"] = expires_at
                session["token"] = token
    if expires_at is None:
        return None
    if expires_at - TOKEN_REFRESH_LEEWAY > now:
        return None
    refresh_token = token.get("refresh_token")
    if not refresh_token:
        app.logger.warning("Session access token expired without refresh token; clearing session.")
        _clear_session_tokens()
        return False
    try:
        new_token = oidc.refresh_token(TOKEN_ENDPOINT, refresh_token=refresh_token)
    except Exception as exc:  # pragma: no cover - depends on Keycloak/oidc runtime behaviour
        app.logger.warning("Token refresh failed: %s", exc, exc_info=False)
        _clear_session_tokens()
        return False
    if not new_token:
        _clear_session_tokens()
        return False
    if "refresh_token" not in new_token:
        new_token["refresh_token"] = refresh_token
    expires_in = new_token.get("expires_in")
    if expires_in is not None:
        try:
            new_token["expires_at"] = time.time() + int(expires_in)
        except (TypeError, ValueError):
            new_token.pop("expires_at", None)
    elif "expires_at" not in new_token and expires_at is not None:
        new_token["expires_at"] = expires_at
    session["token"] = new_token
    try:
        session["id_claims"] = oidc.parse_id_token(new_token)
    except Exception:
        session.pop("id_claims", None)
    session.pop("userinfo", None)
    return True


def _current_user_context():
    token = session.get("token")
    if not token:
        return None, None, None, []
    userinfo = session.get("userinfo")
    if not userinfo:
        userinfo = oidc.get(USERINFO_URL, token=token).json()
        session["userinfo"] = userinfo
    id_claims = session.get("id_claims") or {}
    access_claims = _decode_access_token(token.get("access_token"))
    roles = _collect_roles(id_claims, userinfo, access_claims)
    return token, id_claims, userinfo, roles


def _get_service_token() -> str:
    try:
        return jml.get_service_account_token(
            KEYCLOAK_BASE_URL,
            KEYCLOAK_SERVICE_REALM,
            KEYCLOAK_SERVICE_CLIENT_ID,
            SERVICE_CLIENT_SECRET,
        )
    except requests.HTTPError as exc:
        detail = exc.response.text if getattr(exc, "response", None) is not None else str(exc)
        raise RuntimeError(f"Failed to obtain service account token: {detail}") from exc
    except Exception as exc:  # pragma: no cover - unexpected runtime issues
        raise RuntimeError(f"Failed to obtain service account token: {exc}") from exc


def _user_roles(kc_token: str, user_id: str) -> list[str]:
    resp = requests.get(
        f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/realm",
        headers=jml._auth_headers(kc_token),
        timeout=jml.REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return sorted({role.get("name") for role in resp.json() or [] if role.get("name")})


setattr(app, "_get_service_token", _get_service_token)
setattr(app, "_user_roles", _user_roles)

def _demo_status_stub() -> list[dict]:
    stub_statuses: list[dict] = []
    for info in DEMO_USER_DIRECTORY.values():
        default_role = info.get("default_role", "analyst")
        client_roles = [role for role in info.get("client_roles", []) if role]
        all_roles = [role for role in [default_role] if role] + client_roles
        stub_statuses.append(
            {
                "id": info["username"],
                "username": info["username"],
                "display_name": info["display_name"],
                "email": info["email"],
                "exists": True,
                "enabled": info["username"] != "bob",
                "roles": list(dict.fromkeys(all_roles)),
                "required_actions": [],
                "totp_enrolled": info["username"] == "alice",
            }
        )
    return stub_statuses


def _fetch_user_statuses(kc_token: str) -> list[dict]:
    client_uuid = ""
    client_role_name = REALM_ADMIN_CLIENT_ROLE or REALM_ADMIN_ROLE
    if REALM_ADMIN_CLIENT_ID and client_role_name:
        try:
            client = jml._get_client(KEYCLOAK_BASE_URL, kc_token, KEYCLOAK_REALM, REALM_ADMIN_CLIENT_ID)
            client_uuid = client.get("id") if client else ""
        except requests.HTTPError as exc:
            detail = exc.response.text if getattr(exc, "response", None) is not None else str(exc)
            raise RuntimeError(f"Failed to resolve client '{REALM_ADMIN_CLIENT_ID}': {detail}") from exc
    resp = requests.get(
        f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users",
        params={"max": int(os.environ.get("KEYCLOAK_ADMIN_USER_LIMIT", "50"))},
        headers=jml._auth_headers(kc_token),
        timeout=jml.REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    users = resp.json() or []
    statuses: list[dict] = []
    for user in users:
        user_id = user.get("id")
        if not user_id:
            continue
        display_name = " ".join(
            part for part in [user.get("firstName", ""), user.get("lastName", "")] if part
        ).strip() or user.get("username", "")
        status = {
            "id": user_id,
            "username": user.get("username", ""),
            "display_name": display_name,
            "email": user.get("email") or "",
            "exists": True,
            "enabled": user.get("enabled", False),
            "roles": [],
            "required_actions": user.get("requiredActions") or [],
            "totp_enrolled": False,
        }
        try:
            status["roles"] = _user_roles(kc_token, user_id)
            status["totp_enrolled"] = jml._user_has_totp(
                KEYCLOAK_BASE_URL, kc_token, KEYCLOAK_REALM, user_id
            )
            if client_uuid and client_role_name:
                client_roles_resp = requests.get(
                    f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/clients/{client_uuid}",
                    headers=jml._auth_headers(kc_token),
                    timeout=jml.REQUEST_TIMEOUT,
                )
                client_roles_resp.raise_for_status()
                if any(role.get("name") == client_role_name for role in client_roles_resp.json() or []):
                    if client_role_name not in status["roles"]:
                        status["roles"].append(client_role_name)
        except requests.HTTPError as exc:
            detail = exc.response.text if getattr(exc, "response", None) is not None else str(exc)
            raise RuntimeError(f"Failed to load details for user '{status['username']}': {detail}") from exc
        statuses.append(status)
    statuses.sort(key=lambda item: (item["display_name"] or item["username"]).lower())
    return statuses


def _fetch_assignable_roles(kc_token: str) -> list[str]:
    resp = requests.get(
        f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/roles",
        headers=jml._auth_headers(kc_token),
        timeout=jml.REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    available = [role.get("name") for role in resp.json() or [] if role.get("name")]
    if not available:
        return ASSIGNABLE_ROLES
    filtered = [role for role in available if role.lower() in ASSIGNABLE_ROLES]
    return sorted(filtered or available, key=str.lower)


def _load_admin_context() -> tuple[list[dict], list[str]]:
    if app.config.get("TESTING"):
        return _demo_status_stub(), ASSIGNABLE_ROLES
    token = _get_service_token()
    statuses = _fetch_user_statuses(token)
    roles = _fetch_assignable_roles(token)
    return statuses, roles


def _normalize_username(raw: str) -> str:
    return "".join(char for char in raw.lower().strip() if char.isalnum() or char in {".", "-", "_"})


def _role_is_assignable(role: str) -> bool:
    return role.lower() in ASSIGNABLE_ROLES


def _generate_temp_password(length: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _clear_session_tokens() -> None:
    session.pop("token", None)
    session.pop("userinfo", None)
    session.pop("id_claims", None)


def generate_csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def _is_trusted_proxy(ip_value: str | None) -> bool:
    if not ip_value:
        return False
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return any(address in network for network in TRUSTED_PROXY_NETWORKS)


def _security_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    return response


def require_any_role(*required_roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not _is_authenticated():
                return redirect(url_for("login"))
            _, _, _, roles = _current_user_context()
            if not any(role in roles for role in required_roles):
                return _render_page(
                    "403.html",
                    title="Forbidden",
                    status=403,
                    protect=_is_authenticated(),
                    required_role=required_roles[0] if len(required_roles) == 1 else ", ".join(required_roles),
                )
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def require_role(required_role):
    return require_any_role(required_role)


# ─────────────────────────────────────────────────────────────────────────────
# CSRF & Proxy Guards
# ─────────────────────────────────────────────────────────────────────────────
@app.before_request
def _enforce_proxy_headers() -> None:
    original_remote = request.environ.get("werkzeug.proxy_fix.orig_remote_addr")
    if original_remote and not _is_trusted_proxy(original_remote):
        abort(400, description="Untrusted proxy")

    forwarded_proto = request.headers.get("X-Forwarded-Proto")
    if forwarded_proto and forwarded_proto != "https":
        abort(400, description="Invalid forwarded protocol")

    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for and "," in forwarded_for:
        abort(400, description="Multiple forwarded clients not permitted")

    g.csrf_token = generate_csrf_token()


@app.before_request
def _enforce_csrf() -> None:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    submitted_token = (
        request.form.get("csrf_token")
        if not request.is_json
        else request.headers.get("X-CSRF-Token", "")
    )
    if not submitted_token:
        submitted_token = request.headers.get("X-CSRF-Token", "")
    session_token = session.get(CSRF_SESSION_KEY, "")
    if not session_token or not submitted_token or not hmac.compare_digest(session_token, submitted_token):
        abort(400, description="CSRF validation failed")


@app.before_request
def _ensure_fresh_token():
    if not _is_authenticated():
        return
    endpoint = (request.endpoint or "").rsplit(".", 1)[-1]
    if endpoint in SKIP_TOKEN_REFRESH_ENDPOINTS:
        return
    if request.path.startswith("/static/"):
        return
    outcome = _refresh_session_token()
    if outcome is False and not _is_authenticated():
        return redirect(url_for("login", force=1))


@app.context_processor
def inject_global_context():
    token = g.get("csrf_token") or generate_csrf_token()
    is_admin_user = _user_has_role(REALM_ADMIN_ROLE)
    console_url = None
    if _is_authenticated():
        if _user_has_role(REALM_ADMIN_ROLE):
            console_root = _console_root_url()
            console_url = f"{console_root}/admin/{KEYCLOAK_REALM}/console/"
    else:
        console_url = KEYCLOAK_CONSOLE_URL or _default_console_url(PUBLIC_ISSUER)
    return {
        "csrf_token": token,
        "is_admin_user": is_admin_user,
        "keycloak_console_url": console_url,
        "realm_admin_role": REALM_ADMIN_ROLE,
        "iam_operator_role": IAM_OPERATOR_ROLE,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Protected Routes
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/me")
def me():
    if not _is_authenticated():
        return redirect(url_for("login"))
    _, _, userinfo, roles = _current_user_context()
    visible_roles = {"analyst"}
    for candidate in (REALM_ADMIN_ROLE, REALM_ADMIN_CLIENT_ROLE, IAM_OPERATOR_ROLE):
        if candidate:
            visible_roles.add(candidate)
    filtered_roles = [role for role in roles if role in visible_roles]
    userinfo_json = json.dumps(userinfo or {}, indent=2, ensure_ascii=False)
    return _render_page(
        "me.html",
        title="Profile",
        protect=True,
        roles=filtered_roles,
        userinfo_json=userinfo_json,
    )


@app.route("/admin")
@require_any_role(REALM_ADMIN_ROLE, IAM_OPERATOR_ROLE)
def admin():
    try:
        user_statuses, assignable_roles = _load_admin_context()
    except Exception as exc:
        flash(f"Unable to load Keycloak state: {exc}", "error")
        user_statuses = _demo_status_stub()
        assignable_roles = ASSIGNABLE_ROLES
    existing_users = [user for user in user_statuses if user["exists"]]
    return _render_page(
        "admin.html",
        title="Admin",
        protect=True,
        user_statuses=user_statuses,
        assignable_roles=assignable_roles,
        existing_users=existing_users,
    )


@app.post("/admin/joiner")
@require_any_role(REALM_ADMIN_ROLE, IAM_OPERATOR_ROLE)
def admin_joiner():
    username = _normalize_username(request.form.get("username", ""))
    first = request.form.get("first_name", "").strip()
    last = request.form.get("last_name", "").strip()
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "").strip()
    temp_password = request.form.get("temp_password", "").strip()
    require_totp = request.form.get("require_totp") == "on"

    if not all([username, first, last, email, role]):
        flash("All fields are required to provision a user.", "error")
        return redirect(url_for("admin"))
    if not _role_is_assignable(role):
        flash(f"Role '{role}' is not assignable.", "error")
        return redirect(url_for("admin"))
    if _requires_operator_for_roles([role]) and not _user_has_role(REALM_ADMIN_ROLE):
        flash("Realm-admin privileges are required to assign realm-admin-level roles.", "error")
        return redirect(url_for("admin"))
    if not temp_password:
        temp_password = _generate_temp_password()

    try:
        token = _get_service_token()
        jml.create_user(
            KEYCLOAK_BASE_URL,
            token,
            KEYCLOAK_REALM,
            username,
            email,
            first,
            last,
            temp_password,
            role,
            require_totp=require_totp,
            require_password_update=True,
        )
    except Exception as exc:
        flash(f"Failed to provision user '{username}': {exc}", "error")
    else:
        flash(f"User '{username}' provisioned. Temporary password: {temp_password}", "success")
    return redirect(url_for("admin"))


@app.post("/admin/mover")
@require_any_role(REALM_ADMIN_ROLE, IAM_OPERATOR_ROLE)
def admin_mover():
    username = request.form.get("username", "").strip()
    source_role = request.form.get("source_role", "").strip()
    target_role = request.form.get("target_role", "").strip()

    if not username or not source_role or not target_role:
        flash("User, current role, and new role are required.", "error")
        return redirect(url_for("admin"))
    if source_role == target_role:
        flash("Choose a different target role to perform a mover operation.", "error")
        return redirect(url_for("admin"))
    if not (_role_is_assignable(source_role) and _role_is_assignable(target_role)):
        flash("One of the selected roles is not managed by this console.", "error")
        return redirect(url_for("admin"))

    current_username = _current_username().lower()
    if current_username and username.lower() == current_username:
        flash("You cannot change your own role from this console.", "error")
        return redirect(url_for("admin"))

    try:
        token = _get_service_token()
        target_user = jml.get_user_by_username(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
    except Exception as exc:
        flash(f"Failed to update roles for '{username}': {exc}", "error")
        return redirect(url_for("admin"))

    if not target_user:
        flash(f"User '{username}' not found in realm '{KEYCLOAK_REALM}'.", "error")
        return redirect(url_for("admin"))

    try:
        target_roles = _user_roles(token, target_user["id"])
    except Exception as exc:
        flash(f"Unable to read roles for '{username}': {exc}", "error")
        return redirect(url_for("admin"))

    if (_requires_operator_for_roles(target_roles) or _requires_operator_for_roles([source_role, target_role])) and not _user_has_role(REALM_ADMIN_ROLE):
        flash("Realm-admin privileges are required to modify realm-admin-level access.", "error")
        return redirect(url_for("admin"))

    try:
        jml.change_role(
            KEYCLOAK_BASE_URL,
            token,
            KEYCLOAK_REALM,
            username,
            source_role,
            target_role,
        )
    except Exception as exc:
        flash(f"Failed to update roles for '{username}': {exc}", "error")
    else:
        flash(f"User '{username}' moved from {source_role} to {target_role}.", "success")
    return redirect(url_for("admin"))


@app.post("/admin/leaver")
@require_any_role(REALM_ADMIN_ROLE, IAM_OPERATOR_ROLE)
def admin_leaver():
    username = request.form.get("username", "").strip()
    if not username:
        flash("Select a user to disable.", "error")
        return redirect(url_for("admin"))

    current_username = _current_username().lower()
    if current_username and username.lower() == current_username:
        flash("You cannot disable your own account from this console.", "error")
        return redirect(url_for("admin"))

    try:
        token = _get_service_token()
        target_user = jml.get_user_by_username(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, username)
    except Exception as exc:
        flash(f"Failed to disable '{username}': {exc}", "error")
        return redirect(url_for("admin"))

    if not target_user:
        flash(f"User '{username}' not found in realm '{KEYCLOAK_REALM}'.", "error")
        return redirect(url_for("admin"))

    try:
        target_roles = _user_roles(token, target_user["id"])
    except Exception as exc:
        flash(f"Unable to read roles for '{username}': {exc}", "error")
        return redirect(url_for("admin"))

    if _requires_operator_for_roles(target_roles) and not _user_has_role(REALM_ADMIN_ROLE):
        flash("Realm-admin privileges are required to disable realm-admin-level accounts.", "error")
        return redirect(url_for("admin"))

    try:
        jml.disable_user(
            KEYCLOAK_BASE_URL,
            token,
            KEYCLOAK_REALM,
            username,
        )
    except Exception as exc:
        flash(f"Failed to disable '{username}': {exc}", "error")
    else:
        flash(f"User '{username}' disabled successfully.", "success")
    return redirect(url_for("admin"))


# ─────────────────────────────────────────────────────────────────────────────
# Application Entry Point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
