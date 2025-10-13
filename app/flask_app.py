import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import string
from functools import wraps
from tempfile import gettempdir
from urllib.parse import urlencode

import requests
from authlib.integrations.flask_client import OAuth
from authlib.jose import JsonWebKey, jwt
from flask import (
    Flask,
    abort,
    g,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    from azure.identity import DefaultAzureCredential  # type: ignore
    from azure.keyvault.secrets import SecretClient  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    DefaultAzureCredential = None
    SecretClient = None

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
    client = SecretClient(vault_url=vault_uri, credential=credential)
    mapping = {
        "FLASK_SECRET_KEY": os.environ.get("AZURE_SECRET_FLASK_SECRET_KEY", "flask-secret-key"),
        "FLASK_SECRET_KEY_FALLBACKS": os.environ.get("AZURE_SECRET_FLASK_SECRET_KEY_FALLBACKS", ""),
        "KEYCLOAK_SERVICE_CLIENT_SECRET": os.environ.get(
            "AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET", "keycloak-service-client-secret"
        ),
        "KEYCLOAK_ADMIN_PASSWORD": os.environ.get("AZURE_SECRET_KEYCLOAK_ADMIN_PASSWORD", "keycloak-admin-password"),
        "ALICE_TEMP_PASSWORD": os.environ.get("AZURE_SECRET_ALICE_TEMP_PASSWORD", "alice-temp-password"),
        "BOB_TEMP_PASSWORD": os.environ.get("AZURE_SECRET_BOB_TEMP_PASSWORD", "bob-temp-password"),
    }
    for env_name, secret_name in mapping.items():
        if os.environ.get(env_name):
            continue
        secret_name = secret_name.strip()
        if not secret_name:
            continue
        try:
            secret = client.get_secret(secret_name)
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

DEMO_WARN_VARS = {
    "KEYCLOAK_SERVICE_CLIENT_SECRET": SERVICE_CLIENT_SECRET,
    "KEYCLOAK_ADMIN_PASSWORD": ADMIN_PASSWORD,
    "ALICE_TEMP_PASSWORD": ALICE_PASSWORD,
    "BOB_TEMP_PASSWORD": BOB_PASSWORD,
}

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


def _render_page(template: str, *, status: int = 200, protect: bool = False, **context):
    context.setdefault("flash_message", None)
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


def require_role(required_role):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not _is_authenticated():
                return redirect(url_for("login"))
            _, _, _, roles = _current_user_context()
            if required_role not in roles:
                return _render_page(
                    "403.html",
                    title="Forbidden",
                    status=403,
                    protect=_is_authenticated(),
                    required_role=required_role,
                )
            return fn(*args, **kwargs)

        return wrapper

    return decorator


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


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": g.get("csrf_token") or generate_csrf_token()}


# ─────────────────────────────────────────────────────────────────────────────
# Protected Routes
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/me")
def me():
    if not _is_authenticated():
        return redirect(url_for("login"))
    _, _, userinfo, roles = _current_user_context()
    filtered_roles = [role for role in roles if role in {"admin", "analyst"}]
    userinfo_json = json.dumps(userinfo or {}, indent=2, ensure_ascii=False)
    return _render_page(
        "me.html",
        title="Profile",
        protect=True,
        roles=filtered_roles,
        userinfo_json=userinfo_json,
    )


@app.route("/admin")
@require_role("admin")
def admin():
    return _render_page("admin.html", title="Admin", protect=True)


# ─────────────────────────────────────────────────────────────────────────────
# Application Entry Point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
