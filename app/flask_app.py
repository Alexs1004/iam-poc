import base64
import hashlib
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
from flask import Flask, redirect, url_for, session, render_template, request, make_response
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix

# ─────────────────────────────────────────────────────────────────────────────
# Flask Application & Session Configuration
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "change-me")
app.config["SESSION_TYPE"] = os.environ.get("FLASK_SESSION_TYPE", "filesystem")
if app.config["SESSION_TYPE"] == "filesystem":
    session_dir = os.environ.get("FLASK_SESSION_DIR") or os.path.join(gettempdir(), "iam_poc_flask_session")
    os.makedirs(session_dir, exist_ok=True)
    app.config["SESSION_FILE_DIR"] = session_dir
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_SESSION_COOKIE_SECURE", "false").lower() == "true"
Session(app)

# Trust X-Forwarded-* headers from the first proxy (nginx) when running behind TLS termination.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[attr-defined]

# ─────────────────────────────────────────────────────────────────────────────
# OIDC Configuration (Keycloak)
# ─────────────────────────────────────────────────────────────────────────────
ISSUER = os.environ.get("KEYCLOAK_ISSUER", "http://localhost:8080/realms/demo")
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "flask-app")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:5000/callback")
POST_LOGOUT_REDIRECT_URI = os.environ.get("POST_LOGOUT_REDIRECT_URI", "http://localhost:5000/")

oauth = OAuth(app)
oidc = oauth.register(
    name="keycloak",
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET or None,
    client_kwargs={"scope": "openid profile email roles"},
    fetch_token=lambda: session.get("token"),
)

USERINFO_URL = f"{ISSUER}/protocol/openid-connect/userinfo"
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
    extra = {"prompt": "login"} if force else {}
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
    logout_url = f"{ISSUER}/protocol/openid-connect/logout?{urlencode(params)}"
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
