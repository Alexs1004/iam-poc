import base64
import hashlib
import os
import secrets
import string
from functools import wraps
from tempfile import gettempdir
from urllib.parse import urlencode

import requests
from authlib.integrations.flask_client import OAuth
from authlib.jose import JsonWebKey, jwt
from flask import Flask, redirect, url_for, session, render_template_string, request, make_response
from flask_session import Session

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

ISSUER = os.environ.get("KEYCLOAK_ISSUER", "http://localhost:8081/realms/demo")
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "flask-app")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:5000/callback")
POST_LOGOUT_REDIRECT_URI = os.environ.get("POST_LOGOUT_REDIRECT_URI", "http://localhost:5000/")

oauth = OAuth(app)
oidc = oauth.register(
    name="keycloak",
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET or None,  # public client
    client_kwargs={"scope": "openid profile email roles"},
    fetch_token=lambda: session.get("token"),
)
USERINFO_URL = f"{ISSUER}/protocol/openid-connect/userinfo"
JWKS_CACHE = None


def _generate_code_verifier(length: int = 64) -> str:
    alphabet = string.ascii_letters + string.digits + "-._~"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _build_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _load_jwks():
    """Fetch and cache Keycloak's JWKS so we can verify JWTs locally."""
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
    """Decode the access token to extract realm roles without logging secrets."""
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


TEMPLATE = """
<!doctype html>
<title>IAM Demo</title>
<h1>Mini IAM Demo</h1>
<ul>
  {% if token %}
    <li><a href="{{ url_for('me') }}">/me</a></li>
    <li><a href="{{ url_for('admin') }}">/admin</a></li>
    <li><a href="{{ url_for('logout') }}">Logout (global)</a></li>
    <li><a href="{{ url_for('login', force=1) }}">Login as different user</a></li>
  {% else %}
    <li><a href="{{ url_for('login') }}">Login with Keycloak</a></li>
  {% endif %}
</ul>
{% if msg %}<pre>{{ msg }}</pre>{% endif %}
"""

@app.route("/")
def index():
    return render_template_string(TEMPLATE, token=session.get("token"), msg="")

# Login normal (SSO si session Keycloak encore active)
@app.route("/login")
def login():
    force = request.args.get("force")
    extra = {}
    if force:                     # permet de re-demander les identifiants
        extra["prompt"] = "login" # OIDC: force re-auth
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

# Logout global (Keycloak + app)
@app.route("/logout")
def logout():
    token = session.get("token") or {}
    id_token = token.get("id_token")  # fourni par Authlib après /callback
    session.clear()

    params = {
        # OIDC RP-Initiated Logout
        "post_logout_redirect_uri": os.environ.get("POST_LOGOUT_REDIRECT_URI", "http://localhost:5000/"),
    }
    if id_token:
        params["id_token_hint"] = id_token
    else:
        # fallback si pas d'id_token en session
        params["client_id"] = os.environ.get("OIDC_CLIENT_ID", "flask-app")

    logout_url = f"{ISSUER}/protocol/openid-connect/logout?{urlencode(params)}"
    return redirect(logout_url)

def _collect_roles(*sources):
    roles = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        realm_access = source.get("realm_access")
        if isinstance(realm_access, dict):
            for role in realm_access.get("roles", []):
                if role not in roles:
                    roles.append(role)
        resource_access = source.get("resource_access")
        if isinstance(resource_access, dict):
            for client_access in resource_access.values():
                if not isinstance(client_access, dict):
                    continue
                for role in client_access.get("roles", []):
                    if role not in roles:
                        roles.append(role)
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
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    return response


def require_role(required_role):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = session.get("token")
            if not token:
                return redirect(url_for("login"))
            token, id_claims, userinfo, roles = _current_user_context()
            if required_role not in roles:
                body = render_template_string(
                    TEMPLATE,
                    token=token,
                    msg=f"403 Forbidden: {required_role} role required",
                )
                response = make_response(body, 403)
                return _security_headers(response)
            return fn(*args, **kwargs)

        return wrapper

    return decorator

@app.route("/me")
def me():
    token = session.get("token")
    if not token:
        return redirect(url_for("login"))
    token, id_claims, userinfo, roles = _current_user_context()
    return render_template_string(
        TEMPLATE + "<h2>Userinfo</h2><pre>{{ ui|tojson(indent=2) }}</pre>"
                   "<h2>Roles</h2><pre>{{ roles|tojson(indent=2) }}</pre>",
        token=token, msg="", ui=userinfo, roles = [role for role in roles if role in {"admin", "analyst"}]

    )

@app.route("/admin")
@require_role("admin")
def admin():
    token, _, _, _ = _current_user_context()
    response = make_response(render_template_string(TEMPLATE, token=token, msg="Welcome admin!"))
    return _security_headers(response)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
