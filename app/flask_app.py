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

# ─────────────────────────────────────────────────────────────────────────────
# Flask Application & Session Configuration
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Secret key for signing session cookies; must be strong in production
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "change-me")

# Use server-side sessions (filesystem) to avoid storing tokens in client cookies
app.config["SESSION_TYPE"] = os.environ.get("FLASK_SESSION_TYPE", "filesystem")
if app.config["SESSION_TYPE"] == "filesystem":
    session_dir = os.environ.get("FLASK_SESSION_DIR") or os.path.join(gettempdir(), "iam_poc_flask_session")
    os.makedirs(session_dir, exist_ok=True)
    app.config["SESSION_FILE_DIR"] = session_dir

# Security: prevent JavaScript access to cookies, mitigate CSRF, enforce HTTPS in production
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_SESSION_COOKIE_SECURE", "false").lower() == "true"

Session(app)

# ─────────────────────────────────────────────────────────────────────────────
# OIDC Configuration (Keycloak)
# ─────────────────────────────────────────────────────────────────────────────
ISSUER = os.environ.get("KEYCLOAK_ISSUER", "http://localhost:8081/realms/demo")
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "flask-app")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")  # Empty for public client
REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:5000/callback")
POST_LOGOUT_REDIRECT_URI = os.environ.get("POST_LOGOUT_REDIRECT_URI", "http://localhost:5000/")

# Register Authlib OAuth client for Keycloak OIDC integration
oauth = OAuth(app)
oidc = oauth.register(
    name="keycloak",
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",  # Auto-discover OIDC endpoints
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET or None,  # None indicates a public client
    client_kwargs={"scope": "openid profile email roles"},  # Requested scopes
    fetch_token=lambda: session.get("token"),  # Retrieve token from server-side session
)

USERINFO_URL = f"{ISSUER}/protocol/openid-connect/userinfo"
JWKS_CACHE = None  # Cache for JSON Web Key Set to verify JWT signatures

# ─────────────────────────────────────────────────────────────────────────────
# PKCE Helper Functions (RFC 7636)
# ─────────────────────────────────────────────────────────────────────────────
def _generate_code_verifier(length: int = 64) -> str:
    """
    Generate a cryptographically random code verifier for PKCE.
    Must be 43-128 characters from [A-Za-z0-9-._~].
    """
    alphabet = string.ascii_letters + string.digits + "-._~"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _build_code_challenge(code_verifier: str) -> str:
    """
    Create SHA256 hash of code_verifier, then base64url-encode it.
    This is sent to the authorization endpoint; the verifier is sent to the token endpoint.
    """
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ─────────────────────────────────────────────────────────────────────────────
# JWT Verification (Access Token)
# ─────────────────────────────────────────────────────────────────────────────
def _load_jwks():
    """
    Fetch and cache Keycloak's JSON Web Key Set (JWKS) to verify JWT signatures locally.
    Prevents the need to call Keycloak for every token validation.
    """
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
    """
    Decode and validate the access token (JWT) to extract claims (e.g., realm roles).
    Returns empty dict on failure; never logs the token itself for security.
    """
    if not access_token:
        return {}
    try:
        key_set = _load_jwks()
        claims = jwt.decode(
            access_token,
            key=key_set,
            claims_options={"iss": {"values": [ISSUER]}},  # Verify issuer matches Keycloak
        )
        claims.validate()  # Check exp, nbf, etc.
        return dict(claims)
    except Exception:
        # Silently fail; do not log token or exception details to avoid leaking secrets
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# HTML Template (simple inline for demo purposes)
# ─────────────────────────────────────────────────────────────────────────────
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

# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    """Home page; displays login or navigation links depending on session state."""
    return render_template_string(TEMPLATE, token=session.get("token"), msg="")


@app.route("/login")
def login():
    """
    Initiate OIDC Authorization Code flow with PKCE.
    - Generates a random code_verifier and stores it in the session.
    - Computes the code_challenge (SHA256 hash) and sends it to Keycloak.
    - If 'force=1' query param is present, adds 'prompt=login' to force re-authentication.
    """
    force = request.args.get("force")
    extra = {}
    if force:
        # OIDC prompt parameter: forces user to re-enter credentials even if SSO session exists
        extra["prompt"] = "login"
    
    # Generate PKCE parameters
    code_verifier = _generate_code_verifier()
    session["pkce_code_verifier"] = code_verifier  # Store verifier for later use in /callback
    code_challenge = _build_code_challenge(code_verifier)
    
    # Redirect user to Keycloak authorization endpoint
    return oidc.authorize_redirect(
        redirect_uri=REDIRECT_URI,
        code_challenge=code_challenge,
        code_challenge_method="S256",  # SHA256 method (recommended)
        **extra,
    )


@app.route("/callback")
def callback():
    """
    OIDC callback endpoint: exchange authorization code for tokens.
    - Retrieves the code_verifier from the session.
    - Sends it to Keycloak's token endpoint along with the authorization code.
    - Stores tokens, ID token claims, and userinfo in the server-side session.
    """
    code_verifier = session.pop("pkce_code_verifier", None)
    if not code_verifier:
        # Missing verifier; likely CSRF or session expired. Restart login flow.
        return redirect(url_for("login"))
    
    # Exchange authorization code for tokens (access_token, id_token, refresh_token)
    token = oidc.authorize_access_token(code_verifier=code_verifier)
    session["token"] = token
    
    # Parse and store ID token claims (sub, email, preferred_username, etc.)
    try:
        session["id_claims"] = oidc.parse_id_token(token)
    except Exception:
        session["id_claims"] = {}
    
    # Fetch additional user attributes from userinfo endpoint
    try:
        session["userinfo"] = oidc.get(USERINFO_URL, token=token).json()
    except Exception:
        session["userinfo"] = {}
    
    return redirect(url_for("me"))


@app.route("/logout")
def logout():
    """
    Global logout: clear Flask session and redirect to Keycloak's logout endpoint (RP-Initiated Logout).
    - Includes 'id_token_hint' to identify the user's session at Keycloak.
    - After logout, Keycloak redirects back to POST_LOGOUT_REDIRECT_URI.
    """
    token = session.get("token") or {}
    id_token = token.get("id_token")  # Provided by Authlib after /callback
    session.clear()  # Clear server-side session data

    # Build OIDC logout URL (RP-Initiated Logout spec)
    params = {
        "post_logout_redirect_uri": POST_LOGOUT_REDIRECT_URI,
    }
    if id_token:
        params["id_token_hint"] = id_token  # Preferred method to identify user session
    else:
        # Fallback if id_token is missing (less reliable)
        params["client_id"] = CLIENT_ID

    logout_url = f"{ISSUER}/protocol/openid-connect/logout?{urlencode(params)}"
    return redirect(logout_url)


# ─────────────────────────────────────────────────────────────────────────────
# Authorization Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _collect_roles(*sources):
    """
    Aggregate roles from multiple sources (ID token, userinfo, access token).
    - Checks 'realm_access.roles' for realm-level roles.
    - Checks 'resource_access.<client>.roles' for client-specific roles.
    Returns a deduplicated list of roles.
    """
    roles = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        
        # Realm-level roles
        realm_access = source.get("realm_access")
        if isinstance(realm_access, dict):
            for role in realm_access.get("roles", []):
                if role not in roles:
                    roles.append(role)
        
        # Client-level roles
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
    """
    Build the current user context from session data.
    Returns: (token, id_claims, userinfo, roles)
    - Fetches userinfo if missing.
    - Decodes access token to extract additional roles.
    """
    token = session.get("token")
    if not token:
        return None, None, None, []
    
    # Retrieve or fetch userinfo
    userinfo = session.get("userinfo")
    if not userinfo:
        userinfo = oidc.get(USERINFO_URL, token=token).json()
        session["userinfo"] = userinfo
    
    id_claims = session.get("id_claims") or {}
    access_claims = _decode_access_token(token.get("access_token"))
    
    # Aggregate roles from all sources
    roles = _collect_roles(id_claims, userinfo, access_claims)
    return token, id_claims, userinfo, roles


def _security_headers(response):
    """
    Apply security headers to HTTP responses (Defense in Depth).
    - Cache-Control: no-store → Prevent caching of sensitive data.
    - X-Content-Type-Options: nosniff → Prevent MIME sniffing attacks.
    - X-Frame-Options: DENY → Prevent clickjacking.
    """
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    return response


def require_role(required_role):
    """
    Decorator to enforce role-based access control (RBAC) on routes.
    - Checks if the user is authenticated (has a token).
    - Verifies that the user has the specified role.
    - Returns 403 Forbidden if the role is missing.
    - Applies security headers to the response.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = session.get("token")
            if not token:
                # User not authenticated; redirect to login
                return redirect(url_for("login"))
            
            # Retrieve user roles
            token, id_claims, userinfo, roles = _current_user_context()
            if required_role not in roles:
                # User lacks the required role; return 403
                body = render_template_string(
                    TEMPLATE,
                    token=token,
                    msg=f"403 Forbidden: {required_role} role required",
                )
                response = make_response(body, 403)
                return _security_headers(response)
            
            # Role check passed; proceed to the route handler
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# Protected Routes
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/me")
def me():
    """
    Display current user information and roles (for authenticated users).
    - Shows userinfo claims from Keycloak.
    - Filters roles to display only relevant ones (admin, analyst).
    """
    token = session.get("token")
    if not token:
        return redirect(url_for("login"))
    
    token, id_claims, userinfo, roles = _current_user_context()
    
    # Filter to show only business-relevant roles (optional)
    filtered_roles = [role for role in roles if role in {"admin", "analyst"}]
    
    return render_template_string(
        TEMPLATE + "<h2>Userinfo</h2><pre>{{ ui|tojson(indent=2) }}</pre>"
                   "<h2>Roles</h2><pre>{{ roles|tojson(indent=2) }}</pre>",
        token=token,
        msg="",
        ui=userinfo,
        roles=filtered_roles
    )


@app.route("/admin")
@require_role("admin")
def admin():
    """
    Admin-only route; protected by RBAC decorator.
    - Only users with the 'admin' role can access this page.
    - Applies security headers to the response.
    """
    token, _, _, _ = _current_user_context()
    response = make_response(render_template_string(TEMPLATE, token=token, msg="Welcome admin!"))
    return _security_headers(response)


# ─────────────────────────────────────────────────────────────────────────────
# Application Entry Point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Run Flask development server (NOT for production use)
    app.run(host="0.0.0.0", port=5000, debug=True)
