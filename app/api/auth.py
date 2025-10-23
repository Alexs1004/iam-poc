"""Authentication routes and OIDC helpers."""
from __future__ import annotations
import hashlib
import base64
import secrets
import string
from urllib.parse import urlencode

from flask import Blueprint, session, redirect, url_for, request, current_app
from authlib.integrations.flask_client import OAuth

bp = Blueprint("auth", __name__)

# Module-level OAuth instance (will be initialized by create_app)
oauth: OAuth = None
oidc = None


def init_oauth(app, cfg):
    """Initialize OAuth client with app configuration."""
    global oauth, oidc
    
    oauth = OAuth(app)
    oidc = oauth.register(
        name="keycloak",
        server_metadata_url=f"{cfg.keycloak_server_url}/.well-known/openid-configuration",
        client_id=cfg.oidc_client_id,
        client_secret=cfg.oidc_client_secret or None,
        client_kwargs={"scope": "openid profile email roles"},
        fetch_token=lambda: session.get("token"),
    )
    
    return oauth, oidc


def get_oidc_client():
    """Get the OIDC client instance."""
    if oidc is None:
        raise RuntimeError("OIDC client not initialized. Call init_oauth first.")
    return oidc


# ─────────────────────────────────────────────────────────────────────────────
# PKCE Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _generate_code_verifier(length: int = 64) -> str:
    """Generate PKCE code verifier."""
    alphabet = string.ascii_letters + string.digits + "-._~"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _build_code_challenge(code_verifier: str) -> str:
    """Build PKCE code challenge from verifier."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────
@bp.route("/login")
def login():
    """Initiate OIDC login flow with PKCE."""
    cfg = current_app.config["APP_CONFIG"]
    client = get_oidc_client()
    
    force = request.args.get("force")
    extra = {"prompt": "login", "max_age": "0"} if force else {}
    if force:
        session.pop("token", None)
        session.pop("userinfo", None)
        session.pop("id_claims", None)
    
    code_verifier = _generate_code_verifier()
    session["pkce_code_verifier"] = code_verifier
    code_challenge = _build_code_challenge(code_verifier)
    
    return client.authorize_redirect(
        redirect_uri=cfg.oidc_redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method="S256",
        **extra,
    )


@bp.route("/callback")
def callback():
    """Handle OIDC callback after successful authentication."""
    cfg = current_app.config["APP_CONFIG"]
    client = get_oidc_client()
    
    code_verifier = session.pop("pkce_code_verifier", None)
    if not code_verifier:
        return redirect(url_for("auth.login"))
    
    token = client.authorize_access_token(code_verifier=code_verifier)
    session["token"] = token
    
    try:
        session["id_claims"] = client.parse_id_token(token)
    except Exception:
        session["id_claims"] = {}
    
    try:
        userinfo_url = f"{cfg.keycloak_server_url}/protocol/openid-connect/userinfo"
        session["userinfo"] = client.get(userinfo_url, token=token).json()
    except Exception:
        session["userinfo"] = {}
    
    # Smart redirect based on user role
    from app.core.rbac import collect_roles, has_admin_role
    
    id_claims = session.get("id_claims") or {}
    userinfo = session.get("userinfo") or {}
    access_token = token.get("access_token")
    
    roles = collect_roles(id_claims, userinfo, access_token, cfg.keycloak_issuer)
    
    if has_admin_role(roles, cfg.realm_admin_role, cfg.iam_operator_role):
        current_app.logger.info(f"Admin role detected, redirecting to /admin")
        return redirect(url_for("admin.admin_dashboard"))
    else:
        current_app.logger.info(f"No admin role detected, redirecting to /me")
        return redirect(url_for("admin.me"))


@bp.route("/logout")
def logout():
    """Logout user and redirect to Keycloak logout endpoint."""
    cfg = current_app.config["APP_CONFIG"]
    
    token = session.get("token") or {}
    id_token = token.get("id_token")
    session.clear()
    
    end_session_endpoint = f"{cfg.keycloak_public_issuer.rstrip('/')}/protocol/openid-connect/logout"
    
    params = {"post_logout_redirect_uri": cfg.post_logout_redirect_uri}
    if id_token:
        params["id_token_hint"] = id_token
    else:
        params["client_id"] = cfg.oidc_client_id
    
    logout_url = f"{end_session_endpoint}?{urlencode(params)}"
    return redirect(logout_url)


@bp.route("/")
def index():
    """Home page."""
    from flask import render_template
    from app.core.rbac import is_authenticated
    
    return render_template(
        "index.html",
        title="Welcome",
        is_authenticated=is_authenticated(),
    )
