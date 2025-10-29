"""Flask application factory and bootstrap.

This module provides the create_app() factory function for initializing
the Flask application with all blueprints, middleware, and configuration.
"""
from __future__ import annotations
import ipaddress
import hmac
import os
import secrets
from pathlib import Path
from tempfile import gettempdir

from flask import Flask, session, request, g, abort, redirect, url_for, get_flashed_messages
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import load_settings


# ─────────────────────────────────────────────────────────────────────────────
# Application Factory
# ─────────────────────────────────────────────────────────────────────────────
def create_app() -> Flask:
    """Create and configure Flask application."""
    # Load configuration
    cfg = load_settings()
    
    # Create Flask app
    app = Flask(__name__)
    app.config.setdefault(
        "OPENAPI_SPEC_PATH",
        str(Path(app.root_path).parent / "openapi" / "scim_openapi.yaml"),
    )
    
    # Store config for easy access in routes
    app.config["APP_CONFIG"] = cfg
    
    # Flask session configuration
    app.config["SECRET_KEY"] = cfg.secret_key
    if cfg.secret_key_fallbacks:
        app.config["SECRET_KEY_FALLBACKS"] = cfg.secret_key_fallbacks
    
    app.config["SESSION_TYPE"] = os.environ.get("FLASK_SESSION_TYPE", "filesystem")
    if app.config["SESSION_TYPE"] == "filesystem":
        session_dir = os.environ.get("FLASK_SESSION_DIR") or os.path.join(gettempdir(), "iam_poc_flask_session")
        os.makedirs(session_dir, exist_ok=True)
        app.config["SESSION_FILE_DIR"] = session_dir
    
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = cfg.session_cookie_secure
    
    # Additional OIDC config for middleware
    app.config["OIDC_TOKEN_REFRESH_LEEWAY"] = int(os.environ.get("OIDC_TOKEN_REFRESH_LEEWAY", "60"))
    
    # Initialize session
    Session(app)
    
    # Trust X-Forwarded-* headers from proxy (nginx)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore
    
    # Parse trusted proxy networks
    trusted_proxy_networks = []
    for entry in cfg.trusted_proxy_ips.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            trusted_proxy_networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    
    app.config["TRUSTED_PROXY_NETWORKS"] = trusted_proxy_networks
    app.config["CSRF_SESSION_KEY"] = "_csrf_token"
    
    # Initialize OIDC
    from app.api import auth
    auth.init_oauth(app, cfg)
    
    # Register blueprints
    from app.api import health, errors
    from app.api import admin
    from app.api import scim
    from app.api import docs as docs_routes
    
    app.register_blueprint(auth.bp)
    app.register_blueprint(health.bp)
    app.register_blueprint(admin.bp, url_prefix="/admin")
    app.register_blueprint(scim.bp, url_prefix="/scim/v2")
    app.register_blueprint(docs_routes.bp)
    
    # Register error handlers
    errors.register_error_handlers(app)
    
    # Register middleware/before_request handlers
    _register_middleware(app, trusted_proxy_networks)
    
    # Register context processors
    _register_context_processors(app, cfg)
    
    # Log startup info
    mode_label = "DEMO" if cfg.demo_mode else "PRODUCTION"
    print(f"[flask_app] Mode={mode_label}")
    print(f"[flask_app] SCIM 2.0 API registered at /scim/v2")
    
    if cfg.demo_mode:
        print("[flask_app] WARNING: Demo mode active - do not deploy with demo credentials")
    
    return app


def _register_middleware(app: Flask, trusted_proxy_networks: list):
    """Register before_request middleware."""
    
    @app.before_request
    def enforce_proxy_headers() -> None:
        """Validate proxy headers from trusted sources only."""
        original_remote = request.environ.get("werkzeug.proxy_fix.orig_remote_addr")
        if original_remote:
            try:
                address = ipaddress.ip_address(original_remote)
                if not any(address in network for network in trusted_proxy_networks):
                    abort(400, description="Untrusted proxy")
            except ValueError:
                abort(400, description="Invalid proxy address")
        
        forwarded_proto = request.headers.get("X-Forwarded-Proto")
        if forwarded_proto and forwarded_proto != "https":
            abort(400, description="Invalid forwarded protocol")
        
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for and "," in forwarded_for:
            abort(400, description="Multiple forwarded clients not permitted")
        
        g.csrf_token = _generate_csrf_token()
    
    @app.before_request
    def enforce_csrf() -> None:
        """Validate CSRF token for state-changing requests.
        
        Note: SCIM endpoints (/scim/v2/*) use OAuth Bearer tokens, not CSRF.
        """
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return
        
        # Skip CSRF for SCIM API (OAuth-protected)
        if request.path.startswith("/scim/v2"):
            return
        
        submitted_token = (
            request.form.get("csrf_token")
            if not request.is_json
            else request.headers.get("X-CSRF-Token", "")
        )
        if not submitted_token:
            submitted_token = request.headers.get("X-CSRF-Token", "")
        
        csrf_session_key = app.config["CSRF_SESSION_KEY"]
        session_token = session.get(csrf_session_key, "")
        
        if not session_token or not submitted_token or not hmac.compare_digest(session_token, submitted_token):
            abort(400, description="CSRF validation failed")
    
    @app.before_request
    def ensure_fresh_token():
        """Refresh OIDC token if expiring soon."""
        from app.core.rbac import is_authenticated, refresh_session_token
        
        if not is_authenticated():
            return
        
        # Skip refresh for certain endpoints
        endpoint = (request.endpoint or "").rsplit(".", 1)[-1]
        skip_endpoints = {"login", "logout", "callback", "health_check", "readiness_check", "static"}
        if endpoint in skip_endpoints:
            return
        
        if request.path.startswith("/static/"):
            return
        
        outcome = refresh_session_token()
        if outcome is False and not is_authenticated():
            return redirect(url_for("auth.login", force=1))


def _register_context_processors(app: Flask, cfg):
    """Register context processors for templates."""
    
    @app.context_processor
    def inject_global_context():
        """Inject global variables into all templates."""
        from app.core.rbac import is_authenticated, user_has_role
        from urllib.parse import urlparse
        
        csrf_token = g.get("csrf_token") or _generate_csrf_token()
        is_admin_user = user_has_role(cfg.realm_admin_role) if is_authenticated() else False
        
        # Keycloak console URL
        console_url = None
        if is_authenticated():
            if user_has_role(cfg.realm_admin_role):
                console_root = _console_root_url(cfg)
                console_url = f"{console_root}/admin/{cfg.keycloak_realm}/console/"
        else:
            console_url = _default_console_url(cfg.keycloak_public_issuer)
        
        return {
            "csrf_token": csrf_token,
            "is_authenticated": is_authenticated(),
            "is_admin_user": is_admin_user,
            "keycloak_console_url": console_url,
            "realm_admin_role": cfg.realm_admin_role,
            "iam_operator_role": cfg.iam_operator_role,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────
def _generate_csrf_token() -> str:
    """Generate or retrieve CSRF token for current session."""
    csrf_session_key = "_csrf_token"
    token = session.get(csrf_session_key)
    if not token:
        token = secrets.token_urlsafe(32)
        session[csrf_session_key] = token
    return token


def _console_root_url(cfg) -> str:
    """Get Keycloak console root URL."""
    from urllib.parse import urlparse
    
    root = os.environ.get("SECURITY_ADMIN_ROOT_URL", "").strip()
    if root:
        return root.rstrip("/")
    
    console_url = os.environ.get("KEYCLOAK_CONSOLE_URL", "")
    if console_url:
        parsed = urlparse(console_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    
    parsed = urlparse(cfg.keycloak_public_issuer)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    
    return "https://localhost"


def _default_console_url(public_issuer: str) -> str:
    """Generate default Keycloak console URL from issuer."""
    issuer = public_issuer.rstrip("/")
    if "/realms/" in issuer:
        base, _, _realm = issuer.partition("/realms/")
        return f"{base.rstrip('/')}/admin/master/console/"
    return f"{issuer}/admin/master/console/"


# ─────────────────────────────────────────────────────────────────────────────
# Application Instance (for Gunicorn)
# ─────────────────────────────────────────────────────────────────────────────
app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
