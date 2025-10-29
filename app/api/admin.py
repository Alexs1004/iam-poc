"""Admin dashboard and JML operation routes."""
from __future__ import annotations
import json
import sys
from pathlib import Path
from functools import wraps

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, abort
from scripts import audit
from app.core.keycloak import (
    get_group_by_path,
    get_group_members,
    get_user_by_username,
    _user_has_totp,
    REQUEST_TIMEOUT,
)
from app.core import provisioning_service
from app.core.rbac import (
    is_authenticated,
    user_has_role,
    current_username,
    current_user_context,
    filter_display_roles,
    requires_operator_for_roles,
)

bp = Blueprint("admin", __name__)


# ─────────────────────────────────────────────────────────────────────────────
# Role-based Access Control Decorators
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Decorators
# ─────────────────────────────────────────────────────────────────────────────
def require_any_role(*required_roles):
    """Decorator to require any of the specified roles."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not is_authenticated():
                # Explicit redirect to login page (not back to admin)
                return redirect(url_for("auth.login"), code=302)
            
            cfg = current_app.config["APP_CONFIG"]
            _, _, _, roles = current_user_context()
            
            if not any(role.lower() in [r.lower() for r in roles] for role in required_roles):
                return render_template(
                    "403.html",
                    title="Forbidden",
                    is_authenticated=True,
                    required_role=required_roles[0] if len(required_roles) == 1 else ", ".join(required_roles),
                ), 403
            
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_admin_view(fn):
    """Allow viewing admin dashboard (analyst, manager, iam-operator, realm-admin)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            # Explicit redirect to login page (not back to admin)
            return redirect(url_for("auth.login"), code=302)
        
        cfg = current_app.config["APP_CONFIG"]
        _, _, _, roles = current_user_context()
        
        allowed_roles = [
            "analyst",
            "manager",
            cfg.realm_admin_role,
            cfg.iam_operator_role
        ]
        
        if not any(role.lower() in [r.lower() for r in roles] for role in allowed_roles):
            return render_template(
                "403.html",
                title="Forbidden",
                is_authenticated=True,
                required_role="analyst, manager, iam-operator, or realm-admin",
            ), 403
        
        return fn(*args, **kwargs)
    return wrapper


def require_jml_operator(fn):
    """Restrict JML operations to operators only (iam-operator, realm-admin)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            # Explicit redirect to login page (not back to admin)
            return redirect(url_for("auth.login"), code=302)
        
        cfg = current_app.config["APP_CONFIG"]
        _, _, _, roles = current_user_context()
        
        allowed_roles = [cfg.realm_admin_role, cfg.iam_operator_role]
        
        if not any(role.lower() in [r.lower() for r in roles] for role in allowed_roles):
            return render_template(
                "403.html",
                title="Forbidden",
                is_authenticated=True,
                required_role="iam-operator or realm-admin",
            ), 403
        
        return fn(*args, **kwargs)
    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────
def _user_roles(kc_token: str, user_id: str) -> list[str]:
    """Get user's roles from Keycloak."""
    cfg = current_app.config["APP_CONFIG"]
    keycloak_base_url = cfg.keycloak_server_url.split("/realms/")[0]
    
    import requests
    resp = requests.get(
        f"{keycloak_base_url}/admin/realms/{cfg.keycloak_realm}/users/{user_id}/role-mappings/realm",
        headers={"Authorization": f"Bearer {kc_token}"},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return sorted({role.get("name") for role in resp.json() or [] if role.get("name")})


def _fetch_user_statuses(kc_token: str) -> list[dict]:
    """
    Fetch managed users from iam-poc-managed group with their statuses.
    
    Security guardrails:
    - Only returns users in the managed group (principle of least privilege)
    - Excludes service accounts and admin users from automation workflows
    - Falls back to empty list if group doesn't exist (safe default)
    - Filters out internal Keycloak roles for display
    """
    cfg = current_app.config["APP_CONFIG"]
    keycloak_base_url = cfg.keycloak_server_url.split("/realms/")[0]
    
    import requests
    
    # ─────────────────────────────────────────────────────────────────────────
    # Dynamic user discovery via group membership
    # ─────────────────────────────────────────────────────────────────────────
    managed_group_path = "/iam-poc-managed"
    managed_group = get_group_by_path(keycloak_base_url, kc_token, cfg.keycloak_realm, managed_group_path)
    
    if not managed_group:
        # Group doesn't exist yet (e.g., before initial bootstrap)
        # Return empty list instead of failing (graceful degradation)
        print(f"[admin] Warning: Group '{managed_group_path}' not found, showing empty user list", file=sys.stderr)
        return []
    
    # Get group members (only managed users)
    try:
        users = get_group_members(keycloak_base_url, kc_token, cfg.keycloak_realm, managed_group["id"])
    except requests.HTTPError as exc:
        detail = exc.response.text if hasattr(exc, "response") and exc.response else str(exc)
        print(f"[admin] Error fetching group members: {detail}", file=sys.stderr)
        return []
    
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
            status["totp_enrolled"] = _user_has_totp(
                keycloak_base_url, kc_token, cfg.keycloak_realm, user_id
            )
            status["roles"] = filter_display_roles(status["roles"], cfg.keycloak_realm)
        except requests.HTTPError as exc:
            detail = exc.response.text if getattr(exc, "response", None) is not None else str(exc)
            raise RuntimeError(f"Failed to load details for user '{status['username']}': {detail}") from exc
        
        statuses.append(status)
    
    statuses.sort(key=lambda item: (item["display_name"] or item["username"]).lower())
    return statuses


def _fetch_assignable_roles(kc_token: str) -> list[str]:
    """Fetch assignable roles from Keycloak."""
    cfg = current_app.config["APP_CONFIG"]
    keycloak_base_url = cfg.keycloak_server_url.split("/realms/")[0]
    
    import requests
    resp = requests.get(
        f"{keycloak_base_url}/admin/realms/{cfg.keycloak_realm}/roles",
        headers={"Authorization": f"Bearer {kc_token}"},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    available = [role.get("name") for role in resp.json() or [] if role.get("name")]
    
    if not available:
        return cfg.assignable_roles
    
    filtered = [role for role in available if role.lower() in [r.lower() for r in cfg.assignable_roles]]
    return sorted(filtered or available, key=str.lower)


def _load_admin_context() -> tuple[list[dict], list[str]]:
    """Load user statuses and assignable roles."""
    try:
        token = provisioning_service.get_service_token()
    except provisioning_service.ScimError as exc:
        raise RuntimeError(f"Failed to obtain service account token: {exc.detail}") from exc
    
    statuses = _fetch_user_statuses(token)
    roles = _fetch_assignable_roles(token)
    return statuses, roles


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────
@bp.route("/me")
def me():
    """User profile page."""
    if not is_authenticated():
        return redirect(url_for("auth.login"))
    
    cfg = current_app.config["APP_CONFIG"]
    _, _, userinfo, roles = current_user_context()
    
    visible_roles = {"analyst", "manager"}
    visible_roles.add(cfg.realm_admin_role)
    visible_roles.add(cfg.iam_operator_role)
    
    userinfo = userinfo or {}
    filtered_roles = [role for role in roles if role.lower() in [r.lower() for r in visible_roles]]
    userinfo_json = json.dumps(userinfo, indent=2, ensure_ascii=False)
    
    display_name = (
        userinfo.get("name")
        or userinfo.get("preferred_username")
        or userinfo.get("email")
        or "User"
    )
    initials = "".join(part[0] for part in display_name.split() if part.isalpha())[:2].upper() or "U"
    primary_email = userinfo.get("email") or "—"
    username = userinfo.get("preferred_username") or userinfo.get("sub") or "—"
    email_verified = bool(userinfo.get("email_verified"))
    
    return render_template(
        "me.html",
        title="Profile",
        is_authenticated=True,
        roles=filtered_roles,
        userinfo=userinfo,
        userinfo_json=userinfo_json,
        profile_display_name=display_name,
        profile_initials=initials,
        profile_email=primary_email,
        profile_username=username,
        profile_email_verified=email_verified,
    )


@bp.route("/audit")
@require_admin_view
def admin_audit():
    """Display audit trail of JML operations."""
    audit_file = Path(audit.AUDIT_LOG_FILE)
    events = []
    
    if audit_file.exists():
        with audit_file.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    
    # Reverse chronological order
    events.reverse()
    
    # Verify signatures
    total, valid = audit.verify_audit_log()
    integrity_status = "✓ All signatures valid" if total == valid else f"⚠ {total - valid} invalid signatures"
    
    return render_template(
        "admin_audit.html",
        title="Audit Trail",
        is_authenticated=True,
        events=events,
        total_events=total,
        valid_signatures=valid,
        integrity_status=integrity_status,
    )


@bp.route("/debug")
def admin_debug():
    """Debug endpoint to test user loading."""
    from flask import jsonify
    import os
    
    # Check what's in environment
    secret_from_env = os.environ.get("KEYCLOAK_SERVICE_CLIENT_SECRET", "NOT_SET")
    
    try:
        user_statuses, assignable_roles = _load_admin_context()
        return jsonify({
            "status": "success",
            "user_count": len(user_statuses),
            "secret_info": f"length={len(secret_from_env)}, starts={secret_from_env[:8]}...",
            "users": [{"username": u["username"], "enabled": u["enabled"]} for u in user_statuses],
            "roles": assignable_roles
        })
    except Exception as exc:
        return jsonify({
            "status": "error",
            "message": str(exc),
            "secret_info": f"length={len(secret_from_env)}, starts={secret_from_env[:8] if secret_from_env != 'NOT_SET' else 'NOT_SET'}..."
        }), 500


@bp.route("/")
@require_admin_view
def admin_dashboard():
    """Admin dashboard showing all users."""
    cfg = current_app.config["APP_CONFIG"]
    
    try:
        user_statuses, assignable_roles = _load_admin_context()
    except Exception as exc:
        flash(f"Unable to load Keycloak state: {exc}", "error")
        user_statuses = []
        assignable_roles = cfg.assignable_roles
    
    existing_users = [user for user in user_statuses if user["exists"]]
    
    # Check if user can perform JML operations (not just view)
    _, _, _, roles = current_user_context()
    can_perform_jml = any(
        role.lower() in [cfg.realm_admin_role.lower(), cfg.iam_operator_role.lower()]
        for role in roles
    )
    
    # Get flash messages (category, message) tuples
    from flask import get_flashed_messages
    flash_messages = get_flashed_messages(with_categories=True)
    
    return render_template(
        "admin.html",
        title="Admin",
        is_authenticated=True,
        user_statuses=user_statuses,
        assignable_roles=assignable_roles,
        existing_users=existing_users,
        can_perform_jml=can_perform_jml,
        flash_messages=flash_messages,  # ✅ Pass flash messages explicitly
    )


@bp.post("/joiner")
@require_jml_operator
def admin_joiner():
    """Create user (Joiner operation)."""
    from app.api.helpers import admin_ui
    cfg = current_app.config["APP_CONFIG"]
    
    # Input validation
    try:
        from app.core.validators import normalize_username, validate_email, validate_name
        username = normalize_username(request.form.get("username", ""))
        first = validate_name(request.form.get("first_name", ""), "First name")
        last = validate_name(request.form.get("last_name", ""), "Last name")
        email = validate_email(request.form.get("email", ""))
        role = request.form.get("role", "").strip()
        temp_password = request.form.get("temp_password", "").strip()
        require_totp = request.form.get("require_totp") == "on"
        require_password_update = request.form.get("require_password_update") == "on"
    except ValueError as exc:
        flash(f"Validation error: {exc}", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    if not all([username, first, last, email, role]):
        flash("All fields are required to provision a user.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    if role.lower() not in [r.lower() for r in cfg.assignable_roles]:
        flash(f"Role '{role}' is not assignable.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    if requires_operator_for_roles([role], cfg.realm_admin_role, cfg.iam_operator_role) and not user_has_role(cfg.realm_admin_role):
        flash("Realm-admin privileges are required to assign realm-admin-level roles.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    if not temp_password:
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$-_=+"
        temp_password = "".join(secrets.choice(alphabet) for _ in range(14))
    
    operator = current_username() or "system"
    
    try:
        user_id, returned_password = admin_ui.ui_create_user(
            username=username,
            email=email,
            first_name=first,
            last_name=last,
            role=role,
            temp_password=temp_password,
            require_totp=require_totp,
            require_password_update=require_password_update
        )
        
        flash(f"User '{username}' provisioned. Temporary password: {returned_password}", "success")
    except provisioning_service.ScimError as exc:
        flash(f"Failed to provision user '{username}': {exc.detail}", "error")
        audit.log_jml_event(
            "joiner",
            username,
            operator=operator,
            realm=cfg.keycloak_realm,
            details={"error": exc.detail, "role": role, "status": exc.status},
            success=False,
        )
    except Exception as exc:
        flash(f"Failed to provision user '{username}': {exc}", "error")
        audit.log_jml_event(
            "joiner",
            username,
            operator=operator,
            realm=cfg.keycloak_realm,
            details={"error": str(exc), "role": role},
            success=False,
        )
    
    return redirect(url_for("admin.admin_dashboard"))



@bp.post("/mover")
@require_jml_operator
def admin_mover():
    """Change user role (Mover operation)."""
    from app.api.helpers import admin_ui
    cfg = current_app.config["APP_CONFIG"]
    
    username = request.form.get("username", "").strip()
    source_role = request.form.get("source_role", "").strip()
    target_role = request.form.get("target_role", "").strip()
    
    if not username or not source_role or not target_role:
        flash("User, current role, and new role are required.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    if source_role == target_role:
        flash("Choose a different target role to perform a mover operation.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    current_username_lower = current_username().lower()
    if current_username_lower and username.lower() == current_username_lower:
        flash("You cannot change your own role from this console.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    try:
        token = provisioning_service.get_service_token()
        keycloak_base_url = cfg.keycloak_url or cfg.keycloak_server_url.split("/realms/")[0]
        target_user = get_user_by_username(keycloak_base_url, token, cfg.keycloak_realm, username)
    except provisioning_service.ScimError as exc:
        flash(f"Failed to obtain service token: {exc.detail}", "error")
        return redirect(url_for("admin.admin_dashboard"))
    except Exception as exc:
        flash(f"Failed to update roles for '{username}': {exc}", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    if not target_user:
        flash(f"User '{username}' not found in realm '{cfg.keycloak_realm}'.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    try:
        target_roles = _user_roles(token, target_user["id"])
    except Exception as exc:
        flash(f"Unable to read roles for '{username}': {exc}", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    if (requires_operator_for_roles(target_roles, cfg.realm_admin_role, cfg.iam_operator_role) or 
        requires_operator_for_roles([source_role, target_role], cfg.realm_admin_role, cfg.iam_operator_role)) and \
       not user_has_role(cfg.realm_admin_role):
        flash("Realm-admin privileges are required to modify realm-admin-level access.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    operator = current_username() or "system"
    
    try:
        admin_ui.ui_change_role(username, source_role, target_role)
        flash(f"User '{username}' moved from {source_role} to {target_role}.", "success")
    except provisioning_service.ScimError as exc:
        flash(f"Failed to update roles for '{username}': {exc.detail}", "error")
        audit.log_jml_event(
            "mover",
            username,
            operator=operator,
            realm=cfg.keycloak_realm,
            details={"error": exc.detail, "from_role": source_role, "to_role": target_role, "status": exc.status},
            success=False,
        )
    except Exception as exc:
        flash(f"Failed to update roles for '{username}': {exc}", "error")
        audit.log_jml_event(
            "mover",
            username,
            operator=operator,
            realm=cfg.keycloak_realm,
            details={"error": str(exc), "from_role": source_role, "to_role": target_role},
            success=False,
        )
    
    return redirect(url_for("admin.admin_dashboard"))


@bp.post("/leaver")
@require_jml_operator
def admin_leaver():
    """Disable user (Leaver operation)."""
    from app.api.helpers import admin_ui
    cfg = current_app.config["APP_CONFIG"]
    
    username = request.form.get("username", "").strip()
    if not username:
        flash("Select a user to disable.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    current_username_lower = current_username().lower()
    if current_username_lower and username.lower() == current_username_lower:
        flash("You cannot disable your own account from this console.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    try:
        token = provisioning_service.get_service_token()
        keycloak_base_url = cfg.keycloak_url or cfg.keycloak_server_url.split("/realms/")[0]
        target_user = get_user_by_username(keycloak_base_url, token, cfg.keycloak_realm, username)
    except provisioning_service.ScimError as exc:
        flash(f"Failed to obtain service token: {exc.detail}", "error")
        return redirect(url_for("admin.admin_dashboard"))
    except Exception as exc:
        flash(f"Failed to disable '{username}': {exc}", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    if not target_user:
        flash(f"User '{username}' not found in realm '{cfg.keycloak_realm}'.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    try:
        target_roles = _user_roles(token, target_user["id"])
    except Exception as exc:
        flash(f"Unable to read roles for '{username}': {exc}", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    if requires_operator_for_roles(target_roles, cfg.realm_admin_role, cfg.iam_operator_role) and not user_has_role(cfg.realm_admin_role):
        flash("Realm-admin privileges are required to disable realm-admin-level accounts.", "error")
        return redirect(url_for("admin.admin_dashboard"))
    
    operator = current_username() or "system"
    
    try:
        admin_ui.ui_disable_user(username)
        flash(f"User '{username}' disabled successfully (sessions revoked).", "success")
    except provisioning_service.ScimError as exc:
        flash(f"Failed to disable '{username}': {exc.detail}", "error")
        audit.log_jml_event(
            "leaver",
            username,
            operator=operator,
            realm=cfg.keycloak_realm,
            details={"error": exc.detail, "status": exc.status},
            success=False,
        )
    except Exception as exc:
        flash(f"Failed to disable '{username}': {exc}", "error")
        audit.log_jml_event(
            "leaver",
            username,
            operator=operator,
            realm=cfg.keycloak_realm,
            details={"error": str(exc)},
            success=False,
        )
    
    return redirect(url_for("admin.admin_dashboard"))


@bp.post("/reactivate")
@require_jml_operator
def admin_reactivate():
    """Reactivate user (set active=true)."""
    from app.api.helpers import admin_ui
    cfg = current_app.config["APP_CONFIG"]

    username = request.form.get("username", "").strip()
    if not username:
        flash("Select a user to reactivate.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    current_username_lower = current_username().lower()
    if current_username_lower and username.lower() == current_username_lower:
        flash("You cannot reactivate your own account from this console.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    try:
        token = provisioning_service.get_service_token()
        keycloak_base_url = cfg.keycloak_url or cfg.keycloak_server_url.split("/realms/")[0]
        target_user = get_user_by_username(keycloak_base_url, token, cfg.keycloak_realm, username)
    except provisioning_service.ScimError as exc:
        flash(f"Failed to obtain service token: {exc.detail}", "error")
        return redirect(url_for("admin.admin_dashboard"))
    except Exception as exc:
        flash(f"Failed to reactivate '{username}': {exc}", "error")
        return redirect(url_for("admin.admin_dashboard"))

    if not target_user:
        flash(f"User '{username}' not found in realm '{cfg.keycloak_realm}'.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    if target_user.get("enabled"):
        flash(f"User '{username}' is already active.", "info")
        return redirect(url_for("admin.admin_dashboard"))

    try:
        target_roles = _user_roles(token, target_user["id"])
    except Exception as exc:
        flash(f"Unable to read roles for '{username}': {exc}", "error")
        return redirect(url_for("admin.admin_dashboard"))

    if requires_operator_for_roles(target_roles, cfg.realm_admin_role, cfg.iam_operator_role) and not user_has_role(cfg.realm_admin_role):
        flash("Realm-admin privileges are required to reactivate realm-admin-level accounts.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    operator = current_username() or "system"

    try:
        admin_ui.ui_set_user_active(username, True)
        flash(f"User '{username}' reactivated successfully.", "success")
    except provisioning_service.ScimError as exc:
        flash(f"Failed to reactivate '{username}': {exc.detail}", "error")
        audit.log_jml_event(
            "scim_patch_user_active",
            username,
            operator=operator,
            realm=cfg.keycloak_realm,
            details={"error": exc.detail, "status": exc.status, "requested_active": True},
            success=False,
        )
    except Exception as exc:
        flash(f"Failed to reactivate '{username}': {exc}", "error")
        audit.log_jml_event(
            "scim_patch_user_active",
            username,
            operator=operator,
            realm=cfg.keycloak_realm,
            details={"error": str(exc), "requested_active": True},
            success=False,
        )

    return redirect(url_for("admin.admin_dashboard"))
