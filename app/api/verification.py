"""SCIM verification UI and automated checks."""
from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
    abort,
)

from app.core import provisioning_service
from app.core.rbac import is_authenticated, user_has_role, current_user_context
from app.config.settings import settings
from scripts import audit

REQUEST_TIMEOUT = 15  # seconds (per-request timeout for SCIM calls)
SCIM_MEDIA_TYPE = "application/scim+json"

bp = Blueprint("verification", __name__)

# Rate limiting is handled by nginx reverse proxy
# See proxy/nginx.conf for configuration:
#   - /verification: 10 req/min, burst=5
#   - /scim/v2/*: 60 req/min, burst=10
#   - /admin/*: 30 req/min, burst=8
RATE_LIMITING_AVAILABLE = True  # Nginx rate limiting is configured

# 
@dataclass
class CheckResult:
    """Container for individual verification results."""

    name: str
    status: str
    status_code: Optional[int]
    detail: str
    correlation_id: Optional[str] = None
    duration_ms: Optional[int] = None


def _check_access():
    """Check if user has access to verification page."""
    try:
        print(f"[DEBUG] _check_access() called - verify_page_enabled: {settings.verify_page_enabled}")
        
        if not settings.verify_page_enabled:
            print(f"[DEBUG] Access denied - verification page disabled")
            abort(404)
        
        if settings.demo_mode:
            print(f"[DEBUG] Demo mode - allowing anonymous access")
            # In demo mode, allow anonymous access
            return
        
        print(f"[DEBUG] Production mode - checking authentication")
        
        # In production mode, require authentication and proper role
        if not is_authenticated():
            print(f"[DEBUG] Access denied - user not authenticated")
            abort(403)
        
        _, _, _, roles = current_user_context()
        allowed_roles = [
            settings.realm_admin_role,
            settings.iam_operator_role,
            "iam-verifier",
            "realm-managementrealm-admin"  # TEMPORARY: Add malformed role
        ]
        
        # DEBUG: Log user roles and allowed roles for troubleshooting
        print(f"[DEBUG] User roles: {roles}")
        print(f"[DEBUG] Allowed roles: {allowed_roles}")
        print(f"[DEBUG] Settings realm_admin_role: '{settings.realm_admin_role}'")
        print(f"[DEBUG] Settings iam_operator_role: '{settings.iam_operator_role}'")
        
        if not any(role.lower() in [r.lower() for r in roles] for role in allowed_roles):
            print(f"[DEBUG] Access denied - no matching roles found")
            abort(403)
        
        print(f"[DEBUG] Access granted")
    except Exception as e:
        # Log the actual error for debugging
        print(f"[ERROR] Exception in _check_access(): {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        raise  # Re-raise to let error handler catch it


def _safe_username_check(username: str) -> bool:
    """Ensure username starts with 'verifier-' for safety."""
    return username.startswith("verifier-")


def _make_scim_request(method: str, url: str, **kwargs) -> tuple[requests.Response, int]:
    """Make SCIM request with timeout and correlation tracking."""
    correlation_id = str(uuid.uuid4())
    
    headers = kwargs.get('headers', {})
    headers['X-Correlation-Id'] = correlation_id
    
    # Mask token in headers for logging
    logged_headers = dict(headers)
    if 'Authorization' in logged_headers:
        logged_headers['Authorization'] = 'Bearer ****'
    
    kwargs['headers'] = headers
    kwargs['timeout'] = REQUEST_TIMEOUT
    
    start_time = time.time()
    try:
        response = requests.request(method, url, **kwargs)
        duration_ms = int((time.time() - start_time) * 1000)
        return response, duration_ms
    except requests.Timeout:
        duration_ms = int((time.time() - start_time) * 1000)
        # Create a mock response for timeout
        mock_response = requests.Response()
        mock_response.status_code = 408
        mock_response._content = b'{"detail": "Request timeout"}'
        return mock_response, duration_ms


class VerificationRunner:
    """Run live SCIM verification checks against the deployed API."""

    def __init__(self, client, user_access_token: Optional[str] = None) -> None:
        self.client = client
        self.user_access_token = user_access_token

        self.results: list[CheckResult] = []
        self.created_user: Dict[str, Any] = {}
        self.created_user_id: Optional[str] = None
        self.created_username: Optional[str] = None
        self.deleted = False

        self.service_token = provisioning_service.get_service_token()
        self.put_detail_expected = "Full replace is not supported. Use PATCH (active) or DELETE."

    # ──────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────
    def run(self) -> list[CheckResult]:
        """Execute verification flow end-to-end."""
        try:
            self._create_user()
            self._get_user()
            self._filter_user()
            self._filter_guard()
            self._patch_active(False, "PATCH disable (active=false)")
            self._patch_active(False, "PATCH disable (idempotent)")
            self._patch_active(True, "PATCH enable (active=true)")
            self._put_guard()
            self._content_type_guard()
            self._missing_token_guard()
            self._invalid_token_guard()
            self._insufficient_scope_guard()
            self._delete_user()
        finally:
            self._cleanup()

        self._verify_audit_log()
        return self.results

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────
    def _auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.service_token}"}

    def _append_result(
        self,
        name: str,
        success: bool,
        status_code: Optional[int],
        detail: str,
        correlation_id: Optional[str] = None,
        duration_ms: Optional[int] = None,
    ) -> None:
        status = "success" if success else "failure"
        self.results.append(CheckResult(
            name=name, 
            status=status, 
            status_code=status_code, 
            detail=detail,
            correlation_id=correlation_id,
            duration_ms=duration_ms
        ))

    def _append_skipped(self, name: str, reason: str) -> None:
        self.results.append(CheckResult(name=name, status="skipped", status_code=None, detail=reason))

    def _create_user(self) -> None:
        user_suffix = uuid.uuid4().hex[:10]
        username = f"verifier-{user_suffix}"
        
        if not _safe_username_check(username):
            self._append_result("Create user", False, None, f"Unsafe username: {username}")
            return
            
        payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": username,
            "name": {"givenName": "Verifier", "familyName": user_suffix},
            "emails": [{"value": f"{username}@example.com", "primary": True}],
            "active": True,
        }
        headers = {**self._auth_headers(), "Content-Type": SCIM_MEDIA_TYPE}
        
        # Use Flask test client instead of external HTTP request to avoid deadlocks
        start_time = time.time()
        try:
            response = self.client.post(
                "/scim/v2/Users",
                json=payload,
                headers=headers,
            )
            duration_ms = int((time.time() - start_time) * 1000)
        except Exception as e:
            self._append_result("POST /Users (create)", False, None, f"Request failed: {e}")
            return
            
        correlation_id = None  # Flask test client doesn't return correlation IDs
        
        if hasattr(response, 'status_code') and response.status_code == 408:  # Timeout check (unlikely with test client)
            self._append_result("POST /Users (create)", False, 408, "Skipped (timeout)", correlation_id, duration_ms)
            return
            
        success = response.status_code == 201
        detail = ""
        if success:
            body = response.get_json(silent=True) or {}
            self.created_user = body
            self.created_user_id = body.get("id")
            self.created_username = body.get("userName")
            detail = f"id={self.created_user_id}, userName={self.created_username}, active={body.get('active')}"
        else:
            try:
                body = response.get_json(silent=True) or {}
                detail = body.get("detail") or response.get_data(as_text=True)
            except:
                detail = response.get_data(as_text=True) or "Unknown error"
        self._append_result("POST /Users (create)", success, response.status_code, detail, correlation_id, duration_ms)

    def _get_user(self) -> None:
        if not self.created_user_id:
            self._append_result("GET /Users/{id}", False, None, "User creation failed; GET skipped")
            return

        headers = self._auth_headers()
        response = self.client.get(
            f"/scim/v2/Users/{self.created_user_id}",
            headers=headers,
        )
        success = response.status_code == 200
        body = response.get_json(silent=True) or {}
        detail = f"status={response.status_code}, active={body.get('active')}, userName={body.get('userName')}"
        self._append_result("GET /Users/{id}", success, response.status_code, detail)

    def _filter_user(self) -> None:
        if not self.created_username:
            self._append_result("GET /Users?filter=userName eq", False, None, "User creation failed; filter skipped")
            return

        headers = self._auth_headers()
        response = self.client.get(
            "/scim/v2/Users",
            headers=headers,
            query_string={"filter": f'userName eq "{self.created_username}"'},
        )
        success = response.status_code == 200
        body = response.get_json(silent=True) or {}
        resources = body.get("Resources", [])
        detail = f"status={response.status_code}, matches={len(resources)}"
        self._append_result("GET /Users (filter userName eq)", success, response.status_code, detail)

    def _filter_guard(self) -> None:
        headers = self._auth_headers()
        response = self.client.get(
            "/scim/v2/Users",
            headers=headers,
            query_string={"filter": 'userName co "x"'},
        )
        body = response.get_json(silent=True) or {}
        success = response.status_code == 501
        detail = body.get("detail") or response.get_data(as_text=True)
        self._append_result("GET /Users invalid filter → 501", success, response.status_code, detail)

    def _patch_active(self, active: bool, label: str) -> None:
        if not self.created_user_id:
            self._append_result(label, False, None, "User creation failed; PATCH skipped")
            return

        headers = {**self._auth_headers(), "Content-Type": SCIM_MEDIA_TYPE}
        payload = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": active}],
        }
        response = self.client.patch(
            f"/scim/v2/Users/{self.created_user_id}",
            json=payload,
            headers=headers,
        )
        body = response.get_json(silent=True) or {}
        success = response.status_code == 200 and body.get("active") == active
        detail = f"status={response.status_code}, active={body.get('active')}"
        self._append_result(label, success, response.status_code, detail)

    def _put_guard(self) -> None:
        if not self.created_user_id:
            self._append_result("PUT /Users/{id} → 501", False, None, "User creation failed; PUT skipped")
            return

        headers = {**self._auth_headers(), "Content-Type": SCIM_MEDIA_TYPE}
        payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": self.created_username or "placeholder",
        }
        response = self.client.put(
            f"/scim/v2/Users/{self.created_user_id}",
            json=payload,
            headers=headers,
        )
        body = response.get_json(silent=True) or {}
        detail = body.get("detail") or response.get_data(as_text=True)
        success = response.status_code == 501 and detail == self.put_detail_expected
        self._append_result("PUT /Users/{id} → 501", success, response.status_code, detail)

    def _content_type_guard(self) -> None:
        headers = {**self._auth_headers(), "Content-Type": "application/json"}
        response = self.client.post(
            "/scim/v2/Users",
            data="{}",
            headers=headers,
        )
        body = response.get_json(silent=True) or {}
        detail = body.get("detail") or response.get_data(as_text=True)
        success = response.status_code == 415
        self._append_result("POST wrong Content-Type → 415", success, response.status_code, detail)

    def _missing_token_guard(self) -> None:
        response = self.client.get("/scim/v2/Users")
        body = response.get_json(silent=True) or {}
        detail = body.get("detail") or response.get_data(as_text=True)
        success = response.status_code == 401
        self._append_result("GET without token → 401", success, response.status_code, detail)

    def _invalid_token_guard(self) -> None:
        headers = {"Authorization": "Bearer invalid-token", "Accept": SCIM_MEDIA_TYPE}
        response = self.client.get(
            "/scim/v2/Users",
            headers=headers,
        )
        body = response.get_json(silent=True) or {}
        detail = body.get("detail") or response.get_data(as_text=True)
        success = response.status_code == 401
        self._append_result("GET with invalid token → 401", success, response.status_code, detail)

    def _insufficient_scope_guard(self) -> None:
        if not self.user_access_token:
            self._append_skipped("GET without SCIM scope → 403", "No end-user access token available")
            return

        headers = {
            "Authorization": f"Bearer {self.user_access_token}",
            "Accept": SCIM_MEDIA_TYPE,
        }
        response = self.client.get(
            "/scim/v2/Users",
            headers=headers,
        )
        body = response.get_json(silent=True) or {}
        detail = body.get("detail") or response.get_data(as_text=True)
        success = response.status_code == 403
        self._append_result("GET without SCIM scope → 403", success, response.status_code, detail)

    def _delete_user(self) -> None:
        if not self.created_user_id:
            self._append_result("DELETE /Users/{id}", False, None, "User creation failed; DELETE skipped")
            return

        headers = self._auth_headers()
        response = self.client.delete(
            f"/scim/v2/Users/{self.created_user_id}",
            headers=headers,
        )
        success = response.status_code == 204
        detail = f"status={response.status_code}"
        self.deleted = self.deleted or success
        self._append_result("DELETE /Users/{id}", success, response.status_code, detail)

    def _verify_audit_log(self) -> None:
        total, valid = audit.verify_audit_log()
        success = total == valid
        detail = f"{valid}/{total} signatures valid"
        self.results.append(CheckResult("Audit log signature verification", "success" if success else "failure", None, detail))

    def _cleanup(self) -> None:
        if not self.created_user_id or self.deleted:
            return
        try:
            headers = self._auth_headers()
            self.client.delete(
                f"/scim/v2/Users/{self.created_user_id}",
                headers=headers,
            )
        except Exception:
            pass


def _extract_user_access_token(cfg) -> Optional[str]:
    """Fetch an access token for an end-user (no SCIM scopes)."""
    token = session.get("token")
    access_token = token.get("access_token") if isinstance(token, dict) else None
    if access_token:
        return access_token

    if not cfg.demo_mode:
        return None

    demo_password = cfg.demo_passwords.get("ALICE")
    if not demo_password:
        return None

    data = {
        "grant_type": "password",
        "client_id": cfg.oidc_client_id,
        "username": "alice",
        "password": demo_password,
    }
    if cfg.oidc_client_secret:
        data["client_secret"] = cfg.oidc_client_secret

    try:
        response = requests.post(
            f"{cfg.keycloak_server_url}/protocol/openid-connect/token",
            data=data,
            timeout=REQUEST_TIMEOUT,
            verify=False,
        )
        response.raise_for_status()
        payload = response.json()
        return payload.get("access_token")
    except requests.RequestException:
        return None


# Add cleanup function
def cleanup_verifier_users():
    """Delete leftover verifier-* users. Safe: only touches users starting with 'verifier-'."""
    try:
        token = provisioning_service.get_service_token()
        # Use internal URL for verification tests (avoid nginx SSL from inside container)
        base_url = os.environ.get('VERIFICATION_BASE_URL', 'http://localhost:8000')
        
        # List all users and find verifier-* ones
        response = requests.get(
            f"{base_url}/scim/v2/Users",
            headers={"Authorization": f"Bearer {token}"},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code != 200:
            return 0
            
        data = response.json()
        cleaned = 0
        
        for user in data.get("Resources", []):
            username = user.get("userName", "")
            user_id = user.get("id", "")
            
            if _safe_username_check(username) and user_id:
                # Safe to delete - it's a verifier user
                try:
                    delete_resp = requests.delete(
                        f"{base_url}/scim/v2/Users/{user_id}",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=REQUEST_TIMEOUT,
                    )
                    if delete_resp.status_code in [204, 404]:  # Success or already gone
                        cleaned += 1
                except:
                    pass  # Ignore errors, this is cleanup
                    
        return cleaned
    except:
        return 0


@bp.route("/verification", methods=["GET", "POST"])
def verification_page():
    """SCIM verification page with access control."""
    print(f"[DEBUG] verification_page() called - method: {request.method}")
    print(f"[DEBUG] User-Agent: {request.headers.get('User-Agent', 'N/A')}")
    print(f"[DEBUG] IP: {request.remote_addr}")
    
    _check_access()  # Enforce access control
    
    # Rate limiting is handled by nginx (see proxy/nginx.conf)
    # No application-level rate limiting needed
    
    cfg = current_app.config["APP_CONFIG"]
    results: list[CheckResult] = []
    executed_at: Optional[str] = None
    overall_status = "success"
    cleanup_count = 0

    if request.method == "POST":
        action = request.form.get("action", "run")
        
        if action == "cleanup":
            cleanup_count = cleanup_verifier_users()
            executed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace('+00:00', 'Z')
            
            # SKIP if nothing to clean (no test users found), PASS if cleaned at least 1
            if cleanup_count == 0:
                results = [CheckResult(
                    name="Cleanup verifier users", 
                    status="skipped", 
                    status_code=200, 
                    detail="No verifier-* test users found (already cleaned or tests not yet run)"
                )]
            else:
                results = [CheckResult(
                    name="Cleanup verifier users", 
                    status="success", 
                    status_code=200, 
                    detail=f"Cleaned up {cleanup_count} verifier-* test user(s)"
                )]
        else:
            client = current_app.test_client()
            access_token = _extract_user_access_token(cfg)
            try:
                runner = VerificationRunner(client=client, user_access_token=access_token)
                results = runner.run()
                executed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace('+00:00', 'Z')
            except Exception as exc:  # pragma: no cover - defensive catch for UI
                executed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace('+00:00', 'Z')
                detail = str(exc)
                results = [CheckResult(name="Verification runner", status="failure", status_code=None, detail=detail)]

            # Determine overall status
            for item in results:
                if item.status == "failure":
                    overall_status = "failure"
                    break
            if overall_status == "success" and any(item.status == "skipped" for item in results):
                overall_status = "partial"

    return render_template(
        "verification.html",
        title="SCIM Verification",
        results=results,
        executed_at=executed_at,
        overall_status=overall_status,
        cleanup_count=cleanup_count,
        demo_mode=cfg.demo_mode,
        rate_limiting_available=RATE_LIMITING_AVAILABLE,
    )
