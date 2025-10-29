"""Audit logging utilities for IAM operations (JML events)."""

from __future__ import annotations
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Literal

AUDIT_LOG_DIR = Path(os.environ.get("AUDIT_LOG_DIR", ".runtime/audit"))
_default_secret_paths: list[Path] = []
_env_secret_path_str = os.environ.get("AUDIT_LOG_SIGNING_KEY_FILE")
_env_secret_path: Path | None = None
if _env_secret_path_str:
    _env_secret_path = Path(_env_secret_path_str)
    _default_secret_paths.append(_env_secret_path)
_default_secret_paths.extend([
    Path(".runtime/secrets/audit_log_signing_key"),
    Path(".runtime/audit/audit_log_signing_key"),
])
AUDIT_LOG_FILE = AUDIT_LOG_DIR / "jml-events.jsonl"

def _get_signing_key() -> bytes:
    """Get the audit signing key from environment (loaded lazily to support Key Vault)."""
    if _env_secret_path and _env_secret_path.exists():
        try:
            return _env_secret_path.read_text(encoding="utf-8").strip().encode("utf-8")
        except OSError:
            pass
    if "AUDIT_LOG_SIGNING_KEY" in os.environ:
        key = os.environ.get("AUDIT_LOG_SIGNING_KEY", "")
        stripped = key.strip()
        if stripped:
            return stripped.encode("utf-8")
        return b""
    for path in _default_secret_paths:
        if not path:
            continue
        if path.exists():
            try:
                return path.read_text(encoding="utf-8").strip().encode("utf-8")
            except OSError:
                continue
    demo_default = os.environ.get("AUDIT_LOG_SIGNING_KEY_DEMO", "demo-audit-signing-key-change-in-production")
    if demo_default:
        return demo_default.encode("utf-8")
    return b""

EventType = Literal[
    "joiner", "mover", "leaver",
    "role_grant", "role_revoke", "session_revoke",
    # SCIM API operations
    "scim_create_user", "scim_change_role", "scim_disable_user", "scim_delete_user",
    "scim_patch_user_active"
]


def _ensure_audit_dir() -> None:
    """Create audit directory with restricted permissions."""
    AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_LOG_DIR.chmod(0o700)


def _sign_event(event: dict[str, Any]) -> str:
    """Generate HMAC-SHA256 signature for audit event."""
    signing_key = _get_signing_key()
    if not signing_key:
        return ""
    # Canonical JSON representation for signing
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return hmac.new(signing_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def log_jml_event(
    event_type: EventType,
    username: str,
    *,
    operator: str = "system",
    realm: str = "demo",
    details: dict[str, Any] | None = None,
    success: bool = True,
) -> None:
    """Log a JML event to the audit trail with timestamp and signature.
    
    Args:
        event_type: Type of JML operation (joiner, mover, leaver, etc.)
        username: Target username affected by the operation
        operator: Who performed the operation (user or system)
        realm: Keycloak realm where operation occurred
        details: Additional context (roles, attributes, etc.)
        success: Whether the operation succeeded
    """
    _ensure_audit_dir()
    
    event = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": event_type,
        "realm": realm,
        "username": username,
        "operator": operator,
        "success": success,
        "details": details or {},
    }
    
    signature = _sign_event(event)
    if signature:
        event["signature"] = signature
    
    # Append to JSONL file (one JSON object per line)
    with AUDIT_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    
    AUDIT_LOG_FILE.chmod(0o600)


def safe_log_jml_event(
    event_type: EventType,
    username: str,
    *,
    operator: str = "system",
    realm: str = "demo",
    details: dict[str, Any] | None = None,
    success: bool = True,
) -> bool:
    """Log JML event with automatic error handling (never raises exceptions).
    
    This is a safe wrapper around log_jml_event() that catches all exceptions
    and logs them to stderr instead of propagating them. Use this in production
    code where audit failures should not break application functionality.
    
    Args:
        event_type: Type of JML event (joiner, mover, leaver, etc.)
        username: Username affected by the event
        operator: Who triggered the event (username, "cli", "scim-api", etc.)
        realm: Keycloak realm where event occurred
        details: Additional event-specific metadata (optional)
        success: Whether the operation succeeded
        
    Returns:
        True if event was logged successfully, False if logging failed
        
    Note:
        Failures are logged to stderr but never raise exceptions
    """
    import sys
    try:
        log_jml_event(
            event_type,
            username,
            operator=operator,
            realm=realm,
            details=details,
            success=success
        )
        return True
    except Exception as e:
        print(
            f"[audit] Warning: Failed to log {event_type} event for {username}: {e}",
            file=sys.stderr
        )
        return False


def verify_audit_log() -> tuple[int, int]:
    """Verify all signatures in the audit log.
    
    Returns:
        Tuple of (total_events, valid_signatures)
    """
    if not AUDIT_LOG_FILE.exists():
        return 0, 0
    
    total = 0
    valid = 0
    
    with AUDIT_LOG_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            total += 1
            try:
                event = json.loads(line)
                stored_sig = event.pop("signature", "")
                if not stored_sig:
                    continue
                computed_sig = _sign_event(event)
                if hmac.compare_digest(stored_sig, computed_sig):
                    valid += 1
            except (json.JSONDecodeError, KeyError):
                continue
    
    return total, valid


if __name__ == "__main__":
    # Example verification command
    import sys
    total, valid = verify_audit_log()
    print(f"Audit log: {valid}/{total} events with valid signatures")
    sys.exit(0 if total == valid else 1)
