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
AUDIT_LOG_FILE = AUDIT_LOG_DIR / "jml-events.jsonl"
AUDIT_SIGNING_KEY = os.environ.get("AUDIT_LOG_SIGNING_KEY", "").encode("utf-8")

EventType = Literal["joiner", "mover", "leaver", "role_grant", "role_revoke", "session_revoke"]


def _ensure_audit_dir() -> None:
    """Create audit directory with restricted permissions."""
    AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_LOG_DIR.chmod(0o700)


def _sign_event(event: dict[str, Any]) -> str:
    """Generate HMAC-SHA256 signature for audit event."""
    if not AUDIT_SIGNING_KEY:
        return ""
    # Canonical JSON representation for signing
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return hmac.new(AUDIT_SIGNING_KEY, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


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
