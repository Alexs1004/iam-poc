"""Unit tests for JML audit logging."""

import json
import os
import tempfile
from pathlib import Path

import pytest

# Import after modifying audit log path
from scripts import audit


@pytest.fixture
def temp_audit_dir(monkeypatch):
    """Provide isolated audit directory for each test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_dir = Path(tmpdir) / "audit"
        audit_file = audit_dir / "jml-events.jsonl"
        
        monkeypatch.setattr(audit, "AUDIT_LOG_DIR", audit_dir)
        monkeypatch.setattr(audit, "AUDIT_LOG_FILE", audit_file)
        
        # Set signing key for tests (loaded by _get_signing_key() from environment)
        test_key = "test-signing-key-for-audit-trail"
        monkeypatch.setenv("AUDIT_LOG_SIGNING_KEY", test_key)
        
        yield audit_dir, audit_file


def test_log_jml_event_creates_file(temp_audit_dir):
    """Test that logging creates the audit file."""
    _, audit_file = temp_audit_dir
    
    assert not audit_file.exists()
    
    audit.log_jml_event(
        "joiner",
        "testuser",
        operator="admin",
        realm="demo",
        details={"role": "analyst"},
        success=True,
    )
    
    assert audit_file.exists()
    assert audit_file.stat().st_mode & 0o777 == 0o600  # Check file permissions


def test_log_jml_event_creates_valid_json(temp_audit_dir):
    """Test that logged events are valid JSON."""
    _, audit_file = temp_audit_dir
    
    audit.log_jml_event(
        "mover",
        "alice",
        operator="system",
        realm="demo",
        details={"from_role": "analyst", "to_role": "admin"},
        success=True,
    )
    
    with audit_file.open("r") as f:
        line = f.readline()
        event = json.loads(line)
    
    assert event["event_type"] == "mover"
    assert event["username"] == "alice"
    assert event["operator"] == "system"
    assert event["success"] is True
    assert "timestamp" in event
    assert "signature" in event


def test_log_multiple_events(temp_audit_dir):
    """Test logging multiple events in sequence."""
    _, audit_file = temp_audit_dir
    
    events = [
        ("joiner", "alice", True),
        ("joiner", "bob", True),
        ("mover", "alice", True),
        ("leaver", "bob", True),
    ]
    
    for event_type, username, success in events:
        audit.log_jml_event(
            event_type,
            username,
            operator="test",
            realm="demo",
            success=success,
        )
    
    with audit_file.open("r") as f:
        lines = f.readlines()
    
    assert len(lines) == 4
    
    parsed_events = [json.loads(line) for line in lines]
    assert parsed_events[0]["username"] == "alice"
    assert parsed_events[1]["username"] == "bob"
    assert parsed_events[2]["event_type"] == "mover"
    assert parsed_events[3]["event_type"] == "leaver"


def test_verify_audit_log_with_valid_signatures(temp_audit_dir):
    """Test signature verification for valid events."""
    _, audit_file = temp_audit_dir
    
    # Log several events
    for i in range(5):
        audit.log_jml_event(
            "joiner",
            f"user{i}",
            operator="test",
            realm="demo",
            success=True,
        )
    
    total, valid = audit.verify_audit_log()
    assert total == 5
    assert valid == 5


def test_verify_audit_log_detects_tampering(temp_audit_dir):
    """Test that signature verification detects tampered events."""
    _, audit_file = temp_audit_dir
    
    # Log an event
    audit.log_jml_event(
        "joiner",
        "alice",
        operator="test",
        realm="demo",
        details={"role": "analyst"},
        success=True,
    )
    
    # Read and tamper with the event
    with audit_file.open("r") as f:
        event = json.loads(f.readline())
    
    # Modify the username without updating signature
    event["username"] = "mallory"
    
    # Overwrite file with tampered event
    with audit_file.open("w") as f:
        f.write(json.dumps(event) + "\n")
    
    # Verification should detect tampering
    total, valid = audit.verify_audit_log()
    assert total == 1
    assert valid == 0  # Signature invalid


def test_log_event_without_signing_key(temp_audit_dir, monkeypatch):
    """Test logging when no signing key is configured."""
    monkeypatch.setenv("AUDIT_LOG_SIGNING_KEY", "")
    
    _, audit_file = temp_audit_dir
    
    audit.log_jml_event(
        "joiner",
        "testuser",
        operator="test",
        realm="demo",
        success=True,
    )
    
    with audit_file.open("r") as f:
        event = json.loads(f.readline())
    
    # Should still log, but without signature
    assert "signature" not in event or event["signature"] == ""


def test_log_failed_operation(temp_audit_dir):
    """Test logging of failed operations."""
    _, audit_file = temp_audit_dir
    
    audit.log_jml_event(
        "joiner",
        "baduser",
        operator="test",
        realm="demo",
        details={"error": "Invalid email format"},
        success=False,
    )
    
    with audit_file.open("r") as f:
        event = json.loads(f.readline())
    
    assert event["success"] is False
    assert "error" in event["details"]


def test_audit_directory_permissions(temp_audit_dir):
    """Test that audit directory has restricted permissions."""
    audit_dir, _ = temp_audit_dir
    
    audit.log_jml_event("joiner", "test", success=True)
    
    # Check directory permissions (should be 700)
    assert audit_dir.stat().st_mode & 0o777 == 0o700


def test_verify_empty_audit_log(temp_audit_dir):
    """Test verification when no events exist."""
    total, valid = audit.verify_audit_log()
    assert total == 0
    assert valid == 0
