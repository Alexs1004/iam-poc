#!/usr/bin/env python3
"""
Test ensure-secrets behavior in different modes.
Tests the automatic secret clearing in production mode with Azure Key Vault.
"""
import os
import subprocess
import tempfile
import shutil
from pathlib import Path


def run_command(cmd: str, cwd: str) -> tuple[int, str, str]:
    """Run a shell command and return (exit_code, stdout, stderr)."""
    result = subprocess.run(
        cmd,
        shell=True,
        cwd=cwd,
        capture_output=True,
        text=True,
        executable="/bin/bash"
    )
    return result.returncode, result.stdout, result.stderr


def test_ensure_secrets_demo_mode():
    """Test that ensure-secrets generates secrets in demo mode."""
    print("\n🧪 Test 1: Demo mode with empty secrets")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy Makefile to temp dir
        shutil.copy("Makefile", tmpdir)
        
        # Create .env with demo mode and empty secrets
        env_content = """DEMO_MODE=true
AZURE_USE_KEYVAULT=false
FLASK_SECRET_KEY=
AUDIT_LOG_SIGNING_KEY=
"""
        Path(tmpdir, ".env").write_text(env_content)
        
        # Run ensure-secrets
        exit_code, stdout, stderr = run_command("make ensure-secrets 2>&1", tmpdir)
        output = stdout + stderr
        
        # Check results
        assert exit_code == 0, f"ensure-secrets failed: {output}"
        assert "Demo mode: checking secrets" in output, "Expected demo mode message"
        assert "Generated FLASK_SECRET_KEY" in output, "Expected secret generation"
        assert "Generated AUDIT_LOG_SIGNING_KEY" in output, "Expected audit key generation"
        
        # Verify secrets were generated
        env_after = Path(tmpdir, ".env").read_text()
        assert "FLASK_SECRET_KEY=" in env_after
        assert len([line for line in env_after.split("\n") if line.startswith("FLASK_SECRET_KEY=") and len(line) > 20]) > 0
        
        print("✅ Test 1 passed: Secrets generated in demo mode")


def test_ensure_secrets_production_with_keyvault():
    """Test that ensure-secrets clears secrets in production mode with Azure Key Vault."""
    print("\n🧪 Test 2: Production mode with Azure Key Vault")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy Makefile to temp dir
        shutil.copy("Makefile", tmpdir)
        
        # Create .env with production mode, Key Vault, and existing secrets
        env_content = """DEMO_MODE=false
AZURE_USE_KEYVAULT=true
AZURE_KEY_VAULT_NAME=my-test-vault
FLASK_SECRET_KEY=old-secret-value-to-be-cleared
AUDIT_LOG_SIGNING_KEY=old-audit-key-to-be-cleared
"""
        Path(tmpdir, ".env").write_text(env_content)
        
        # Run ensure-secrets
        exit_code, stdout, stderr = run_command("make ensure-secrets 2>&1", tmpdir)
        output = stdout + stderr
        
        # Check results
        assert exit_code == 0, f"ensure-secrets failed: {output}"
        assert "Production mode detected" in output, "Expected production mode message"
        assert "Azure Key Vault enabled: clearing local secrets" in output, "Expected clearing message"
        assert "FLASK_SECRET_KEY cleared" in output, "Expected Flask key cleared"
        assert "AUDIT_LOG_SIGNING_KEY cleared" in output, "Expected audit key cleared"
        
        # Verify secrets were cleared
        env_after = Path(tmpdir, ".env").read_text()
        assert "FLASK_SECRET_KEY=\n" in env_after or "FLASK_SECRET_KEY=old" not in env_after
        assert "AUDIT_LOG_SIGNING_KEY=\n" in env_after or "AUDIT_LOG_SIGNING_KEY=old" not in env_after
        
        # Verify they are empty (just the key name with = but no value)
        lines = env_after.split("\n")
        flask_line = [l for l in lines if l.startswith("FLASK_SECRET_KEY=")]
        audit_line = [l for l in lines if l.startswith("AUDIT_LOG_SIGNING_KEY=")]
        
        assert len(flask_line) == 1 and flask_line[0] == "FLASK_SECRET_KEY=", f"Flask key not empty: {flask_line}"
        assert len(audit_line) == 1 and audit_line[0] == "AUDIT_LOG_SIGNING_KEY=", f"Audit key not empty: {audit_line}"
        
        print("✅ Test 2 passed: Secrets cleared in production mode with Key Vault")


def test_ensure_secrets_production_without_keyvault():
    """Test that ensure-secrets warns in production mode without Azure Key Vault."""
    print("\n🧪 Test 3: Production mode without Azure Key Vault")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy Makefile to temp dir
        shutil.copy("Makefile", tmpdir)
        
        # Create .env with production mode but no Key Vault
        env_content = """DEMO_MODE=false
AZURE_USE_KEYVAULT=false
FLASK_SECRET_KEY=manual-secret-123
AUDIT_LOG_SIGNING_KEY=manual-audit-456
"""
        Path(tmpdir, ".env").write_text(env_content)
        
        # Run ensure-secrets
        exit_code, stdout, stderr = run_command("make ensure-secrets 2>&1", tmpdir)
        output = stdout + stderr
        
        # Check results
        assert exit_code == 0, f"ensure-secrets failed: {output}"
        assert "Production mode detected" in output, "Expected production mode message"
        assert "WARNING: Production mode without Azure Key Vault" in output, "Expected warning"
        assert "You must manually set FLASK_SECRET_KEY and AUDIT_LOG_SIGNING_KEY" in output, "Expected manual instruction"
        
        # Verify secrets were NOT changed
        env_after = Path(tmpdir, ".env").read_text()
        assert "FLASK_SECRET_KEY=manual-secret-123" in env_after, "Secret should not be changed"
        assert "AUDIT_LOG_SIGNING_KEY=manual-audit-456" in env_after, "Audit key should not be changed"
        
        print("✅ Test 3 passed: Warning shown, secrets unchanged")


def test_ensure_secrets_idempotent():
    """Test that ensure-secrets is idempotent (safe to run multiple times)."""
    print("\n🧪 Test 4: Idempotent behavior in demo mode")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy Makefile to temp dir
        shutil.copy("Makefile", tmpdir)
        
        # Create .env with demo mode and empty secrets
        env_content = """DEMO_MODE=true
AZURE_USE_KEYVAULT=false
FLASK_SECRET_KEY=
AUDIT_LOG_SIGNING_KEY=
"""
        Path(tmpdir, ".env").write_text(env_content)
        
        # Run ensure-secrets first time
        exit_code1, stdout1, stderr1 = run_command("make ensure-secrets 2>&1", tmpdir)
        output1 = stdout1 + stderr1
        assert exit_code1 == 0
        assert "Generated FLASK_SECRET_KEY" in output1
        
        env_after_first = Path(tmpdir, ".env").read_text()
        
        # Run ensure-secrets second time
        exit_code2, stdout2, stderr2 = run_command("make ensure-secrets 2>&1", tmpdir)
        output2 = stdout2 + stderr2
        assert exit_code2 == 0
        assert "FLASK_SECRET_KEY already set" in output2, "Should detect existing secret"
        assert "Generated FLASK_SECRET_KEY" not in output2, "Should not regenerate"
        
        env_after_second = Path(tmpdir, ".env").read_text()
        
        # Verify secrets unchanged
        assert env_after_first == env_after_second, "Secrets should not change on second run"
        
        print("✅ Test 4 passed: Idempotent behavior confirmed")


if __name__ == "__main__":
    print("=" * 60)
    print("Testing ensure-secrets behavior")
    print("=" * 60)
    
    try:
        test_ensure_secrets_demo_mode()
        test_ensure_secrets_production_with_keyvault()
        test_ensure_secrets_production_without_keyvault()
        test_ensure_secrets_idempotent()
        
        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        exit(1)
