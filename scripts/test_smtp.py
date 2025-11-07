#!/usr/bin/env python3
"""
Quick SMTP connection test to verify credentials.
Run: docker-compose exec flask-app python3 scripts/test_smtp.py
"""
import smtplib
import os
import sys

# Load SMTP_PASSWORD from /run/secrets/smtp_password
SMTP_PASSWORD_FILE = "/run/secrets/smtp_password"
if os.path.exists(SMTP_PASSWORD_FILE):
    with open(SMTP_PASSWORD_FILE, "r") as f:
        SMTP_PASSWORD = f.read().strip()
else:
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)

print(f"🔧 Testing SMTP connection...")
print(f"   Host: {SMTP_HOST}:{SMTP_PORT}")
print(f"   User: {SMTP_USER}")
print(f"   From: {SMTP_FROM}")
print(f"   Password: {'✓ loaded' if SMTP_PASSWORD else '✗ missing'}")
print()

if not SMTP_USER or not SMTP_PASSWORD:
    print("❌ Missing SMTP_USER or SMTP_PASSWORD")
    sys.exit(1)

try:
    # Connect to SMTP server
    print("📡 Connecting to SMTP server...")
    server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
    server.set_debuglevel(0)  # Set to 1 for verbose output
    
    print("🔐 Starting TLS...")
    server.starttls()
    
    print("🔑 Authenticating...")
    server.login(SMTP_USER, SMTP_PASSWORD)
    
    print("✅ SMTP authentication successful!")
    print()
    print("📧 Your SMTP configuration is working correctly.")
    print("   Keycloak should be able to send password reset emails.")
    
    server.quit()
    sys.exit(0)
    
except smtplib.SMTPAuthenticationError as e:
    print(f"❌ Authentication failed: {e}")
    print()
    print("Possible causes:")
    print("  1. Wrong App Password (check Azure Key Vault: smtp-password)")
    print("  2. SMTP_USER doesn't match the Gmail account")
    print("  3. 2FA not enabled on Gmail account")
    print("  4. App Password was revoked")
    sys.exit(1)
    
except Exception as e:
    print(f"❌ Connection failed: {e}")
    print()
    print("Check:")
    print("  1. SMTP_HOST and SMTP_PORT are correct")
    print("  2. Network connectivity to Gmail SMTP server")
    sys.exit(1)
