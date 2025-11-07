#!/usr/bin/env python3
"""
Configure SMTP settings in Keycloak realm for password reset emails.

This script configures Keycloak to send password reset emails when users are created
in production mode (DEMO_MODE=false).

Usage:
    # From host (loads .env + /run/secrets):
    python scripts/configure_smtp.py
    
    # From Docker container (secrets already loaded):
    docker-compose exec flask-app python scripts/configure_smtp.py

Environment variables required:
    SMTP_HOST: SMTP server (e.g., smtp.gmail.com, smtp.office365.com)
    SMTP_PORT: SMTP port (usually 587 for TLS)
    SMTP_USER: SMTP username/email
    SMTP_PASSWORD: SMTP password or app-specific password (loaded from Key Vault)
    SMTP_FROM: Email address for "From" field
    KEYCLOAK_URL: Keycloak base URL (default: http://localhost:8080)
    KEYCLOAK_REALM: Realm name (default: demo)
"""
import os
import sys
import requests

# Try to load SMTP_PASSWORD from /run/secrets/smtp_password (Docker secret pattern)
SMTP_PASSWORD_FILE = "/run/secrets/smtp_password"
if os.path.exists(SMTP_PASSWORD_FILE):
    with open(SMTP_PASSWORD_FILE, "r") as f:
        SMTP_PASSWORD = f.read().strip()
else:
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

# Load KEYCLOAK_ADMIN_PASSWORD from /run/secrets/keycloak_admin_password
KEYCLOAK_ADMIN_PASSWORD_FILE = "/run/secrets/keycloak_admin_password"
if os.path.exists(KEYCLOAK_ADMIN_PASSWORD_FILE):
    with open(KEYCLOAK_ADMIN_PASSWORD_FILE, "r") as f:
        KEYCLOAK_ADMIN_PASSWORD = f.read().strip()
else:
    KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin")

# Load environment variables
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "demo")
KEYCLOAK_ADMIN = os.getenv("KEYCLOAK_ADMIN", "admin")
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = os.getenv("SMTP_PORT", "587")
SMTP_USER = os.getenv("SMTP_USER")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
SMTP_REPLY_TO = os.getenv("SMTP_REPLY_TO", SMTP_FROM)

def get_admin_token():
    """Get admin token for Keycloak API."""
    response = requests.post(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data={
            "client_id": "admin-cli",
            "username": KEYCLOAK_ADMIN,
            "password": KEYCLOAK_ADMIN_PASSWORD,
            "grant_type": "password"
        }
    )
    response.raise_for_status()
    return response.json()["access_token"]


def configure_smtp():
    """Configure SMTP in Keycloak realm."""
    # Validate required environment variables
    required_vars = {
        "SMTP_HOST": SMTP_HOST,
        "SMTP_USER": SMTP_USER,
        "SMTP_PASSWORD": SMTP_PASSWORD,
    }
    
    missing = [var for var, value in required_vars.items() if not value]
    if missing:
        print(f"❌ Error: Missing required environment variables: {', '.join(missing)}")
        print("\nExample:")
        print("  export SMTP_HOST=smtp.gmail.com")
        print("  export SMTP_PORT=587")
        print("  export SMTP_USER=noreply@example.com")
        print("  export SMTP_PASSWORD='your-app-password'")
        print("  python scripts/configure_smtp.py")
        sys.exit(1)
    
    # SMTP configuration
    smtp_config = {
        "from": SMTP_FROM,
        "fromDisplayName": "IAM Platform",
        "replyTo": SMTP_REPLY_TO,
        "host": SMTP_HOST,
        "port": SMTP_PORT,
        "starttls": "true",
        "auth": "true",
        "user": SMTP_USER,
        "password": SMTP_PASSWORD
    }
    
    print(f"🔧 Configuring SMTP in Keycloak realm '{KEYCLOAK_REALM}'...")
    print(f"   Host: {SMTP_HOST}:{SMTP_PORT}")
    print(f"   From: {SMTP_FROM}")
    print(f"   User: {SMTP_USER}")
    
    # Get admin token
    try:
        token = get_admin_token()
    except Exception as e:
        print(f"❌ Failed to authenticate with Keycloak: {e}")
        print("\nMake sure Keycloak is running and credentials are correct:")
        print(f"   KEYCLOAK_ADMIN={KEYCLOAK_ADMIN}")
        print(f"   KEYCLOAK_ADMIN_PASSWORD=<loaded from {KEYCLOAK_ADMIN_PASSWORD_FILE if os.path.exists(KEYCLOAK_ADMIN_PASSWORD_FILE) else 'environment'}>")
        sys.exit(1)
    
    # Update realm with SMTP config
    try:
        response = requests.put(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}",
            headers={"Authorization": f"Bearer {token}"},
            json={"smtpServer": smtp_config}
        )
        response.raise_for_status()
        print("✅ SMTP configured successfully!")
        print("\n📧 Test the configuration:")
        print("   1. Create a user via UI (/admin/joiner)")
        print("   2. Check the user's email inbox for password reset link")
        print("\n⚠️  Note: Make sure DEMO_MODE=false in .env for production behavior")
    except requests.HTTPError as e:
        print(f"❌ Failed to configure SMTP: {e}")
        print(f"   Response: {e.response.text if e.response else 'No response'}")
        sys.exit(1)


if __name__ == "__main__":
    configure_smtp()
