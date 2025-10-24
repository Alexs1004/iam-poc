#!/usr/bin/env python3
"""Test script to verify settings load correctly without calling Azure from container."""
import os
import sys

# Simulate production environment
os.environ["DEMO_MODE"] = "false"
os.environ["AZURE_USE_KEYVAULT"] = "true"
os.environ["KEYCLOAK_URL"] = "http://keycloak:8080"
os.environ["KEYCLOAK_REALM"] = "demo"
os.environ["KEYCLOAK_SERVICE_CLIENT_ID"] = "automation-cli"

# This should load secrets from /run/secrets (mounted from .runtime/secrets/)
try:
    from app.config.settings import load_settings
    settings = load_settings()
    print(f"✅ Settings loaded successfully!")
    print(f"   DEMO_MODE: {settings.demo_mode}")
    print(f"   Secret loaded: {settings.service_client_secret_resolved[:10]}..." if settings.service_client_secret_resolved else "   Secret: NONE")
    sys.exit(0)
except Exception as e:
    print(f"❌ Failed to load settings: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
