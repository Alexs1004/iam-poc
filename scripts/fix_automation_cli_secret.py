#!/usr/bin/env python3
"""Script to update automation-cli secret in Keycloak."""
import requests
import sys
import os

def main():
    # Load admin password from Docker secret
    admin_password_file = "/run/secrets/keycloak_admin_password"
    if os.path.exists(admin_password_file):
        with open(admin_password_file) as f:
            admin_password = f.read().strip()
    else:
        admin_password = "admin"  # Fallback for demo mode
    
    # 1. Get admin token
    admin_token_resp = requests.post(
        "http://keycloak:8080/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": admin_password
        }
    )
    if admin_token_resp.status_code != 200:
        print(f"❌ Failed to get admin token: {admin_token_resp.text}")
        sys.exit(1)
    admin_token = admin_token_resp.json()["access_token"]
    print("✓ Got admin token")

    # 2. Get client UUID
    clients_resp = requests.get(
        "http://keycloak:8080/admin/realms/demo/clients?clientId=automation-cli",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    client_data = clients_resp.json()[0]
    client_uuid = client_data["id"]
    print(f"✓ Found automation-cli client: {client_uuid}")
    print(f"  Current secret: {client_data.get('secret', 'N/A')}")

    # 3. Update secret via PUT (modify client representation)
    client_data["secret"] = "demo-service-secret"
    update_resp = requests.put(
        f"http://keycloak:8080/admin/realms/demo/clients/{client_uuid}",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json"
        },
        json=client_data
    )
    if update_resp.status_code not in (200, 204):
        print(f"❌ Failed to update client: HTTP {update_resp.status_code}")
        print(f"   Response: {update_resp.text}")
        sys.exit(1)
    print(f"✓ Updated secret: HTTP {update_resp.status_code}")

    # 4. Test new secret
    test_resp = requests.post(
        "http://keycloak:8080/realms/demo/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "automation-cli",
            "client_secret": "demo-service-secret"
        }
    )
    if test_resp.status_code == 200:
        print("✅ SUCCESS! Token obtained with demo-service-secret")
        sys.exit(0)
    else:
        print(f"❌ FAILED: {test_resp.text}")
        sys.exit(1)

if __name__ == "__main__":
    main()
