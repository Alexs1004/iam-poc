import argparse
import requests
import sys
import time

def get_admin_token(kc_url, username, password):
    url = f"{kc_url}/realms/master/protocol/openid-connect/token"
    data = {
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": username,
        "password": password,
    }
    resp = requests.post(url, data=data)
    resp.raise_for_status()
    return resp.json()["access_token"]

def realm_exists(kc_url, token, realm):
    r = requests.get(f"{kc_url}/admin/realms/{realm}", headers={"Authorization": f"Bearer {token}"})
    return r.status_code == 200

def create_realm(kc_url, token, realm):
    if realm_exists(kc_url, token, realm):
        print(f"[init] Realm '{realm}' already exists")
        return
    payload = {
        "realm": realm,
        "enabled": True
    }
    r = requests.post(f"{kc_url}/admin/realms", json=payload, headers={"Authorization": f"Bearer {token}"})
    if r.status_code in (201, 409):
        print(f"[init] Realm '{realm}' created (or already existed)")
    else:
        print(r.text)
        r.raise_for_status()

def create_client(kc_url, token, realm, client_id, redirect_uri):
    r = requests.get(f"{kc_url}/admin/realms/{realm}/clients", params={"clientId": client_id},
                     headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    if r.json():
        print(f"[init] Client '{client_id}' already exists")
        return
    payload = {
        "clientId": client_id,
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "redirectUris": [redirect_uri],
        "webOrigins": ["http://localhost:5000"],
        "attributes": {
            "post.logout.redirect.uris": "+"
        }
    }
    r = requests.post(f"{kc_url}/admin/realms/{realm}/clients", json=payload, headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    print(f"[init] Client '{client_id}' created")

def create_role(kc_url, token, realm, role_name):
    r = requests.get(f"{kc_url}/admin/realms/{realm}/roles/{role_name}", headers={"Authorization": f"Bearer {token}"})
    if r.status_code == 200:
        print(f"[init] Role '{role_name}' already exists")
        return
    payload = {"name": role_name}
    r = requests.post(f"{kc_url}/admin/realms/{realm}/roles", json=payload, headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    print(f"[init] Role '{role_name}' created")

def get_user_by_username(kc_url, token, realm, username):
    r = requests.get(f"{kc_url}/admin/realms/{realm}/users", params={"username": username},
                     headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    users = r.json()
    for u in users:
        if u.get("username") == username:
            return u
    return None

def create_user(kc_url, token, realm, username, email, first, last, temp_password, role):
    exists = get_user_by_username(kc_url, token, realm, username)
    if exists:
        print(f"[joiner] User '{username}' already exists")
        user_id = exists["id"]
    else:
        payload = {
            "username": username,
            "email": email,
            "firstName": first,
            "lastName": last,
            "enabled": True,
            "emailVerified": True,
            "requiredActions": ["CONFIGURE_TOTP", "UPDATE_PASSWORD"]
        }
        r = requests.post(f"{kc_url}/admin/realms/{realm}/users", json=payload, headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        time.sleep(0.5)
        user_id = get_user_by_username(kc_url, token, realm, username)["id"]
        print(f"[joiner] User '{username}' created (id={user_id})")

    r = requests.put(f"{kc_url}/admin/realms/{realm}/users/{user_id}/reset-password",
                     json={"type":"password","temporary":True,"value":temp_password},
                     headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    print(f"[joiner] Temp password set for '{username}'")

    rr = requests.get(f"{kc_url}/admin/realms/{realm}/roles/{role}", headers={"Authorization": f"Bearer {token}"})
    rr.raise_for_status()
    role_rep = rr.json()
    r = requests.post(f"{kc_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
                      json=[{"id": role_rep["id"], "name": role_rep["name"]}],
                      headers={"Authorization": f"Bearer {token}"})
    if r.status_code in (204, 201):
        print(f"[joiner] Assigned role '{role}' to '{username}'")
    else:
        print(r.text)
        r.raise_for_status()

def change_role(kc_url, token, realm, username, from_role, to_role):
    user = get_user_by_username(kc_url, token, realm, username)
    if not user:
        print(f"[mover] User '{username}' not found")
        sys.exit(1)
    user_id = user["id"]
    rr = requests.get(f"{kc_url}/admin/realms/{realm}/roles/{from_role}", headers={"Authorization": f"Bearer {token}"})
    rr.raise_for_status()
    r = requests.delete(f"{kc_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
                        json=[{"id": rr.json()["id"], "name": rr.json()["name"]}],
                        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    if r.status_code in (204, 404):
        print(f"[mover] Removed role '{from_role}' (if present)")
    rr = requests.get(f"{kc_url}/admin/realms/{realm}/roles/{to_role}", headers={"Authorization": f"Bearer {token}"})
    rr.raise_for_status()
    r = requests.post(f"{kc_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
                      json=[{"id": rr.json()["id"], "name": rr.json()["name"]}],
                      headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    r.raise_for_status()
    print(f"[mover] Added role '{to_role}' to '{username}'")

def disable_user(kc_url, token, realm, username):
    user = get_user_by_username(kc_url, token, realm, username)
    if not user:
        print(f"[leaver] User '{username}' not found")
        sys.exit(1)
    user_id = user["id"]
    user["enabled"] = False
    r = requests.put(f"{kc_url}/admin/realms/{realm}/users/{user_id}", json=user,
                     headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    print(f"[leaver] User '{username}' disabled")

def main():
    p = argparse.ArgumentParser(description="Keycloak JML helper")
    p.add_argument("--kc-url", default="http://localhost:8080", help="Keycloak base URL")
    p.add_argument("--admin-user", default="admin")
    p.add_argument("--admin-pass", default="admin")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("init")
    sp.add_argument("--realm", default="demo")
    sp.add_argument("--client-id", default="flask-app")
    sp.add_argument("--redirect-uri", default="http://localhost:5000/callback")

    sj = sub.add_parser("joiner")
    sj.add_argument("--realm", default="demo")
    sj.add_argument("--username", required=True)
    sj.add_argument("--email", required=True)
    sj.add_argument("--first", required=True)
    sj.add_argument("--last", required=True)
    sj.add_argument("--role", default="analyst")
    sj.add_argument("--temp-password", default="Passw0rd!")

    sm = sub.add_parser("mover")
    sm.add_argument("--realm", default="demo")
    sm.add_argument("--username", required=True)
    sm.add_argument("--from-role", required=True)
    sm.add_argument("--to-role", required=True)

    sl = sub.add_parser("leaver")
    sl.add_argument("--realm", default="demo")
    sl.add_argument("--username", required=True)

    args = p.parse_args()
    token = get_admin_token(args.kc_url, args.admin_user, args.admin_pass)

    if args.cmd == "init":
        create_realm(args.kc_url, token, args.realm)
        create_client(args.kc_url, token, args.realm, args.client_id, args.redirect_uri)
        for role in ["admin", "analyst"]:
            create_role(args.kc_url, token, args.realm, role)
    elif args.cmd == "joiner":
        create_user(args.kc_url, token, args.realm, args.username, args.email, args.first, args.last, args.temp_password, args.role)
    elif args.cmd == "mover":
        change_role(args.kc_url, token, args.realm, args.username, args.from_role, args.to_role)
    elif args.cmd == "leaver":
        disable_user(args.kc_url, token, args.realm, args.username)
    else:
        p.print_help()

if __name__ == "__main__":
    main()
