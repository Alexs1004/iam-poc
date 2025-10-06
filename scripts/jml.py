import argparse
import sys
import time

import requests

def _auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


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
    r = requests.get(f"{kc_url}/admin/realms/{realm}", headers=_auth_headers(token))
    return r.status_code == 200

def create_realm(kc_url, token, realm):
    if realm_exists(kc_url, token, realm):
        print(f"[init] Realm '{realm}' already exists")
        return
    payload = {
        "realm": realm,
        "enabled": True
    }
    r = requests.post(f"{kc_url}/admin/realms", json=payload, headers=_auth_headers(token))
    if r.status_code in (201, 409):
        print(f"[init] Realm '{realm}' created (or already existed)")
    else:
        print(r.text)
        r.raise_for_status()

def create_client(kc_url, token, realm, client_id, redirect_uri):
    r = requests.get(
        f"{kc_url}/admin/realms/{realm}/clients",
        params={"clientId": client_id},
        headers=_auth_headers(token),
    )
    r.raise_for_status()
    existing = r.json()
    desired_logout = "http://localhost:5000/"
    desired_redirects = [redirect_uri]
    desired_web_origins = ["http://localhost:5000"]
    if existing:
        client = existing[0]
        client_uuid = client.get("id")
        needs_update = False
        update_payload = {"clientId": client_id}

        current_redirects = sorted(client.get("redirectUris") or [])
        if sorted(desired_redirects) != current_redirects:
            needs_update = True
            update_payload["redirectUris"] = desired_redirects

        current_web_origins = sorted(client.get("webOrigins") or [])
        if sorted(desired_web_origins) != current_web_origins:
            needs_update = True
            update_payload["webOrigins"] = desired_web_origins

        current_attrs = client.get("attributes") or {}
        if current_attrs.get("post.logout.redirect.uris") != desired_logout:
            needs_update = True
            current_attrs["post.logout.redirect.uris"] = desired_logout
            update_payload["attributes"] = current_attrs

        if needs_update and client_uuid:
            put = requests.put(
                f"{kc_url}/admin/realms/{realm}/clients/{client_uuid}",
                json=update_payload,
                headers={**_auth_headers(token), "Content-Type": "application/json"},
            )
            put.raise_for_status()
            print(f"[init] Client '{client_id}' updated")
        else:
            print(f"[init] Client '{client_id}' already configured")
        return
    payload = {
        "clientId": client_id,
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "redirectUris": desired_redirects,
        "webOrigins": desired_web_origins,
        "attributes": {
            # newline separated allowed URIs; we stick to the Flask dev origin
            "post.logout.redirect.uris": desired_logout
        },
        "defaultClientScopes": ["profile", "email", "roles", "web-origins", "role_list"],
    }
    r = requests.post(
        f"{kc_url}/admin/realms/{realm}/clients",
        json=payload,
        headers=_auth_headers(token),
    )
    r.raise_for_status()
    print(f"[init] Client '{client_id}' created")

def create_role(kc_url, token, realm, role_name):
    r = requests.get(
        f"{kc_url}/admin/realms/{realm}/roles/{role_name}",
        headers=_auth_headers(token),
    )
    if r.status_code == 200:
        print(f"[init] Role '{role_name}' already exists")
        return
    payload = {"name": role_name}
    r = requests.post(
        f"{kc_url}/admin/realms/{realm}/roles",
        json=payload,
        headers=_auth_headers(token),
    )
    r.raise_for_status()
    print(f"[init] Role '{role_name}' created")


def ensure_required_action(kc_url, token, realm, alias):
    url = f"{kc_url}/admin/realms/{realm}/authentication/required-actions"
    r = requests.get(url, headers=_auth_headers(token))
    r.raise_for_status()
    actions = r.json()
    target = next((act for act in actions if act.get("alias") == alias), None)
    if not target:
        print(f"[init] Required action '{alias}' not found; please verify Keycloak configuration")
        return
    if target.get("enabled") and target.get("defaultAction"):
        print(f"[init] Required action '{alias}' already enforced")
        return
    update = {
        "alias": target.get("alias"),
        "name": target.get("name"),
        "providerId": target.get("providerId"),
        "defaultAction": True,
        "enabled": True,
        "priority": target.get("priority", 0),
        "config": target.get("config", {}),
    }
    put = requests.put(
        f"{url}/{alias}",
        json=update,
        headers={**_auth_headers(token), "Content-Type": "application/json"},
    )
    if put.status_code in (200, 204):
        print(f"[init] Required action '{alias}' enforced (enabled + default)")
    else:
        print(put.text)
        put.raise_for_status()


def ensure_user_required_actions(kc_url, token, realm, user_id, actions):
    url = f"{kc_url}/admin/realms/{realm}/users/{user_id}"
    r = requests.get(url, headers=_auth_headers(token))
    r.raise_for_status()
    user_rep = r.json()
    existing = set(user_rep.get("requiredActions") or [])
    desired = set(actions)
    if desired.issubset(existing):
        return
    user_rep["requiredActions"] = sorted(existing.union(desired))
    put = requests.put(
        url,
        json=user_rep,
        headers={**_auth_headers(token), "Content-Type": "application/json"},
    )
    put.raise_for_status()
    print(f"[joiner] Required actions set to {user_rep['requiredActions']}")

def get_user_by_username(kc_url, token, realm, username):
    r = requests.get(
        f"{kc_url}/admin/realms/{realm}/users",
        params={"username": username},
        headers=_auth_headers(token),
    )
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
        r = requests.post(
            f"{kc_url}/admin/realms/{realm}/users",
            json=payload,
            headers=_auth_headers(token),
        )
        r.raise_for_status()
        time.sleep(0.5)
        user_id = get_user_by_username(kc_url, token, realm, username)["id"]
        print(f"[joiner] User '{username}' created (id={user_id})")

    ensure_user_required_actions(kc_url, token, realm, user_id, ["CONFIGURE_TOTP", "UPDATE_PASSWORD"])

    r = requests.put(
        f"{kc_url}/admin/realms/{realm}/users/{user_id}/reset-password",
        json={"type": "password", "temporary": True, "value": temp_password},
        headers={**_auth_headers(token), "Content-Type": "application/json"},
    )
    r.raise_for_status()
    print(f"[joiner] Temp password set for '{username}'")

    rr = requests.get(
        f"{kc_url}/admin/realms/{realm}/roles/{role}",
        headers=_auth_headers(token),
    )
    rr.raise_for_status()
    role_rep = rr.json()
    r = requests.post(
        f"{kc_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
        json=[{"id": role_rep["id"], "name": role_rep["name"]}],
        headers={**_auth_headers(token), "Content-Type": "application/json"},
    )
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
    rr = requests.get(
        f"{kc_url}/admin/realms/{realm}/roles/{from_role}",
        headers=_auth_headers(token),
    )
    rr.raise_for_status()
    r = requests.delete(
        f"{kc_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
        json=[{"id": rr.json()["id"], "name": rr.json()["name"]}],
        headers={**_auth_headers(token), "Content-Type": "application/json"},
    )
    if r.status_code in (204, 404):
        print(f"[mover] Removed role '{from_role}' (if present)")
    rr = requests.get(
        f"{kc_url}/admin/realms/{realm}/roles/{to_role}",
        headers=_auth_headers(token),
    )
    rr.raise_for_status()
    r = requests.post(
        f"{kc_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
        json=[{"id": rr.json()["id"], "name": rr.json()["name"]}],
        headers={**_auth_headers(token), "Content-Type": "application/json"},
    )
    r.raise_for_status()
    print(f"[mover] Added role '{to_role}' to '{username}'")

def disable_user(kc_url, token, realm, username):
    user = get_user_by_username(kc_url, token, realm, username)
    if not user:
        print(f"[leaver] User '{username}' not found")
        sys.exit(1)
    user_id = user["id"]
    user["enabled"] = False
    r = requests.put(
        f"{kc_url}/admin/realms/{realm}/users/{user_id}",
        json=user,
        headers={**_auth_headers(token), "Content-Type": "application/json"},
    )
    r.raise_for_status()
    print(f"[leaver] User '{username}' disabled")

def main():
    p = argparse.ArgumentParser(description="Keycloak JML helper")
    p.add_argument("--kc-url", default="http://localhost:8081", help="Keycloak base URL")
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
        ensure_required_action(args.kc_url, token, args.realm, "CONFIGURE_TOTP")
        ensure_required_action(args.kc_url, token, args.realm, "UPDATE_PASSWORD")
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
