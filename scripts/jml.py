from __future__ import annotations
import argparse
import os
import sys
import time

import requests

REQUEST_TIMEOUT = 5


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def get_admin_token(kc_url: str, username: str, password: str, realm: str = "master") -> str:
    url = f"{kc_url}/realms/{realm}/protocol/openid-connect/token"
    data = {
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": username,
        "password": password,
    }
    resp = requests.post(url, data=data, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_service_account_token(kc_url: str, auth_realm: str, client_id: str, client_secret: str) -> str:
    url = f"{kc_url}/realms/{auth_realm}/protocol/openid-connect/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    resp = requests.post(url, data=data, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    return resp.json()["access_token"]


def _get_client(kc_url: str, token: str, realm: str, client_id: str) -> dict | None:
    resp = requests.get(
        f"{kc_url}/admin/realms/{realm}/clients",
        params={"clientId": client_id},
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    clients = resp.json()
    return clients[0] if clients else None


def realm_exists(kc_url: str, token: str, realm: str) -> bool:
    resp = requests.get(
        f"{kc_url}/admin/realms/{realm}",
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    return resp.status_code == 200


def create_realm(kc_url: str, token: str, realm: str) -> None:
    if realm_exists(kc_url, token, realm):
        print(f"[init] Realm '{realm}' already exists", file=sys.stderr)
        return
    payload = {"realm": realm, "enabled": True}
    resp = requests.post(
        f"{kc_url}/admin/realms",
        json=payload,
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code in (201, 409):
        print(f"[init] Realm '{realm}' created (or already existed)", file=sys.stderr)
    elif resp.status_code == 403:
        raise SystemExit("[init] Missing permission to create realm. Run bootstrap-service-account from master realm first.")
    else:
        print(resp.text)
        resp.raise_for_status()


def create_client(kc_url: str, token: str, realm: str, client_id: str, redirect_uri: str) -> None:
    resp = requests.get(
        f"{kc_url}/admin/realms/{realm}/clients",
        params={"clientId": client_id},
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    existing = resp.json()
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
                headers=_auth_headers(token),
                timeout=REQUEST_TIMEOUT,
            )
            put.raise_for_status()
            print(f"[init] Client '{client_id}' updated", file=sys.stderr)
        else:
            print(f"[init] Client '{client_id}' already configured", file=sys.stderr)
        return
    payload = {
        "clientId": client_id,
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "redirectUris": desired_redirects,
        "webOrigins": desired_web_origins,
        "attributes": {
            "post.logout.redirect.uris": desired_logout
        },
        "defaultClientScopes": ["profile", "email", "roles", "web-origins", "role_list"],
    }
    resp = requests.post(
        f"{kc_url}/admin/realms/{realm}/clients",
        json=payload,
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    print(f"[init] Client '{client_id}' created", file=sys.stderr)


def create_role(kc_url: str, token: str, realm: str, role_name: str) -> None:
    resp = requests.get(
        f"{kc_url}/admin/realms/{realm}/roles/{role_name}",
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code == 200:
        print(f"[init] Role '{role_name}' already exists", file=sys.stderr)
        return
    payload = {"name": role_name}
    resp = requests.post(
        f"{kc_url}/admin/realms/{realm}/roles",
        json=payload,
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    print(f"[init] Role '{role_name}' created", file=sys.stderr)


def ensure_required_action(kc_url: str, token: str, realm: str, alias: str) -> None:
    url = f"{kc_url}/admin/realms/{realm}/authentication/required-actions"
    resp = requests.get(url, headers=_auth_headers(token), timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    actions = resp.json()
    target = next((act for act in actions if act.get("alias") == alias), None)
    if not target:
        print(f"[init] Required action '{alias}' not found; please verify Keycloak configuration", file=sys.stderr)
        return
    if target.get("enabled") and target.get("defaultAction"):
        print(f"[init] Required action '{alias}' already enforced", file=sys.stderr)
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
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    if put.status_code in (200, 204):
        print(f"[init] Required action '{alias}' enforced (enabled + default)", file=sys.stderr)
    else:
        print(put.text)
        put.raise_for_status()


def ensure_user_required_actions(kc_url: str, token: str, realm: str, user_id: str, actions: list[str]) -> None:
    url = f"{kc_url}/admin/realms/{realm}/users/{user_id}"
    resp = requests.get(url, headers=_auth_headers(token), timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    user_rep = resp.json()
    existing = set(user_rep.get("requiredActions") or [])
    desired = set(actions)
    if desired.issubset(existing):
        return
    user_rep["requiredActions"] = sorted(existing.union(desired))
    put = requests.put(
        url,
        json=user_rep,
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    put.raise_for_status()
    print(f"[joiner] Required actions set to {user_rep['requiredActions']}", file=sys.stderr)




def _user_has_totp(kc_url: str, token: str, realm: str, user_id: str) -> bool:
    cred_resp = requests.get(
        f"{kc_url}/admin/realms/{realm}/users/{user_id}/credentials",
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    cred_resp.raise_for_status()
    return any(cred.get("type") == "otp" for cred in cred_resp.json() or [])


def _desired_required_actions(kc_url: str, token: str, realm: str, user_id: str) -> list[str]:
    actions = {"UPDATE_PASSWORD"}
    if not _user_has_totp(kc_url, token, realm, user_id):
        actions.add("CONFIGURE_TOTP")
    return sorted(actions)


def get_user_by_username(kc_url: str, token: str, realm: str, username: str) -> dict | None:
    resp = requests.get(
        f"{kc_url}/admin/realms/{realm}/users",
        params={"username": username},
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    for user in resp.json():
        if user.get("username") == username:
            return user
    return None


def create_user(
    kc_url: str,
    token: str,
    realm: str,
    username: str,
    email: str,
    first: str,
    last: str,
    temp_password: str,
    role: str,
) -> None:
    exists = get_user_by_username(kc_url, token, realm, username)
    if exists:
        print(f"[joiner] User '{username}' already exists", file=sys.stderr)
        user_id = exists["id"]
    else:
        payload = {
            "username": username,
            "email": email,
            "firstName": first,
            "lastName": last,
            "enabled": True,
            "emailVerified": True,
        }
        resp = requests.post(
            f"{kc_url}/admin/realms/{realm}/users",
            json=payload,
            headers=_auth_headers(token),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        time.sleep(0.5)
        user_id = get_user_by_username(kc_url, token, realm, username)["id"]
        print(f"[joiner] User '{username}' created (id={user_id})", file=sys.stderr)

    ensure_user_required_actions(kc_url, token, realm, user_id, _desired_required_actions(kc_url, token, realm, user_id))

    resp = requests.put(
        f"{kc_url}/admin/realms/{realm}/users/{user_id}/reset-password",
        json={"type": "password", "temporary": True, "value": temp_password},
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    print(f"[joiner] Temp password set for '{username}'", file=sys.stderr)

    role_lookup = requests.get(
        f"{kc_url}/admin/realms/{realm}/roles/{role}",
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    role_lookup.raise_for_status()
    role_rep = role_lookup.json()
    resp = requests.post(
        f"{kc_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
        json=[{"id": role_rep["id"], "name": role_rep["name"]}],
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code in (204, 201):
        print(f"[joiner] Assigned role '{role}' to '{username}'", file=sys.stderr)
    else:
        print(resp.text)
        resp.raise_for_status()


def change_role(kc_url: str, token: str, realm: str, username: str, from_role: str, to_role: str) -> None:
    user = get_user_by_username(kc_url, token, realm, username)
    if not user:
        print(f"[mover] User '{username}' not found", file=sys.stderr)
        sys.exit(1)
    user_id = user["id"]
    current_role = requests.get(
        f"{kc_url}/admin/realms/{realm}/roles/{from_role}",
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    current_role.raise_for_status()
    resp = requests.delete(
        f"{kc_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
        json=[{"id": current_role.json()["id"], "name": current_role.json()["name"]}],
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code in (204, 404):
        print(f"[mover] Removed role '{from_role}' (if present)", file=sys.stderr)
    target_role = requests.get(
        f"{kc_url}/admin/realms/{realm}/roles/{to_role}",
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    target_role.raise_for_status()
    resp = requests.post(
        f"{kc_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
        json=[{"id": target_role.json()["id"], "name": target_role.json()["name"]}],
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    print(f"[mover] Added role '{to_role}' to '{username}'", file=sys.stderr)


def disable_user(kc_url: str, token: str, realm: str, username: str) -> None:
    user = get_user_by_username(kc_url, token, realm, username)
    if not user:
        print(f"[leaver] User '{username}' not found", file=sys.stderr)
        sys.exit(1)
    user_id = user["id"]
    user["enabled"] = False
    resp = requests.put(
        f"{kc_url}/admin/realms/{realm}/users/{user_id}",
        json=user,
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    print(f"[leaver] User '{username}' disabled", file=sys.stderr)


def delete_realm(kc_url: str, token: str, realm: str) -> None:
    if realm == "master":
        print("[reset] Refusing to delete the master realm", file=sys.stderr)
        return
    resp = requests.delete(
        f"{kc_url}/admin/realms/{realm}",
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code == 204:
        print(f"[reset] Realm '{realm}' deleted", file=sys.stderr)
        return
    if resp.status_code == 404:
        print(f"[reset] Realm '{realm}' not found", file=sys.stderr)
        return
    try:
        details = resp.json()
    except ValueError:
        details = resp.text
    print(f"[reset] Failed to delete realm '{realm}': {details}", file=sys.stderr)
    resp.raise_for_status()


def _ensure_service_account_client(kc_url: str, token: str, realm: str, client_id: str) -> tuple[str, str]:
    client = _get_client(kc_url, token, realm, client_id)
    if not client:
        payload = {
            "clientId": client_id,
            "protocol": "openid-connect",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "clientAuthenticatorType": "client-secret",
        }
        resp = requests.post(
            f"{kc_url}/admin/realms/{realm}/clients",
            json=payload,
            headers=_auth_headers(token),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        client = _get_client(kc_url, token, realm, client_id)
        print(f"[bootstrap] Client '{client_id}' created in realm '{realm}'", file=sys.stderr)

    client_uuid = client.get("id")
    if not client_uuid:
        raise RuntimeError("Unable to resolve client UUID for service account")

    desired_flags = {
        "serviceAccountsEnabled": True,
        "publicClient": False,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "clientAuthenticatorType": "client-secret",
        "protocol": client.get("protocol") or "openid-connect",
    }
    updated = False
    for key, desired in desired_flags.items():
        if client.get(key) != desired:
            client[key] = desired
            updated = True
    if updated:
        put = requests.put(
            f"{kc_url}/admin/realms/{realm}/clients/{client_uuid}",
            json=client,
            headers=_auth_headers(token),
            timeout=REQUEST_TIMEOUT,
        )
        put.raise_for_status()
        client = _get_client(kc_url, token, realm, client_id)
        print(f"[bootstrap] Client '{client_id}' updated for service accounts", file=sys.stderr)

    secret_resp = requests.post(
        f"{kc_url}/admin/realms/{realm}/clients/{client_uuid}/client-secret",
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    secret_resp.raise_for_status()
    secret = secret_resp.json().get("value")
    if not secret:
        raise RuntimeError("Failed to retrieve service account secret")
    print("[bootstrap] Client secret rotated; update your environment variables.", file=sys.stderr)
    return client_uuid, secret


def _assign_service_account_roles(
    kc_url: str,
    token: str,
    realm: str,
    client_uuid: str,
    role_names: list[str],
) -> None:
    svc_user_resp = requests.get(
        f"{kc_url}/admin/realms/{realm}/clients/{client_uuid}/service-account-user",
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    svc_user_resp.raise_for_status()
    svc_user = svc_user_resp.json()
    svc_user_id = svc_user["id"]

    realm_mgmt_client = _get_client(kc_url, token, realm, "realm-management")
    if not realm_mgmt_client:
        print(f"[bootstrap] realm-management client missing in realm '{realm}'", file=sys.stderr)
        return
    realm_mgmt_uuid = realm_mgmt_client["id"]

    existing_resp = requests.get(
        f"{kc_url}/admin/realms/{realm}/users/{svc_user_id}/role-mappings/clients/{realm_mgmt_uuid}",
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    existing_resp.raise_for_status()
    existing = {role["name"] for role in existing_resp.json()}

    to_add = []
    for role_name in role_names:
        if role_name in existing:
            continue
        role_resp = requests.get(
            f"{kc_url}/admin/realms/{realm}/clients/{realm_mgmt_uuid}/roles/{role_name}",
            headers=_auth_headers(token),
            timeout=REQUEST_TIMEOUT,
        )
        if role_resp.status_code == 404:
            print(f"[bootstrap] Role '{role_name}' not found in realm-management", file=sys.stderr)
            continue
        role_resp.raise_for_status()
        to_add.append(role_resp.json())

    if not to_add:
        print(f"[bootstrap] Service account already holds required roles", file=sys.stderr)
        return

    assign_resp = requests.post(
        f"{kc_url}/admin/realms/{realm}/users/{svc_user_id}/role-mappings/clients/{realm_mgmt_uuid}",
        json=to_add,
        headers=_auth_headers(token),
        timeout=REQUEST_TIMEOUT,
    )
    assign_resp.raise_for_status()
    print(
        f"[bootstrap] Assigned roles {sorted(role['name'] for role in to_add)} to service account",
        file=sys.stderr,
    )


def bootstrap_service_account(
    kc_url: str,
    admin_user: str,
    admin_pass: str,
    svc_realm: str,
    svc_client_id: str,
    target_realm: str,
    role_names: list[str],
) -> str:
    if svc_realm != "master":
        raise SystemExit("bootstrap-service-account requires --auth-realm master for admin login")
    try:
        admin_token = get_admin_token(kc_url, admin_user, admin_pass)
    except requests.HTTPError as exc:
        raise SystemExit(f"[bootstrap] Admin authentication failed: {exc}") from exc
    try:
        create_realm(kc_url, admin_token, target_realm)
        client_uuid, secret = _ensure_service_account_client(kc_url, admin_token, target_realm, svc_client_id)
        _assign_service_account_roles(kc_url, admin_token, target_realm, client_uuid, role_names)
    except requests.HTTPError as exc:
        detail = exc.response.text if exc.response is not None else str(exc)
        raise SystemExit(f"[bootstrap] Failed to configure service account: {detail}") from exc
    return secret


def main() -> None:
    parser = argparse.ArgumentParser(description="Keycloak JML helper")
    parser.add_argument("--kc-url", default="http://localhost:8080", help="Keycloak base URL")
    parser.add_argument(
        "--auth-realm",
        default=os.environ.get("KEYCLOAK_SERVICE_REALM", "master"),
        help="Realm that hosts the service account client (default: master)",
    )
    parser.add_argument(
        "--svc-client-id",
        default=os.environ.get("KEYCLOAK_SERVICE_CLIENT_ID", "automation-cli"),
        help="Service account client ID (default: automation-cli)",
    )
    parser.add_argument(
        "--svc-client-secret",
        default=os.environ.get("KEYCLOAK_SERVICE_CLIENT_SECRET"),
        help="Service account client secret (or set KEYCLOAK_SERVICE_CLIENT_SECRET)",
    )

    sub = parser.add_subparsers(dest="cmd")

    bootstrap = sub.add_parser("bootstrap-service-account", help="One-time setup (requires master admin credentials)")
    bootstrap.add_argument("--realm", default=os.environ.get("KEYCLOAK_REALM", "demo"))
    bootstrap.add_argument("--admin-user", default=os.environ.get("KEYCLOAK_ADMIN", "admin"))
    bootstrap.add_argument("--admin-pass", default=os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"))
    bootstrap.add_argument(
        "--roles",
        nargs="*",
        default=[
            "manage-realm",
            "manage-users",
            "manage-clients",
        ],
        help="realm-management roles to grant to the service account",
    )

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

    dr = sub.add_parser("delete-realm", help="Delete a realm (use with caution)")
    dr.add_argument("--realm", required=True)

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        return

    if args.cmd == "bootstrap-service-account":
        if not args.admin_user or not args.admin_pass:
            parser.error("Admin credentials required for bootstrap-service-account")
        secret = bootstrap_service_account(
            args.kc_url,
            args.admin_user,
            args.admin_pass,
            args.auth_realm,
            args.svc_client_id,
            args.realm,
            args.roles,
        )
        # Emit the secret on stdout so callers (e.g., demo_jml.sh) can capture it.
        print(secret)
        return

    if not args.svc_client_secret:
        parser.error("Missing service account secret. Provide --svc-client-secret or set KEYCLOAK_SERVICE_CLIENT_SECRET.")

    target_realm = getattr(args, "realm", None)
    if not target_realm:
        parser.error("Command requires --realm")

    token = get_service_account_token(
        args.kc_url,
        args.auth_realm,
        args.svc_client_id,
        args.svc_client_secret,
    )

    if args.cmd == "init":
        create_realm(args.kc_url, token, target_realm)
        create_client(args.kc_url, token, target_realm, args.client_id, args.redirect_uri)
        for role in ["admin", "analyst"]:
            create_role(args.kc_url, token, target_realm, role)
        ensure_required_action(args.kc_url, token, target_realm, "CONFIGURE_TOTP")
        ensure_required_action(args.kc_url, token, target_realm, "UPDATE_PASSWORD")
    elif args.cmd == "joiner":
        create_user(
            args.kc_url,
            token,
            target_realm,
            args.username,
            args.email,
            args.first,
            args.last,
            args.temp_password,
            args.role,
        )
    elif args.cmd == "mover":
        change_role(args.kc_url, token, target_realm, args.username, args.from_role, args.to_role)
    elif args.cmd == "leaver":
        disable_user(args.kc_url, token, target_realm, args.username)
    elif args.cmd == "delete-realm":
        delete_realm(args.kc_url, token, target_realm)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
