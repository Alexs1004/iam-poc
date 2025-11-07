"""Utilities for provisioning Keycloak realms and demonstrating JML flows.

This module serves as a CLI wrapper around app.core.keycloak services.
"""
from __future__ import annotations
import argparse
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.keycloak import (
    get_service_account_token,
    bootstrap_service_account,
    create_realm,
    create_client,
    configure_security_admin_console,
    create_role,
    create_group,
    ensure_required_action,
    create_user,
    grant_client_role,
    add_realm_role,
    change_role,
    disable_user,
    delete_realm,
)
from app.core.keycloak.exceptions import (
    UserNotFoundError,
    RoleNotFoundError,
    GroupNotFoundError,
    ClientNotFoundError,
    KeycloakAPIError,
)
from scripts import audit


def main() -> None:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="Keycloak JML helper")
    parser.add_argument("--kc-url", default="http://localhost:8080")
    parser.add_argument("--auth-realm", default=os.environ.get("KEYCLOAK_SERVICE_REALM", "master"))
    parser.add_argument("--svc-client-id", default=os.environ.get("KEYCLOAK_SERVICE_CLIENT_ID", "automation-cli"))
    parser.add_argument("--svc-client-secret", default=os.environ.get("KEYCLOAK_SERVICE_CLIENT_SECRET"))
    parser.add_argument("--operator", default="automation", 
                       help="Operator identifier for audit logs (default: automation)")

    sub = parser.add_subparsers(dest="cmd")

    bootstrap = sub.add_parser("bootstrap-service-account")
    bootstrap.add_argument("--realm", default=os.environ.get("KEYCLOAK_REALM", "demo"))
    bootstrap.add_argument("--admin-user", default=os.environ.get("KEYCLOAK_ADMIN", "admin"))
    bootstrap.add_argument("--admin-pass", default=os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"))
    bootstrap.add_argument("--roles", nargs="*", default=["manage-realm", "manage-users", "manage-clients"])

    sp = sub.add_parser("init")
    sp.add_argument("--realm", default="demo")
    sp.add_argument("--client-id", default="flask-app")
    sp.add_argument("--redirect-uri", default="http://localhost:5000/callback")
    sp.add_argument("--post-logout-redirect-uri", default="http://localhost:5000/")

    sj = sub.add_parser("joiner")
    sj.add_argument("--realm", default="demo")
    sj.add_argument("--username", required=True)
    sj.add_argument("--email", required=True)
    sj.add_argument("--first", required=True)
    sj.add_argument("--last", required=True)
    sj.add_argument("--role", default="analyst")
    sj.add_argument("--temp-password", default=os.environ.get("ALICE_TEMP_PASSWORD_DEMO", "Temp123!"))
    sj.add_argument("--no-password-update", action="store_true")
    sj.add_argument("--no-totp", action="store_true")

    scr = sub.add_parser("client-role")
    scr.add_argument("--realm", default="demo")
    scr.add_argument("--username", required=True)
    scr.add_argument("--client-id", required=True)
    scr.add_argument("--role", required=True)

    sr = sub.add_parser("grant-role")
    sr.add_argument("--realm", default="demo")
    sr.add_argument("--username", required=True)
    sr.add_argument("--role", required=True)

    sm = sub.add_parser("mover")
    sm.add_argument("--realm", default="demo")
    sm.add_argument("--username", required=True)
    sm.add_argument("--from-role", required=True)
    sm.add_argument("--to-role", required=True)

    sl = sub.add_parser("leaver")
    sl.add_argument("--realm", default="demo")
    sl.add_argument("--username", required=True)

    dr = sub.add_parser("delete-realm")
    dr.add_argument("--realm", required=True)

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        return

    if args.cmd == "bootstrap-service-account":
        if not args.admin_user or not args.admin_pass:
            parser.error("Admin credentials required")
        secret = bootstrap_service_account(
            args.kc_url, args.admin_user, args.admin_pass,
            args.auth_realm, args.svc_client_id, args.realm, args.roles
        )
        print(secret)
        return

    if not args.svc_client_secret:
        parser.error("Missing service account secret")

    target_realm = getattr(args, "realm", None)
    if not target_realm:
        parser.error("Command requires --realm")

    token = get_service_account_token(args.kc_url, args.auth_realm, args.svc_client_id, args.svc_client_secret)

    if args.cmd == "init":
        create_realm(args.kc_url, token, target_realm)
        create_client(args.kc_url, token, target_realm, args.client_id, args.redirect_uri, args.post_logout_redirect_uri)
        configure_security_admin_console(args.kc_url, token, target_realm)
        for role in ["analyst", "manager", "iam-operator", "realm-admin"]:
            create_role(args.kc_url, token, target_realm, role)
        create_group(args.kc_url, token, target_realm, "iam-poc-managed", attributes={
            "description": ["Users managed by IAM POC JML workflows"],
            "managed_by": ["iam-poc"],
            "purpose": ["dynamic-user-discovery"],
        })
        if os.environ.get("ENFORCE_TOTP_REQUIRED_ACTION", "true").lower() == "true":
            ensure_required_action(args.kc_url, token, target_realm, "CONFIGURE_TOTP")
        ensure_required_action(args.kc_url, token, target_realm, "UPDATE_PASSWORD")
    elif args.cmd == "joiner":
        try:
            create_user(args.kc_url, token, target_realm, args.username, args.email, args.first, args.last,
                        args.temp_password, args.role, require_totp=not args.no_totp,
                        require_password_update=not args.no_password_update)
            audit.log_jml_event(
                "joiner",
                args.username,
                operator=args.operator,
                realm=target_realm,
                details={
                    "email": args.email,
                    "first_name": args.first,
                    "last_name": args.last,
                    "role": args.role,
                    "totp_required": not args.no_totp,
                    "password_update_required": not args.no_password_update,
                },
                success=True
            )
        except (UserNotFoundError, KeycloakAPIError) as e:
            print(f"[joiner] Error: {e}", file=sys.stderr)
            audit.log_jml_event(
                "joiner",
                args.username,
                operator=args.operator,
                realm=target_realm,
                details={"error": str(e)},
                success=False
            )
            sys.exit(1)
    elif args.cmd == "client-role":
        grant_client_role(args.kc_url, token, target_realm, args.username, args.client_id, args.role)
    elif args.cmd == "grant-role":
        add_realm_role(args.kc_url, token, target_realm, args.username, args.role)
    elif args.cmd == "mover":
        try:
            change_role(args.kc_url, token, target_realm, args.username, args.from_role, args.to_role)
            audit.log_jml_event(
                "mover",
                args.username,
                operator=args.operator,
                realm=target_realm,
                details={
                    "from_role": args.from_role,
                    "to_role": args.to_role,
                },
                success=True
            )
        except (UserNotFoundError, RoleNotFoundError, KeycloakAPIError) as e:
            print(f"[mover] Error: {e}", file=sys.stderr)
            audit.log_jml_event(
                "mover",
                args.username,
                operator=args.operator,
                realm=target_realm,
                details={
                    "from_role": args.from_role,
                    "to_role": args.to_role,
                    "error": str(e)
                },
                success=False
            )
            sys.exit(1)
    elif args.cmd == "leaver":
        try:
            # Pass operator to disable_user so it logs with correct operator
            disable_user(args.kc_url, token, target_realm, args.username, operator=args.operator)
        except (UserNotFoundError, KeycloakAPIError) as e:
            print(f"[leaver] Error: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.cmd == "delete-realm":
        delete_realm(args.kc_url, token, target_realm)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
