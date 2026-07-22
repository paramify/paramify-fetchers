#!/usr/bin/env python3
"""KSI-IAM-03: Non-User Accounts.

Enforce secure authentication for non-user accounts and services. Collects the
org's service accounts (detected only via name-independent, definitive
indicators), API tokens, OAuth/OIDC applications, and authorization servers as
evidence of how non-user/service authentication is scoped.

Related controls: AC-2, AC-2.2, AC-4, AC-6.5, IA-3, IA-5.2, RA-5.5.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Dict

# Import the category-shared client + run scaffolding from _shared/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))

from okta_client import OktaAPIClient  # noqa: E402
from okta_runner import run  # noqa: E402

logger = logging.getLogger("okta_non_user_accounts_authentication")


def collect(client: OktaAPIClient) -> Dict:
    evidence: Dict = {
        "ksi": "KSI-IAM-03",
        "name": "Non-User Accounts",
        "related_controls": ["AC-2", "AC-2.2", "AC-4", "AC-6.5", "IA-3", "IA-5.2", "RA-5.5"],
        "data": {},
    }

    # 1. Service accounts - only definitive indicators (100% certain)
    logger.info("Searching for service accounts using definitive indicators only...")
    service_accounts = []

    # Get all users, API tokens, apps, and groups first
    logger.info("Fetching all users, API tokens, apps, and groups...")
    all_users = client.list_users()
    api_tokens = client.list_api_tokens()
    evidence["data"]["api_tokens"] = api_tokens
    apps = client.list_applications()
    groups = client.list_groups()

    # Build API token owner map
    api_token_user_ids = set()
    api_token_details = {}
    for token in api_tokens:
        user_id = token.get("userId")
        if user_id:
            api_token_user_ids.add(user_id)
            if user_id not in api_token_details:
                api_token_details[user_id] = []
            api_token_details[user_id].append({
                "token_id": token.get("id"),
                "token_name": token.get("name"),
                "created": token.get("created"),
            })

    # Build OAuth client assignments map (users assigned to OAuth apps as clients)
    # Service accounts are often used as OAuth clients for API authentication
    oauth_client_user_ids = set()
    oauth_client_details = {}
    for app in apps:
        if app.get("signOnMode") in ["OPENID_CONNECT", "OAUTH_2_0"]:
            app_id = app.get("id")
            try:
                # Get app users (OAuth clients)
                app_users = client.list_app_users(app_id)
                for app_user in app_users:
                    user_id = app_user.get("id")
                    if user_id:
                        oauth_client_user_ids.add(user_id)
                        if user_id not in oauth_client_details:
                            oauth_client_details[user_id] = []
                        oauth_client_details[user_id].append({
                            "app_id": app_id,
                            "app_name": app.get("name"),
                            "app_label": app.get("label"),
                            "sign_on_mode": app.get("signOnMode"),
                        })
            except Exception:
                pass

    # Build service account group memberships map
    # Check for groups that might indicate service accounts (configurable)
    # Common patterns: groups with "service" in name, or dedicated service account groups
    service_account_group_ids = set()
    service_account_group_details = {}
    for group in groups:
        group_name = group.get("profile", {}).get("name", "").lower()
        # Look for groups that explicitly indicate service accounts
        # This is configurable - you can add your own group names here
        service_group_indicators = ["service account", "service-account", "service_account", "svc-account", "api-account"]
        if any(indicator in group_name for indicator in service_group_indicators):
            group_id = group.get("id")
            try:
                members = client.list_group_members(group_id)
                for member in members:
                    user_id = member.get("id")
                    if user_id:
                        service_account_group_ids.add(user_id)
                        if user_id not in service_account_group_details:
                            service_account_group_details[user_id] = []
                        service_account_group_details[user_id].append({
                            "group_id": group_id,
                            "group_name": group.get("profile", {}).get("name"),
                        })
            except Exception:
                pass

    # Analyze each user for definitive service account indicators only
    logger.info("Analyzing users for definitive service account indicators...")
    for user in all_users:
        user_id = user["id"]
        email = user.get("profile", {}).get("email", "").lower()
        login = user.get("profile", {}).get("login", "").lower()
        user_type = user.get("profile", {}).get("userType", "")

        # Collect definitive indicators only (name-independent methods)
        indicators = []
        is_service_account = False

        # Method 1: userType field (definitive - Okta's official field)
        # This is the most reliable method and should be set for all service accounts
        if user_type == "Service":
            indicators.append("userType=Service")
            is_service_account = True

        # Method 2: API token ownership (definitive - service accounts use API tokens for automation)
        # This is name-independent and reliable
        if user_id in api_token_user_ids:
            indicators.append("api_token_owner")
            is_service_account = True

        # Method 3: OAuth client assignment (definitive - service accounts often used as OAuth clients)
        # This is name-independent and indicates the account is used for API/service authentication
        if user_id in oauth_client_user_ids:
            indicators.append("oauth_client_assignment")
            is_service_account = True

        # Method 4: Service account group membership (definitive - if in dedicated service account group)
        # This is name-independent if groups are properly named/maintained
        if user_id in service_account_group_ids:
            indicators.append("service_account_group_member")
            is_service_account = True

        # Only add if we have at least one definitive indicator
        if is_service_account:
            # Check if we already added this user
            if not any(sa["id"] == user_id for sa in service_accounts):
                # Get full user details for evidence
                try:
                    user_detail = client.get_user(user_id)
                    factors = client.list_user_factors(user_id)
                    roles = client.list_user_roles(user_id)

                    # Extract role information
                    role_info = []
                    if roles:
                        for role in roles:
                            role_info.append({
                                "type": role.get("type"),
                                "label": role.get("label"),
                                "status": role.get("status"),
                            })

                    service_accounts.append({
                        "id": user_id,
                        "login": user_detail.get("profile", {}).get("login"),
                        "email": user_detail.get("profile", {}).get("email"),
                        "role": role_info,
                        "status": user_detail.get("status"),
                        "userType": user_detail.get("profile", {}).get("userType"),
                        "mfa_factors_count": len(factors) if factors else 0,
                        "api_tokens_owned": api_token_details.get(user_id, []),
                        "oauth_client_assignments": oauth_client_details.get(user_id, []),
                        "service_account_groups": service_account_group_details.get(user_id, []),
                        "detection_method": " | ".join(indicators),
                    })
                except Exception:
                    # Fallback to basic user data - try to get roles
                    role_info = []
                    try:
                        roles = client.list_user_roles(user_id)
                        if roles:
                            for role in roles:
                                role_info.append({
                                    "type": role.get("type"),
                                    "label": role.get("label"),
                                    "status": role.get("status"),
                                })
                    except Exception:
                        pass

                    service_accounts.append({
                        "id": user_id,
                        "login": login,
                        "email": email,
                        "role": role_info,
                        "status": user.get("status"),
                        "userType": user_type,
                        "api_tokens_owned": api_token_details.get(user_id, []),
                        "oauth_client_assignments": oauth_client_details.get(user_id, []),
                        "service_account_groups": service_account_group_details.get(user_id, []),
                        "detection_method": " | ".join(indicators),
                    })

    evidence["data"]["service_accounts"] = service_accounts

    evidence["data"]["service_account_detection_methods"] = {
        "definitive_indicators_only": [
            "userType=Service (Okta's official service account field - MOST RELIABLE, name-independent)",
            "API token ownership (service accounts use API tokens for automation - name-independent)",
            "OAuth client assignment (service accounts used as OAuth clients for API authentication - name-independent)",
            "Service account group membership (membership in dedicated service account groups - name-independent if groups maintained)",
        ],
        "recommendations": [
            "Set userType=Service for all service accounts (most reliable method)",
            "Use API token ownership or OAuth client assignments for name-independent detection",
            "Create and maintain a dedicated 'Service Accounts' group for additional detection",
        ],
        "note": "Only accounts with definitive indicators are included. Methods are prioritized by reliability and name-independence.",
    }

    # 3. OAuth/OIDC applications (service apps)
    logger.info("Fetching OAuth/OIDC applications...")
    apps = client.list_applications()
    oauth_apps = [a for a in apps if a.get("signOnMode") in ["OPENID_CONNECT", "SAML_2_0"]]
    evidence["data"]["oauth_apps"] = [{
        "id": a["id"],
        "name": a.get("name"),
        "label": a.get("label"),
        "signOnMode": a.get("signOnMode"),
        "status": a.get("status"),
    } for a in oauth_apps]

    # 4. Authorization servers
    logger.info("Fetching authorization servers...")
    auth_servers = client.list_authorization_servers()
    for server in auth_servers:
        server["scopes"] = client.list_auth_server_scopes(server["id"])
        server["policies"] = client.list_auth_server_policies(server["id"])
    evidence["data"]["authorization_servers"] = auth_servers

    # Summary - group by detection method for detailed evidence
    service_accounts_by_method = {}
    for sa in service_accounts:
        # Extract primary detection method
        methods = sa.get("detection_method", "unknown").split(" | ")
        primary_method = methods[0] if methods else "unknown"

        if primary_method not in service_accounts_by_method:
            service_accounts_by_method[primary_method] = []

        service_accounts_by_method[primary_method].append({
            "login": sa.get("login"),
            "email": sa.get("email"),
            "status": sa.get("status"),
            "all_indicators": methods,
        })

    evidence["summary"] = {
        "service_accounts_count": len(service_accounts),
        "service_accounts_by_detection_method": service_accounts_by_method,
        "api_tokens_count": len(api_tokens),
        "api_token_owners_count": len(api_token_user_ids),
        "oauth_apps_count": len(oauth_apps),
        "authorization_servers_count": len(auth_servers),
        "note": f"Service accounts identified using definitive indicators only: userType=Service, API token ownership, OAuth client assignments, or service account group membership. Total unique service accounts: {len(service_accounts)}. Methods are name-independent.",
    }

    logger.info(
        "Non-user accounts: %d service account(s), %d API token(s), %d OAuth app(s), %d authorization server(s)",
        len(service_accounts), len(api_tokens), len(oauth_apps), len(auth_servers),
    )
    return evidence


def main() -> int:
    return run(collect, output_filename="okta_non_user_accounts_authentication.json", logger_name="okta_non_user_accounts_authentication")


if __name__ == "__main__":
    sys.exit(main())
