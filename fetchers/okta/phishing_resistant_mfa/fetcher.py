#!/usr/bin/env python3
"""KSI-IAM-01: Phishing-Resistant MFA.

Enforce MFA using methods that are difficult to intercept or impersonate.
Collects the org's authenticator configuration (highlighting phishing-resistant
FIDO2/WebAuthn methods and their FIPS/attestation settings), access and sign-on
policies, a sample of users' enrolled MFA factors, and recent MFA authentication
logs as evidence.

Related controls: AC-2, IA-2, IA-2.1, IA-2.2, IA-2.8, IA-5, IA-8, SC-23.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict

# Import the category-shared client + run scaffolding from _shared/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))

from okta_client import OktaAPIClient, lookup_aaguid_model_name  # noqa: E402
from okta_runner import run  # noqa: E402

logger = logging.getLogger("okta_phishing_resistant_mfa")

# How far back to scan the system log for MFA authentication events.
# Overridable via env for orgs with longer/shorter retention.
MFA_LOG_LOOKBACK_DAYS = int(os.environ.get("OKTA_MFA_LOG_LOOKBACK_DAYS", "7"))


def collect(client: OktaAPIClient) -> Dict:
    evidence = {
        "ksi": "KSI-IAM-01",
        "name": "Phishing-Resistant MFA",
        "related_controls": ["AC-2", "IA-2", "IA-2.1", "IA-2.2", "IA-2.8", "IA-5", "IA-8", "SC-23"],
        "data": {}
    }

    # 1. Authenticators configuration
    logger.info("Fetching authenticators...")
    authenticators = client.list_authenticators()
    evidence["data"]["authenticators"] = authenticators

    # Identify phishing-resistant authenticators (FIDO2/WebAuthn)
    phishing_resistant_types = ["security_key", "webauthn"]
    phishing_resistant = [a for a in authenticators if a.get("type") in phishing_resistant_types]

    # Fetch detailed methods/settings for each phishing-resistant authenticator
    # This includes FIPS mode, attestation requirements, etc.
    logger.info("Fetching phishing-resistant authenticator details (FIPS, attestation)...")
    for auth in phishing_resistant:
        auth_id = auth.get("id")
        if auth_id:
            methods = client.get_authenticator_methods(auth_id)
            auth["methods"] = methods

            # Extract key FIPS/security details for easy reference
            auth["security_details"] = {
                "authenticator_type": auth.get("type"),
                "authenticator_key": auth.get("key"),
                "authenticator_name": auth.get("name"),
                "status": auth.get("status"),
                "methods_count": len(methods) if methods else 0,
                "method_details": []
            }

            # Parse method details for FIPS, user verification, attestation settings
            for method in (methods or []):
                method_info = {
                    "type": method.get("type"),
                    "status": method.get("status")
                }
                settings = method.get("settings", {})
                if settings:
                    # Capture FIPS and attestation settings if present
                    method_info["fips_compliant"] = settings.get("fipsCompliant")
                    method_info["user_verification"] = settings.get("userVerification")
                    method_info["attestation"] = settings.get("attestation")
                    method_info["authenticator_attachment"] = settings.get("authenticatorAttachment")
                    method_info["aaguid_groups"] = settings.get("aaguidGroups")  # Allowed authenticator models
                    method_info["all_settings"] = settings  # Full settings for audit
                auth["security_details"]["method_details"].append(method_info)

    evidence["data"]["phishing_resistant_authenticators"] = phishing_resistant

    # 2. Authentication/Access policies
    logger.info("Fetching access policies...")
    access_policies = client.list_policies("ACCESS_POLICY")
    for policy in access_policies:
        policy["rules"] = client.list_policy_rules(policy["id"])
    evidence["data"]["access_policies"] = access_policies

    # 3. Sign-on policies
    logger.info("Fetching sign-on policies...")
    signon_policies = client.list_policies("OKTA_SIGN_ON")
    for policy in signon_policies:
        policy["rules"] = client.list_policy_rules(policy["id"])
    evidence["data"]["sign_on_policies"] = signon_policies

    # 4. Sample users with MFA factors
    logger.info("Fetching user MFA factors (sampling active users)...")
    active_users = client.list_users(filter_query='status eq "ACTIVE"', limit=100)
    users_with_factors = []

    for i, user in enumerate(active_users[:50]):  # Sample first 50
        if (i + 1) % 10 == 0:
            logger.info("Processing user %d/50...", i + 1)

        factors = client.list_user_factors(user["id"])
        user_summary = {
            "id": user["id"],
            "login": user.get("profile", {}).get("login"),
            "status": user.get("status"),
            "factors": factors,
            "has_phishing_resistant": any(
                f.get("factorType") in ["webauthn", "token:hotp", "u2f"] or
                f.get("provider") == "FIDO"
                for f in factors
            ),
            "factor_types": list(set(f.get("factorType") for f in factors))
        }
        users_with_factors.append(user_summary)

    evidence["data"]["users_mfa_status"] = users_with_factors

    # 5. MFA authentication logs (last MFA_LOG_LOOKBACK_DAYS days)
    logger.info("Fetching MFA authentication logs...")
    since = (datetime.utcnow() - timedelta(days=MFA_LOG_LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    mfa_logs = client.get_system_logs(
        since=since,
        filter_query='eventType eq "user.authentication.auth_via_mfa"'
    )
    evidence["data"]["mfa_authentication_logs"] = mfa_logs[:100]  # Limit for output size

    # Summary
    # Extract FIPS and security details for the summary
    phishing_resistant_details = []
    for auth in phishing_resistant:
        detail = {
            "type": auth.get("type"),
            "name": auth.get("name"),
            "status": auth.get("status")
        }
        # Add FIPS info if available
        security_details = auth.get("security_details", {})
        for method_detail in security_details.get("method_details", []):
            if method_detail.get("fips_compliant") is not None:
                detail["fips_compliant"] = method_detail.get("fips_compliant")
            if method_detail.get("user_verification"):
                detail["user_verification"] = method_detail.get("user_verification")
            if method_detail.get("attestation"):
                detail["attestation"] = method_detail.get("attestation")
            if method_detail.get("aaguid_groups"):
                # Translate AAGUIDs to human-readable model names
                aaguid_groups = method_detail.get("aaguid_groups", [])
                translated_groups = []
                for group in aaguid_groups:
                    translated_group = {
                        "name": group.get("name"),
                        "aaguids": group.get("aaguids", []),
                        "model_names": [
                            lookup_aaguid_model_name(aaguid)
                            for aaguid in group.get("aaguids", [])
                        ]
                    }
                    translated_groups.append(translated_group)
                detail["allowed_authenticator_models"] = translated_groups
        phishing_resistant_details.append(detail)

    # Calculate percentage
    total_users = len(users_with_factors)
    users_with_phishing_resistant = sum(1 for u in users_with_factors if u["has_phishing_resistant"])
    phishing_resistant_mfa_percentage = round((users_with_phishing_resistant / total_users * 100), 1) if total_users > 0 else 0

    evidence["summary"] = {
        "phishing_resistant_authenticator_types_count": len(phishing_resistant),
        "phishing_resistant_types": [a.get("type") for a in phishing_resistant],
        "phishing_resistant_authenticator_details": phishing_resistant_details,
        "total_users": total_users,
        "users_with_phishing_resistant_mfa": users_with_phishing_resistant,
        "phishing_resistant_mfa_percentage": phishing_resistant_mfa_percentage,
        "mfa_events_last_7_days": len(mfa_logs)
    }

    return evidence


def main() -> int:
    return run(collect, output_filename="okta_phishing_resistant_mfa.json", logger_name="okta_phishing_resistant_mfa")


if __name__ == "__main__":
    sys.exit(main())
