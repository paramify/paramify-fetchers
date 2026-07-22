#!/usr/bin/env python3
"""Okta authenticators evidence (EVD-OKTA-AUTHENTICATORS).

Collects, in one evidence set:
  - FIDO2 authenticator configuration + a per-config phishing-resistance analysis
  - Applications + their per-app authentication policies
  - Authenticator-enrollment policies + rules (with a phishing-resistant-MFA flag)
  - Policy-simulation results against a few representative test cases

Ported from the previous fetcher.sh to Python on the shared Okta client so the
whole okta category shares one implementation style.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Dict, List

# Import the category-shared client + run scaffolding from _shared/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))

from okta_client import OktaAPIClient  # noqa: E402
from okta_runner import run  # noqa: E402

logger = logging.getLogger("okta_authenticators")

# Authenticator types considered phishing-resistant (FIDO2/WebAuthn).
PHISHING_RESISTANT_TYPES = ("security_key", "webauthn")

# Recommended maximum WebAuthn ceremony timeout (seconds).
FIDO2_TIMEOUT_MAX_SECONDS = 300

# Representative policy-simulation inputs: no factor, password only, password +
# security key — used to observe how enrollment/access policies would resolve.
_SIMULATION_TEST_CASES: List[Dict] = [
    {"user": {"id": "test_user"}, "context": {"network": {"ip": "192.168.1.1"}, "device": {"os": "Windows"}}, "authenticators": []},
    {"user": {"id": "test_user"}, "context": {"network": {"ip": "192.168.1.1"}, "device": {"os": "Windows"}}, "authenticators": [{"type": "password"}]},
    {"user": {"id": "test_user"}, "context": {"network": {"ip": "192.168.1.1"}, "device": {"os": "Windows"}}, "authenticators": [{"type": "password"}, {"type": "security_key"}]},
]


def _analyze_fido2(auth: Dict) -> Dict:
    """Per-authenticator phishing-resistance analysis (mirrors the prior jq logic)."""
    settings = auth.get("settings") or {}
    timeout = settings.get("timeout")
    return {
        "status": "PASS",
        "checks": {
            "user_verification": {
                "required": settings.get("userVerification") == "required",
                "recommended": True,
                "description": "User verification should be required for phishing resistance",
            },
            "resident_key": {
                "required": settings.get("residentKey") == "required",
                "recommended": True,
                "description": "Resident keys should be required for better security",
            },
            "attestation": {
                "required": settings.get("attestation") == "required",
                "recommended": True,
                "description": "Attestation should be required to verify authenticator authenticity",
            },
            "timeout": {
                # jq treated a missing timeout (null <= 300) as within limits.
                "within_limits": timeout is None or timeout <= FIDO2_TIMEOUT_MAX_SECONDS,
                "recommended": True,
                "description": "Timeout should be 300 seconds or less",
            },
        },
    }


def collect(client: OktaAPIClient) -> Dict:
    results: Dict[str, List] = {
        "applications": [],
        "enrollment_policies": [],
        "simulation_results": [],
        "fido2_config": [],
    }

    # --- FIDO2 authenticator configuration + analysis ----------------------
    logger.info("Fetching authenticator configuration...")
    for authenticator in client.list_authenticators():
        if authenticator.get("type") not in PHISHING_RESISTANT_TYPES:
            continue
        detail = client.get_authenticator(authenticator.get("id"))
        if not isinstance(detail, dict):  # request failed -> skip (as the shell did)
            continue
        entry = dict(detail)
        entry["Analysis"] = _analyze_fido2(detail)
        results["fido2_config"].append(entry)

    # --- Applications + per-app authentication policies --------------------
    logger.info("Fetching applications and per-app policies...")
    for app in client.list_applications():
        app_id = app.get("id")
        entry = dict(app)
        entry["Policies"] = client._request("GET", f"/apps/{app_id}/policies")
        results["applications"].append(entry)

    # --- Authenticator enrollment policies + rules -------------------------
    logger.info("Fetching authenticator enrollment policies...")
    for policy in client.list_policies("AUTHENTICATOR_ENROLLMENT"):
        rules = client.list_policy_rules(policy.get("id"))
        has_phishing_resistant = any(
            a.get("type") in PHISHING_RESISTANT_TYPES
            for rule in rules
            for a in ((rule.get("conditions", {}) or {}).get("authenticators", []) or [])
        )
        entry = dict(policy)
        entry["Rules"] = rules
        entry["HasPhishingResistantMFA"] = has_phishing_resistant
        results["enrollment_policies"].append(entry)

    # --- Policy simulation against test cases ------------------------------
    logger.info("Running policy simulations...")
    for test_case in _SIMULATION_TEST_CASES:
        results["simulation_results"].append(
            client._request("POST", "/policies/simulate", data=test_case)
        )

    return {"results": results}


def main() -> int:
    return run(collect, output_filename="okta_authenticators.json", logger_name="okta_authenticators")


if __name__ == "__main__":
    sys.exit(main())
