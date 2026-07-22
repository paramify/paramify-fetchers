#!/usr/bin/env python3
"""Shared Okta API client for the okta category fetchers.

This module holds ONLY reusable infrastructure — an HTTP client over the Okta
Management API and thin per-endpoint wrappers. Evidence-collection logic lives in
each fetcher's own ``fetcher.py``; nothing org-specific belongs here.

Auth: SSWS API token. Config comes from the environment (OKTA_ORG_URL,
OKTA_API_TOKEN); the caller/runner is responsible for populating it.

Reference: https://developer.okta.com/docs/api/
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("okta.client")

_AAGUID_PATH = Path(__file__).resolve().parent / "aaguid_models.json"


def _load_aaguid_models() -> Dict[str, str]:
    """Load the AAGUID -> model-name lookup from the sidecar data file."""
    try:
        return json.loads(_AAGUID_PATH.read_text()).get("models", {})
    except (OSError, ValueError) as exc:  # pragma: no cover - data file ships with repo
        logger.warning("Could not load AAGUID model table: %s", exc)
        return {}


AAGUID_MODEL_NAMES: Dict[str, str] = _load_aaguid_models()


def lookup_aaguid_model_name(aaguid: str) -> str:
    """Human-readable model name for a FIDO2/WebAuthn AAGUID (best-effort)."""
    return AAGUID_MODEL_NAMES.get(aaguid, f"Unknown Model ({aaguid})")


class OktaAPIClient:
    """Okta Management API client (v1, SSWS token auth).

    Reference: https://developer.okta.com/docs/api/
    """

    def __init__(self) -> None:
        self.org_url = os.getenv("OKTA_ORG_URL", "").rstrip("/")
        self.api_token = os.getenv("OKTA_API_TOKEN")

        if not self.org_url:
            raise RuntimeError("OKTA_ORG_URL environment variable is required")
        if not self.api_token:
            raise RuntimeError("OKTA_API_TOKEN environment variable is required")

        # Okta uses the SSWS prefix for API-token authentication.
        # Reference: https://developer.okta.com/docs/api/#authentication
        self.headers = {
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.api_base = f"{self.org_url}/api/v1"

        # Feature-availability tracking (populated by the compatibility check).
        self.feature_availability: Dict[str, Any] = {}
        self.unavailable_features: List[Dict[str, Any]] = []

        # Network-level API failures (connection errors, timeouts, DNS). 4xx HTTP
        # responses are NOT tracked here — callers treat those as expected
        # "feature unavailable" signals. Wrappers read this to decide exit code.
        self.api_failures: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # Compatibility / feature detection
    # ------------------------------------------------------------------ #

    def check_endpoint_availability(self, endpoint: str, feature_name: str) -> bool:
        """Check whether an endpoint is reachable and record the result."""
        url = f"{self.api_base}{endpoint}"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            available = response.status_code == 200
            self.feature_availability[feature_name] = {
                "available": available,
                "status_code": response.status_code,
                "endpoint": endpoint,
            }
            if not available:
                self.unavailable_features.append({
                    "feature": feature_name,
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "reason": self._get_unavailable_reason(response.status_code),
                    "prediction": self._get_feature_prediction(feature_name, response.status_code),
                })
            return available
        except Exception as exc:
            self.feature_availability[feature_name] = {
                "available": False,
                "error": str(exc),
                "endpoint": endpoint,
            }
            self.unavailable_features.append({
                "feature": feature_name,
                "endpoint": endpoint,
                "status_code": None,
                "reason": str(exc),
                "prediction": self._get_feature_prediction(feature_name, None),
            })
            return False

    def _get_unavailable_reason(self, status_code: Optional[int]) -> str:
        reasons = {
            401: "Authentication failed - check API token",
            403: "Access denied - insufficient permissions or feature not enabled",
            404: "Feature not available (may require Okta Identity Engine or add-on)",
            429: "Rate limited",
        }
        return reasons.get(status_code, f"HTTP {status_code}")

    def _get_feature_prediction(self, feature_name: str, status_code: Optional[int]) -> str:
        predictions = {
            "Authenticators API (OIE)": "Requires Okta Identity Engine (OIE). Upgrade from Classic Engine to OIE to enable this feature.",
            "Access Policies (OIE)": "Requires Okta Identity Engine (OIE). Upgrade from Classic Engine to OIE to enable this feature.",
            "Authenticator Enrollment (OIE)": "Requires Okta Identity Engine (OIE). Upgrade from Classic Engine to OIE to enable this feature.",
            "Authorization Servers (API AM)": "Requires API Access Management add-on. Contact Okta support to enable this paid add-on feature.",
            "Group Rules": "Requires Okta Identity Engine (OIE) or may need specific admin permissions. Verify you have Group Management admin role.",
            "MFA Enrollment Policies": "Requires Okta Identity Engine (OIE). Upgrade from Classic Engine to OIE to enable this feature.",
            "API Tokens (Super Admin)": "Requires Super Admin role. Only Super Admins can access the API Tokens endpoint.",
            "Users API": "Check API token permissions. Ensure token has User Read permissions.",
            "Groups API": "Check API token permissions. Ensure token has Group Read permissions.",
            "Applications API": "Check API token permissions. Ensure token has Application Read permissions.",
            "Password Policies": "Check API token permissions. Ensure token has Policy Read permissions.",
            "Sign-On Policies": "Check API token permissions. Ensure token has Policy Read permissions.",
            "System Log API": "Check API token permissions. Ensure token has Log Read permissions.",
        }
        prediction = predictions.get(feature_name, "Unknown feature - check Okta documentation for requirements")
        if status_code == 401:
            prediction += " Also verify your API token is valid and not expired."
        elif status_code == 403:
            prediction += " Verify your API token has the required scopes/permissions for this feature."
        elif status_code == 404:
            if "OIE" in feature_name or "Identity Engine" in prediction:
                prediction += " This is a 404 error, which typically means the feature is not available in your org type."
            else:
                prediction += " This feature may not be available in your Okta org or may require a different API endpoint."
        return prediction

    def run_compatibility_check(self) -> Dict:
        """Probe every endpoint the okta fetchers rely on and summarize support."""
        logger.info("Running Okta API compatibility check...")

        checks = [
            ("/users?limit=1", "Users API"),
            ("/groups?limit=1", "Groups API"),
            ("/apps?limit=1", "Applications API"),
            ("/policies?type=PASSWORD", "Password Policies"),
            ("/policies?type=OKTA_SIGN_ON", "Sign-On Policies"),
            ("/logs?limit=1", "System Log API"),
            ("/authenticators", "Authenticators API (OIE)"),
            ("/policies?type=ACCESS_POLICY", "Access Policies (OIE)"),
            ("/policies?type=AUTHENTICATOR_ENROLLMENT", "Authenticator Enrollment (OIE)"),
            ("/authorizationServers", "Authorization Servers (API AM)"),
            ("/groups/rules", "Group Rules"),
            ("/policies?type=MFA_ENROLL", "MFA Enrollment Policies"),
            ("/api-tokens", "API Tokens (Super Admin)"),
        ]

        for endpoint, feature_name in checks:
            available = self.check_endpoint_availability(endpoint, feature_name)
            logger.debug("  [%s] %s", "available" if available else "unavailable", feature_name)

        is_oie = self.feature_availability.get("Authenticators API (OIE)", {}).get("available", False)
        org_type = "Okta Identity Engine (OIE)" if is_oie else "Okta Classic"
        logger.info("Org type: %s", org_type)

        if self.unavailable_features:
            logger.info(
                "%d feature(s) unavailable (evidence collection continues; they return empty data):",
                len(self.unavailable_features),
            )
            for uf in self.unavailable_features:
                logger.info("  - %s: %s", uf["feature"], uf["reason"])
        else:
            logger.info("All features available.")

        return {
            "org_type": org_type,
            "features_checked": len(checks),
            "features_available": len(checks) - len(self.unavailable_features),
            "features_unavailable": len(self.unavailable_features),
            "unavailable_details": self.unavailable_features,
            "feature_availability": self.feature_availability,
        }

    # ------------------------------------------------------------------ #
    # Low-level request helpers
    # ------------------------------------------------------------------ #

    def _request(self, method: str, endpoint: str, params: Optional[Dict] = None, data: Optional[Dict] = None) -> Any:
        """Make a single Okta API request.

        Reference: https://developer.okta.com/docs/api/#http-verbs
        """
        url = f"{self.api_base}{endpoint}"
        try:
            response = requests.request(
                method=method, url=url, headers=self.headers, params=params, json=data, timeout=30
            )
            # Reference: https://developer.okta.com/docs/api/#errors
            if response.status_code == 401:
                raise RuntimeError("Authentication failed. Check your OKTA_API_TOKEN.")
            elif response.status_code == 403:
                logger.warning("Access denied for %s", endpoint)
                return []
            elif response.status_code == 404:
                return []
            elif response.status_code == 429:
                logger.warning("Rate limited on %s", endpoint)
                return []

            response.raise_for_status()
            if not response.content:
                return []
            return response.json()
        except requests.exceptions.RequestException as exc:
            self.api_failures.append({
                "endpoint": endpoint,
                "type": type(exc).__name__,
                "message": str(exc),
            })
            logger.warning("Request failed for %s: %s", endpoint, exc)
            return []

    def _paginated_get(self, endpoint: str, params: Optional[Dict] = None, max_pages: int = 10) -> List[Dict]:
        """GET an endpoint, following Okta Link-header pagination.

        Reference: https://developer.okta.com/docs/api/#pagination
        """
        results: List[Dict] = []
        url = f"{self.api_base}{endpoint}"
        page = 0

        if params is None:
            params = {}
        if "limit" not in params:
            params["limit"] = "200"  # Max allowed by most endpoints

        while url and page < max_pages:
            try:
                response = requests.get(url, headers=self.headers, params=params, timeout=30)

                if response.status_code == 401:
                    # Some endpoints 401 when the feature is not licensed — don't crash.
                    logger.warning("Access denied (401) on %s - feature may require additional license", endpoint)
                    break
                elif response.status_code in (403, 404):
                    break
                elif response.status_code == 429:
                    logger.warning("Rate limited, stopping pagination on %s", endpoint)
                    break

                response.raise_for_status()
                data = response.json() if response.content else []

                if isinstance(data, list):
                    results.extend(data)
                elif isinstance(data, dict):
                    results.append(data)

                # Follow the Link header's rel="next".
                # Reference: https://developer.okta.com/docs/api/#link-header
                url = None
                params = None  # URL already carries the params
                for link in response.headers.get("Link", "").split(","):
                    if 'rel="next"' in link:
                        url = link.split(";")[0].strip("<> ")
                        break

                page += 1
            except requests.exceptions.RequestException as exc:
                self.api_failures.append({
                    "endpoint": endpoint,
                    "type": type(exc).__name__,
                    "message": str(exc),
                })
                logger.warning("Pagination failed on %s: %s", endpoint, exc)
                break

        return results

    # ------------------------------------------------------------------ #
    # Okta API endpoints — https://developer.okta.com/docs/api/
    # ------------------------------------------------------------------ #

    # --- Users ---
    def list_users(self, filter_query: str = None, search: str = None, limit: int = 200) -> List[Dict]:
        """List users with an optional filter/search."""
        params = {"limit": str(limit)}
        if filter_query:
            params["filter"] = filter_query
        if search:
            params["search"] = search
        return self._paginated_get("/users", params)

    def get_user(self, user_id: str) -> Dict:
        """Get a single user."""
        return self._request("GET", f"/users/{user_id}")

    def list_user_factors(self, user_id: str) -> List[Dict]:
        """List a user's enrolled MFA factors."""
        return self._paginated_get(f"/users/{user_id}/factors")

    def list_user_roles(self, user_id: str) -> List[Dict]:
        """List admin roles assigned to a user."""
        return self._paginated_get(f"/users/{user_id}/roles")

    # --- Groups ---
    def list_groups(self, filter_query: str = None) -> List[Dict]:
        """List all groups."""
        params = {}
        if filter_query:
            params["filter"] = filter_query
        return self._paginated_get("/groups", params)

    def list_group_members(self, group_id: str) -> List[Dict]:
        """List members of a group."""
        return self._paginated_get(f"/groups/{group_id}/users")

    def list_group_rules(self) -> List[Dict]:
        """List group rules (dynamic membership)."""
        return self._paginated_get("/groups/rules")

    def list_group_roles(self, group_id: str) -> List[Dict]:
        """List admin roles assigned to a group.

        Distinct from ``list_user_roles``: the per-user endpoint returns only
        directly-assigned roles, so group-inherited admin privilege is only
        visible here.
        """
        return self._paginated_get(f"/groups/{group_id}/roles")

    # --- Applications ---
    def list_applications(self) -> List[Dict]:
        """List all applications."""
        return self._paginated_get("/apps")

    def list_app_users(self, app_id: str) -> List[Dict]:
        """List users assigned to an application."""
        return self._paginated_get(f"/apps/{app_id}/users")

    def list_app_groups(self, app_id: str) -> List[Dict]:
        """List groups assigned to an application."""
        return self._paginated_get(f"/apps/{app_id}/groups")

    # --- Authenticators ---
    def list_authenticators(self) -> List[Dict]:
        """List all authenticators (MFA methods)."""
        return self._paginated_get("/authenticators")

    def get_authenticator(self, authenticator_id: str) -> Dict:
        """Get a single authenticator configuration."""
        return self._request("GET", f"/authenticators/{authenticator_id}")

    def get_authenticator_methods(self, authenticator_id: str) -> List[Dict]:
        """Get an authenticator's methods/settings (FIPS, attestation, etc.)."""
        return self._paginated_get(f"/authenticators/{authenticator_id}/methods")

    # --- Policies ---
    def list_policies(self, policy_type: str) -> List[Dict]:
        """List policies by type (OKTA_SIGN_ON, PASSWORD, MFA_ENROLL, ACCESS_POLICY,
        PROFILE_ENROLLMENT, AUTHENTICATOR_ENROLLMENT)."""
        return self._paginated_get("/policies", params={"type": policy_type})

    def list_policy_rules(self, policy_id: str) -> List[Dict]:
        """List a policy's rules."""
        return self._paginated_get(f"/policies/{policy_id}/rules")

    # --- Authorization servers ---
    def list_authorization_servers(self) -> List[Dict]:
        """List all authorization servers."""
        return self._paginated_get("/authorizationServers")

    def list_auth_server_scopes(self, auth_server_id: str) -> List[Dict]:
        """List an authorization server's scopes."""
        return self._paginated_get(f"/authorizationServers/{auth_server_id}/scopes")

    def list_auth_server_claims(self, auth_server_id: str) -> List[Dict]:
        """List an authorization server's claims."""
        return self._paginated_get(f"/authorizationServers/{auth_server_id}/claims")

    def list_auth_server_policies(self, auth_server_id: str) -> List[Dict]:
        """List an authorization server's policies."""
        return self._paginated_get(f"/authorizationServers/{auth_server_id}/policies")

    # --- System log ---
    def get_system_logs(self, since: str = None, filter_query: str = None, limit: int = 500) -> List[Dict]:
        """Get system-log events. Filter operators: eq, ne, lt, le, gt, ge, sw, co.
        Reference: https://developer.okta.com/docs/api/#filter
        """
        params = {"limit": str(limit)}
        if since:
            params["since"] = since
        if filter_query:
            params["filter"] = filter_query
        return self._paginated_get("/logs", params, max_pages=5)

    # --- API tokens ---
    def list_api_tokens(self) -> List[Dict]:
        """List API tokens."""
        return self._paginated_get("/api-tokens")

    # --- ThreatInsight ---
    def get_threat_insight_settings(self) -> Dict:
        """Get ThreatInsight settings."""
        try:
            return self._request("GET", "/threatInsight")
        except Exception:
            return {}

    # --- Behavior detection ---
    def list_behaviors(self) -> List[Dict]:
        """List behavior-detection rules."""
        try:
            return self._paginated_get("/behaviors")
        except Exception:
            return []
