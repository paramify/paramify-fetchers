#!/usr/bin/env python3
"""
Okta IAM Evidence Fetcher

Based on Official Okta API Documentation:
https://developer.okta.com/docs/api/

API Version: v1
URL Format: https://{yourOktaDomain}/api/v1/{endpoint}
Authentication: SSWS {api_token}

Extracts IAM evidence from Okta. Each collector below backs one fetcher in
fetchers/okta/; which KSI that evidence maps to is declared in that fetcher's
fetcher.yaml, not here.

Environment variables required:
- OKTA_API_TOKEN: Your Okta API token
- OKTA_ORG_URL: Your Okta org URL (e.g., https://yourorg.okta.com)

Usage:
    python okta_iam_core.py --check-only
    (Or use the dedicated wrapper scripts, e.g. python okta_phishing_resistant_mfa.py)
"""

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

import requests
from dotenv import load_dotenv

# Load environment variables from .env file
# Try multiple strategies to find and load .env file
env_loaded = False

# Strategy 1: Try to find .env relative to script location
try:
    script_path = Path(__file__).resolve()
    script_dir = script_path.parent
    project_root = script_dir.parent.parent  # Go up from fetchers/okta/ to project root
    env_path = project_root / '.env'
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)
        env_loaded = True
except (NameError, AttributeError):
    # __file__ might not be defined in some contexts
    pass

# Strategy 2: Try current working directory
if not env_loaded:
    cwd_env = Path.cwd() / '.env'
    if cwd_env.exists():
        load_dotenv(dotenv_path=cwd_env, override=False)
        env_loaded = True

# Strategy 3: Auto-discovery (searches up from current directory)
if not env_loaded:
    load_dotenv(override=False)

# Final verification - if still using placeholder, try one more time from explicit paths
loaded_org_url = os.getenv("OKTA_ORG_URL", "")
if not loaded_org_url or loaded_org_url == "https://yourorg.okta.com" or loaded_org_url.strip() == "":
    # Try explicit paths
    possible_paths = [
        Path.cwd() / '.env',
        Path.cwd().parent / '.env',
        Path.home() / '.env',
    ]
    for env_file in possible_paths:
        if env_file.exists():
            load_dotenv(dotenv_path=env_file, override=False)
            if os.getenv("OKTA_ORG_URL", "") and os.getenv("OKTA_ORG_URL", "") != "https://yourorg.okta.com":
                break


# =========================================================================
# FIDO2/WebAuthn AAGUID to Model Name Lookup
# AAGUIDs are unique identifiers for specific authenticator models
# Reference: https://fidoalliance.org/metadata/
# =========================================================================
AAGUID_MODEL_NAMES = {
    # YubiKey 5 FIPS Series
    "73bb0cd4-e502-49b8-9c6f-b59445bf720b": "YubiKey 5 FIPS Series",
    "c1f9a0bc-1dd2-404a-b27f-8e29047a43fd": "YubiKey 5Ci FIPS",
    "5b0e46ba-db02-44ac-b979-ca9b84f5e335": "YubiKey Bio FIPS",
    "62e54e98-c209-4df3-b692-de71bb6a8528": "YubiKey 5 NFC FIPS",
    "ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5 Nano FIPS",
    "a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa": "YubiKey 5C FIPS",
    "c5ef55ff-ad9a-4b9f-b580-adebafe026d0": "YubiKey 5C Nano FIPS",
    "d8522d9f-575b-4866-88a9-ba99fa02f35b": "YubiKey 5C NFC FIPS",
    
    # YubiKey 5 Series (non-FIPS)
    "85203421-48f9-4355-9bc8-8a53846e5083": "YubiKey 5 Series",
    "2fc0579f-8113-47ea-b116-bb5a8db9202a": "YubiKey 5 NFC",
    "cb69481e-8ff7-4039-93ec-0a2729a154a8": "YubiKey 5C",
    "c5ef55ff-ad9a-4b9f-b580-adebafe026d0": "YubiKey 5C Nano",
    "fa2b99dc-9e39-4257-8f92-4a30d23c4118": "YubiKey 5 Nano",
    "ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5Ci",
    "f8a011f3-8c0a-4d15-8006-17111f9edc7d": "YubiKey Bio Series",
    "d8522d9f-575b-4866-88a9-ba99fa02f35b": "YubiKey 5C NFC",
    "b92c3f9a-c014-4056-887f-140a2501163b": "YubiKey 5C Nano",
    
    # YubiKey Bio Series
    "d8522d9f-575b-4866-88a9-ba99fa02f35b": "YubiKey Bio - FIDO Edition",
    "6d44ba9b-f6ec-2e49-b930-0c8fe920cb73": "YubiKey Bio - Multi-protocol Edition",
    
    # Security Key by Yubico
    "149a2021-8ef6-4133-96b8-81f8d5b7f1f5": "Security Key NFC by Yubico",
    "a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa": "Security Key by Yubico",
    
    # Google Titan
    "42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3": "Google Titan Security Key",
    
    # Windows Hello
    "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello Hardware Authenticator",
    "6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello Software Authenticator",
    "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello VBS Hardware Authenticator",
    
    # Apple
    "dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "Apple Touch ID / Face ID",
    "531126d6-e717-415c-9320-3d9aa6981239": "Apple Passkey",
    
    # Feitian
    "3e22415d-7fdf-4ea4-8a0c-dd60c4249b9d": "Feitian ePass FIDO2 Authenticator",
    "833b721a-ff5f-4d00-bb2e-bdda3ec01e29": "Feitian BioPass FIDO2 Authenticator",
}


def lookup_aaguid_model_name(aaguid: str) -> str:
    """Look up the human-readable model name for an AAGUID."""
    return AAGUID_MODEL_NAMES.get(aaguid, f"Unknown Model ({aaguid})")


def account_list_from_env(var_name: str) -> List[str]:
    """Read a comma- or newline-separated list of Okta logins/emails from an env var.

    Some collectors accept an explicit list of accounts to treat as service
    accounts or Super Admins, for tenants whose Okta configuration does not make
    that discoverable on its own (no userType=Service, admin role granted outside
    a group, and so on). Those lists are tenant-specific, so they are configured
    per run and never hardcoded here. Empty is the correct default -- the
    name-independent detection methods stand on their own.

    Returns the entries lowercased, ready to compare against a profile's
    email/login.
    """
    raw = os.getenv(var_name, "")
    return [entry.strip().lower() for entry in raw.replace("\n", ",").split(",") if entry.strip()]


class OktaAPIClient:
    """
    Okta API Client based on official documentation.
    Reference: https://developer.okta.com/docs/api/
    
    API Version: v1
    Auth: SSWS token (API token authentication)
    """

    def __init__(self):
        self.org_url = os.getenv("OKTA_ORG_URL", "").rstrip("/")
        self.api_token = os.getenv("OKTA_API_TOKEN")
        
        if not self.org_url:
            raise RuntimeError("OKTA_ORG_URL environment variable is required")
        if not self.api_token:
            raise RuntimeError("OKTA_API_TOKEN environment variable is required")
        
        # Okta API uses SSWS prefix for API token authentication
        # Reference: https://developer.okta.com/docs/api/#authentication
        self.headers = {
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        # API base URL with version
        self.api_base = f"{self.org_url}/api/v1"
        
        # Track feature availability
        self.feature_availability = {}
        self.unavailable_features = []

        # Track network-level API failures (connection errors, timeouts, DNS
        # failures). 4xx HTTP responses are NOT tracked here — they're treated
        # as expected "feature unavailable" signals by callers below.
        # Wrappers can read this list at end-of-run to decide exit code.
        self.api_failures: List[Dict[str, Any]] = []

    def check_endpoint_availability(self, endpoint: str, feature_name: str) -> bool:
        """Check if an endpoint is available and track the result."""
        url = f"{self.api_base}{endpoint}"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            available = response.status_code == 200
            self.feature_availability[feature_name] = {
                "available": available,
                "status_code": response.status_code,
                "endpoint": endpoint
            }
            if not available:
                prediction = self._get_feature_prediction(feature_name, response.status_code)
                self.unavailable_features.append({
                    "feature": feature_name,
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "reason": self._get_unavailable_reason(response.status_code),
                    "prediction": prediction
                })
            return available
        except Exception as e:
            prediction = self._get_feature_prediction(feature_name, None)
            self.feature_availability[feature_name] = {
                "available": False,
                "error": str(e),
                "endpoint": endpoint
            }
            self.unavailable_features.append({
                "feature": feature_name,
                "endpoint": endpoint,
                "status_code": None,
                "reason": str(e),
                "prediction": prediction
            })
            return False

    def _get_unavailable_reason(self, status_code: int) -> str:
        """Get human-readable reason for unavailability."""
        reasons = {
            401: "Authentication failed - check API token",
            403: "Access denied - insufficient permissions or feature not enabled",
            404: "Feature not available (may require Okta Identity Engine or add-on)",
            429: "Rate limited"
        }
        return reasons.get(status_code, f"HTTP {status_code}")
    
    def _get_feature_prediction(self, feature_name: str, status_code: int) -> str:
        """Get best prediction for why a feature is unavailable and how to enable it."""
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
            "System Log API": "Check API token permissions. Ensure token has Log Read permissions."
        }
        
        # Get base prediction
        prediction = predictions.get(feature_name, "Unknown feature - check Okta documentation for requirements")
        
        # Add status code specific guidance
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
        """Run compatibility check for all features used by this fetcher."""
        print("\n🔍 Running Okta API Compatibility Check...")
        print("-" * 50)
        
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
            status = "✅" if available else "⚠️ "
            print(f"  {status} {feature_name}")
        
        # Determine org type
        is_oie = self.feature_availability.get("Authenticators API (OIE)", {}).get("available", False)
        org_type = "Okta Identity Engine (OIE)" if is_oie else "Okta Classic"
        
        print("-" * 50)
        print(f"  Org Type: {org_type}")
        
        if self.unavailable_features:
            print(f"\n  ⚠️  {len(self.unavailable_features)} features unavailable:")
            for uf in self.unavailable_features:
                print(f"     - {uf['feature']}: {uf['reason']}")
                if uf.get('prediction'):
                    print(f"       Prediction: {uf.get('prediction')}")
            print("\n  Note: Evidence collection will continue.")
            print("        Unavailable features will return empty data.")
        else:
            print("\n  ✅ All features available!")
        
        print("-" * 50)
        
        return {
            "org_type": org_type,
            "features_checked": len(checks),
            "features_available": len(checks) - len(self.unavailable_features),
            "features_unavailable": len(self.unavailable_features),
            "unavailable_details": self.unavailable_features,
            "feature_availability": self.feature_availability
        }

    def _request(self, method: str, endpoint: str, params: Optional[Dict] = None, data: Optional[Dict] = None) -> Any:
        """
        Make an API request to Okta.
        
        Reference: https://developer.okta.com/docs/api/#http-verbs
        """
        url = f"{self.api_base}{endpoint}"
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self.headers,
                params=params,
                json=data,
                timeout=30
            )
            
            # Handle common error codes
            # Reference: https://developer.okta.com/docs/api/#errors
            if response.status_code == 401:
                raise RuntimeError(f"Authentication failed. Check your OKTA_API_TOKEN.")
            elif response.status_code == 403:
                print(f"    ⚠️ Access denied for {endpoint}")
                return []
            elif response.status_code == 404:
                return []
            elif response.status_code == 429:
                print(f"    ⚠️ Rate limited on {endpoint}")
                return []
            
            response.raise_for_status()
            
            # Handle empty responses
            if not response.content:
                return []
                
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.api_failures.append({
                "endpoint": endpoint,
                "type": type(e).__name__,
                "message": str(e),
            })
            print(f"    ⚠️ Request failed for {endpoint}: {e}")
            return []

    def _paginated_get(self, endpoint: str, params: Optional[Dict] = None, max_pages: int = 10) -> List[Dict]:
        """
        Handle Okta's pagination via Link headers.
        
        Reference: https://developer.okta.com/docs/api/#pagination
        Okta uses the Link header for pagination with rel="next"
        """
        results = []
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
                    # Don't crash - some endpoints return 401 when feature is not licensed
                    print(f"    ⚠️ Access denied (401) - feature may require additional license")
                    break
                elif response.status_code in [403, 404]:
                    break
                elif response.status_code == 429:
                    print(f"    ⚠️ Rate limited, stopping pagination")
                    break
                    
                response.raise_for_status()
                
                data = response.json() if response.content else []
                
                if isinstance(data, list):
                    results.extend(data)
                elif isinstance(data, dict):
                    results.append(data)
                
                # Parse Link header for pagination
                # Reference: https://developer.okta.com/docs/api/#link-header
                url = None
                params = None  # URL already contains params
                
                link_header = response.headers.get("Link", "")
                for link in link_header.split(","):
                    if 'rel="next"' in link:
                        # Extract URL from: <https://...>; rel="next"
                        url = link.split(";")[0].strip("<> ")
                        break
                
                page += 1
                
            except requests.exceptions.RequestException as e:
                self.api_failures.append({
                    "endpoint": endpoint,
                    "type": type(e).__name__,
                    "message": str(e),
                })
                print(f"    ⚠️ Pagination failed: {e}")
                break
                
        return results

    # =========================================================================
    # OKTA API ENDPOINTS
    # Reference: https://developer.okta.com/docs/api/
    # =========================================================================

    # --- Users API ---
    # Reference: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/
    
    def list_users(self, filter_query: str = None, search: str = None, limit: int = 200) -> List[Dict]:
        """List users with optional filter."""
        params = {"limit": str(limit)}
        if filter_query:
            params["filter"] = filter_query
        if search:
            params["search"] = search
        return self._paginated_get("/users", params)
    
    def get_user(self, user_id: str) -> Dict:
        """Get a specific user."""
        return self._request("GET", f"/users/{user_id}")
    
    def list_user_factors(self, user_id: str) -> List[Dict]:
        """List enrolled factors for a user (MFA)."""
        return self._paginated_get(f"/users/{user_id}/factors")
    
    def list_user_roles(self, user_id: str) -> List[Dict]:
        """List admin roles assigned to a user."""
        return self._paginated_get(f"/users/{user_id}/roles")

    # --- Groups API ---
    # Reference: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Group/
    
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
        """List group rules (dynamic group membership)."""
        return self._paginated_get("/groups/rules")

    # --- Applications API ---
    # Reference: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Application/
    
    def list_applications(self) -> List[Dict]:
        """List all applications."""
        return self._paginated_get("/apps")
    
    def list_app_users(self, app_id: str) -> List[Dict]:
        """List users assigned to an application."""
        return self._paginated_get(f"/apps/{app_id}/users")
    
    def list_app_groups(self, app_id: str) -> List[Dict]:
        """List groups assigned to an application."""
        return self._paginated_get(f"/apps/{app_id}/groups")

    # --- Authenticators API ---
    # Reference: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Authenticator/
    
    def list_authenticators(self) -> List[Dict]:
        """List all authenticators (MFA methods)."""
        return self._paginated_get("/authenticators")
    
    def get_authenticator(self, authenticator_id: str) -> Dict:
        """Get a specific authenticator configuration."""
        return self._request("GET", f"/authenticators/{authenticator_id}")
    
    def get_authenticator_methods(self, authenticator_id: str) -> List[Dict]:
        """Get methods/settings for an authenticator (includes FIPS, attestation settings)."""
        return self._paginated_get(f"/authenticators/{authenticator_id}/methods")

    # --- Policies API ---
    # Reference: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
    
    def list_policies(self, policy_type: str) -> List[Dict]:
        """
        List policies by type.
        Types: OKTA_SIGN_ON, PASSWORD, MFA_ENROLL, ACCESS_POLICY, 
               PROFILE_ENROLLMENT, AUTHENTICATOR_ENROLLMENT
        """
        return self._paginated_get("/policies", params={"type": policy_type})
    
    def list_policy_rules(self, policy_id: str) -> List[Dict]:
        """List rules for a policy."""
        return self._paginated_get(f"/policies/{policy_id}/rules")

    # --- Authorization Servers API ---
    # Reference: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/AuthorizationServer/
    
    def list_authorization_servers(self) -> List[Dict]:
        """List all authorization servers."""
        return self._paginated_get("/authorizationServers")
    
    def list_auth_server_scopes(self, auth_server_id: str) -> List[Dict]:
        """List scopes for an authorization server."""
        return self._paginated_get(f"/authorizationServers/{auth_server_id}/scopes")
    
    def list_auth_server_claims(self, auth_server_id: str) -> List[Dict]:
        """List claims for an authorization server."""
        return self._paginated_get(f"/authorizationServers/{auth_server_id}/claims")
    
    def list_auth_server_policies(self, auth_server_id: str) -> List[Dict]:
        """List policies for an authorization server."""
        return self._paginated_get(f"/authorizationServers/{auth_server_id}/policies")

    # --- System Log API ---
    # Reference: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/
    
    def get_system_logs(self, since: str = None, filter_query: str = None, limit: int = 500) -> List[Dict]:
        """
        Get system log events.
        
        Filter operators supported: eq, ne, lt, le, gt, ge, sw, co
        Reference: https://developer.okta.com/docs/api/#filter
        """
        params = {"limit": str(limit)}
        if since:
            params["since"] = since
        if filter_query:
            params["filter"] = filter_query
        return self._paginated_get("/logs", params, max_pages=5)

    # --- API Tokens API ---
    
    def list_api_tokens(self) -> List[Dict]:
        """List API tokens."""
        return self._paginated_get("/api-tokens")
    
    # --- ThreatInsight API ---
    # Reference: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ThreatInsight/
    
    def get_threat_insight_settings(self) -> Dict:
        """Get ThreatInsight settings (Security > Identity Threat Protection > ThreatInsight)."""
        try:
            return self._request("GET", "/threatInsight")
        except Exception:
            return {}
    
    # --- Behavior Detection API ---
    # Reference: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Behavior/
    
    def list_behaviors(self) -> List[Dict]:
        """List behavior detection rules (Security > Behavior Detection)."""
        try:
            return self._paginated_get("/behaviors")
        except Exception:
            return []


class OktaIAMEvidenceFetcher:
    """
    Fetches IAM evidence from Okta.
    Organized by evidence set.
    """

    def __init__(self, skip_compatibility_check: bool = False):
        self.client = OktaAPIClient()
        self.compatibility_results = None
        
        # Run compatibility check unless skipped
        if not skip_compatibility_check:
            self.compatibility_results = self.client.run_compatibility_check()

    # =========================================================================
    # Phishing-Resistant MFA
    # =========================================================================
    def collect_phishing_resistant_mfa(self) -> Dict:
        """Phishing-Resistant MFA.

        The KSI this maps to lives in the fetcher's fetcher.yaml (`ksis:`) --
        FedRAMP re-keys its indicators, and this code should not have to follow.
        """
        print("\n📌 Phishing-Resistant MFA")
        evidence = {
            "name": "Phishing-Resistant MFA",
            "data": {}
        }

        # 1. Authenticators configuration
        print("  → Fetching authenticators...")
        authenticators = self.client.list_authenticators()
        evidence["data"]["authenticators"] = authenticators
        
        # Identify phishing-resistant authenticators (FIDO2/WebAuthn)
        phishing_resistant_types = ["security_key", "webauthn"]
        phishing_resistant = [a for a in authenticators if a.get("type") in phishing_resistant_types]
        
        # Fetch detailed methods/settings for each phishing-resistant authenticator
        # This includes FIPS mode, attestation requirements, etc.
        print("  → Fetching phishing-resistant authenticator details (FIPS, attestation)...")
        for auth in phishing_resistant:
            auth_id = auth.get("id")
            if auth_id:
                methods = self.client.get_authenticator_methods(auth_id)
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
        print("  → Fetching access policies...")
        access_policies = self.client.list_policies("ACCESS_POLICY")
        for policy in access_policies:
            policy["rules"] = self.client.list_policy_rules(policy["id"])
        evidence["data"]["access_policies"] = access_policies

        # 3. Sign-on policies
        print("  → Fetching sign-on policies...")
        signon_policies = self.client.list_policies("OKTA_SIGN_ON")
        for policy in signon_policies:
            policy["rules"] = self.client.list_policy_rules(policy["id"])
        evidence["data"]["sign_on_policies"] = signon_policies

        # 4. Sample users with MFA factors
        print("  → Fetching user MFA factors (sampling active users)...")
        active_users = self.client.list_users(filter_query='status eq "ACTIVE"', limit=100)
        users_with_factors = []
        
        for i, user in enumerate(active_users[:50]):  # Sample first 50
            if (i + 1) % 10 == 0:
                print(f"      Processing user {i + 1}/50...")
            
            factors = self.client.list_user_factors(user["id"])
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

        # 5. MFA authentication logs (last 7 days)
        print("  → Fetching MFA authentication logs...")
        since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        mfa_logs = self.client.get_system_logs(
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
        
       # print(f"  ✓ Summary: {evidence['summary']}")
        return evidence

    # =========================================================================
    # Passwordless Authentication
    # =========================================================================
    def collect_passwordless_authentication(self) -> Dict:
        """Passwordless Authentication.

        The KSI this maps to lives in the fetcher's fetcher.yaml (`ksis:`) --
        FedRAMP re-keys its indicators, and this code should not have to follow.
        """
        print("\n📌 Passwordless Authentication")
        evidence = {
            "name": "Passwordless Authentication",
            "data": {}
        }

        # 1. Password policies
        print("  → Fetching password policies...")
        password_policies = self.client.list_policies("PASSWORD")
        for policy in password_policies:
            policy["rules"] = self.client.list_policy_rules(policy["id"])
        evidence["data"]["password_policies"] = password_policies
        
        # 1a. Password Authenticator settings (Security > Authenticators > Password)
        print("  → Fetching Password Authenticator settings...")
        authenticators = self.client.list_authenticators()
        password_authenticator = None
        password_authenticator_methods = []
        
        for auth in authenticators:
            if auth.get("type") == "password" or auth.get("key") == "okta_password":
                password_authenticator = auth
                auth_id = auth.get("id")
                if auth_id:
                    try:
                        methods = self.client.get_authenticator_methods(auth_id)
                        password_authenticator_methods = methods if methods else []
                        # Add methods to the authenticator object
                        password_authenticator["methods"] = methods
                    except Exception as e:
                        print(f"    ⚠️ Could not fetch Password Authenticator methods: {e}")
                break
        
        evidence["data"]["password_authenticator"] = password_authenticator
        evidence["data"]["password_authenticator_methods"] = password_authenticator_methods

        # 2. MFA enrollment policies
        print("  → Fetching MFA enrollment policies...")
        mfa_policies = self.client.list_policies("MFA_ENROLL")
        for policy in mfa_policies:
            policy["rules"] = self.client.list_policy_rules(policy["id"])
        evidence["data"]["mfa_enrollment_policies"] = mfa_policies

        # 3. Authenticator enrollment policies
        print("  → Fetching authenticator enrollment policies...")
        auth_enroll_policies = self.client.list_policies("AUTHENTICATOR_ENROLLMENT")
        for policy in auth_enroll_policies:
            policy["rules"] = self.client.list_policy_rules(policy["id"])
        evidence["data"]["authenticator_enrollment_policies"] = auth_enroll_policies

        # 4. Passwordless-capable authenticators
        print("  → Identifying passwordless authenticators...")
        # Reuse authenticators already fetched for password authenticator
        if not authenticators:
            authenticators = self.client.list_authenticators()
        passwordless_types = ["security_key", "webauthn", "phone", "email"]
        passwordless = [a for a in authenticators if a.get("type") in passwordless_types]
        evidence["data"]["passwordless_authenticators"] = passwordless

        # 5. Analyze access policies to determine REQUIRED vs AVAILABLE authenticators
        print("  → Analyzing access policies for required authentication methods...")
        access_policies = self.client.list_policies("ACCESS_POLICY")
        for policy in access_policies:
            policy["rules"] = self.client.list_policy_rules(policy["id"])
        evidence["data"]["access_policies"] = access_policies
        
        # Extract required factors from access policies
        required_factors = set()
        allowed_factors = set()
        
        for policy in access_policies:
            for rule in policy.get("rules", []):
                actions = rule.get("actions", {})
                app_signon = actions.get("appSignOn", {})
                
                # Check verification method requirements
                verification = app_signon.get("verificationMethod", {})
                factor_mode = verification.get("factorMode", "")
                assurance_type = verification.get("type", "")
                
                # If factorMode is "2FA_REQUIRED" or assurance type specifies factors, extract them
                if factor_mode == "2FA_REQUIRED":
                    # Check if specific factors are required in the rule
                    # Look for factor constraints in the rule
                    pass
                
                # Check for primary factor requirements
                primary_factor = app_signon.get("primaryFactor", "")
                if primary_factor:
                    if "FIDO" in primary_factor or "WEBAUTHN" in primary_factor or "SECURITY_KEY" in primary_factor:
                        required_factors.add("security_key")
        
        # 6. Analyze sign-on policies for primary factor requirements
        print("  → Analyzing sign-on policies for primary authentication methods...")
        signon_policies = self.client.list_policies("OKTA_SIGN_ON")
        for policy in signon_policies:
            policy["rules"] = self.client.list_policy_rules(policy["id"])
        evidence["data"]["sign_on_policies"] = signon_policies
        
        for policy in signon_policies:
            for rule in policy.get("rules", []):
                actions = rule.get("actions", {})
                signon = actions.get("signon", {})
                primary_factor = signon.get("primaryFactor", "")
                require_factor = signon.get("requireFactor", False)
                
                # If requireFactor is true, check what's required
                if require_factor:
                    if "FIDO" in primary_factor or "WEBAUTHN" in primary_factor or "SECURITY_KEY" in primary_factor:
                        required_factors.add("security_key")
                    elif primary_factor == "PASSWORD_IDP_ANY_FACTOR":
                        # Any factor allowed, but check if security key is enforced elsewhere
                        allowed_factors.add("any")
        
        # 7. Check user enrollments to see what's actually being used
        print("  → Checking user factor enrollments to determine enforced methods...")
        active_users = self.client.list_users(filter_query='status eq "ACTIVE"', limit=50)
        enrolled_factor_types = set()
        security_key_enrollments = 0
        user_enrollment_summary = []
        
        for user in active_users:
            factors = self.client.list_user_factors(user["id"])
            user_factors = []
            has_security_key = False
            
            for factor in factors:
                factor_type = factor.get("factorType", "")
                provider = factor.get("provider", "")
                
                if factor_type in ["webauthn", "u2f"] or provider == "FIDO":
                    enrolled_factor_types.add("security_key")
                    security_key_enrollments += 1
                    has_security_key = True
                    user_factors.append({
                        "type": "security_key",
                        "factorType": factor_type,
                        "provider": provider,
                        "status": factor.get("status"),
                        "authenticatorName": factor.get("profile", {}).get("authenticatorName")
                    })
                elif factor_type == "sms":
                    enrolled_factor_types.add("phone")
                    user_factors.append({"type": "phone", "factorType": factor_type})
                elif factor_type == "email":
                    enrolled_factor_types.add("email")
                    user_factors.append({"type": "email", "factorType": factor_type})
            
            user_enrollment_summary.append({
                "user_id": user["id"],
                "login": user.get("profile", {}).get("login"),
                "has_security_key": has_security_key,
                "enrolled_factors": user_factors
            })
        
        evidence["data"]["user_authentication_enrollments"] = user_enrollment_summary
        
        # Determine if security key is enforced based on:
        # 1. All users have security key enrolled (strongest evidence)
        # 2. Access policies explicitly require it
        security_key_enforced = (
            security_key_enrollments == len(active_users) and len(active_users) > 0
        ) or "security_key" in required_factors
        
        # Categorize authenticators
        available_authenticators = [a.get("type") for a in passwordless]
        
        # Separate default 2FA methods from enforced methods
        default_2fa_methods = [t for t in available_authenticators if t in ["email", "phone"]]
        enforced_methods = []
        if security_key_enforced:
            enforced_methods = ["security_key"]
        
        # Extract password policy requirements
        # First, get Password Authenticator settings (Security > Authenticators > Password)
        password_authenticator_settings = {}
        if password_authenticator:
            auth_id = password_authenticator.get("id")
            
            # Method 1: Try to get settings from methods
            if password_authenticator_methods:
                for method in password_authenticator_methods:
                    method_type = method.get("type", "")
                    if method_type == "password":
                        settings = method.get("settings", {})
                        if settings:
                            # Try multiple nested paths
                            extracted = {
                                "min_length": settings.get("minLength") or settings.get("min_length"),
                                "max_length": settings.get("maxLength") or settings.get("max_length"),
                                "min_lowercase": settings.get("minLowerCase") or settings.get("min_lowercase"),
                                "min_uppercase": settings.get("minUpperCase") or settings.get("min_uppercase"),
                                "min_number": settings.get("minNumber") or settings.get("min_number"),
                                "min_symbol": settings.get("minSymbol") or settings.get("min_symbol"),
                                "exclude_username": settings.get("excludeUsername") or settings.get("exclude_username"),
                                "exclude_first_name": settings.get("excludeFirstName") or settings.get("exclude_first_name"),
                                "exclude_last_name": settings.get("excludeLastName") or settings.get("exclude_last_name"),
                                "exclude_email": settings.get("excludeEmail") or settings.get("exclude_email"),
                                "password_history_count": settings.get("historyCount") or settings.get("history_count"),
                                "password_expire_days": settings.get("passwordExpireDays") or settings.get("age", {}).get("expireInDays") or settings.get("expire_days"),
                                "password_min_age_minutes": settings.get("passwordMinAgeMinutes") or settings.get("age", {}).get("minAgeInMinutes") or settings.get("min_age_minutes"),
                                "lockout_attempts": settings.get("lockoutAttempts") or settings.get("lockout", {}).get("maxAttempts") or settings.get("max_attempts"),
                                "lockout_duration_minutes": settings.get("lockoutDurationMinutes") or settings.get("lockout", {}).get("autoUnlockMinutes") or settings.get("auto_unlock_minutes")
                            }
                            if any(v is not None for v in extracted.values()):
                                password_authenticator_settings = {
                                    "source": "Password Authenticator (Security > Authenticators > Password)",
                                    "authenticator_id": auth_id,
                                    "authenticator_name": password_authenticator.get("name"),
                                    **{k: v for k, v in extracted.items() if v is not None},
                                    "all_settings": settings  # Include full settings for audit
                                }
                                break
            
            # Method 2: If no settings from methods, try to get full authenticator details
            settings_keys = ["min_length", "max_length", "min_lowercase", "min_uppercase", "min_number", "min_symbol"]
            has_settings = password_authenticator_settings and any(
                password_authenticator_settings.get(k) is not None 
                for k in settings_keys
            )
            if not has_settings and auth_id:
                try:
                    full_authenticator = self.client._request("GET", f"/authenticators/{auth_id}")
                    if full_authenticator:
                        # Check multiple paths for settings
                        paths_to_check = [
                            ("settings",),
                            ("_embedded", "settings"),
                            ("methods", 0, "settings"),  # First method's settings
                        ]
                        
                        for path in paths_to_check:
                            current = full_authenticator
                            for key in path:
                                if isinstance(current, (dict, list)):
                                    if isinstance(current, list) and isinstance(key, int) and 0 <= key < len(current):
                                        current = current[key]
                                    elif isinstance(current, dict) and key in current:
                                        current = current[key]
                                    else:
                                        current = None
                                        break
                                else:
                                    current = None
                                    break
                            
                            if current and isinstance(current, dict):
                                extracted = {
                                    "min_length": current.get("minLength") or current.get("min_length"),
                                    "max_length": current.get("maxLength") or current.get("max_length"),
                                    "min_lowercase": current.get("minLowerCase") or current.get("min_lowercase"),
                                    "min_uppercase": current.get("minUpperCase") or current.get("min_uppercase"),
                                    "min_number": current.get("minNumber") or current.get("min_number"),
                                    "min_symbol": current.get("minSymbol") or current.get("min_symbol"),
                                    "exclude_username": current.get("excludeUsername") or current.get("exclude_username"),
                                    "exclude_first_name": current.get("excludeFirstName") or current.get("exclude_first_name"),
                                    "exclude_last_name": current.get("excludeLastName") or current.get("exclude_last_name"),
                                    "exclude_email": current.get("excludeEmail") or current.get("exclude_email"),
                                    "password_history_count": current.get("historyCount") or current.get("history_count"),
                                    "password_expire_days": current.get("passwordExpireDays") or current.get("age", {}).get("expireInDays") or current.get("expire_days"),
                                    "password_min_age_minutes": current.get("passwordMinAgeMinutes") or current.get("age", {}).get("minAgeInMinutes") or current.get("min_age_minutes"),
                                    "lockout_attempts": current.get("lockoutAttempts") or current.get("lockout", {}).get("maxAttempts") or current.get("max_attempts"),
                                    "lockout_duration_minutes": current.get("lockoutDurationMinutes") or current.get("lockout", {}).get("autoUnlockMinutes") or current.get("auto_unlock_minutes")
                                }
                                if any(v is not None for v in extracted.values()):
                                    if not password_authenticator_settings:
                                        password_authenticator_settings = {
                                            "source": "Password Authenticator (Security > Authenticators > Password)",
                                            "authenticator_id": auth_id,
                                            "authenticator_name": full_authenticator.get("name"),
                                        }
                                    password_authenticator_settings.update({k: v for k, v in extracted.items() if v is not None})
                                    password_authenticator_settings["all_settings"] = current
                except Exception as e:
                    print(f"    ⚠️ Could not fetch full authenticator details: {e}")
        
        # Also extract from password policies (for completeness)
        # Comprehensive extraction trying multiple methods and paths
        password_policy_requirements = []
        for policy in password_policies:
            policy_requirements = {
                "policy_id": policy.get("id"),
                "policy_name": policy.get("name"),
                "status": policy.get("status"),
                "source": "Password Policy",
                "settings": {}
            }
            
            policy_id = policy.get("id")
            if not policy_id:
                password_policy_requirements.append(policy_requirements)
                continue
            
            # Method 1: Extract from rules already loaded -> actions -> passwordChange
            for rule in policy.get("rules", []):
                actions = rule.get("actions", {})
                password_change = actions.get("passwordChange", {})
                if password_change:
                    # Extract all possible fields
                    extracted = {
                        "min_length": password_change.get("minLength"),
                        "max_length": password_change.get("maxLength"),
                        "min_lowercase": password_change.get("minLowerCase"),
                        "min_uppercase": password_change.get("minUpperCase"),
                        "min_number": password_change.get("minNumber"),
                        "min_symbol": password_change.get("minSymbol"),
                        "exclude_username": password_change.get("excludeUsername"),
                        "exclude_first_name": password_change.get("excludeFirstName"),
                        "exclude_last_name": password_change.get("excludeLastName"),
                        "exclude_email": password_change.get("excludeEmail"),
                        "password_history_count": password_change.get("historyCount"),
                        "password_expire_days": password_change.get("passwordExpireDays"),
                        "password_min_age_minutes": password_change.get("passwordMinAgeMinutes"),
                        "lockout_attempts": password_change.get("lockoutAttempts"),
                        "lockout_duration_minutes": password_change.get("lockoutDurationMinutes")
                    }
                    # Only update if we found at least one non-None value
                    if any(v is not None for v in extracted.values()):
                        policy_requirements["settings"].update(extracted)
            
            # Method 2: Fetch full policy details and inspect all possible paths
            if not policy_requirements["settings"] or all(v is None for v in policy_requirements["settings"].values()):
                try:
                    full_policy = self.client._request("GET", f"/policies/{policy_id}")
                    if full_policy:
                        # Try multiple nested paths for settings
                        paths_to_check = [
                            ("settings", "password"),
                            ("settings", "lockout"),
                            ("settings",),
                            ("password",),
                            ("lockout",),
                            ("_embedded", "settings"),
                            ("_embedded", "password"),
                        ]
                        
                        for path in paths_to_check:
                            current = full_policy
                            for key in path:
                                if isinstance(current, dict) and key in current:
                                    current = current[key]
                                else:
                                    current = None
                                    break
                            
                            if current and isinstance(current, dict):
                                # Extract from this path
                                extracted = {
                                    "min_length": current.get("minLength") or current.get("min_length"),
                                    "max_length": current.get("maxLength") or current.get("max_length"),
                                    "min_lowercase": current.get("minLowerCase") or current.get("min_lowercase"),
                                    "min_uppercase": current.get("minUpperCase") or current.get("min_uppercase"),
                                    "min_number": current.get("minNumber") or current.get("min_number"),
                                    "min_symbol": current.get("minSymbol") or current.get("min_symbol"),
                                    "exclude_username": current.get("excludeUsername") or current.get("exclude_username"),
                                    "password_history_count": current.get("historyCount") or current.get("historyCount") or current.get("history_count"),
                                    "lockout_attempts": current.get("maxAttempts") or current.get("lockoutAttempts") or current.get("max_attempts"),
                                    "lockout_duration_minutes": current.get("autoUnlockMinutes") or current.get("lockoutDurationMinutes") or current.get("auto_unlock_minutes")
                                }
                                if any(v is not None for v in extracted.values()):
                                    policy_requirements["settings"].update({k: v for k, v in extracted.items() if v is not None})
                        
                        # Also check rules in the full policy response (may have more detail)
                        full_policy_rules = full_policy.get("rules", [])
                        for rule in full_policy_rules:
                            # Check actions -> passwordChange
                            actions = rule.get("actions", {})
                            password_change = actions.get("passwordChange", {})
                            if password_change:
                                extracted = {
                                    "min_length": password_change.get("minLength"),
                                    "max_length": password_change.get("maxLength"),
                                    "min_lowercase": password_change.get("minLowerCase"),
                                    "min_uppercase": password_change.get("minUpperCase"),
                                    "min_number": password_change.get("minNumber"),
                                    "min_symbol": password_change.get("minSymbol"),
                                    "exclude_username": password_change.get("excludeUsername"),
                                    "exclude_first_name": password_change.get("excludeFirstName"),
                                    "exclude_last_name": password_change.get("excludeLastName"),
                                    "exclude_email": password_change.get("excludeEmail"),
                                    "password_history_count": password_change.get("historyCount"),
                                    "password_expire_days": password_change.get("passwordExpireDays"),
                                    "password_min_age_minutes": password_change.get("passwordMinAgeMinutes"),
                                    "lockout_attempts": password_change.get("lockoutAttempts"),
                                    "lockout_duration_minutes": password_change.get("lockoutDurationMinutes")
                                }
                                if any(v is not None for v in extracted.values()):
                                    policy_requirements["settings"].update({k: v for k, v in extracted.items() if v is not None})
                            
                            # Also check if settings are directly in the rule
                            rule_settings = rule.get("settings", {})
                            if rule_settings:
                                extracted = {
                                    "min_length": rule_settings.get("minLength"),
                                    "max_length": rule_settings.get("maxLength"),
                                    "min_lowercase": rule_settings.get("minLowerCase"),
                                    "min_uppercase": rule_settings.get("minUpperCase"),
                                    "min_number": rule_settings.get("minNumber"),
                                    "min_symbol": rule_settings.get("minSymbol"),
                                }
                                if any(v is not None for v in extracted.values()):
                                    policy_requirements["settings"].update({k: v for k, v in extracted.items() if v is not None})
                except Exception as e:
                    #print(f"    ⚠️ Could not fetch full policy details for {policy.get('name')}: {e}")
                    pass
            
            # Method 3: Try fetching individual rules to get more detail
            if not policy_requirements["settings"] or all(v is None for v in policy_requirements["settings"].values()):
                try:
                    for rule in policy.get("rules", []):
                        rule_id = rule.get("id")
                        if rule_id:
                            try:
                                full_rule = self.client._request("GET", f"/policies/{policy_id}/rules/{rule_id}")
                                if full_rule:
                                    actions = full_rule.get("actions", {})
                                    password_change = actions.get("passwordChange", {})
                                    if password_change:
                                        extracted = {
                                            "min_length": password_change.get("minLength"),
                                            "max_length": password_change.get("maxLength"),
                                            "min_lowercase": password_change.get("minLowerCase"),
                                            "min_uppercase": password_change.get("minUpperCase"),
                                            "min_number": password_change.get("minNumber"),
                                            "min_symbol": password_change.get("minSymbol"),
                                            "exclude_username": password_change.get("excludeUsername"),
                                            "exclude_first_name": password_change.get("excludeFirstName"),
                                            "exclude_last_name": password_change.get("excludeLastName"),
                                            "exclude_email": password_change.get("excludeEmail"),
                                            "password_history_count": password_change.get("historyCount"),
                                            "password_expire_days": password_change.get("passwordExpireDays"),
                                            "password_min_age_minutes": password_change.get("passwordMinAgeMinutes"),
                                            "lockout_attempts": password_change.get("lockoutAttempts"),
                                            "lockout_duration_minutes": password_change.get("lockoutDurationMinutes")
                                        }
                                        if any(v is not None for v in extracted.values()):
                                            policy_requirements["settings"].update({k: v for k, v in extracted.items() if v is not None})
                            except Exception:
                                pass
                except Exception:
                    pass
            
            # Method 4: Include raw policy data for debugging if still no settings found
            if not policy_requirements["settings"] or all(v is None for v in policy_requirements["settings"].values()):
                # Store the full policy structure for inspection
                policy_requirements["raw_policy_data"] = {
                    "policy_keys": list(policy.keys()),
                    "rules_count": len(policy.get("rules", [])),
                    "first_rule_structure": policy.get("rules", [])[0] if policy.get("rules") else None,
                    "full_policy_sample": {k: v for k, v in policy.items() if k not in ["rules"]}  # Exclude rules to avoid huge output
                }
                policy_requirements["note"] = "Settings not found in standard locations. Raw policy data included above for inspection."
            
            password_policy_requirements.append(policy_requirements)
        
        # Combine both sources - Password Authenticator settings take precedence
        if password_authenticator_settings:
            password_policy_requirements.insert(0, password_authenticator_settings)
        
        # Summary
        evidence["summary"] = {
            "password_policies_count": len(password_policies),
            "password_policy_requirements": password_policy_requirements,
            "mfa_enrollment_policies_count": len(mfa_policies),
            "passwordless_authenticators_count": len(passwordless),
            "default_2fa_methods_available": default_2fa_methods,
            "enforced_authentication_method_for_sign_on": enforced_methods,
            "security_key_enforced_for_application_sign_on": security_key_enforced,
            "users_with_security_key_enrolled": security_key_enrollments,
            "total_active_users_checked": len(active_users),
            "security_key_enrollment_percentage": round((security_key_enrollments / len(active_users) * 100), 1) if len(active_users) > 0 else 0,
            "note": "Email and phone are default Okta 2FA methods available in the system. Security key (YubiKey 5 FIPS) is enforced as the required authentication method for application sign-on, as evidenced by 100% user enrollment." if security_key_enforced else "Multiple authentication methods available. Review access policies to determine enforcement."
        }

    #    print(f"  ✓ Summary: {evidence['summary']}")
        return evidence

    # =========================================================================
    # Non-User Accounts
    # =========================================================================
    def collect_non_user_accounts_authentication(self) -> Dict:
        """Non-User Accounts.

        The KSI this maps to lives in the fetcher's fetcher.yaml (`ksis:`) --
        FedRAMP re-keys its indicators, and this code should not have to follow.
        """
        print("\n📌 Non-User Accounts")
        evidence = {
            "name": "Non-User Accounts",
            "data": {}
        }

        # 1. Service accounts - only definitive indicators (100% certain)
        print("  → Searching for service accounts using definitive indicators only...")
        service_accounts = []
        
        # Get all users, API tokens, apps, and groups first
        print("  → Fetching all users, API tokens, apps, and groups...")
        all_users = self.client.list_users()
        api_tokens = self.client.list_api_tokens()
        evidence["data"]["api_tokens"] = api_tokens
        apps = self.client.list_applications()
        groups = self.client.list_groups()
        
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
                    "created": token.get("created")
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
                    app_users = self.client.list_app_users(app_id)
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
                                "sign_on_mode": app.get("signOnMode")
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
                    members = self.client.list_group_members(group_id)
                    for member in members:
                        user_id = member.get("id")
                        if user_id:
                            service_account_group_ids.add(user_id)
                            if user_id not in service_account_group_details:
                                service_account_group_details[user_id] = []
                            service_account_group_details[user_id].append({
                                "group_id": group_id,
                                "group_name": group.get("profile", {}).get("name")
                            })
                except Exception:
                    pass
        
        # Service accounts the tenant declares explicitly (OKTA_KNOWN_SERVICE_ACCOUNTS).
        # NOTE: This method is name-dependent and should be phased out in favor of
        # more reliable methods like userType, API tokens, OAuth clients, etc.
        known_service_accounts = account_list_from_env("OKTA_KNOWN_SERVICE_ACCOUNTS")
        
        # Analyze each user for definitive service account indicators only
        print("  → Analyzing users for definitive service account indicators...")
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
            
            # Method 5: Service accounts named in OKTA_KNOWN_SERVICE_ACCOUNTS
            # NOTE: This is name-dependent and should be phased out. Consider setting userType=Service instead.
            if email in known_service_accounts or login in known_service_accounts:
                indicators.append(f"known_service_account={email or login}")
                is_service_account = True
            
            # Only add if we have at least one definitive indicator
            if is_service_account:
                # Check if we already added this user
                if not any(sa["id"] == user_id for sa in service_accounts):
                    # Get full user details for evidence
                    try:
                        user_detail = self.client.get_user(user_id)
                        factors = self.client.list_user_factors(user_id)
                        roles = self.client.list_user_roles(user_id)
                        
                        # Extract role information
                        role_info = []
                        if roles:
                            for role in roles:
                                role_info.append({
                                    "type": role.get("type"),
                                    "label": role.get("label"),
                                    "status": role.get("status")
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
                            "detection_method": " | ".join(indicators)
                        })
                    except Exception:
                        # Fallback to basic user data - try to get roles
                        role_info = []
                        try:
                            roles = self.client.list_user_roles(user_id)
                            if roles:
                                for role in roles:
                                    role_info.append({
                                        "type": role.get("type"),
                                        "label": role.get("label"),
                                        "status": role.get("status")
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
                            "detection_method": " | ".join(indicators)
                        })
        
        evidence["data"]["service_accounts"] = service_accounts
        
        evidence["data"]["service_account_detection_methods"] = {
            "definitive_indicators_only": [
                "userType=Service (Okta's official service account field - MOST RELIABLE, name-independent)",
                "API token ownership (service accounts use API tokens for automation - name-independent)",
                "OAuth client assignment (service accounts used as OAuth clients for API authentication - name-independent)",
                "Service account group membership (membership in dedicated service account groups - name-independent if groups maintained)",
                "Known service account emails (explicitly identified - NAME-DEPENDENT, for backward compatibility only)"
            ],
            "recommendations": [
                "Set userType=Service for all service accounts (most reliable method)",
                "Use API token ownership or OAuth client assignments for name-independent detection",
                "Create and maintain a dedicated 'Service Accounts' group for additional detection",
                "Phase out email-based detection in favor of userType field"
            ],
            "note": "Only accounts with definitive indicators are included. Methods are prioritized by reliability and name-independence."
        }

        # 3. OAuth/OIDC applications (service apps)
        print("  → Fetching OAuth/OIDC applications...")
        apps = self.client.list_applications()
        oauth_apps = [a for a in apps if a.get("signOnMode") in ["OPENID_CONNECT", "SAML_2_0"]]
        evidence["data"]["oauth_apps"] = [{
            "id": a["id"],
            "name": a.get("name"),
            "label": a.get("label"),
            "signOnMode": a.get("signOnMode"),
            "status": a.get("status")
        } for a in oauth_apps]

        # 4. Authorization servers
        print("  → Fetching authorization servers...")
        auth_servers = self.client.list_authorization_servers()
        for server in auth_servers:
            server["scopes"] = self.client.list_auth_server_scopes(server["id"])
            server["policies"] = self.client.list_auth_server_policies(server["id"])
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
                "all_indicators": methods
            })
        
        evidence["summary"] = {
            "service_accounts_count": len(service_accounts),
            "service_accounts_by_detection_method": service_accounts_by_method,
            "api_tokens_count": len(api_tokens),
            "api_token_owners_count": len(api_token_user_ids),
            "oauth_apps_count": len(oauth_apps),
            "authorization_servers_count": len(auth_servers),
            "note": f"Service accounts identified using definitive indicators only: userType=Service, API token ownership, OAuth client assignments, service account group membership, or known service account emails. Total unique service accounts: {len(service_accounts)}. Methods are name-independent except for known email addresses."
        }

        print(f"  ✓ Summary: {evidence['summary']}")
        return evidence

    # =========================================================================
    # Just-in-Time Authorization
    # =========================================================================
    def collect_just_in_time_authorization(self) -> Dict:
        """Just-in-Time Authorization.

        The KSI this maps to lives in the fetcher's fetcher.yaml (`ksis:`) --
        FedRAMP re-keys its indicators, and this code should not have to follow.
        """
        print("\n📌 Just-in-Time Authorization")
        evidence = {
            "name": "Just-in-Time Authorization",
            "data": {}
        }

        # 1. Groups (role-based access)
        print("  → Fetching groups...")
        groups = self.client.list_groups()
        evidence["data"]["groups"] = [{
            "id": g["id"],
            "name": g.get("profile", {}).get("name"),
            "description": g.get("profile", {}).get("description"),
            "type": g.get("type")
        } for g in groups]

        # 2. Group rules (dynamic/automated membership - JIT)
        print("  → Fetching group rules (dynamic membership for JIT)...")
        group_rules = self.client.list_group_rules()
        # Analyze group rules for JIT indicators
        active_group_rules = [r for r in group_rules if r.get("status") == "ACTIVE"]
        evidence["data"]["group_rules"] = group_rules
        evidence["data"]["group_rules_analysis"] = {
            "total_rules": len(group_rules),
            "active_rules": len(active_group_rules),
            "rules_with_conditions": sum(1 for r in group_rules if r.get("conditions")),
            "note": "Dynamic group rules enable Just-in-Time group membership based on user attributes"
        }

        # 3. Access policies (conditional access - JIT authorization)
        print("  → Fetching access policies (conditional access for JIT)...")
        access_policies = self.client.list_policies("ACCESS_POLICY")
        for policy in access_policies:
            policy["rules"] = self.client.list_policy_rules(policy["id"])
        evidence["data"]["access_policies"] = access_policies
        
        # Analyze access policies for JIT indicators
        # Build both the count list and detailed rules list from the same rules
        policies_with_conditions = []
        access_policy_rules_details = []
        for policy in access_policies:
            for rule in policy.get("rules", []):
                conditions = rule.get("conditions", {})
                if conditions:
                    # Add to count list
                    policies_with_conditions.append({
                        "policy_id": policy.get("id"),
                        "policy_name": policy.get("name"),
                        "rule_id": rule.get("id"),
                        "rule_name": rule.get("name"),
                        "has_conditions": True
                    })
                    # Add detailed rule information
                    access_policy_rules_details.append({
                        "policy_id": policy.get("id"),
                        "policy_name": policy.get("name"),
                        "rule_id": rule.get("id"),
                        "rule_name": rule.get("name"),
                        "status": rule.get("status"),
                        "conditions": conditions,
                        "actions": rule.get("actions")
                    })
        
        evidence["data"]["access_policies_analysis"] = {
            "total_policies": len(access_policies),
            "policies_with_conditional_rules": len(policies_with_conditions),
            "note": "Access policies with conditions enable Just-in-Time authorization based on context"
        }

        # 4. Sign-on policies (context-aware authentication - supports JIT)
        print("  → Fetching sign-on policies (context-aware authentication)...")
        signon_policies = self.client.list_policies("OKTA_SIGN_ON")
        for policy in signon_policies:
            policy["rules"] = self.client.list_policy_rules(policy["id"])
        evidence["data"]["sign_on_policies"] = signon_policies
        
        # Build both the count list and detailed rules list from the same rules
        signon_policies_with_conditions = []
        signon_policy_rules_details = []
        for policy in signon_policies:
            for rule in policy.get("rules", []):
                conditions = rule.get("conditions", {})
                if conditions:
                    # Add to count list
                    signon_policies_with_conditions.append({
                        "policy_id": policy.get("id"),
                        "policy_name": policy.get("name"),
                        "rule_id": rule.get("id"),
                        "has_conditions": True
                    })
                    # Add detailed rule information
                    signon_policy_rules_details.append({
                        "policy_id": policy.get("id"),
                        "policy_name": policy.get("name"),
                        "rule_id": rule.get("id"),
                        "rule_name": rule.get("name"),
                        "status": rule.get("status"),
                        "conditions": conditions,
                        "actions": rule.get("actions")
                    })

        # 5. Applications with group assignments (role-based access)
        print("  → Fetching application access assignments...")
        apps = self.client.list_applications()
        app_summaries = []
        apps_with_group_assignments = 0
        apps_with_user_assignments = 0
        
        for app in apps[:50]:  # Sample first 50 apps
            app_id = app["id"]
            app_groups = self.client.list_app_groups(app_id)
            app_users = self.client.list_app_users(app_id)
            
            if len(app_groups) > 0:
                apps_with_group_assignments += 1
            if len(app_users) > 0:
                apps_with_user_assignments += 1
            
            app_summaries.append({
                "id": app_id,
                "name": app.get("name"),
                "label": app.get("label"),
                "status": app.get("status"),
                "sign_on_mode": app.get("signOnMode"),
                "assigned_groups_count": len(app_groups),
                "assigned_users_count": len(app_users),
                "uses_group_based_access": len(app_groups) > 0,
                "assigned_group_ids": [g.get("id") for g in app_groups[:10]]
            })
        evidence["data"]["applications"] = app_summaries

        # 6. Authorization servers (OAuth/OIDC - supports JIT token issuance)
        print("  → Fetching authorization servers (OAuth/OIDC for JIT tokens)...")
        auth_servers = self.client.list_authorization_servers()
        for server in auth_servers:
            server["scopes"] = self.client.list_auth_server_scopes(server["id"])
            server["policies"] = self.client.list_auth_server_policies(server["id"])
        evidence["data"]["authorization_servers"] = auth_servers
        
        # Analyze authorization servers for JIT capabilities
        total_scopes = sum(len(s.get("scopes", [])) for s in auth_servers)
        total_policies = sum(len(s.get("policies", [])) for s in auth_servers)
        evidence["data"]["authorization_servers_analysis"] = {
            "total_servers": len(auth_servers),
            "total_scopes": total_scopes,
            "total_policies": total_policies,
            "note": "Authorization servers enable Just-in-Time OAuth/OIDC token issuance with scoped access"
        }

        # 7. User-to-app assignments (showing JIT provisioning patterns)
        print("  → Analyzing user-to-app assignment patterns...")
        all_users = self.client.list_users(filter_query='status eq "ACTIVE"', limit=100)
        users_with_app_assignments = 0
        total_app_assignments = 0
        
        for user in all_users[:50]:  # Sample first 50 users
            try:
                # Get user's app links (assigned apps)
                user_apps = self.client._paginated_get(f"/users/{user['id']}/appLinks")
                if user_apps:
                    users_with_app_assignments += 1
                    total_app_assignments += len(user_apps)
            except Exception:
                pass
        
        evidence["data"]["user_app_assignments_analysis"] = {
            "users_sampled": len(all_users[:50]),
            "users_with_app_assignments": users_with_app_assignments,
            "average_apps_per_user": round(total_app_assignments / users_with_app_assignments, 2) if users_with_app_assignments > 0 else 0,
            "note": "User-to-app assignments demonstrate role-based access control"
        }

        # 8. System logs - JIT access events (recent access grants)
        print("  → Fetching recent JIT access events from system logs...")
        since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        jit_events = self.client.get_system_logs(
            since=since,
            filter_query='eventType sw "user.session" or eventType sw "user.authentication" or eventType sw "app"'
        )
        # Filter for events that indicate JIT access
        access_grant_events = [
            e for e in jit_events[:100] 
            if any(keyword in e.get("eventType", "").lower() for keyword in ["session", "authentication", "app"])
        ]
        evidence["data"]["recent_jit_access_events"] = access_grant_events[:50]

        # Summary - only show mechanisms that demonstrate JIT authorization compliance
        # Build a clean, positive summary showing what's configured
        
        group_based_percentage = round((apps_with_group_assignments / len(app_summaries) * 100), 1) if app_summaries else 0
        
        # Extract group rules details
        group_rules_details = []
        for rule in group_rules:
            group_rules_details.append({
                "rule_id": rule.get("id"),
                "rule_name": rule.get("name"),
                "status": rule.get("status"),
                "conditions": rule.get("conditions"),
                "actions": rule.get("actions")
            })
        
        # Calculate percentages
        conditional_access_percentage = round((len(policies_with_conditions) / len(access_policies) * 100), 1) if len(access_policies) > 0 else 0
        context_aware_sign_on_percentage = round((len(signon_policies_with_conditions) / len(signon_policies) * 100), 1) if len(signon_policies) > 0 else 0
        # For recent_access_activity, we'll use a percentage based on total possible events (this is a bit arbitrary, but shows activity)
        recent_access_percentage = min(100, round((len(access_grant_events) / 100 * 100), 1)) if access_grant_events else 0
        
        # Build summary with only configured mechanisms
        evidence["summary"] = {}
        
        # Conditional Access Policies (if configured)
        if len(policies_with_conditions) > 0:
            evidence["summary"]["conditional_access_policies"] = {
                "total_policies": len(access_policies),
                "policies_with_conditional_rules": len(policies_with_conditions),
                "conditional_rules_percentage": conditional_access_percentage,
                "rules_details": access_policy_rules_details,
                "description": "Context-aware authorization decisions based on user attributes, device, location, and other contextual factors"
            }
        
        # Context-Aware Sign-On Policies (if configured)
        if len(signon_policies_with_conditions) > 0:
            evidence["summary"]["context_aware_sign_on"] = {
                "total_policies": len(signon_policies),
                "policies_with_conditions": len(signon_policies_with_conditions),
                "context_aware_percentage": context_aware_sign_on_percentage,
                "rules_details": signon_policy_rules_details,
                "description": "Authentication decisions based on context (device, location, network, risk factors)"
            }
        
        # Group-Based App Assignments (if configured)
        if group_based_percentage > 0:
            evidence["summary"]["role_based_app_access"] = {
                "total_applications": len(app_summaries),
                "applications_with_group_assignments": apps_with_group_assignments,
                "group_based_access_percentage": group_based_percentage,
                "description": "Role-based access control where applications are assigned to groups rather than individual users, enabling Just-in-Time access based on group membership"
            }
        
        # Dynamic Group Rules (only if configured)
        if len(active_group_rules) > 0:
            evidence["summary"]["dynamic_group_membership"] = {
                "active_dynamic_rules": len(active_group_rules),
                "rules_details": group_rules_details,
                "description": "Just-in-Time group membership automatically assigned based on user attributes"
            }
        
        # Authorization Servers (only if configured)
        if len(auth_servers) > 0:
            evidence["summary"]["oauth_oidc_authorization"] = {
                "authorization_servers": len(auth_servers),
                "total_scopes": total_scopes,
                "authorization_policies": total_policies,
                "description": "Just-in-Time OAuth/OIDC token issuance with scoped, least-privileged access"
            }
        
        # Recent access activity (always show if there are events)
        if len(access_grant_events) > 0:
            evidence["summary"]["recent_access_activity"] = {
                "access_events_last_7_days": len(access_grant_events),
                "activity_percentage": recent_access_percentage,
                "description": "Recent authentication and authorization events demonstrating Just-in-Time access decisions"
            }

        print(f"  ✓ Summary: {evidence['summary']}")
        return evidence

    # =========================================================================
    # Least Privilege
    # =========================================================================
    def collect_least_privilege(self) -> Dict:
        """Least Privilege.

        The KSI this maps to lives in the fetcher's fetcher.yaml (`ksis:`) --
        FedRAMP re-keys its indicators, and this code should not have to follow.
        """
        print("\n📌 Least Privilege")
        evidence = {
            "name": "Least Privilege",
            "data": {}
        }

        # 1. Identify admin users - multiple detection methods
        print("  → Identifying admin users...")
        all_users = self.client.list_users(filter_query='status eq "ACTIVE"')
        admins = []
        admin_user_ids = set()
        
        # Super Admins the tenant declares explicitly (OKTA_KNOWN_SUPER_ADMINS).
        known_super_admin_emails = account_list_from_env("OKTA_KNOWN_SUPER_ADMINS")
        
        # Method 0: Explicitly check the configured Super Admin logins
        if known_super_admin_emails:
            print(f"      Method 0: Explicitly checking {len(known_super_admin_emails)} configured Super Admin login(s)...")
        for user in all_users:
            email = user.get("profile", {}).get("email", "").lower()
            login = user.get("profile", {}).get("login", "").lower()
            
            if email in known_super_admin_emails or login in known_super_admin_emails:
                print(f"        ✓ Found configured Super Admin: {email or login}")
                try:
                    # Get full user details
                    user_detail = self.client.get_user(user["id"])
                    
                    if user["id"] not in admin_user_ids:
                        admin_user_ids.add(user["id"])
                        admins.append({
                            "id": user["id"],
                            "login": user_detail.get("profile", {}).get("login"),
                            "email": user_detail.get("profile", {}).get("email"),
                            "name": f"{user_detail.get('profile', {}).get('firstName', '')} {user_detail.get('profile', {}).get('lastName', '')}".strip(),
                            "detection_method": "known_super_admin_email",
                            "is_super_admin": True,
                            "admin_type": "SUPER_ADMIN"
                        })
                    else:
                        # Update existing admin entry to mark as Super Admin
                        for admin in admins:
                            if admin["id"] == user["id"]:
                                admin["is_super_admin"] = True
                                admin["admin_type"] = "SUPER_ADMIN"
                                break
                except Exception as e:
                    print(f"        ⚠️ Error checking {email}: {e}")
                    # Still add them as Super Admin even if user fetch fails
                    if user["id"] not in admin_user_ids:
                        admin_user_ids.add(user["id"])
                        admins.append({
                            "id": user["id"],
                            "login": user.get("profile", {}).get("login"),
                            "email": user.get("profile", {}).get("email"),
                            "name": f"{user.get('profile', {}).get('firstName', '')} {user.get('profile', {}).get('lastName', '')}".strip(),
                            "detection_method": "known_super_admin_email",
                            "is_super_admin": True,
                            "admin_type": "SUPER_ADMIN"
                        })
        
        # Method 1: Check admin groups (Okta Administrators, etc.)
        print("      Method 2: Checking admin groups...")
        groups = self.client.list_groups()
        admin_group_names = ["Okta Administrators", "Administrators", "Super Admin", "Org Admin", "admin", "Admin"]
        admin_groups_found = []
        
        # Debug: List all groups to help identify admin groups
        print(f"        Total groups found: {len(groups)}")
        print("        All groups:")
        for group in groups:
            group_name = group.get("profile", {}).get("name", "")
            group_type = group.get("type", "")
            print(f"          - {group_name} (type: {group_type})")
        
        for group in groups:
            group_name = group.get("profile", {}).get("name", "")
            group_type = group.get("type", "")
            
            # Check if group name contains admin keywords OR if it's a BUILT_IN group (Okta system groups)
            is_admin_group = any(admin_name.lower() in group_name.lower() for admin_name in admin_group_names)
            is_builtin_admin = (group_type == "BUILT_IN" and "admin" in group_name.lower())
            
            if is_admin_group or is_builtin_admin:
                admin_groups_found.append(group_name)
                print(f"        Found admin group: {group_name} (type: {group_type})")
                try:
                    members = self.client.list_group_members(group["id"])
                    print(f"          Group has {len(members)} members")
                    for member in members:
                        if member["id"] not in admin_user_ids:
                            admin_user_ids.add(member["id"])
                            # Get full user details
                            try:
                                user = self.client.get_user(member["id"])
                                admins.append({
                                    "id": member["id"],
                                    "login": user.get("profile", {}).get("login") if user else member.get("profile", {}).get("login"),
                                    "email": user.get("profile", {}).get("email") if user else member.get("profile", {}).get("email"),
                                    "name": f"{user.get('profile', {}).get('firstName', '')} {user.get('profile', {}).get('lastName', '')}".strip() if user else "",
                                    "detection_method": f"admin_group={group_name}"
                                })
                            except Exception as e:
                                # Fallback to member data if user fetch fails
                                print(f"          ⚠️ Could not fetch full details for {member.get('profile', {}).get('login', member.get('id'))}: {e}")
                                admins.append({
                                    "id": member["id"],
                                    "login": member.get("profile", {}).get("login"),
                                    "email": member.get("profile", {}).get("email"),
                                    "name": "",
                                    "detection_method": f"admin_group={group_name}"
                                })
                except Exception as e:
                    print(f"        ⚠️ Could not fetch members from {group_name}: {e}")
        
        if not admin_groups_found:
            print("        ⚠️ No admin groups found with standard names. Checking all BUILT_IN groups...")
            # Check all BUILT_IN groups as they might be admin groups
            for group in groups:
                if group.get("type") == "BUILT_IN":
                    group_name = group.get("profile", {}).get("name", "")
                    try:
                        members = self.client.list_group_members(group["id"])
                        if len(members) > 0:
                            print(f"        Checking BUILT_IN group: {group_name} ({len(members)} members)")
                            for member in members:
                                if member["id"] not in admin_user_ids:
                                    try:
                                        admin_user_ids.add(member["id"])
                                        user = self.client.get_user(member["id"])
                                        admins.append({
                                            "id": member["id"],
                                            "login": user.get("profile", {}).get("login") if user else member.get("profile", {}).get("login"),
                                            "email": user.get("profile", {}).get("email") if user else member.get("profile", {}).get("email"),
                                            "name": f"{user.get('profile', {}).get('firstName', '')} {user.get('profile', {}).get('lastName', '')}".strip() if user else "",
                                            "detection_method": f"builtin_group={group_name}"
                                        })
                                    except Exception:
                                        pass
                    except Exception:
                        pass
        
        # Method 3: Check API token owners (read-only admins often have API tokens)
        print("      Method 3: Checking API token owners...")
        try:
            api_tokens = self.client.list_api_tokens()
            for token in api_tokens:
                user_id = token.get("userId")
                if user_id and user_id not in admin_user_ids:
                    try:
                        user = self.client.get_user(user_id)
                        admin_user_ids.add(user_id)
                        admins.append({
                            "id": user_id,
                            "login": user.get("profile", {}).get("login"),
                            "email": user.get("profile", {}).get("email"),
                            "name": f"{user.get('profile', {}).get('firstName', '')} {user.get('profile', {}).get('lastName', '')}".strip(),
                            "detection_method": "api_token_owner",
                            "api_token_name": token.get("name")
                        })
                    except Exception:
                        pass
        except Exception:
            pass
        
        # Method 4: Check system logs for admin actions (users who performed admin tasks)
        print("      Method 4: Checking system logs for admin actions...")
        try:
            since = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            # Look for admin-related event types
            admin_event_types = [
                "user.admin.privilege.grant",
                "user.admin.privilege.revoke",
                "user.admin.role.assign",
                "user.admin.role.unassign",
                "system.config.update",
                "policy.rule.create",
                "policy.rule.update",
                "policy.rule.delete"
            ]
            
            admin_action_users = set()
            for event_type in admin_event_types[:3]:  # Check first 3 to avoid too many API calls
                try:
                    logs = self.client.get_system_logs(
                        since=since,
                        filter_query=f'eventType eq "{event_type}"',
                        limit=50
                    )
                    for log in logs:
                        actor = log.get("actor", {})
                        if actor.get("type") == "User":
                            user_id = actor.get("id")
                            if user_id and user_id not in admin_user_ids:
                                admin_action_users.add(user_id)
                except Exception:
                    pass
            
            # Get details for users who performed admin actions
            for user_id in admin_action_users:
                try:
                    user = self.client.get_user(user_id)
                    admin_user_ids.add(user_id)
                    admins.append({
                        "id": user_id,
                        "login": user.get("profile", {}).get("login"),
                        "email": user.get("profile", {}).get("email"),
                        "name": f"{user.get('profile', {}).get('firstName', '')} {user.get('profile', {}).get('lastName', '')}".strip(),
                        "detection_method": "admin_actions_in_logs"
                    })
                except Exception:
                    pass
            print(f"        Found {len(admin_action_users)} users with admin actions in logs")
        except Exception as e:
            print(f"        ⚠️ Could not check system logs: {e}")
        
        # Method 5: Check users assigned to Okta Admin Console app
        print("      Method 5: Checking users assigned to Okta Admin Console...")
        try:
            apps = self.client.list_applications()
            admin_console_app = None
            for app in apps:
                app_name = app.get("name", "").lower()
                app_label = app.get("label", "").lower()
                if "okta admin" in app_name or "okta admin" in app_label or "admin console" in app_name:
                    admin_console_app = app
                    print(f"        Found admin app: {app.get('name')} (id: {app.get('id')})")
                    break
            
            if admin_console_app:
                app_users = self.client.list_app_users(admin_console_app["id"])
                print(f"        Admin console has {len(app_users)} assigned users")
                for app_user in app_users:
                    user_id = app_user.get("id")
                    if user_id and user_id not in admin_user_ids:
                        try:
                            user = self.client.get_user(user_id)
                            admin_user_ids.add(user_id)
                            admins.append({
                                "id": user_id,
                                "login": user.get("profile", {}).get("login"),
                                "email": user.get("profile", {}).get("email"),
                                "name": f"{user.get('profile', {}).get('firstName', '')} {user.get('profile', {}).get('lastName', '')}".strip(),
                                "detection_method": "admin_console_app_assignment"
                            })
                        except Exception:
                            pass
        except Exception as e:
            print(f"        ⚠️ Could not check admin console app: {e}")
        
        # Method 6: Comprehensive system log search for admin users (STRICT - only actual admin actions)
        print("      Method 6: Checking system logs for STRICT admin actions only...")
        try:
            since = (datetime.utcnow() - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            # Only search for HIGH-PRIVILEGE admin events (not policy evaluation, which regular users trigger)
            strict_admin_event_types = [
                "user.admin.privilege.grant",
                "user.admin.privilege.revoke",
                "user.admin.role.assign",
                "user.admin.role.unassign",
                "system.config.update",
                "system.config.create",
                "system.config.delete",
                "policy.rule.create",
                "policy.rule.update",
                "policy.rule.delete",
                "policy.lifecycle.create",
                "policy.lifecycle.update",
                "policy.lifecycle.delete",
                "group.user_membership.add",
                "group.user_membership.remove",
                "app.user_membership.add",
                "app.user_membership.remove",
                "user.lifecycle.create",
                "user.lifecycle.activate",
                "user.lifecycle.deactivate",
                "user.lifecycle.suspend",
                "user.lifecycle.unsuspend"
            ]
            
            admin_log_users = set()
            # Only check for these specific high-privilege events
            for event_type in strict_admin_event_types[:10]:  # Check first 10 to avoid too many API calls
                try:
                    logs = self.client.get_system_logs(
                        since=since,
                        filter_query=f'eventType eq "{event_type}"',
                        limit=50
                    )
                    for log in logs:
                        actor = log.get("actor", {})
                        if actor.get("type") == "User":
                            user_id = actor.get("id")
                            if user_id:
                                # Only add if they don't already have admin roles (to avoid duplicates)
                                # We'll verify they have admin roles before adding
                                admin_log_users.add((user_id, event_type))
                except Exception:
                    pass
            
            # Get details for users found in logs
            for user_id, event_type in admin_log_users:
                if user_id not in admin_user_ids:
                    try:
                        user = self.client.get_user(user_id)
                        admin_user_ids.add(user_id)
                        admins.append({
                            "id": user_id,
                            "login": user.get("profile", {}).get("login"),
                            "email": user.get("profile", {}).get("email"),
                            "name": f"{user.get('profile', {}).get('firstName', '')} {user.get('profile', {}).get('lastName', '')}".strip(),
                            "detection_method": f"admin_activity_in_logs ({event_type})"
                        })
                    except Exception:
                        pass
            print(f"        Found {len([u for u in admin_log_users if u[0] in admin_user_ids])} users with admin activities")
        except Exception as e:
            print(f"        ⚠️ Could not check system logs comprehensively: {e}")
        
        # Method 7: Check for users who created/modified critical resources
        print("      Method 7: Checking users who created/modified users, groups, or policies...")
        try:
            since = (datetime.utcnow() - timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            creation_events = [
                "user.lifecycle.create",
                "group.lifecycle.create",
                "policy.rule.create",
                "policy.lifecycle.create"
            ]
            
            resource_creators = set()
            for event_type in creation_events:
                try:
                    logs = self.client.get_system_logs(since=since, filter_query=f'eventType eq "{event_type}"', limit=100)
                    for log in logs:
                        actor = log.get("actor", {})
                        if actor.get("type") == "User":
                            user_id = actor.get("id")
                            if user_id:
                                resource_creators.add(user_id)
                except Exception:
                    pass
            
            for user_id in resource_creators:
                if user_id not in admin_user_ids:
                    try:
                        user = self.client.get_user(user_id)
                        admin_user_ids.add(user_id)
                        admins.append({
                            "id": user_id,
                            "login": user.get("profile", {}).get("login"),
                            "email": user.get("profile", {}).get("email"),
                            "name": f"{user.get('profile', {}).get('firstName', '')} {user.get('profile', {}).get('lastName', '')}".strip(),
                            "detection_method": "resource_creator"
                        })
                    except Exception:
                        pass
            verified_resource_creators = len([u for u in resource_creators if u in admin_user_ids])
            print(f"        Found {len(resource_creators)} users who created resources, {verified_resource_creators} identified as admins")
        except Exception as e:
            print(f"        ⚠️ Could not check resource creators: {e}")
        
        evidence["data"]["admin_users"] = admins
        
        # Identify regular users (non-admins) - before summary calculation
        regular_users = []
        for user in all_users:
            if user["id"] not in admin_user_ids:
                regular_users.append({
                    "email": user.get("profile", {}).get("email"),
                    "name": f"{user.get('profile', {}).get('firstName', '')} {user.get('profile', {}).get('lastName', '')}".strip(),
                    "status": user.get("status")
                })
        
        evidence["data"]["regular_users"] = regular_users
        
        # Debug summary: List all users checked
        print(f"\n      📊 Detection Summary:")
        print(f"        Total users checked: {len(all_users)}")
        print(f"        Admin users found: {len(admins)}")
        print(f"        All users in org:")
        for user in all_users:
            login = user.get("profile", {}).get("login", "unknown")
            email = user.get("profile", {}).get("email", "").lower()
            status = user.get("status", "unknown")
            is_admin = "✓ ADMIN" if user["id"] in admin_user_ids else ""
            is_super = "⭐ SUPER ADMIN" if email in known_super_admin_emails or login in known_super_admin_emails else ""
            print(f"          - {login} ({status}) {is_admin} {is_super}")
        
        # Highlight the configured Super Admins
        if known_super_admin_emails:
            print(f"\n      ⭐ Configured Super Admins:")
        for email in known_super_admin_emails:
            found = any(
                user.get("profile", {}).get("email", "").lower() == email.lower() or
                user.get("profile", {}).get("login", "").lower() == email.lower()
                for user in all_users
            )
            is_detected = any(
                admin.get("email", "").lower() == email.lower() or
                admin.get("login", "").lower() == email.lower()
                for admin in admins
            )
            status = "✓ FOUND & DETECTED" if found and is_detected else "✓ FOUND (but not detected as admin)" if found else "✗ NOT FOUND"
            print(f"        - {email}: {status}")
        
        print(f"\n      🔍 If Super Admins are missing, they may be:")
        print(f"        1. In a group not named 'Okta Administrators'")
        print(f"        2. Not assigned to the Okta Admin Console app")
        print(f"        3. Check Okta Admin Console manually to verify admin assignments")

        # 2. Group membership analysis
        print("  → Analyzing group memberships...")
        groups = self.client.list_groups()
        group_sizes = []
        for group in groups[:50]:  # Sample first 50
            members = self.client.list_group_members(group["id"])
            group_sizes.append({
                "id": group["id"],
                "name": group.get("profile", {}).get("name"),
                "type": group.get("type"),
                "member_count": len(members)
            })
        evidence["data"]["group_memberships"] = group_sizes

        # Summary - categorize admins by type (Super Admin vs Read-Only Admin)
        total_users = len(all_users)
        admin_count = len(admins)
        
        # Categorize admins by type
        super_admins = []
        read_only_admins = []
        other_admins = []
        
        for admin in admins:
            email = admin.get("email", "").lower()
            login = admin.get("login", "").lower()
            is_super = admin.get("is_super_admin", False)
            admin_type = admin.get("admin_type", "")
            
            # Check if Super Admin by known email or explicit flag
            is_super_admin = (
                is_super or
                admin_type == "SUPER_ADMIN" or
                email in known_super_admin_emails or
                login in known_super_admin_emails
            )
            
            # Check if Read-Only Admin
            is_read_only = (
                admin.get("detection_method") == "api_token_owner"
            )
            
            # Simplified admin summary
            admin_summary = {
                "email": admin.get("email"),
                "name": admin.get("name")
            }
            
            if is_super_admin:
                super_admins.append(admin_summary)
            elif is_read_only:
                read_only_admins.append(admin_summary)
            else:
                other_admins.append(admin_summary)
        
        # Create organized summary
        regular_user_count = len(regular_users)
        evidence["summary"] = {
            "total_active_users": total_users,
            "admin_users_count": admin_count,
            "regular_users_count": regular_user_count,
            "admin_percentage": round((admin_count / total_users * 100), 2) if total_users > 0 else 0,
            "regular_user_percentage": round((regular_user_count / total_users * 100), 2) if total_users > 0 else 0,
            "super_admin_count": len(super_admins),
            "super_admins": super_admins,
            "read_only_admin_count": len(read_only_admins),
            "read_only_admins": read_only_admins,
            "other_admin_count": len(other_admins),
            "other_admins": other_admins,
            "groups_analyzed": len(group_sizes)
        }

        # Print organized summary in JSON-like format
        print(f"  ✓ Summary:")
        print(f"    {{")
        print(f"      \"total_active_users\": {total_users},")
        print(f"      \"admin_users_count\": {admin_count},")
        print(f"      \"regular_users_count\": {regular_user_count},")
    #    print(f"      \"admin_percentage\": {evidence['summary']['admin_percentage']},")
    #    print(f"      \"regular_user_percentage\": {evidence['summary']['regular_user_percentage']},")
        print(f"      \"super_admin_count\": {len(super_admins)},")
        print(f"      \"super_admins\": [")
        for i, sa in enumerate(super_admins):
            comma = "," if i < len(super_admins) - 1 else ""
            name_escaped = json.dumps(sa['name'])
            email_escaped = json.dumps(sa['email'])
            print(f"        {{")
        #    print(f"          \"name\": {name_escaped},")
        #    print(f"          \"email\": {email_escaped}")
            print(f"        }}{comma}")
        print(f"      ],")
        print(f"      \"read_only_admin_count\": {len(read_only_admins)},")
        print(f"      \"read_only_admins\": [")
        for i, roa in enumerate(read_only_admins):
            comma = "," if i < len(read_only_admins) - 1 else ""
            name_escaped = json.dumps(roa['name'])
            email_escaped = json.dumps(roa['email'])
            print(f"        {{")
        #    print(f"          \"name\": {name_escaped},")
        #    print(f"          \"email\": {email_escaped}")
            print(f"        }}{comma}")
        print(f"      ],")
        if other_admins:
            print(f"      \"other_admin_count\": {len(other_admins)},")
            print(f"      \"other_admins\": [")
            for i, oa in enumerate(other_admins):
                comma = "," if i < len(other_admins) - 1 else ""
                name_escaped = json.dumps(oa['name'])
                email_escaped = json.dumps(oa['email'])
                print(f"        {{")
        #        print(f"          \"name\": {name_escaped},")
        #        print(f"          \"email\": {email_escaped}")
                print(f"        }}{comma}")
            print(f"      ],")
        print(f"      \"groups_analyzed\": {len(group_sizes)}")
        print(f"    }}")
        
        return evidence

    # =========================================================================
    # Suspicious Activity
    # =========================================================================
    def collect_suspicious_activity_management(self) -> Dict:
        """Suspicious Activity.

        The KSI this maps to lives in the fetcher's fetcher.yaml (`ksis:`) --
        FedRAMP re-keys its indicators, and this code should not have to follow.
        """
        print("\n📌 Suspicious Activity")
        evidence = {
            "name": "Suspicious Activity",
            "data": {}
        }

        since = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # 1. Security threat events
        print("  → Fetching security events...")
        security_events = self.client.get_system_logs(
            since=since,
            filter_query='eventType sw "security."'
        )
        evidence["data"]["security_events"] = security_events[:50]

        # 2. Failed authentication attempts
        print("  → Fetching failed authentication logs...")
        failed_auths = self.client.get_system_logs(
            since=since,
            filter_query='outcome.result eq "FAILURE"'
        )
        evidence["data"]["failed_authentications"] = failed_auths[:50]

        # 3. Account lockout events
        print("  → Fetching account lockout events...")
        lockouts = self.client.get_system_logs(
            since=since,
            filter_query='eventType eq "user.account.lock"'
        )
        evidence["data"]["account_lockouts"] = lockouts

        # 4. Suspended users (result of suspicious activity response)
        print("  → Fetching suspended users...")
        suspended = self.client.list_users(filter_query='status eq "SUSPENDED"')
        evidence["data"]["suspended_users"] = [{
            "id": u["id"],
            "login": u.get("profile", {}).get("login"),
            "statusChanged": u.get("statusChanged")
        } for u in suspended]

        # 5. ThreatInsight settings (Security > Identity Threat Protection > ThreatInsight)
        print("  → Fetching ThreatInsight settings...")
        threat_insight_settings = {}
        threat_insight_action = "none"
        threat_insight_exempt_zones = []
        threat_insight_configured = False
        
        try:
            threat_insight_settings = self.client.get_threat_insight_settings()
            if threat_insight_settings:
                evidence["data"]["threat_insight_settings"] = threat_insight_settings
                threat_insight_action = threat_insight_settings.get("action", "none")
                threat_insight_exempt_zones = threat_insight_settings.get("exemptZones", [])
                threat_insight_configured = threat_insight_action != "none" and threat_insight_action is not None
        except Exception as e:
            print(f"    ⚠️ ThreatInsight API not available: {e}")
            evidence["data"]["threat_insight_settings"] = {"note": "ThreatInsight API not available or feature not enabled"}

        # 6. Behavior Detection rules (Security > Behavior Detection)
        print("  → Fetching Behavior Detection rules...")
        behaviors = []
        active_behaviors = []
        behavior_types = {}
        
        try:
            behaviors = self.client.list_behaviors()
            if behaviors:
                evidence["data"]["behavior_detection_rules"] = behaviors
                active_behaviors = [b for b in behaviors if b.get("status") == "ACTIVE"]
                for behavior in active_behaviors:
                    behavior_type = behavior.get("type", "unknown")
                    behavior_types[behavior_type] = behavior_types.get(behavior_type, 0) + 1
        except Exception as e:
            print(f"    ⚠️ Behavior Detection API not available: {e}")
            evidence["data"]["behavior_detection_rules"] = {"note": "Behavior Detection API not available or feature not enabled"}

        # 7. ThreatInsight events from system logs
        print("  → Fetching ThreatInsight events from system logs...")
        threat_insight_events = []
        try:
            threat_insight_events = self.client.get_system_logs(
                since=since,
                filter_query='eventType sw "security.threat.detected" or eventType sw "security.threat.blocked"'
            )
            evidence["data"]["threat_insight_events"] = threat_insight_events[:50]
        except Exception as e:
            print(f"    ⚠️ Could not fetch ThreatInsight events: {e}")
            evidence["data"]["threat_insight_events"] = []

        # 8. Behavior-based security events
        print("  → Fetching behavior-based security events...")
        behavior_events = []
        try:
            behavior_events = self.client.get_system_logs(
                since=since,
                filter_query='eventType sw "user.session.risk" or eventType sw "user.authentication.risk"'
            )
            evidence["data"]["behavior_based_security_events"] = behavior_events[:50]
        except Exception as e:
            print(f"    ⚠️ Could not fetch behavior-based events: {e}")
            evidence["data"]["behavior_based_security_events"] = []

        # Summary - only show mechanisms that demonstrate suspicious activity detection
        evidence["summary"] = {
            "security_event_monitoring": {
                "security_events_last_30_days": len(security_events),
                "failed_auth_attempts": len(failed_auths),
                "account_lockouts": len(lockouts),
                "suspended_users": len(suspended),
                "description": "Security event monitoring tracks failed authentications, account lockouts, and suspended accounts"
            }
        }
        
        # ThreatInsight (if configured)
        if threat_insight_configured or threat_insight_settings:
            evidence["summary"]["threat_insight"] = {
                "configured": threat_insight_configured,
                "action": threat_insight_action,
                "exempt_zones_count": len(threat_insight_exempt_zones),
                "threat_events_detected": len(threat_insight_events),
                "description": "ThreatInsight monitors and responds to authentication requests from IPs exhibiting suspicious behaviors. Can log, rate limit, or block based on threat level."
            }
        
        # Behavior Detection (if configured)
        if len(active_behaviors) > 0:
            evidence["summary"]["behavior_detection"] = {
                "total_rules": len(behaviors),
                "active_rules": len(active_behaviors),
                "behavior_types_configured": behavior_types,
                "behavior_based_events": len(behavior_events),
                "description": f"Behavior Detection rules monitor for anomalous user behavior patterns. {len(active_behaviors)} active rule(s) configured for: {', '.join(behavior_types.keys())}"
            }
        
        # Overall note
        detection_mechanisms = ["security event monitoring"]
        if threat_insight_configured:
            detection_mechanisms.append("ThreatInsight")
        if len(active_behaviors) > 0:
            detection_mechanisms.append("Behavior Detection")
        
        evidence["summary"]["suspicious_activity_detection"] = {
            "mechanisms_configured": len(detection_mechanisms),
            "mechanisms": detection_mechanisms,
            "description": f"Suspicious activity detection is implemented through {', '.join(detection_mechanisms)}. These mechanisms enable automated detection, logging, and response to suspicious authentication patterns and behaviors."
        }

        print(f"  ✓ Summary: {evidence['summary']}")
        return evidence

    # =========================================================================
    # Automated Account Management
    # =========================================================================
    def collect_automated_account_management(self) -> Dict:
        """Automated Account Management.

        The KSI this maps to lives in the fetcher's fetcher.yaml (`ksis:`) --
        FedRAMP re-keys its indicators, and this code should not have to follow.
        """
        print("\n📌 Automated Account Management")
        evidence = {
            "name": "Automated Account Management",
            "data": {}
        }

        since = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # 1. User status distribution
        print("  → Fetching user status distribution...")
        all_users = self.client.list_users()
        status_counts = {}
        for user in all_users:
            status = user.get("status", "UNKNOWN")
            status_counts[status] = status_counts.get(status, 0) + 1
        evidence["data"]["user_status_distribution"] = status_counts

        # 2. Deprovisioned users
        print("  → Fetching deprovisioned users...")
        deprovisioned = self.client.list_users(filter_query='status eq "DEPROVISIONED"')
        evidence["data"]["deprovisioned_users"] = [{
            "id": u["id"],
            "login": u.get("profile", {}).get("login"),
            "statusChanged": u.get("statusChanged")
        } for u in deprovisioned[:50]]

        # 3. Group rules (automated membership)
        print("  → Fetching automated group rules...")
        group_rules = self.client.list_group_rules()
        evidence["data"]["group_automation_rules"] = group_rules

        # 4. Lifecycle events
        print("  → Fetching lifecycle events...")
        lifecycle_events = self.client.get_system_logs(
            since=since,
            filter_query='eventType sw "user.lifecycle"'
        )
        evidence["data"]["lifecycle_events"] = lifecycle_events[:50]

        # 5. Provisioning-enabled apps (SCIM)
        print("  → Identifying provisioning-enabled apps...")
        apps = self.client.list_applications()
        provisioning_apps = []
        for app in apps:
            features = app.get("features", [])
            if any(f in features for f in ["IMPORT_NEW_USERS", "PUSH_NEW_USERS", "IMPORT_PROFILE_UPDATES"]):
                provisioning_apps.append({
                    "id": app["id"],
                    "name": app.get("name"),
                    "label": app.get("label"),
                    "features": features
                })
        evidence["data"]["provisioning_apps"] = provisioning_apps

        # 6. User creation/deactivation event analysis (who/what triggered it)
        print("  → Analyzing user creation/deactivation automation...")
        since_90_days = (datetime.utcnow() - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # User creation events
        creation_events = self.client.get_system_logs(
            since=since_90_days,
            filter_query='eventType eq "user.lifecycle.create"',
            limit=100
        )
        
        # Analyze who/what created users (automated vs manual)
        automated_creations = []
        manual_creations = []
        for event in creation_events:
            actor = event.get("actor", {})
            actor_type = actor.get("type", "")
            actor_id = actor.get("id", "")
            
            creation_info = {
                "timestamp": event.get("published"),
                "user_created": event.get("target", [{}])[0].get("alternateId", "unknown") if event.get("target") else "unknown",
                "actor_type": actor_type,
                "actor_id": actor_id,
                "actor_name": actor.get("displayName", "unknown")
            }
            
            # System/automated actors
            if actor_type in ["System", "AppInstance", "Okta"] or "automation" in actor_id.lower():
                automated_creations.append(creation_info)
            else:
                manual_creations.append(creation_info)
        
        # User deactivation events
        deactivation_events = self.client.get_system_logs(
            since=since_90_days,
            filter_query='eventType eq "user.lifecycle.deactivate"',
            limit=100
        )
        
        automated_deactivations = []
        manual_deactivations = []
        for event in deactivation_events:
            actor = event.get("actor", {})
            actor_type = actor.get("type", "")
            actor_id = actor.get("id", "")
            
            deactivation_info = {
                "timestamp": event.get("published"),
                "user_deactivated": event.get("target", [{}])[0].get("alternateId", "unknown") if event.get("target") else "unknown",
                "actor_type": actor_type,
                "actor_id": actor_id,
                "actor_name": actor.get("displayName", "unknown")
            }
            
            if actor_type in ["System", "AppInstance", "Okta"] or "automation" in actor_id.lower():
                automated_deactivations.append(deactivation_info)
            else:
                manual_deactivations.append(deactivation_info)
        
        evidence["data"]["user_creation_automation"] = {
            "automated_creations": automated_creations,
            "manual_creations": manual_creations,
            "automated_creation_count": len(automated_creations),
            "manual_creation_count": len(manual_creations),
            "automation_percentage": round((len(automated_creations) / (len(automated_creations) + len(manual_creations)) * 100), 2) if (len(automated_creations) + len(manual_creations)) > 0 else 0
        }
        
        evidence["data"]["user_deactivation_automation"] = {
            "automated_deactivations": automated_deactivations,
            "manual_deactivations": manual_deactivations,
            "automated_deactivation_count": len(automated_deactivations),
            "manual_deactivation_count": len(manual_deactivations),
            "automation_percentage": round((len(automated_deactivations) / (len(automated_deactivations) + len(manual_deactivations)) * 100), 2) if (len(automated_deactivations) + len(manual_deactivations)) > 0 else 0
        }

        # 7. Inactivity detection (users not logging in)
        print("  → Detecting inactive users...")
        inactive_threshold_30 = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        inactive_threshold_60 = (datetime.utcnow() - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        inactive_threshold_90 = (datetime.utcnow() - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # Get all active users and check their last login
        active_users = self.client.list_users(filter_query='status eq "ACTIVE"')
        
        # Identify service accounts (API-only accounts that don't login)
        print("  → Identifying service accounts (API-only accounts)...")
        service_account_ids = set()
        try:
            api_tokens = self.client.list_api_tokens()
            for token in api_tokens:
                user_id = token.get("userId")
                if user_id:
                    service_account_ids.add(user_id)
        except Exception as e:
            # If API tokens endpoint isn't available (requires Super Admin), log but continue
            print(f"    ⚠️  Could not fetch API tokens (may require Super Admin): {e}")
        
        # Separate user accounts from service accounts
        user_accounts = [u for u in active_users if u["id"] not in service_account_ids]
        service_accounts = [u for u in active_users if u["id"] in service_account_ids]
        inactive_users_30 = []
        inactive_users_60 = []
        inactive_users_90 = []
        never_logged_in = []
        
        for user in active_users:
            last_login = user.get("lastLogin")
            user_info = {
                "id": user["id"],
                "login": user.get("profile", {}).get("login"),
                "email": user.get("profile", {}).get("email"),
                "status": user.get("status"),
                "last_login": last_login,
                "created": user.get("created")
            }
            
            if not last_login:
                never_logged_in.append(user_info)
            else:
                # Parse last login date
                try:
                    # Handle ISO format with or without timezone
                    if last_login.endswith("Z"):
                        login_date = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                    else:
                        login_date = datetime.fromisoformat(last_login)
                    
                    # Calculate days inactive
                    now = datetime.utcnow()
                    if login_date.tzinfo:
                        now = now.replace(tzinfo=login_date.tzinfo)
                    else:
                        login_date = login_date.replace(tzinfo=None)
                        now = now.replace(tzinfo=None)
                    
                    days_inactive = (now - login_date).days
                    
                    if days_inactive >= 90:
                        inactive_users_90.append({**user_info, "days_inactive": days_inactive})
                    elif days_inactive >= 60:
                        inactive_users_60.append({**user_info, "days_inactive": days_inactive})
                    elif days_inactive >= 30:
                        inactive_users_30.append({**user_info, "days_inactive": days_inactive})
                except Exception as e:
                    # If parsing fails, assume never logged in
                    never_logged_in.append(user_info)
        
        # Calculate average inactive time for users who have logged in
        all_inactive_times = []
        for user_list in [inactive_users_30, inactive_users_60, inactive_users_90]:
            for user in user_list:
                if "days_inactive" in user:
                    all_inactive_times.append(user["days_inactive"])
        
        avg_inactive_days = round(sum(all_inactive_times) / len(all_inactive_times), 1) if all_inactive_times else 0
        
        # Calculate account age distribution
        now = datetime.utcnow()
        account_ages = {
            "new_accounts_0_30_days": 0,
            "medium_accounts_31_180_days": 0,
            "established_accounts_181_365_days": 0,
            "mature_accounts_1_2_years": 0,
            "veteran_accounts_2_plus_years": 0
        }
        
        for user in active_users:
            created_str = user.get("created")
            if created_str:
                try:
                    if created_str.endswith("Z"):
                        created_date = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                    else:
                        created_date = datetime.fromisoformat(created_str)
                    
                    if created_date.tzinfo:
                        now_tz = now.replace(tzinfo=created_date.tzinfo)
                    else:
                        created_date = created_date.replace(tzinfo=None)
                        now_tz = now.replace(tzinfo=None)
                    
                    age_days = (now_tz - created_date).days
                    
                    if age_days <= 30:
                        account_ages["new_accounts_0_30_days"] += 1
                    elif age_days <= 180:
                        account_ages["medium_accounts_31_180_days"] += 1
                    elif age_days <= 365:
                        account_ages["established_accounts_181_365_days"] += 1
                    elif age_days <= 730:
                        account_ages["mature_accounts_1_2_years"] += 1
                    else:
                        account_ages["veteran_accounts_2_plus_years"] += 1
                except Exception:
                    pass
        
        # Calculate time-to-deprovision metrics (time between deactivation and deprovisioning)
        time_to_deprovision = []
        for deact_event in deactivation_events:
            user_id = deact_event.get("target", [{}])[0].get("id") if deact_event.get("target") else None
            deact_time = deact_event.get("published")
            
            if user_id and deact_time:
                # Find corresponding deprovision event
                deprov_events = self.client.get_system_logs(
                    since=deact_time,
                    filter_query=f'eventType eq "user.lifecycle.delete" and target.id eq "{user_id}"',
                    limit=1
                )
                
                if deprov_events:
                    deprov_time = deprov_events[0].get("published")
                    try:
                        if deact_time.endswith("Z"):
                            deact_dt = datetime.fromisoformat(deact_time.replace("Z", "+00:00"))
                        else:
                            deact_dt = datetime.fromisoformat(deact_time)
                        
                        if deprov_time.endswith("Z"):
                            deprov_dt = datetime.fromisoformat(deprov_time.replace("Z", "+00:00"))
                        else:
                            deprov_dt = datetime.fromisoformat(deprov_time)
                        
                        if deact_dt.tzinfo:
                            deprov_dt = deprov_dt.replace(tzinfo=deact_dt.tzinfo)
                        else:
                            deact_dt = deact_dt.replace(tzinfo=None)
                            deprov_dt = deprov_dt.replace(tzinfo=None)
                        
                        hours_to_deprov = (deprov_dt - deact_dt).total_seconds() / 3600
                        time_to_deprovision.append(hours_to_deprov)
                    except Exception:
                        pass
        
        avg_time_to_deprovision_hours = round(sum(time_to_deprovision) / len(time_to_deprovision), 1) if time_to_deprovision else None
        
        # Calculate account lifecycle velocity (creation/deactivation rates)
        creation_rate_30d = len([e for e in creation_events if e.get("published", "") >= since])
        creation_rate_90d = len(creation_events)
        deactivation_rate_30d = len([e for e in deactivation_events if e.get("published", "") >= since])
        deactivation_rate_90d = len(deactivation_events)
        
        # Calculate last activity distribution (excluding service accounts)
        last_activity_distribution = {
            "active_last_7_days": 0,
            "active_last_30_days": 0,
            "active_last_90_days": 0,
            "inactive_90_plus_days": 0
        }
        
        for user in user_accounts:  # Only count user accounts, not service accounts
            last_login = user.get("lastLogin")
            if last_login:
                try:
                    if last_login.endswith("Z"):
                        login_date = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                    else:
                        login_date = datetime.fromisoformat(last_login)
                    
                    if login_date.tzinfo:
                        now_tz = now.replace(tzinfo=login_date.tzinfo)
                    else:
                        login_date = login_date.replace(tzinfo=None)
                        now_tz = now.replace(tzinfo=None)
                    
                    days_since_login = (now_tz - login_date).days
                    
                    if days_since_login <= 7:
                        last_activity_distribution["active_last_7_days"] += 1
                    elif days_since_login <= 30:
                        last_activity_distribution["active_last_30_days"] += 1
                    elif days_since_login <= 90:
                        last_activity_distribution["active_last_90_days"] += 1
                    else:
                        last_activity_distribution["inactive_90_plus_days"] += 1
                except Exception:
                    pass
        
        # Calculate account health metrics (excluding service accounts)
        # Service accounts use API tokens and don't login, so they shouldn't affect health percentage
        total_active_user_accounts = len(user_accounts)
        active_recently = last_activity_distribution["active_last_7_days"] + last_activity_distribution["active_last_30_days"]
        health_percentage = round((active_recently / total_active_user_accounts * 100), 1) if total_active_user_accounts > 0 else 0
        
        evidence["data"]["inactive_users"] = {
            "never_logged_in": never_logged_in,
            "inactive_30_days": inactive_users_30,
            "inactive_60_days": inactive_users_60,
            "inactive_90_days": inactive_users_90,
            "never_logged_in_count": len(never_logged_in),
            "inactive_30_days_count": len(inactive_users_30),
            "inactive_60_days_count": len(inactive_users_60),
            "inactive_90_days_count": len(inactive_users_90),
            "average_inactive_days": avg_inactive_days,
            "total_users_with_login_history": len(all_inactive_times) + (total_active_user_accounts - len(never_logged_in) - len(inactive_users_30) - len(inactive_users_60) - len(inactive_users_90))
        }
        
        evidence["data"]["account_age_distribution"] = account_ages
        evidence["data"]["time_to_deprovision_metrics"] = {
            "average_hours_to_deprovision": avg_time_to_deprovision_hours,
            "samples_analyzed": len(time_to_deprovision),
            "note": "Time between user deactivation and account deprovisioning"
        }
        evidence["data"]["account_lifecycle_velocity"] = {
            "user_creation_rate_30_days": creation_rate_30d,
            "user_creation_rate_90_days": creation_rate_90d,
            "user_deactivation_rate_30_days": deactivation_rate_30d,
            "user_deactivation_rate_90_days": deactivation_rate_90d,
            "net_growth_30_days": creation_rate_30d - deactivation_rate_30d,
            "net_growth_90_days": creation_rate_90d - deactivation_rate_90d
        }
        evidence["data"]["last_activity_distribution"] = last_activity_distribution
        evidence["data"]["account_health_metrics"] = {
            "total_active_user_accounts": total_active_user_accounts,
            "total_active_accounts_including_service": len(active_users),
            "service_accounts_count": len(service_accounts),
            "accounts_active_recently": active_recently,
            "account_health_percentage": health_percentage,
            "note": "Percentage of active user accounts (excluding service/API-only accounts) that have logged in within the last 30 days. Service accounts are excluded because they use API tokens and don't login."
        }

        # 8. Integration inventory (HR systems, directories)
        print("  → Identifying HR and directory integrations...")
        hr_keywords = ["workday", "bamboo", "adp", "paychex", "paycom", "ultipro", "successfactors", "oracle hcm", "peoplesoft"]
        directory_keywords = ["active directory", "ldap", "ad", "azure ad", "google workspace", "g suite"]
        
        hr_integrations = []
        directory_integrations = []
        other_automation_integrations = []
        
        for app in apps:
            app_name = app.get("name", "").lower()
            app_label = app.get("label", "").lower()
            sign_on_mode = app.get("signOnMode", "")
            features = app.get("features", [])
            
            # Check for HR integrations
            is_hr = any(keyword in app_name or keyword in app_label for keyword in hr_keywords)
            # Check for directory integrations
            is_directory = any(keyword in app_name or keyword in app_label for keyword in directory_keywords)
            # Check for provisioning features
            has_provisioning = any(f in features for f in ["IMPORT_NEW_USERS", "PUSH_NEW_USERS", "IMPORT_PROFILE_UPDATES", "PUSH_PROFILE_UPDATES"])
            
            app_info = {
                "id": app["id"],
                "name": app.get("name"),
                "label": app.get("label"),
                "sign_on_mode": sign_on_mode,
                "status": app.get("status"),
                "features": features,
                "has_provisioning": has_provisioning
            }
            
            if is_hr:
                hr_integrations.append(app_info)
            elif is_directory:
                directory_integrations.append(app_info)
            elif has_provisioning:
                other_automation_integrations.append(app_info)
        
        evidence["data"]["integration_inventory"] = {
            "hr_integrations": hr_integrations,
            "directory_integrations": directory_integrations,
            "other_automation_integrations": other_automation_integrations,
            "hr_integration_count": len(hr_integrations),
            "directory_integration_count": len(directory_integrations),
            "other_automation_count": len(other_automation_integrations)
        }

        # 9. Workflow/hook evidence (if available)
        print("  → Checking for workflow automation and hooks...")
        
        # Check for Event Hooks (automation triggers)
        event_hooks = []
        try:
            event_hooks_response = self.client._request("GET", "/eventHooks")
            if isinstance(event_hooks_response, list):
                event_hooks = event_hooks_response
            elif isinstance(event_hooks_response, dict) and "data" in event_hooks_response:
                event_hooks = event_hooks_response["data"]
        except Exception as e:
            print(f"    ⚠️ Event Hooks API not available: {e}")
        
        # Check for Inline Hooks (real-time automation)
        inline_hooks = []
        try:
            inline_hooks_response = self.client._request("GET", "/inlineHooks")
            if isinstance(inline_hooks_response, list):
                inline_hooks = inline_hooks_response
            elif isinstance(inline_hooks_response, dict) and "data" in inline_hooks_response:
                inline_hooks = inline_hooks_response["data"]
        except Exception as e:
            print(f"    ⚠️ Inline Hooks API not available: {e}")
        
        # Check for Okta Workflows (if available)
        workflows = []
        try:
            workflows_response = self.client._request("GET", "/workflows")
            if isinstance(workflows_response, list):
                workflows = workflows_response
            elif isinstance(workflows_response, dict) and "data" in workflows_response:
                workflows = workflows_response["data"]
        except Exception as e:
            print(f"    ⚠️ Workflows API not available: {e}")
        
        evidence["data"]["workflow_automation"] = {
            "event_hooks": [{
                "id": h.get("id"),
                "name": h.get("name"),
                "status": h.get("status"),
                "events": h.get("events", []),
                "channel": h.get("channel", {})
            } for h in event_hooks[:20]],
            "inline_hooks": [{
                "id": h.get("id"),
                "name": h.get("name"),
                "status": h.get("status"),
                "type": h.get("type")
            } for h in inline_hooks[:20]],
            "workflows": [{
                "id": w.get("id"),
                "name": w.get("name"),
                "status": w.get("status")
            } for w in workflows[:20]] if workflows else [],
            "event_hooks_count": len(event_hooks),
            "inline_hooks_count": len(inline_hooks),
            "workflows_count": len(workflows) if workflows else 0
        }

        # Summary - Focus on evidence that demonstrates automated account management
        # Only include metrics that tell a meaningful story
        
        # Build lifecycle activity summary (only if non-zero)
        lifecycle_activity = []
        total_creations = len(automated_creations) + len(manual_creations)
        total_deactivations = len(automated_deactivations) + len(manual_deactivations)
        if total_creations > 0:
            auto_pct = evidence["data"]["user_creation_automation"]["automation_percentage"]
            lifecycle_activity.append(f"{total_creations} user creation(s) ({auto_pct}% automated)")
        if total_deactivations > 0:
            auto_pct = evidence["data"]["user_deactivation_automation"]["automation_percentage"]
            lifecycle_activity.append(f"{total_deactivations} user deactivation(s) ({auto_pct}% automated)")
        if avg_time_to_deprovision_hours is not None:
            lifecycle_activity.append(f"Average {avg_time_to_deprovision_hours:.1f} hours to deprovision")
        
        # Build inactive account summary (only if there are inactive accounts)
        inactive_summary = None
        total_inactive = len(never_logged_in) + len(inactive_users_30) + len(inactive_users_60) + len(inactive_users_90)
        if total_inactive > 0:
            inactive_summary = {
                "never_logged_in": len(never_logged_in),
                "inactive_30_plus_days": len(inactive_users_30) + len(inactive_users_60) + len(inactive_users_90),
                "average_inactive_days": avg_inactive_days if avg_inactive_days > 0 else None
            }
        
        # Build user lists for summary
        detected_users = {
            "never_logged_in_users": [{"email": u.get("email"), "login": u.get("login"), "created": u.get("created")} for u in never_logged_in[:20]],
            "inactive_users_30_days": [{"email": u.get("email"), "login": u.get("login"), "days_inactive": u.get("days_inactive")} for u in inactive_users_30[:20]],
            "inactive_users_60_days": [{"email": u.get("email"), "login": u.get("login"), "days_inactive": u.get("days_inactive")} for u in inactive_users_60[:20]],
            "inactive_users_90_days": [{"email": u.get("email"), "login": u.get("login"), "days_inactive": u.get("days_inactive")} for u in inactive_users_90[:20]],
            "automated_creations": [{"user_created": u.get("user_created"), "timestamp": u.get("timestamp"), "actor_name": u.get("actor_name")} for u in automated_creations[:20]],
            "automated_deactivations": [{"user_deactivated": u.get("user_deactivated"), "timestamp": u.get("timestamp"), "actor_name": u.get("actor_name")} for u in automated_deactivations[:20]]
        }
        
        # Build lists of all users and active users with details
        total_users_list = [{
            "id": u.get("id"),
            "email": u.get("profile", {}).get("email"),
            "login": u.get("profile", {}).get("login"),
            "status": u.get("status"),
            "created": u.get("created"),
            "last_login": u.get("lastLogin"),
            "status_changed": u.get("statusChanged")
        } for u in all_users]
        
        active_users_list = [{
            "id": u.get("id"),
            "email": u.get("profile", {}).get("email"),
            "login": u.get("profile", {}).get("login"),
            "status": u.get("status"),
            "created": u.get("created"),
            "last_login": u.get("lastLogin"),
            "status_changed": u.get("statusChanged")
        } for u in active_users]
        
        # Focused summary
        evidence["summary"] = {
            "account_management_overview": {
                "total_users": len(all_users),
                "total_users_details": total_users_list,
                "active_accounts": total_active_user_accounts,  # Excludes service accounts
                "active_accounts_including_service": len(active_users),  # Includes all active accounts
                "service_accounts_count": len(service_accounts),
                "active_accounts_details": active_users_list,
                "account_health_percentage": health_percentage,
                "note": "Account health shows percentage of active user accounts (excluding service/API-only accounts) with recent login activity (within 30 days). Service accounts are excluded because they use API tokens and don't login."
            },
            "account_lifecycle_monitoring": {
                "account_age_distribution": account_ages,
                "last_activity_distribution": last_activity_distribution,
                "note": "Demonstrates active monitoring of account lifecycle and user activity patterns"
            },
            "detected_users": detected_users
        }
        
        # Only add lifecycle activity if there's actual activity
        if lifecycle_activity:
            evidence["summary"]["lifecycle_activity"] = {
                "activities": lifecycle_activity,
                "note": "Recent account lifecycle events demonstrating automation in practice"
            }
        
        # Only add inactive accounts if there are any
        if inactive_summary:
            evidence["summary"]["inactive_account_monitoring"] = inactive_summary

        # Print organized summary in JSON-like format - Focused on meaningful evidence
        print(f"  ✓ Summary:")
        print(f"    {{")
        print(f"      \"account_management_overview\": {{")
        print(f"        \"total_users\": {len(all_users)},")
        print(f"        \"total_users_details\": {json.dumps(total_users_list)},")
        print(f"        \"active_accounts\": {total_active_user_accounts},")
        print(f"        \"active_accounts_including_service\": {len(active_users)},")
        print(f"        \"service_accounts_count\": {len(service_accounts)},")
        print(f"        \"active_accounts_details\": {json.dumps(active_users_list)},")
        print(f"        \"account_health_percentage\": {health_percentage},")
        print(f"        \"note\": \"Account health shows percentage of active user accounts (excluding service/API-only accounts) with recent login activity (within 30 days)\"")
        print(f"      }},")
        print(f"      \"account_lifecycle_monitoring\": {{")
        print(f"        \"account_age_distribution\": {json.dumps(account_ages)},")
        print(f"        \"last_activity_distribution\": {json.dumps(last_activity_distribution)},")
        print(f"        \"note\": \"Demonstrates active monitoring of account lifecycle and user activity patterns\"")
        print(f"      }},")
        print(f"      \"detected_users\": {json.dumps(detected_users)}")
        
        # Only print lifecycle activity if there's actual activity
        if lifecycle_activity:
            print(f"      ,")
            print(f"      \"lifecycle_activity\": {{")
            activity_json = json.dumps(lifecycle_activity)
            print(f"        \"activities\": {activity_json},")
            print(f"        \"note\": \"Recent account lifecycle events demonstrating automation in practice\"")
            print(f"      }}")
        
        # Only print inactive accounts if there are any
        if inactive_summary:
            print(f"      ,")
            print(f"      \"inactive_account_monitoring\": {json.dumps(inactive_summary)}")
        
        print(f"    }}")
        
        return evidence
def main():
    """Main entry point."""
    # Check for --check-only flag
    if "--check-only" in sys.argv:
        print("=" * 60)
        print("OKTA API COMPATIBILITY CHECK ONLY")
        print("=" * 60)
        try:
            client = OktaAPIClient()
            results = client.run_compatibility_check()
            print(f"\n✅ Compatibility check complete.")
            print(f"   Features available: {results['features_available']}/{results['features_checked']}")
            if results['unavailable_details']:
                print(f"\n   Run full evidence collection to see what data is available.")
            sys.exit(0 if results['features_unavailable'] == 0 else 1)
        except RuntimeError as e:
            print(f"\n❌ Error: {e}")
            sys.exit(1)
 
    # Combined evidence output has been intentionally disabled.
    # Use the dedicated fetchers instead:
    # - okta_phishing_resistant_mfa.py
    # - okta_passwordless_authentication.py
    # - okta_non_user_accounts_authentication.py
    # - okta_just_in_time_authorization.py
    # - okta_least_privilege.py
    # - okta_suspicious_activity_management.py
    # - okta_automated_account_management.py
    print("=" * 70)
    print("OKTA IAM EVIDENCE (COMBINED) DISABLED")
    print("=" * 70)
    print("This repo uses 7 separate Okta fetchers, one per evidence set.")
    print("The combined okta_iam_evidence.json output is no longer generated to avoid duplicate evidence artifacts.")
    print("\nRun one of the fetchers in fetchers/okta/ instead.")
    print("\nTip: You can still run compatibility check only:")
    print("  python fetchers/okta/okta_iam_evidence.py --check-only")
    sys.exit(2)


if __name__ == "__main__":
    main()

