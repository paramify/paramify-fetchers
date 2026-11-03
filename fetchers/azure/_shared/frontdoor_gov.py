"""Azure Government variants of the Front Door fetchers.

Azure Government gets new Resource Manager API versions later than the public
cloud. The Front Door fetchers read Microsoft.Cdn with the azure-mgmt-cdn
default (2026-10-01) and, for origins and security policies, a pinned
2026-07-01. Azure Government does not offer either yet, so every call fails with
InvalidResourceType ("could not be found ... for api version").

The *_gov fetchers reuse the public-cloud fetcher code unchanged. They load the
original fetcher module from its own directory and pin every Microsoft.Cdn
client it builds to GOV_CDN_API_VERSION, the newest stable version Azure
Government lists for every Microsoft.Cdn profiles/* type the fetchers read.

Known gap: the public-cloud fetchers pin 2026-07-01 for origins and security
policies because that version returns fields an older one may not (for
example isProfileLevel and associations[].routes on security policies). On
GOV_CDN_API_VERSION those fields can come back empty. Check the evidence from a
real Azure Government run before relying on those fields.
"""

from __future__ import annotations

import importlib.util
import logging
import os
from pathlib import Path
from types import ModuleType
from typing import Optional

# Newest stable (non-preview) Microsoft.Cdn version that Azure Government lists for
# profiles, afdendpoints, afdendpoints/routes, customdomains, origingroups,
# origingroups/origins, rulesets, rulesets/rules, secrets and securitypolicies.
GOV_CDN_API_VERSION = "2025-12-01"

# Module-level constants in the public-cloud fetchers that pin a newer version.
PINNED_VERSION_CONSTANTS = ("ORIGIN_API_VERSION", "SECURITY_POLICY_API_VERSION")

GOV_AUTHORITY_HOST = "login.microsoftonline.us"

AZURE_FETCHERS_DIR = Path(__file__).resolve().parent.parent

logger = logging.getLogger("azure_front_door_gov")


def is_gov_authority(authority: Optional[str] = None) -> bool:
    """True when AZURE_AUTHORITY_HOST points at Azure Government."""
    value = authority if authority is not None else os.environ.get("AZURE_AUTHORITY_HOST", "")
    host = value.replace("https://", "").replace("http://", "").strip("/").lower()
    return host == GOV_AUTHORITY_HOST


def load_gov_variant(original: str) -> ModuleType:
    """Load fetchers/azure/<original>/fetcher.py and pin its Microsoft.Cdn clients.

    The original file is only read, never changed. Every cdn_client(...) call the
    loaded module makes is built with GOV_CDN_API_VERSION, whatever version the
    call asks for, and the module's pinned-version constants are set to it so the
    evidence reports the version that was actually used.
    """
    path = AZURE_FETCHERS_DIR / original / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"_{original}_gov_base", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    base_cdn_client = module.cdn_client

    def gov_cdn_client(subscription_id, cred, collector, api_version=None):
        return base_cdn_client(subscription_id, cred, collector, api_version=GOV_CDN_API_VERSION)

    module.cdn_client = gov_cdn_client
    for name in PINNED_VERSION_CONSTANTS:
        if hasattr(module, name):
            setattr(module, name, GOV_CDN_API_VERSION)
    return module


def run_gov_variant(original: str) -> int:
    """Run the original fetcher's main() with its Microsoft.Cdn clients pinned for Azure Government."""
    module = load_gov_variant(original)
    if not is_gov_authority():
        logger.warning(
            "AZURE_AUTHORITY_HOST is not https://%s; this fetcher is meant for Azure Government "
            "and pins Microsoft.Cdn to %s. Use azure_%s in the public cloud.",
            GOV_AUTHORITY_HOST,
            GOV_CDN_API_VERSION,
            original,
        )
    return module.main()
