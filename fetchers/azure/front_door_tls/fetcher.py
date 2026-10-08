#!/usr/bin/env python3
"""Azure Front Door TLS: routes that accept only HTTPS, and each custom domain's TLS floor and certificate, for one subscription."""

import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)
from frontdoor import (  # noqa: E402
    arm_key,
    cdn_client,
    custom_domains,
    endpoints_with_routes,
    front_door_profiles,
    route_hosts,
    route_https,
    route_serving,
    rule_sets_with_rules,
)

logger = logging.getLogger("azure_front_door_tls")

EXPIRY_WARNING_DAYS = 30
# A predefined cipher-suite set fixes the floor; minimumTlsVersion applies only to Customized.
CIPHER_SUITE_SET_FLOOR = {"TLS10_2019": "TLS10", "TLS12_2022": "TLS12", "TLS12_2023": "TLS12"}
TLS_RANK = {"TLS10": 10, "TLS12": 12, "TLS13": 13}
MANAGED_CERTIFICATE_TYPES = ("ManagedCertificate", "AzureFirstPartyManagedCertificate")
CERTIFICATE_SECRET_TYPES = ("CustomerCertificate", "ManagedCertificate", "AzureFirstPartyManagedCertificate")
# Python 3.10's fromisoformat takes only 3 or 6 fractional digits; ARM can send 7.
FRACTION = re.compile(r"\.(\d+)")


# --- projection: the only code here that touches an azure-mgmt model ---

def project_secret(secret) -> dict:
    params = model_attr(model_attr(secret, "properties"), "parameters")
    return {
        "id": model_attr(secret, "id"),
        "name": model_attr(secret, "name"),
        "type": model_attr(params, "type"),
        "subject": model_attr(params, "subject"),
        "subject_alternative_names": list(model_attr(params, "subject_alternative_names") or []),
        "certificate_authority": model_attr(params, "certificate_authority"),
        "thumbprint": model_attr(params, "thumbprint"),
        "expiration_date": model_attr(params, "expiration_date"),
        "key_vault_secret_id": model_attr(model_attr(params, "secret_source"), "id"),
        "secret_version": model_attr(params, "secret_version"),
        "use_latest_version": model_attr(params, "use_latest_version"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def parse_timestamp(value) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            text = FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), value.replace("Z", "+00:00"), count=1)
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def certificate_expiry(expiration_date, now: datetime) -> dict:
    end = parse_timestamp(expiration_date)
    if end is None:
        days = expired = expiring_soon = None
    else:
        days, expired = (end - now).days, end <= now
        expiring_soon = not expired and days <= EXPIRY_WARNING_DAYS
    return {
        "days_until_expiry": days,
        "certificate_expired": expired,
        "certificate_expiring_soon": expiring_soon,
        "expiry_warning_days": EXPIRY_WARNING_DAYS,
    }


def effective_minimum_tls(domain: dict) -> tuple[str | None, str]:
    """The TLS floor a domain enforces, and which field decided it."""
    cipher_set, minimum = domain["cipher_suite_set_type"], domain["minimum_tls_version"]
    if cipher_set == "Customized":
        return minimum, "customized"
    if cipher_set in CIPHER_SUITE_SET_FLOOR:
        return CIPHER_SUITE_SET_FLOOR[cipher_set], "cipher_suite_set"
    if cipher_set:
        return None, "unknown_cipher_suite_set"
    if minimum:
        return minimum, "minimum_tls_version"
    return None, "unset"


def route_record(profile: dict, endpoint: dict, route: dict, domains_by_key: dict, rule_sets_by_key: dict) -> dict:
    hosts = route_hosts(endpoint, route, domains_by_key)
    return {
        "profile": profile["name"],
        "profile_sku": profile["sku"],
        "endpoint": endpoint["name"],
        "endpoint_host_name": endpoint["host_name"],
        "route": route["name"],
        "route_id": route["id"],
        "serving": route_serving(endpoint, route),
        "supported_protocols": route["supported_protocols"],
        "https_redirect": route["https_redirect"],
        "forwarding_protocol": route["forwarding_protocol"],
        "rule_sets": [
            rule_sets_by_key[arm_key(i)]["name"] if arm_key(i) in rule_sets_by_key else i for i in route["rule_set_ids"]
        ],
        "hosts": [h["host_name"] for h in hosts],
        "serves_endpoint_default_domain": any(h["kind"] == "endpoint_default" for h in hosts),
        **route_https(route, rule_sets_by_key),
    }


def certificate_status(certificate_type, secret) -> str:
    if secret is not None:
        return "found"
    # Measured: managed-certificate domains on a Standard profile carry no secret reference at all.
    if certificate_type in MANAGED_CERTIFICATE_TYPES:
        return "managed_without_secret"
    return "missing"


def domain_record(profile: dict, domain: dict, secrets_by_key: dict, routed: set, served: set, now: datetime) -> dict:
    floor, basis = effective_minimum_tls(domain)
    secret = secrets_by_key.get(arm_key(domain["secret_id"])) if domain["secret_id"] else None
    key = arm_key(domain["id"])
    return {
        "profile": profile["name"],
        "profile_sku": profile["sku"],
        **domain,
        "routed": key in routed,
        "served": key in served,
        "effective_minimum_tls": floor,
        "effective_minimum_tls_basis": basis,
        "below_tls12": None if floor not in TLS_RANK else TLS_RANK[floor] < TLS_RANK["TLS12"],
        "certificate_status": certificate_status(domain["certificate_type"], secret),
        "certificate": secret,
        **certificate_expiry(secret["expiration_date"] if secret else None, now),
    }


def tls_for_profile(collected: dict, now: datetime) -> dict:
    profile = collected["profile"]
    domains_by_key = {arm_key(d["id"]): d for d in collected["custom_domains"]}
    secrets_by_key = {arm_key(s["id"]): s for s in collected["secrets"]}
    routes, routed, served = [], set(), set()
    for endpoint in collected["endpoints"]:
        for route in endpoint["routes"]:
            keys = {arm_key(d["id"]) for d in route["custom_domains"]}
            routed |= keys
            if route_serving(endpoint, route):
                served |= keys
            routes.append(route_record(profile, endpoint, route, domains_by_key, collected["rule_sets"]))
    domains = [domain_record(profile, d, secrets_by_key, routed, served, now) for d in collected["custom_domains"]]
    return {"routes": routes, "custom_domains": domains}


def summarize(profiles: list[dict], skipped_by_sku: dict, routes: list[dict], domains: list[dict], secrets: list[dict]) -> dict:
    serving = [r for r in routes if r["serving"]]
    served = [d for d in domains if d["served"]]

    def count(items, pred) -> int:
        return sum(1 for i in items if pred(i))

    return {
        "total_front_door_profiles": len(profiles),
        "premium_profiles": count(profiles, lambda p: p["sku"] == "Premium_AzureFrontDoor"),
        "standard_profiles": count(profiles, lambda p: p["sku"] == "Standard_AzureFrontDoor"),
        "skipped_profiles_by_sku": skipped_by_sku,
        "total_routes": len(routes),
        "serving_routes": len(serving),
        "serving_routes_https_only": count(serving, lambda r: r["https_only"]),
        "serving_routes_accepting_plain_http": count(serving, lambda r: not r["https_only"]),
        **{
            f"serving_routes_{basis}": count(serving, lambda r, b=basis: r["https_only_basis"] == b)
            for basis in ("https_only_protocols", "https_redirect", "rule_set_redirect")
        },
        "serving_routes_on_endpoint_default_domain": count(serving, lambda r: r["serves_endpoint_default_domain"]),
        "total_custom_domains": len(domains),
        "served_custom_domains": len(served),
        "unrouted_custom_domains": count(domains, lambda d: not d["routed"]),
        "served_domains_below_tls12": count(served, lambda d: d["below_tls12"] is True),
        "served_domains_minimum_tls13": count(served, lambda d: d["effective_minimum_tls"] == "TLS13"),
        "served_domains_tls_floor_unknown": count(served, lambda d: d["below_tls12"] is None),
        "served_domains_validation_not_approved": count(served, lambda d: d["domain_validation_state"] != "Approved"),
        "served_domains_certificate_missing": count(served, lambda d: d["certificate_status"] == "missing"),
        "served_domains_managed_certificate_without_secret": count(
            served, lambda d: d["certificate_status"] == "managed_without_secret"
        ),
        "served_domains_certificate_expired": count(served, lambda d: d["certificate_expired"] is True),
        "served_domains_certificate_expiring_soon": count(served, lambda d: d["certificate_expiring_soon"] is True),
        "served_domains_certificate_expiry_unknown": count(served, lambda d: d["certificate_expired"] is None),
        "domains_by_cipher_suite_set": dict(sorted(Counter(str(d["cipher_suite_set_type"]) for d in domains).items())),
        "domains_by_certificate_type": dict(sorted(Counter(str(d["certificate_type"]) for d in domains).items())),
        "certificate_secrets": count(secrets, lambda s: s["type"] in CERTIFICATE_SECRET_TYPES),
        "expiry_warning_days": EXPIRY_WARNING_DAYS,
    }


# --- collection (lazy azure imports) ---

def collect_profiles(subscription_id, cred, collector: Collector) -> tuple[list[dict], dict]:
    cdn = cdn_client(subscription_id, cred, collector)
    if cdn is None:
        return [], {}
    profiles, skipped = front_door_profiles(cdn, collector)
    collected = []
    for profile in profiles:
        rg, name = resource_group_from_id(profile["id"]), profile["name"]
        collected.append({
            "profile": profile,
            "endpoints": endpoints_with_routes(cdn, collector, profile),
            "custom_domains": custom_domains(cdn, collector, profile),
            "rule_sets": rule_sets_with_rules(cdn, collector, profile),
            "secrets": collector.guard(
                f"cdn.secrets.list_by_profile({name})",
                lambda: [project_secret(s) for s in cdn.secrets.list_by_profile(rg, name)],
                default=[],
            ),
        })
    return collected, skipped


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure SDKs log every HTTP request at INFO, which would bury the runner's stderr tail.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    collected: list[dict] = []
    skipped_by_sku: dict = {}
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Cdn")
        if registration == NOT_REGISTERED:
            logger.warning("Microsoft.Cdn is not registered on subscription %s", subscription_id)
        collected, skipped_by_sku = collect_profiles(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    now = datetime.now(timezone.utc)
    profiles, routes, domains, secrets = [], [], [], []
    for c in collected:
        tls = tls_for_profile(c, now)
        routes += tls["routes"]
        domains += tls["custom_domains"]
        secrets += c["secrets"]
        profiles.append({
            **c["profile"],
            "route_count": len(tls["routes"]),
            "custom_domain_count": len(tls["custom_domains"]),
            "secret_count": len(c["secrets"]),
            "rule_set_count": len(c["rule_sets"]),
        })

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "routes": routes,
            "custom_domains": domains,
            "profiles": profiles,
            "provider_registration_status": registration,
        },
        summary={
            **summarize(profiles, skipped_by_sku, routes, domains, secrets),
            "provider_registration_status": registration,
        },
    )
    filename = f"azure_front_door_tls_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
