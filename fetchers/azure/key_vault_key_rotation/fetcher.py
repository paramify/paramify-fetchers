#!/usr/bin/env python3
"""Azure Key Vault key rotation for one subscription: each key's rotation policy and
expiry, each secret's expiry. No key material or secret value is read.

Ported from prowler/providers/azure/services/keyvault/keyvault_service.py (Apache-2.0).
Both planes are read and merged by key name, and `rotation_policy_source` records which
answered. Contrary to Prowler's premise, verified live: the management plane's per-key
`keys.get` returns `rotationPolicy`, `kty` and `keySize` where `keys.list` returns none,
so ARM Reader alone yields rotation policies. A vault whose data plane the credential
cannot open answers 403 — recorded as `data_plane_status` inaccessible, a posture, not a
failed run.
"""

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_key_vault_key_rotation")

# Per-vault data-plane outcome. "inaccessible" is a normal posture, not a fault: a
# credential can hold ARM Reader (control plane) and no Key Vault data action.
DATA_PLANE_ACCESSIBLE = "accessible"
DATA_PLANE_INACCESSIBLE = "inaccessible"
DATA_PLANE_NOT_ATTEMPTED = "not_attempted"

# Matched case-insensitively because the two planes disagree: the data plane's
# KeyRotationPolicyAction spells it "Rotate", azure-mgmt-keyvault's
# KeyRotationPolicyActionType "rotate" (both verified against the installed SDKs).
ROTATE_ACTION = "rotate"

# Which plane a merged policy came from: "no policy" vs "we could not see it".
SOURCE_DATA_PLANE = "data_plane"
SOURCE_MANAGEMENT_PLANE = "management_plane"

# Fallback host suffix, used only when ARM returned no `vault_uri`. Prowler
# hardcodes this form; preferring `vault_uri` is what keeps this correct in the
# sovereign clouds (vault.usgovcloudapi.net / vault.azure.cn).
DEFAULT_VAULT_URI_SUFFIX = "vault.azure.net"


# --- projection: the only code that touches an SDK model ---

def properties_bag(model):
    """Return the model's `properties` sub-model, or the model itself.

    azure-mgmt-keyvault 14.x does NOT flatten `properties` onto the resource, which
    is why Prowler reads `secret.properties.attributes`. Older msrest-generated
    releases DO flatten it, and then there is no `properties` attribute at all.
    """
    bag = model_attr(model, "properties")
    return model if bag is None else bag


def _iso8601_duration(value) -> str | None:
    """Render a `timedelta` as the ISO-8601 duration string the wire carries ("P90D").

    The installed SDKs type rotation durations as `str`, but msrest deserializes a
    duration-typed field into a `timedelta`, and `json.dump(default=str)` would then
    write "90 days, 0:00:00" — a payload change for identical input (a real bug on
    azure-mgmt-security's free_trial_remaining_time; see
    fetchers/azure/defender_plans/fetcher.py, which this copies). Matches the SDK
    serializer exactly: zero components omitted, a bare zero is "P0D", fractional
    seconds keep no trailing zeros ("P2DT30.5S"). Non-timedeltas pass through.
    """
    if not isinstance(value, timedelta):
        return value
    hours, remainder = divmod(value.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    date_part = f"{value.days}D" if value.days else ""
    time_part = ""
    if hours:
        time_part += f"{hours}H"
    if minutes:
        time_part += f"{minutes}M"
    if seconds or value.microseconds:
        if value.microseconds:
            fractional = f"{seconds + value.microseconds / 1_000_000:.6f}"
            time_part += fractional.rstrip("0").rstrip(".") + "S"
        else:
            time_part += f"{seconds}S"
    if not date_part and not time_part:
        return "P0D"
    return f"P{date_part}" + (f"T{time_part}" if time_part else "")


def _iso8601_timestamp(value) -> str | None:
    """Render a key/secret attribute date as one UTC ISO-8601 string.

    One conceptual field, three types, all verified against the installed SDK:
    azure-mgmt-keyvault 14.x types `KeyAttributes.created/updated/expires` as `int`
    epoch seconds, `SecretAttributes`' inherited equivalents as `datetime`, and the
    data plane's `KeyProperties.created_on` as `datetime`. Left alone, one evidence
    file carries both 1749081600 and "2026-06-05 00:00:00+00:00".
    """
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, bool):
        # bool is an int subclass; an epoch of True/False is nonsense, not a date.
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def project_management_key(key) -> dict:
    """Read an azure-mgmt-keyvault `Key` into a flat dict — public parameters only."""
    properties = properties_bag(key)
    attributes = model_attr(properties, "attributes")
    return {
        "id": model_attr(key, "id"),
        "name": model_attr(key, "name"),
        "location": model_attr(key, "location"),
        "enabled": model_attr(attributes, "enabled"),
        "created": model_attr(attributes, "created"),
        "updated": model_attr(attributes, "updated"),
        "expires": model_attr(attributes, "expires"),
        "not_before": model_attr(attributes, "not_before"),
        "recovery_level": model_attr(attributes, "recovery_level"),
        "key_type": model_attr(properties, "kty"),
        "key_size": model_attr(properties, "key_size"),
        "curve_name": model_attr(properties, "curve_name"),
        # Returned by keys.get but NOT by keys.list (verified live), which is why
        # each listed key is followed by a GET.
        "rotation_policy": project_management_rotation_policy(
            model_attr(properties, "rotation_policy")
        ),
    }


def project_management_secret(secret) -> dict:
    """Read an azure-mgmt-keyvault `Secret` into a flat dict — NAME AND DATES ONLY.

    `SecretProperties.value` exists on this model and is deliberately NOT read, nor
    is `content_type` (caller-supplied free text).
    """
    properties = properties_bag(secret)
    attributes = model_attr(properties, "attributes")
    return {
        "id": model_attr(secret, "id"),
        "name": model_attr(secret, "name"),
        "location": model_attr(secret, "location"),
        "enabled": model_attr(attributes, "enabled"),
        "created": model_attr(attributes, "created"),
        "updated": model_attr(attributes, "updated"),
        "expires": model_attr(attributes, "expires"),
        "not_before": model_attr(attributes, "not_before"),
    }


def project_key_properties(properties) -> dict:
    """Read a data-plane `KeyProperties` into `project_management_key`'s shape."""
    return {
        "id": model_attr(properties, "id"),
        "name": model_attr(properties, "name"),
        "location": None,
        "enabled": model_attr(properties, "enabled"),
        "created": model_attr(properties, "created_on"),
        "updated": model_attr(properties, "updated_on"),
        "expires": model_attr(properties, "expires_on"),
        "not_before": model_attr(properties, "not_before"),
        "recovery_level": model_attr(properties, "recovery_level"),
        "key_type": None,
        "key_size": None,
        "curve_name": None,
        "rotation_policy": None,
    }


def project_rotation_policy(policy) -> dict | None:
    """Read a data-plane `KeyRotationPolicy` into a flat dict.

    `action` is an enum on this plane, which `model_attr` unwraps to "Rotate".
    """
    if policy is None:
        return None
    return {
        "id": model_attr(policy, "id"),
        "expires_in": _iso8601_duration(model_attr(policy, "expires_in")),
        "created": model_attr(policy, "created_on"),
        "updated": model_attr(policy, "updated_on"),
        "lifetime_actions": [
            {
                "action": model_attr(action, "action"),
                "time_after_create": _iso8601_duration(
                    model_attr(action, "time_after_create")
                ),
                "time_before_expiry": _iso8601_duration(
                    model_attr(action, "time_before_expiry")
                ),
            }
            for action in (model_attr(policy, "lifetime_actions") or [])
        ],
    }


def project_management_rotation_policy(policy) -> dict | None:
    """Read an azure-mgmt-keyvault `RotationPolicy` into the SAME flat dict.

    The control plane nests what the data plane flattens: the duration under
    `lifetime_actions[].trigger`, the verb under `lifetime_actions[].action.type` and
    spelled "rotate", not "Rotate".
    """
    if policy is None:
        return None
    attributes = model_attr(policy, "attributes")
    actions = []
    for action in model_attr(policy, "lifetime_actions") or []:
        trigger = model_attr(action, "trigger")
        actions.append(
            {
                "action": model_attr(model_attr(action, "action"), "type"),
                "time_after_create": _iso8601_duration(
                    model_attr(trigger, "time_after_create")
                ),
                "time_before_expiry": _iso8601_duration(
                    model_attr(trigger, "time_before_expiry")
                ),
            }
        )
    return {
        "id": model_attr(policy, "id"),
        "expires_in": _iso8601_duration(model_attr(attributes, "expiry_time")),
        "created": model_attr(attributes, "created"),
        "updated": model_attr(attributes, "updated"),
        "lifetime_actions": actions,
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def rotation_policy_record(policy: dict | None) -> dict | None:
    """Normalize a projected rotation policy from either plane."""
    if not policy:
        return None
    return {
        "id": policy.get("id"),
        "expires_in": _iso8601_duration(policy.get("expires_in")),
        "created": _iso8601_timestamp(policy.get("created")),
        "updated": _iso8601_timestamp(policy.get("updated")),
        "lifetime_actions": [
            {
                "action": action.get("action"),
                "time_after_create": _iso8601_duration(action.get("time_after_create")),
                "time_before_expiry": _iso8601_duration(action.get("time_before_expiry")),
            }
            for action in (policy.get("lifetime_actions") or [])
        ],
    }


def has_rotate_action(policy: dict | None) -> bool:
    """Prowler's keyvault_key_rotation_enabled predicate, case-insensitively.

    Prowler compares `action.action == "Rotate"` (the data plane's spelling) where the
    control plane says "rotate", so case-folding is what stops the evidence claiming a
    rotating key has no rotation.
    """
    if not policy:
        return False
    return any(
        str(action.get("action") or "").strip().lower() == ROTATE_ACTION
        for action in (policy.get("lifetime_actions") or [])
    )


def key_record(
    key: dict, policy_source: str | None = None, policy_readable: bool = False
) -> dict:
    """Normalize one projected key (from either plane) into an evidence record.

    `policy_readable` asserts a DEFINITIVE answer about this key's policy — the plane
    answered, with a policy or with "there is none". It separates "does not rotate"
    from "could not see", and is the denominator of the rotation percentage.
    """
    policy = rotation_policy_record(key.get("rotation_policy"))
    expires = _iso8601_timestamp(key.get("expires"))
    return {
        "id": key.get("id"),
        "name": key.get("name"),
        "location": key.get("location"),
        # Coerced: ARM omits `enabled` on a key never disabled, and absent means
        # enabled — but a validator asserting `true` would not match `null`.
        "enabled": True if key.get("enabled") is None else bool(key.get("enabled")),
        "created": _iso8601_timestamp(key.get("created")),
        "updated": _iso8601_timestamp(key.get("updated")),
        "expires": expires,
        "not_before": _iso8601_timestamp(key.get("not_before")),
        "expiration_set": expires is not None,
        "recovery_level": key.get("recovery_level"),
        "key_type": key.get("key_type"),
        "key_size": key.get("key_size"),
        "curve_name": key.get("curve_name"),
        "rotation_policy": policy,
        "rotation_enabled": has_rotate_action(policy),
        "rotation_policy_source": policy_source if policy else None,
        "rotation_policy_readable": bool(policy_readable),
    }


def secret_record(secret: dict) -> dict:
    """Normalize one projected secret — name and dates, never a value."""
    expires = _iso8601_timestamp(secret.get("expires"))
    return {
        "id": secret.get("id"),
        "name": secret.get("name"),
        "location": secret.get("location"),
        "enabled": True if secret.get("enabled") is None else bool(secret.get("enabled")),
        "created": _iso8601_timestamp(secret.get("created")),
        "updated": _iso8601_timestamp(secret.get("updated")),
        "expires": expires,
        "not_before": _iso8601_timestamp(secret.get("not_before")),
        "expiration_set": expires is not None,
    }


def merge_rotation_policies(keys: list[dict], data_plane_policies: dict) -> list[dict]:
    """Attach each data-plane rotation policy to its management-plane key, by name.

    Prowler's merge plus one addition: a key the data plane knows but the
    management-plane list did not return is still emitted, never quietly dropped the
    way Prowler's `keys_dict[name]` lookup drops it.
    """
    by_name = {key["name"]: key for key in keys if key.get("name")}
    for name, policy in sorted(data_plane_policies.items()):
        record = by_name.get(name)
        if record is None:
            record = key_record({"name": name})
            keys.append(record)
            by_name[name] = record
        if policy is None:
            # A 404 (or an ungranted policy read) for one key: what the management
            # plane knows stands, and readability is not upgraded.
            continue
        normalized = rotation_policy_record(policy)
        record["rotation_policy"] = normalized
        record["rotation_enabled"] = has_rotate_action(normalized)
        record["rotation_policy_source"] = SOURCE_DATA_PLANE
        record["rotation_policy_readable"] = True
    return sorted(keys, key=lambda r: r.get("name") or "")


def vault_record(vault: dict) -> dict:
    """Normalize one projected vault's key/secret inventory into a record."""
    resource_id = vault.get("id")
    return {
        "id": resource_id,
        "name": vault.get("name"),
        "location": vault.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "vault_uri": vault.get("vault_uri"),
        "rbac_authorization_enabled": bool(vault.get("enable_rbac_authorization") or False),
        # Per vault, because it decides how `rotation_policy: null` reads: "no policy
        # configured" vs "not visible to this credential".
        "data_plane_status": vault.get("data_plane_status") or DATA_PLANE_NOT_ATTEMPTED,
        "data_plane_message": vault.get("data_plane_message"),
        "keys": vault.get("keys") or [],
        "secrets": vault.get("secrets") or [],
    }


def summarize(vaults: list[dict]) -> dict:
    """Rotation-policy coverage across keys is the headline.

    Measured over `rotation_policy_readable` keys only: keys the collector could never
    ask about would measure its permissions, not the tenant's key management.
    """
    keys = [key for vault in vaults for key in vault["keys"]]
    secrets = [secret for vault in vaults for secret in vault["secrets"]]
    visible_keys = [key for key in keys if key["rotation_policy_readable"]]
    rotating = sum(1 for key in visible_keys if key["rotation_enabled"])
    keys_with_expiration = sum(1 for key in keys if key["expiration_set"])
    secrets_with_expiration = sum(1 for secret in secrets if secret["expiration_set"])

    return {
        "total_key_vaults": len(vaults),
        "data_plane_accessible_vaults": sum(
            1 for v in vaults if v["data_plane_status"] == DATA_PLANE_ACCESSIBLE
        ),
        "data_plane_inaccessible_vaults": sum(
            1 for v in vaults if v["data_plane_status"] == DATA_PLANE_INACCESSIBLE
        ),
        "rbac_authorization_vaults": sum(1 for v in vaults if v["rbac_authorization_enabled"]),
        "total_keys": len(keys),
        "enabled_keys": sum(1 for key in keys if key["enabled"]),
        "keys_with_readable_rotation_policy": len(visible_keys),
        "keys_with_rotation_policy": sum(1 for key in keys if key["rotation_policy"]),
        "keys_with_rotation_enabled": rotating,
        "rotation_enabled_percentage": coverage_percentage(rotating, len(visible_keys)),
        "keys_with_expiration": keys_with_expiration,
        "key_expiration_percentage": coverage_percentage(keys_with_expiration, len(keys)),
        "total_secrets": len(secrets),
        "enabled_secrets": sum(1 for secret in secrets if secret["enabled"]),
        "secrets_with_expiration": secrets_with_expiration,
        "secret_expiration_percentage": coverage_percentage(
            secrets_with_expiration, len(secrets)
        ),
    }


# --- collection (lazy azure imports) ---

def is_data_plane_inaccessible(exc: BaseException) -> bool:
    """Is this "the credential cannot open this vault's data plane"?

    Prowler's `HttpResponseError` catch, matched by walking class NAMES rather than
    isinstance: every HTTP-shaped Key Vault error is a subclass, and the predicate
    stays importable with no azure-core installed. A TRANSPORT failure
    (ServiceRequestError, DNS, TLS) is NOT in that hierarchy, so it still reaches
    Collector and exits 1 — unreachable is a broken run, no data action is a posture.
    """
    return any(cls.__name__ == "HttpResponseError" for cls in type(exc).__mro__)


def vault_data_plane_uri(vault: dict) -> str | None:
    """The vault's data-plane URL: `vault_uri` from ARM, else Prowler's form.

    Prowler hardcodes f"https://{name}.vault.azure.net/"; preferring ARM's own
    `vault_uri` is what keeps this correct in Azure Government / China
    (vault.usgovcloudapi.net / vault.azure.cn).
    """
    uri = vault.get("vault_uri")
    if uri:
        return uri
    name = vault.get("name")
    return f"https://{name}.{DEFAULT_VAULT_URI_SUFFIX}/" if name else None


def collect_management_plane_keys(client, collector: Collector, group: str, name: str) -> list[dict]:
    """keys.list for one vault, then one keys.get per key.

    The GET is not redundant: ARM's LIST response carries only `{attributes, keyUri}`
    (verified live) while the GET adds `kty`, `keySize` and — crucially —
    `rotationPolicy`. Both are `Microsoft.KeyVault/vaults/keys/read`, so a GET failure
    after a successful list is a real collection failure, not a posture.
    """
    records = []
    for listed in client.keys.list(group, name):
        key_name = model_attr(listed, "name")
        detailed = collector.guard(
            f"keyvault.keys.get ({name}/{key_name})",
            lambda key_name=key_name: client.keys.get(group, name, key_name),
        )
        records.append(
            key_record(
                project_management_key(detailed if detailed is not None else listed),
                SOURCE_MANAGEMENT_PLANE,
                policy_readable=detailed is not None,
            )
        )
    return records


def collect_management_plane(subscription_id, cred, collector: Collector) -> list[dict]:
    """vaults.list_by_subscription(), then keys.list/get + secrets.list per vault.

    All control-plane and covered by ARM Reader, so a failure here IS a collection
    failure and goes through `Collector.guard`.
    """
    from azure.mgmt.keyvault import KeyVaultManagementClient

    def _client():
        return KeyVaultManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("keyvault.KeyVaultManagementClient (init)", _client)
    if client is None:
        return []

    def _list_vaults():
        # ItemPaged: the SDK follows nextLink itself.
        return [
            {
                "id": model_attr(v, "id"),
                "name": model_attr(v, "name"),
                "location": model_attr(v, "location"),
                "vault_uri": model_attr(properties_bag(v), "vault_uri"),
                "enable_rbac_authorization": model_attr(
                    properties_bag(v), "enable_rbac_authorization"
                ),
            }
            for v in client.vaults.list_by_subscription()
        ]

    vaults = collector.guard("keyvault.vaults.list_by_subscription", _list_vaults, default=[])

    for vault in vaults:
        group, name = resource_group_from_id(vault.get("id")), vault.get("name")
        if not group or not name:
            collector.record(
                "keyvault.keys.list",
                RuntimeError(f"key vault {name!r} has no resource group in its id"),
            )
            vault["keys"], vault["secrets"] = [], []
            continue
        vault["keys"] = collector.guard(
            f"keyvault.keys.list ({name})",
            lambda group=group, name=name: collect_management_plane_keys(
                client, collector, group, name
            ),
            default=[],
        )
        vault["secrets"] = sorted(
            collector.guard(
                f"keyvault.secrets.list ({name})",
                lambda group=group, name=name: [
                    secret_record(project_management_secret(s))
                    for s in client.secrets.list(group, name)
                ],
                default=[],
            ),
            key=lambda r: r.get("name") or "",
        )

    return vaults


def collect_rotation_policies(vault: dict, cred, collector: Collector) -> None:
    """Open one vault's data plane and read every key's rotation policy.

    Nothing here can flip the exit code except a non-HTTP failure — see
    `is_data_plane_inaccessible`.
    """
    from azure.keyvault.keys import KeyClient

    vault_uri = vault_data_plane_uri(vault)
    if not vault_uri:
        vault["data_plane_status"] = DATA_PLANE_NOT_ATTEMPTED
        vault["data_plane_message"] = "no vault uri and no vault name to derive one from"
        return

    name = vault.get("name")
    try:
        key_client = KeyClient(vault_url=vault_uri, credential=cred)
        # list() forces the ItemPaged: a 403 surfaces on the first page, not here.
        properties = list(key_client.list_properties_of_keys())
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if is_data_plane_inaccessible(exc):
            # Prowler's exact reading: a vault the credential holds no data action on
            # is a posture to report, not a failed collection.
            logger.warning(
                "key vault %s: data plane not accessible to this credential "
                "(no Key Vault data-plane role assignment or access policy) — %s",
                name,
                str(exc).strip().splitlines()[0],
            )
            vault["data_plane_status"] = DATA_PLANE_INACCESSIBLE
            vault["data_plane_message"] = " ".join(str(exc).split())[:300]
            return
        collector.record(f"keyvault.keys.list_properties_of_keys ({name})", exc)
        vault["data_plane_status"] = DATA_PLANE_NOT_ATTEMPTED
        vault["data_plane_message"] = " ".join(str(exc).split())[:300]
        return

    policies: dict[str, dict | None] = {}
    for key_properties in properties:
        key_name = model_attr(key_properties, "name")
        if not key_name:
            continue
        policies.setdefault(key_name, None)
        try:
            policies[key_name] = project_rotation_policy(
                key_client.get_key_rotation_policy(key_name)
            )
        except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash
            if is_data_plane_inaccessible(exc):
                # Prowler's `_get_single_rotation_policy` returns (name, None) here.
                # A key with no policy configured answers 404, which is the finding.
                logger.warning(
                    "key vault %s: no readable rotation policy for key %s — %s",
                    name,
                    key_name,
                    str(exc).strip().splitlines()[0],
                )
                continue
            collector.record(f"keyvault.keys.get_key_rotation_policy ({name}/{key_name})", exc)

    vault["data_plane_status"] = DATA_PLANE_ACCESSIBLE
    vault["keys"] = merge_rotation_policies(vault.get("keys") or [], policies)


def collect_key_vaults(subscription_id, cred, collector: Collector) -> list[dict]:
    """Both planes: the management-plane inventory, then per-vault rotation policies."""
    vaults = collect_management_plane(subscription_id, cred, collector)
    for vault in vaults:
        collect_rotation_policies(vault, cred, collector)
    return sorted((vault_record(v) for v in vaults), key=lambda r: r.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every request header at INFO; warnings still get through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    vaults: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # ARM returns an empty list, not an error, for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.KeyVault"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.KeyVault is not registered on subscription %s — no key "
                "vaults in use; reporting status not_registered",
                subscription_id,
            )
        vaults = collect_key_vaults(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "key_vaults": vaults,
            "provider_registration_status": registration,
        },
        summary={**summarize(vaults), "provider_registration_status": registration},
    )

    filename = (
        f"azure_key_vault_key_rotation_"
        f"{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
