#!/usr/bin/env python3
"""
Check every field the OCI fetchers read against Oracle's own generated models.

Why this exists
---------------
A hand-written test double cannot catch a wrong field name, because the double
is built from the same guess as the fetcher — the two agree with each other and
both disagree with the API. This project has re-learned that three times now
(CrowdStrike's Zero Trust signal map, Splunk's `content` block, and OCI's own
`step_status_counts`, which an early revision of the DR fetcher spelled as flat
`succeeded`/`failed`/`ignored` keys that do not exist on any model).

The cure is a source independent of both. Oracle publishes one, and unlike
CrowdStrike's it is already installed: the `oci` SDK's model classes are
generated from the same OpenAPI specification that serves the API, and each
carries a `swagger_types` mapping of wire field name to declared type.

That makes this check strictly simpler than its CrowdStrike ancestor
(`tools/crowdstrike_schema_check.py`), which downloads gofalcon and commits a
snapshot so CI can run offline. `oci` is a declared dependency in
`_categories/oci.yaml` and `requirements.txt`, so there is nothing to download
and no snapshot to drift — this check is offline by construction.

What it checks
--------------
1. NAMES. Every `.get("field")` inside a fetcher's record functions must exist
   on the model that function normalizes. A miss is a field that would read
   None forever while every test passed.

2. USAGE. A field declared as a nested model, read in a boolean context, is
   flagged — the `FwmgrFirewallRuleV1.monitor` bug from the CrowdStrike work,
   where a mandatory object was tested for truthiness and a logging control
   therefore reported as fully in place on every host. Lists are not flagged
   (`if x.get("ports")` legitimately means "any at all"), and neither is the
   defaulting idiom `x.get("y") or {}`, which is presence-handling on the way
   to a read rather than a truth test.

The function -> model mapping below is the one thing that must be maintained by
hand, and it is deliberately small: it names which SDK model each record
function normalizes, not which fields it reads. The fields come from the AST, so
adding a `.get()` to a fetcher extends the check automatically rather than
silently escaping it.

Usage
-----
    python tools/oci_schema_check.py        # exits non-zero on a finding

`tests/test_oci_schema_contract.py` runs the same checks under pytest.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Dict, Iterator, List, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_ROOT = REPO_ROOT / "fetchers" / "oci"

# record function -> (sdk module, model class). The model is the shape the
# function receives as a dict, after oci.util.to_dict().
#
# Where a fetcher reads a nested sub-object out of the parent dict, the nested
# model is named separately and the parent's own entry does not have to repeat
# its fields.
FUNCTION_MODELS: Dict[Tuple[str, str], Tuple[str, str]] = {
    ("dr_plan_executions", "execution_record"): ("disaster_recovery", "DrPlanExecution"),
    ("dr_plan_executions", "plan_record"): ("disaster_recovery", "DrPlanSummary"),
    ("dr_plan_executions", "protection_group_record"): (
        "disaster_recovery", "DrProtectionGroupSummary",
    ),
    ("dr_plan_executions", "step_counts"): (
        "disaster_recovery", "DrPlanExecutionStepStatusCounts",
    ),
    ("dependency_vulnerabilities", "audit_record"): ("adm", "VulnerabilityAuditSummary"),
    ("dependency_vulnerabilities", "suppression_delta"): ("adm", "VulnerabilityAuditSummary"),
    ("dependency_vulnerabilities", "remediation_run_record"): ("adm", "RemediationRunSummary"),
    ("dependency_vulnerabilities", "recipe_record"): ("adm", "RemediationRecipeSummary"),
    ("dependency_vulnerabilities", "knowledge_base_record"): ("adm", "KnowledgeBaseSummary"),
    ("bastion_sessions", "bastion_record"): ("bastion", "Bastion"),
    ("bastion_sessions", "session_record"): ("bastion", "SessionSummary"),
    ("certificates", "certificate_record"): (
        "certificates_management", "CertificateSummary",
    ),
    ("certificates", "authority_record"): (
        "certificates_management", "CertificateAuthoritySummary",
    ),
    ("certificates", "version_facts"): (
        "certificates_management", "CertificateVersionSummary",
    ),
    ("certificates", "renewal_rule"): (
        "certificates_management", "CertificateRenewalRule",
    ),
    ("cloud_guard_posture", "configuration_record"): ("cloud_guard", "Configuration"),
    ("cloud_guard_posture", "target_record"): ("cloud_guard", "Target"),
    ("cloud_guard_posture", "detector_recipe_record"): ("cloud_guard", "TargetDetectorRecipe"),
    ("cloud_guard_posture", "responder_recipe_record"): ("cloud_guard", "TargetResponderRecipe"),
    ("cloud_guard_posture", "detector_rule_facts"): (
        "cloud_guard", "TargetDetectorRecipeDetectorRule",
    ),
    ("cloud_guard_posture", "responder_rule_facts"): (
        "cloud_guard", "TargetResponderRecipeResponderRule",
    ),
    ("cloud_guard_posture", "security_zone_record"): ("cloud_guard", "SecurityZoneSummary"),
    ("cloud_guard_posture", "security_recipe_record"): ("cloud_guard", "SecurityRecipeSummary"),
    ("cloud_guard_posture", "problem_record"): ("cloud_guard", "ProblemSummary"),
    ("zpr_policies", "policy_record"): ("zpr", "ZprPolicySummary"),
    ("zpr_policies", "namespace_record"): (
        "security_attribute", "SecurityAttributeNamespaceSummary",
    ),
    ("zpr_policies", "attribute_record"): ("security_attribute", "SecurityAttributeSummary"),
    ("zpr_policies", "vcn_record"): ("core", "Vcn"),
    ("iam_users_credentials", "user_record"): ("identity", "User"),
    ("iam_policies", "policy_record"): ("identity", "Policy"),
    ("iam_policies", "dynamic_group_record"): ("identity", "DynamicGroup"),
    ("iam_password_policy", "password_policy_record"): ("identity_domains", "PasswordPolicy"),
    ("iam_password_policy", "domain_record"): ("identity", "Domain"),
    ("iam_password_policy", "legacy_policy_record"): ("identity", "AuthenticationPolicy"),
    ("vault_keys", "key_record"): ("key_management", "Key"),
    ("vault_keys", "vault_record"): ("key_management", "Vault"),
    ("data_service_exposure", "autonomous_database_record"): (
        "database", "AutonomousDatabaseSummary",
    ),
    ("data_service_exposure", "db_system_record"): ("database", "DbSystemSummary"),
    ("data_service_exposure", "file_system_record"): ("file_storage", "FileSystemSummary"),
    ("data_service_exposure", "export_record"): ("file_storage", "Export"),
    ("data_service_exposure", "mount_target_record"): ("file_storage", "MountTargetSummary"),
    ("data_service_exposure", "integration_instance_record"): (
        "integration", "IntegrationInstanceSummary",
    ),
    ("audit_logging_events", "audit_record"): ("audit", "Configuration"),
    ("audit_logging_events", "log_group_record"): ("logging", "LogGroupSummary"),
    ("audit_logging_events", "log_record"): ("logging", "LogSummary"),
    ("audit_logging_events", "rule_record"): ("events", "Rule"),
    ("audit_logging_events", "action_record"): ("events", "NotificationServiceAction"),
    ("audit_logging_events", "topic_record"): ("ons", "NotificationTopicSummary"),
    ("compute_instances", "instance_record"): ("core", "Instance"),
    ("compute_instances", "vnic_record"): ("core", "Vnic"),
    ("network_exposure", "rule_record"): ("core", "SecurityRule"),
    ("network_exposure", "_port_range"): ("core", "TcpOptions"),
    ("network_exposure", "route_table_routes_to_internet"): ("core", "RouteTable"),
    ("network_exposure", "internet_gateway_record"): ("core", "InternetGateway"),
    ("network_exposure", "security_list_record"): ("core", "SecurityList"),
    ("network_exposure", "nsg_record"): ("core", "NetworkSecurityGroup"),
    ("network_exposure", "subnet_record"): ("core", "Subnet"),
    ("network_exposure", "flow_log_record"): ("logging", "LogSummary"),
    ("object_storage_buckets", "bucket_record"): ("object_storage", "Bucket"),
    ("object_storage_buckets", "par_record"): (
        "object_storage", "PreauthenticatedRequestSummary",
    ),
    ("object_storage_buckets", "retention_rule_record"): ("object_storage", "RetentionRule"),
    ("object_storage_buckets", "replication_record"): (
        "object_storage", "ReplicationPolicySummary",
    ),
    ("object_storage_buckets", "log_record"): ("logging", "LogSummary"),
    ("block_volume_encryption", "volume_record"): ("core", "Volume"),
    ("block_volume_encryption", "attachment_record"): ("core", "VolumeAttachment"),
    ("block_volume_encryption", "backup_record"): ("core", "VolumeBackup"),
    # One transform over six credential models; the rest are declared as
    # alternates below, so a field passes only if one of them declares it.
    ("iam_users_credentials", "credential_record"): ("identity", "AuthToken"),
    ("iam_users_credentials", "scim_user"): ("identity_domains", "User"),
    ("iam_users_credentials", "scim_credential"): ("identity_domains", "AuthToken"),
    # Each control/assignment transform reads the list summary as `summary` and
    # the full GET as `full`; the full model is declared as the nested receiver.
    ("operator_access_control", "operator_control_record"): (
        "operator_access_control", "OperatorControlSummary",
    ),
    ("operator_access_control", "assignment_record"): (
        "operator_access_control", "OperatorControlAssignmentSummary",
    ),
    ("operator_access_control", "access_request_record"): (
        "operator_access_control", "AccessRequestSummary",
    ),
    ("operator_access_control", "delegation_control_record"): (
        "delegate_access_control", "DelegationControlSummary",
    ),
    ("operator_access_control", "delegated_request_record"): (
        "delegate_access_control", "DelegatedResourceAccessRequestSummary",
    ),
}

# Fields a record function reads off a NESTED dict it pulled out of the parent,
# rather than off the parent model itself. Keyed the same way, valued by the
# model the nested dict actually is.
NESTED_MODELS: Dict[Tuple[str, str], List[Tuple[str, str, str]]] = {
    ("dr_plan_executions", "step_counts"): [
        ("remaining_steps", "disaster_recovery", "DrPlanExecutionRemainingStepStatusCounts"),
        ("skipped_steps", "disaster_recovery", "DrPlanExecutionSkippedStepStatusCounts"),
        ("successful_steps", "disaster_recovery", "DrPlanExecutionSuccessfulStepStatusCounts"),
        ("warning_steps", "disaster_recovery", "DrPlanExecutionWarningStepStatusCounts"),
        ("failed_steps", "disaster_recovery", "DrPlanExecutionFailedStepStatusCounts"),
    ],
    ("dr_plan_executions", "ignored_failures"): [
        ("skipped_steps", "disaster_recovery", "DrPlanExecutionSkippedStepStatusCounts"),
        ("warning_steps", "disaster_recovery", "DrPlanExecutionWarningStepStatusCounts"),
    ],
    ("dr_plan_executions", "execution_record"): [
        ("step_status_counts", "disaster_recovery", "DrPlanExecutionStepStatusCounts"),
        ("log_location", "disaster_recovery", "ObjectStorageLogLocation"),
    ],
    ("bastion_sessions", "session_record"): [
        # Polymorphic: the managed-SSH subtype is the widest, and the
        # port-forwarding one is a subset apart from target_resource_fqdn.
        (
            "target_resource_details",
            "bastion",
            "ManagedSshSessionTargetResourceDetails",
        ),
    ],
    ("certificates", "certificate_record"): [
        ("subject", "certificates_management", "CertificateSubject"),
    ],
    ("certificates", "authority_record"): [
        ("subject", "certificates_management", "CertificateSubject"),
    ],
    ("certificates", "version_facts"): [
        ("validity", "certificates_management", "Validity"),
        ("revocation_status", "certificates_management", "RevocationStatus"),
    ],
    ("cloud_guard_posture", "detector_rule_facts"): [
        ("details", "cloud_guard", "TargetDetectorDetails"),
    ],
    ("cloud_guard_posture", "responder_rule_facts"): [
        ("details", "cloud_guard", "ResponderRuleDetails"),
    ],
    ("cloud_guard_posture", "security_zone_record"): [
        ("recipe", "cloud_guard", "SecurityRecipeSummary"),
    ],
    ("iam_users_credentials", "user_record"): [
        ("capabilities", "identity", "UserCapabilities"),
    ],
    ("iam_users_credentials", "scim_user"): [
        ("meta", "identity_domains", "Meta"),
        ("mfa", "identity_domains", "ExtensionMfaUser"),
        ("state", "identity_domains", "ExtensionUserStateUser"),
        ("capabilities", "identity_domains", "ExtensionCapabilitiesUser"),
    ],
    ("iam_users_credentials", "scim_credential"): [
        ("meta", "identity_domains", "Meta"),
        # Alternate shape: fingerprint is API-key-only, status is on every other type.
        ("_api_key", "identity_domains", "ApiKey"),
    ],
    ("iam_password_policy", "password_policy_record"): [
        ("g", "identity_domains", "PasswordPolicyGroups"),
    ],
    ("iam_password_policy", "legacy_policy_record"): [
        ("password", "identity", "PasswordPolicy"),
    ],
    # Block and boot volumes share one transform; the boot models are declared
    # as alternates, so a field passes only if one of the pair declares it
    # (image_id is boot-only, encryption_in_transit_type boot-attachment-only).
    # SecurityRule (NSG) is the widest rule model; the security-list pair carry
    # one direction each, so they are declared as alternates.
    ("data_service_exposure", "export_record"): [
        ("option", "file_storage", "ClientOptions"),
    ],
    ("data_service_exposure", "integration_instance_record"): [
        ("endpoint", "integration", "PublicEndpointDetails"),
    ],
    ("audit_logging_events", "action_record"): [
        ("_stream", "events", "StreamingServiceAction"),
        ("_faas", "events", "FaaSAction"),
    ],
    ("audit_logging_events", "rule_record"): [
        ("actions", "events", "ActionDetailsList"),
    ],
    ("audit_logging_events", "log_record"): [
        ("source", "logging", "OciService"),
        ("configuration", "logging", "Configuration"),
    ],
    ("audit_logging_events", "topic_record"): [
        ("s", "ons", "SubscriptionSummary"),
    ],
    ("compute_instances", "instance_record"): [
        ("options", "core", "InstanceOptions"),
        ("launch", "core", "LaunchOptions"),
        ("agent", "core", "InstanceAgentConfig"),
        # The widest platform config; every shielded field lives on it.
        ("platform", "core", "AmdMilanBmPlatformConfig"),
        ("p", "core", "InstanceAgentPluginConfigDetails"),
    ],
    ("network_exposure", "_port_range"): [
        ("options", "core", "TcpOptions"),
    ],
    ("network_exposure", "nsg_record"): [
        ("r", "core", "SecurityRule"),
    ],
    ("network_exposure", "route_table_routes_to_internet"): [
        ("rule", "core", "RouteRule"),
    ],
    ("network_exposure", "rule_record"): [
        ("_ingress", "core", "IngressSecurityRule"),
        ("_egress", "core", "EgressSecurityRule"),
        ("icmp_options", "core", "IcmpOptions"),
    ],
    ("network_exposure", "flow_log_record"): [
        ("source", "logging", "OciService"),
        ("configuration", "logging", "Configuration"),
    ],
    ("object_storage_buckets", "retention_rule_record"): [
        ("duration", "object_storage", "Duration"),
    ],
    ("object_storage_buckets", "log_record"): [
        ("source", "logging", "OciService"),
        ("configuration", "logging", "Configuration"),
    ],
    ("block_volume_encryption", "volume_record"): [
        ("_boot", "core", "BootVolume"),
    ],
    ("block_volume_encryption", "attachment_record"): [
        ("_boot", "core", "BootVolumeAttachment"),
    ],
    ("block_volume_encryption", "backup_record"): [
        ("_boot", "core", "BootVolumeBackup"),
    ],
    ("operator_access_control", "operator_control_record"): [
        ("full", "operator_access_control", "OperatorControl"),
    ],
    ("operator_access_control", "assignment_record"): [
        ("full", "operator_access_control", "OperatorControlAssignment"),
    ],
    ("operator_access_control", "delegation_control_record"): [
        ("full", "delegate_access_control", "DelegationControl"),
    ],
    ("vault_keys", "key_record"): [
        ("rotation", "key_management", "AutoKeyRotationDetails"),
        ("key_shape", "key_management", "KeyShape"),
        ("current_version", "key_management", "KeyVersion"),
        ("vault", "key_management", "Vault"),
    ],
    # Not nested: alternate shapes of the same `credential` dict. The names are
    # never a receiver, so these only widen which fields are accepted.
    ("iam_users_credentials", "credential_record"): [
        ("_api_key", "identity", "ApiKey"),
        ("_oauth2", "identity", "OAuth2ClientCredentialSummary"),
        ("_db", "identity", "DbCredentialSummary"),
        ("_smtp", "identity", "SmtpCredentialSummary"),
        ("_secret_key", "identity", "CustomerSecretKeySummary"),
    ],
}

# Keys a record function reads that this fetcher itself put there, not the API.
# Kept explicit so they cannot quietly excuse a genuine typo.
SYNTHETIC_KEYS: Dict[Tuple[str, str], Set[str]] = {
    # _port_range receives a TcpOptions/UdpOptions dict; min/max come from the
    # nested PortRange, which has no receiver of its own to key on.
    ("network_exposure", "_port_range"): {"destination_port_range", "min", "max"},
    ("bastion_sessions", "session_record"): {"session_type"},
    # security_attributes is dict(str, dict(str, object)): {ns: {key: {value, mode}}}.
    # The SDK types the leaf as a bare object, so there is no model to check against.
    ("zpr_policies", "vcn_record"): {"value", "mode"},
}


def model_types(module: str, name: str) -> Dict[str, str]:
    """`swagger_types` for one SDK model: wire field name -> declared type."""
    import oci  # imported here so --help works without the SDK

    models = getattr(oci, module).models
    cls = getattr(models, name)
    return dict(cls().swagger_types)


def _is_nested_model(declared: str) -> bool:
    """True when a declared type is a single nested model, not a scalar or list.

    `list[Vulnerability]` and `dict(str, str)` are containers — reading either
    for emptiness is legitimate. A bare capitalised name is an object that is
    present whether or not it means anything, and is the truthiness trap.
    """
    if declared.startswith(("list[", "dict(")):
        return False
    return declared[:1].isupper()


def _is_empty_literal(node: ast.AST) -> bool:
    """True for `{}`, `[]`, `()`, `""`, `0` and `None` — a defaulting fallback."""
    if isinstance(node, ast.Dict) and not node.keys:
        return True
    if isinstance(node, (ast.List, ast.Tuple)) and not node.elts:
        return True
    return isinstance(node, ast.Constant) and not node.value


def _string_arg(node: ast.Call) -> str | None:
    """The literal string argument of a `.get("x")` call, if it is one."""
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "get":
        return None
    if not node.args or not isinstance(node.args[0], ast.Constant):
        return None
    value = node.args[0].value
    return value if isinstance(value, str) else None


def _truthy_contexts(tree: ast.AST) -> Set[int]:
    """`id()` of every Call node evaluated for truth rather than for its value.

    `x.get("y") or {}` is excluded: the `or` is defaulting, and the value is
    used afterwards. `bool(x.get("y"))`, `if x.get("y")` and `not x.get("y")`
    are all truth tests.
    """
    truthy: Set[int] = set()

    class Walker(ast.NodeVisitor):
        def _mark(self, node: ast.AST) -> None:
            if isinstance(node, ast.Call):
                truthy.add(id(node))

        def visit_If(self, node: ast.If) -> None:
            self._mark(node.test)
            self.generic_visit(node)

        def visit_IfExp(self, node: ast.IfExp) -> None:
            self._mark(node.test)
            self.generic_visit(node)

        def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
            if isinstance(node.op, ast.Not):
                self._mark(node.operand)
            self.generic_visit(node)

        def visit_BoolOp(self, node: ast.BoolOp) -> None:
            # `x.get("y") or {}` is DEFAULTING, not a truth test: the result is
            # used afterwards, and the `or` only supplies a fallback when the
            # key is absent. Recognised by the last operand being an empty
            # literal. Without this the check flags every nested-object read in
            # the codebase, which is the opposite of useful.
            if isinstance(node.op, ast.Or) and _is_empty_literal(node.values[-1]):
                self.generic_visit(node)
                return
            for operand in node.values[:-1]:
                self._mark(operand)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Name) and node.func.id == "bool":
                for arg in node.args:
                    self._mark(arg)
            self.generic_visit(node)

    Walker().visit(tree)
    return truthy


def _reads(func: ast.FunctionDef, truthy: Set[int]) -> Iterator[Tuple[str, str, bool]]:
    """Every `.get("field")` in `func`, as (receiver, field, is_truth_test)."""
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        field = _string_arg(node)
        if field is None:
            continue
        receiver = ""
        target = getattr(node.func, "value", None)
        if isinstance(target, ast.Name):
            receiver = target.id
        elif isinstance(target, ast.Attribute):
            receiver = target.attr
        elif isinstance(target, ast.BoolOp) and target.values:
            # The `(parent.get("child") or {}).get("field")` shape: the receiver
            # is whatever key the inner get pulled out, so that names the nested
            # model to check `field` against.
            inner = target.values[0]
            if isinstance(inner, ast.Call):
                receiver = _string_arg(inner) or ""
        yield receiver, field, id(node) in truthy


def check() -> List[str]:
    """Every finding, as a human-readable line. Empty means clean."""
    findings: List[str] = []

    for (fetcher, func_name), (module, model) in sorted(FUNCTION_MODELS.items()):
        source_path = FETCHER_ROOT / fetcher / "fetcher.py"
        if not source_path.exists():
            findings.append(f"{fetcher}: no fetcher.py")
            continue

        tree = ast.parse(source_path.read_text())
        truthy = _truthy_contexts(tree)
        func = next(
            (n for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef) and n.name == func_name),
            None,
        )
        if func is None:
            findings.append(f"{fetcher}.{func_name}: function not found")
            continue

        parent_types = model_types(module, model)
        nested = {
            var: model_types(mod, cls)
            for var, mod, cls in NESTED_MODELS.get((fetcher, func_name), [])
        }
        # A nested dict is bound to a local whose name matches the key it came
        # from, so the receiver name selects which model to check against.
        nested_by_receiver = {var: types for var, types in nested.items()}
        synthetic = SYNTHETIC_KEYS.get((fetcher, func_name), set())

        for receiver, field, is_truth_test in _reads(func, truthy):
            types = nested_by_receiver.get(receiver, parent_types)
            # A nested read may also be spelled against the parent in the same
            # function; accept the field if ANY model in play declares it.
            candidates = [types] if receiver in nested_by_receiver else [parent_types, *nested.values()]

            declared = next(
                (c[field] for c in candidates if field in c),
                None,
            )
            if declared is None:
                if field in synthetic:
                    continue
                findings.append(
                    f"{fetcher}.{func_name}: .get({field!r}) is not a field on "
                    f"{model} or any declared nested model"
                )
                continue

            if is_truth_test and _is_nested_model(declared):
                findings.append(
                    f"{fetcher}.{func_name}: .get({field!r}) is declared "
                    f"{declared}, a nested object that is present whether or not "
                    f"it is meaningful — testing it for truth is always True"
                )

    return findings


def main() -> int:
    findings = check()
    if findings:
        print("OCI schema check FAILED:\n")
        for finding in findings:
            print("  -", finding)
        return 1
    checked = len(FUNCTION_MODELS)
    print(f"OCI schema check passed — {checked} record functions verified "
          f"against the generated SDK models")
    return 0


if __name__ == "__main__":
    sys.exit(main())
