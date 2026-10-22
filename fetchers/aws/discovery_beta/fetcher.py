#!/usr/bin/env python3
"""
AWS — Discovery

Lists what this identity can see in one AWS account. Writes a discovery
document, not evidence; nothing here is uploaded.

Two layers:

1. A curated list of resource types, read directly, in every region enabled for
   the account. Its scope is set by a rule, not by taste: every AWS service an
   AWS fetcher in this repo reads has at least one type here, because discovery
   exists to say which fetchers apply (tests/test_discovery.py enforces it).
   Each (type, region) pair has its own status, so "denied in eu-west-1" never
   reads as "denied" for the account. Global types are listed once.
2. Everything else, from AWS Resource Explorer: a count per resource type (of
   the 600-odd it supports) in each region that has an index. A region without
   one is "not enabled", which is what it is.

Driven through the aws CLI, like every other AWS fetcher: same credential chain,
same profile and region handling from a manifest target, and nothing new to
install. Calls run in parallel across regions.

Output: $EVIDENCE_DIR/aws_discovery_beta_<profile|ambient>.json
"""

import json
import logging
import os
import re
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from discovery import (  # noqa: E402
    CallFailed,
    Resource,
    by,
    enumerate_resource,
    setup_logging,
    write,
)
from fetcher_status import report_failure  # noqa: E402

FETCHER = "aws_discovery_beta"
WORKERS = 24
CALL_TIMEOUT = 180

logger = logging.getLogger(FETCHER)

# The same patterns fetchers/aws/_shared/aws.sh uses (aws_service_unavailable and
# aws_classify_code), so discovery and the evidence fetchers agree on what a
# given AWS error means. Keep them in step.
_NOT_ENABLED = re.compile(
    r"SubscriptionRequiredException|OptInRequired|needs a subscription for the service|"
    r"InvalidAccessException|AWSOrganizationsNotInUseException|not a member of an organization|"
    r"is not enabled|ResourceNotFoundException",
    re.I,
)
_DENIED = re.compile(
    r"AccessDenied|UnauthorizedOperation|not authorized to perform|AuthorizationError|explicit deny|\(403\)",
    re.I,
)
_BAD_CREDENTIALS = re.compile(
    r"ExpiredToken|InvalidClientTokenId|UnrecognizedClientException|SignatureDoesNotMatch|"
    r"Unable to locate credentials|The security token included in the request is (expired|invalid)|"
    r"NoCredentialProviders|sso session .* is expired|Your session has expired",
    re.I,
)

_NAME_TAG = "Tags[?Key=='Name'] | [0].Value"

_CLI_ERROR = re.compile(r"An error occurred \((\w+)\)(?: when calling the \w+ operation)?:?\s*(.*)")


def _short_reason(stderr: str) -> str:
    """The last stderr line, as "<ErrorCode>: <message>" when the CLI wrapped it
    in "aws: [ERROR]: An error occurred (X) when calling the Y operation: ...".
    """
    lines = [ln.strip() for ln in stderr.splitlines() if ln.strip()]
    if not lines:
        return ""
    line = re.sub(r"^aws: \[ERROR\]:\s*", "", lines[-1])
    m = _CLI_ERROR.search(line)
    if m:
        line = f"{m.group(1)}: {m.group(2)}".rstrip(": ")
    return line[:400]


def _aws(cmd: str, extra: Tuple[str, ...], query: str, region: str) -> Any:
    """Run one read-only aws CLI call and return its JSON. The CLI pages for us."""
    argv = ["aws", *cmd.split(), *extra, "--region", region, "--output", "json", "--query", query]
    env = {**os.environ, "AWS_PAGER": ""}
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=CALL_TIMEOUT, env=env)
    except subprocess.TimeoutExpired as e:
        raise CallFailed("error", f"timed out after {CALL_TIMEOUT}s") from e
    except OSError as e:
        raise CallFailed("error", f"could not run the aws CLI: {e}") from e
    if proc.returncode != 0:
        reason = _short_reason(proc.stderr) or f"exit {proc.returncode}"
        if _NOT_ENABLED.search(proc.stderr):
            raise CallFailed("not_enabled", reason)
        if _DENIED.search(proc.stderr):
            raise CallFailed("denied", reason)
        raise CallFailed("error", reason)
    out = proc.stdout.strip()
    return json.loads(out) if out else None


def aws_resource(type_: str, label: str, cmd: str, query: str, *extra: str,
                 region: Optional[str] = None, off_when: Optional[Callable[[Any], Optional[str]]] = None,
                 **kw: Any) -> Resource:
    """A Resource whose call is `aws <cmd> <extra> --query <query>`.

    The JMESPath query flattens each record to {id, name, ...}, so the engine's
    defaults apply and summaries can group on plain fields. `region` pins a
    service whose API answers in one region only (us-east-1 for Shield). For a
    service that answers "disabled" instead of erroring, `off_when` reads the
    response and returns why it is off, which makes the entry not_enabled.
    """
    return Resource(
        type_, cmd, params={"extra": extra, "query": query, "region": region, "off_when": off_when},
        source=" ".join(["aws", cmd, *extra]), label=label, **kw,
    )


def _inspector_off(data: Any) -> Optional[str]:
    states = {row.get("status") for row in data or [] if isinstance(row, dict)}
    return None if "ENABLED" in states else "Inspector is not enabled for this account (status: " + (
        ", ".join(sorted(s for s in states if s)) or "unknown") + ")"


def _shield_off(data: Any) -> Optional[str]:
    rows = data or []
    state = rows[0].get("name") if rows and isinstance(rows[0], dict) else None
    return None if state == "ACTIVE" else f"no Shield Advanced subscription (state: {state or 'unknown'})"


# Engines that rds describe-db-* also returns but that have their own types.
_NOT_RDS = "Engine != 'docdb' && Engine != 'neptune'"

# --------------------------------------------------------------------------- #
# Layer 1, regional: listed once per enabled region.
# --------------------------------------------------------------------------- #
REGIONAL = [
    # Compute and containers
    aws_resource("ec2_instance", "EC2 instance", "ec2 describe-instances",
                 f"Reservations[].Instances[].{{id: InstanceId, name: {_NAME_TAG}, type: InstanceType, "
                 f"state: State.Name, vpc: VpcId}}",
                 fields=["type", "state", "vpc"], summary=by("state", "type")),
    aws_resource("auto_scaling_group", "Auto Scaling group", "autoscaling describe-auto-scaling-groups",
                 "AutoScalingGroups[].{id: AutoScalingGroupName, name: AutoScalingGroupName, "
                 "min: MinSize, max: MaxSize, desired: DesiredCapacity}",
                 fields=["min", "max", "desired"]),
    aws_resource("ssm_managed_instance", "SSM managed instance", "ssm describe-instance-information",
                 "InstanceInformationList[].{id: InstanceId, name: ComputerName, platform: PlatformType, "
                 "ping: PingStatus}",
                 fields=["platform", "ping"], summary=by("ping")),
    aws_resource("lambda_function", "Lambda function", "lambda list-functions",
                 "Functions[].{id: FunctionName, name: FunctionName, runtime: Runtime}",
                 fields=["runtime"], summary=by("runtime")),
    aws_resource("eks_cluster", "EKS cluster", "eks list-clusters", "clusters"),
    aws_resource("ecs_cluster", "ECS cluster", "ecs list-clusters", "clusterArns"),
    aws_resource("ecr_repository", "ECR repository", "ecr describe-repositories",
                 "repositories[].{id: repositoryName, name: repositoryName, "
                 "scan_on_push: imageScanningConfiguration.scanOnPush}",
                 fields=["scan_on_push"]),
    aws_resource("emr_cluster", "EMR cluster", "emr list-clusters",
                 "Clusters[].{id: Id, name: Name, state: Status.State}", "--active",
                 fields=["state"]),
    aws_resource("sagemaker_notebook", "SageMaker notebook instance", "sagemaker list-notebook-instances",
                 "NotebookInstances[].{id: NotebookInstanceName, name: NotebookInstanceName, "
                 "status: NotebookInstanceStatus}",
                 fields=["status"]),
    aws_resource("sagemaker_endpoint", "SageMaker endpoint", "sagemaker list-endpoints",
                 "Endpoints[].{id: EndpointName, name: EndpointName, status: EndpointStatus}",
                 fields=["status"]),

    # Networking
    aws_resource("vpc", "VPC", "ec2 describe-vpcs",
                 f"Vpcs[].{{id: VpcId, name: {_NAME_TAG}, cidr: CidrBlock, default: IsDefault}}",
                 fields=["cidr", "default"], summary=by("default")),
    aws_resource("subnet", "Subnet", "ec2 describe-subnets",
                 f"Subnets[].{{id: SubnetId, name: {_NAME_TAG}, vpc: VpcId, zone: AvailabilityZone, "
                 f"cidr: CidrBlock, public_ip_on_launch: MapPublicIpOnLaunch}}",
                 fields=["vpc", "zone", "cidr", "public_ip_on_launch"]),
    aws_resource("security_group", "Security group", "ec2 describe-security-groups",
                 "SecurityGroups[].{id: GroupId, name: GroupName, vpc: VpcId}",
                 fields=["vpc"]),
    aws_resource("vpc_flow_log", "VPC flow log", "ec2 describe-flow-logs",
                 "FlowLogs[].{id: FlowLogId, name: ResourceId, traffic: TrafficType, "
                 "destination: LogDestinationType, status: FlowLogStatus}",
                 fields=["traffic", "destination", "status"]),
    aws_resource("load_balancer", "Load balancer", "elbv2 describe-load-balancers",
                 "LoadBalancers[].{id: LoadBalancerName, name: LoadBalancerName, type: Type, scheme: Scheme}",
                 fields=["type", "scheme"], summary=by("type", "scheme")),
    aws_resource("network_firewall", "Network Firewall", "network-firewall list-firewalls",
                 "Firewalls[].{id: FirewallName, name: FirewallName}"),
    aws_resource("api_gateway_rest_api", "API Gateway REST API", "apigateway get-rest-apis",
                 "items[].{id: id, name: name}"),
    aws_resource("api_gateway_http_api", "API Gateway HTTP/WebSocket API", "apigatewayv2 get-apis",
                 "Items[].{id: ApiId, name: Name, protocol: ProtocolType}",
                 fields=["protocol"]),
    aws_resource("acm_certificate", "ACM certificate", "acm list-certificates",
                 "CertificateSummaryList[].{id: CertificateArn, name: DomainName, status: Status, in_use: InUse}",
                 fields=["status", "in_use"], summary=by("status")),
    aws_resource("waf_web_acl", "WAF web ACL (regional)", "wafv2 list-web-acls",
                 "WebACLs[].{id: Id, name: Name}", "--scope", "REGIONAL"),
    aws_resource("transfer_server", "Transfer Family server", "transfer list-servers",
                 "Servers[].{id: ServerId, name: ServerId, endpoint: EndpointType, state: State}",
                 fields=["endpoint", "state"]),

    # Storage
    aws_resource("ebs_volume", "EBS volume", "ec2 describe-volumes",
                 f"Volumes[].{{id: VolumeId, name: {_NAME_TAG}, size_gib: Size, encrypted: Encrypted, "
                 f"state: State}}",
                 fields=["size_gib", "encrypted", "state"], summary=by("encrypted")),
    aws_resource("ebs_snapshot", "EBS snapshot", "ec2 describe-snapshots",
                 f"Snapshots[].{{id: SnapshotId, name: {_NAME_TAG}, size_gib: VolumeSize, "
                 f"encrypted: Encrypted}}",
                 "--owner-ids", "self",
                 fields=["size_gib", "encrypted"], summary=by("encrypted")),
    aws_resource("dlm_policy", "DLM lifecycle policy", "dlm get-lifecycle-policies",
                 "Policies[].{id: PolicyId, name: Description, state: State}",
                 fields=["state"]),
    aws_resource("efs_file_system", "EFS file system", "efs describe-file-systems",
                 "FileSystems[].{id: FileSystemId, name: Name, encrypted: Encrypted}",
                 fields=["encrypted"]),
    aws_resource("fsx_file_system", "FSx file system", "fsx describe-file-systems",
                 f"FileSystems[].{{id: FileSystemId, name: {_NAME_TAG}, type: FileSystemType}}",
                 fields=["type"]),
    aws_resource("glacier_vault", "Glacier vault", "glacier list-vaults",
                 "VaultList[].{id: VaultName, name: VaultName, archives: NumberOfArchives}",
                 "--account-id", "-", fields=["archives"]),
    aws_resource("backup_vault", "Backup vault", "backup list-backup-vaults",
                 "BackupVaultList[].{id: BackupVaultName, name: BackupVaultName, "
                 "recovery_points: NumberOfRecoveryPoints}",
                 fields=["recovery_points"]),

    # Databases and analytics
    aws_resource("rds_instance", "RDS instance", "rds describe-db-instances",
                 f"DBInstances[?{_NOT_RDS}].{{id: DBInstanceIdentifier, name: DBInstanceIdentifier, "
                 f"engine: Engine, encrypted: StorageEncrypted, multi_az: MultiAZ}}",
                 fields=["engine", "encrypted", "multi_az"], summary=by("engine")),
    aws_resource("rds_cluster", "RDS cluster", "rds describe-db-clusters",
                 f"DBClusters[?{_NOT_RDS}].{{id: DBClusterIdentifier, name: DBClusterIdentifier, "
                 f"engine: Engine, encrypted: StorageEncrypted}}",
                 fields=["engine", "encrypted"]),
    aws_resource("documentdb_cluster", "DocumentDB cluster", "docdb describe-db-clusters",
                 "DBClusters[?Engine == 'docdb'].{id: DBClusterIdentifier, name: DBClusterIdentifier, "
                 "encrypted: StorageEncrypted}",
                 fields=["encrypted"]),
    aws_resource("neptune_cluster", "Neptune cluster", "neptune describe-db-clusters",
                 "DBClusters[?Engine == 'neptune'].{id: DBClusterIdentifier, name: DBClusterIdentifier, "
                 "encrypted: StorageEncrypted}",
                 fields=["encrypted"]),
    aws_resource("dynamodb_table", "DynamoDB table", "dynamodb list-tables", "TableNames"),
    aws_resource("elasticache_cluster", "ElastiCache cluster", "elasticache describe-cache-clusters",
                 "CacheClusters[].{id: CacheClusterId, name: CacheClusterId, engine: Engine}",
                 fields=["engine"]),
    aws_resource("memorydb_cluster", "MemoryDB cluster", "memorydb describe-clusters",
                 "Clusters[].{id: Name, name: Name, tls: TLSEnabled}",
                 fields=["tls"]),
    aws_resource("redshift_cluster", "Redshift cluster", "redshift describe-clusters",
                 "Clusters[].{id: ClusterIdentifier, name: ClusterIdentifier, encrypted: Encrypted}",
                 fields=["encrypted"]),
    aws_resource("opensearch_domain", "OpenSearch domain", "opensearch list-domain-names",
                 "DomainNames[].{id: DomainName, name: DomainName, engine: EngineType}",
                 fields=["engine"]),
    aws_resource("dms_replication_instance", "DMS replication instance", "dms describe-replication-instances",
                 "ReplicationInstances[].{id: ReplicationInstanceIdentifier, name: ReplicationInstanceIdentifier, "
                 "public: PubliclyAccessible}",
                 fields=["public"]),
    aws_resource("athena_workgroup", "Athena workgroup", "athena list-work-groups",
                 "WorkGroups[].{id: Name, name: Name, state: State}",
                 fields=["state"]),
    aws_resource("glue_database", "Glue database", "glue get-databases",
                 "DatabaseList[].{id: Name, name: Name}"),
    aws_resource("glue_job", "Glue job", "glue list-jobs", "JobNames"),

    # Messaging and streaming
    aws_resource("sqs_queue", "SQS queue", "sqs list-queues", "QueueUrls"),
    aws_resource("sns_topic", "SNS topic", "sns list-topics", "Topics[].TopicArn"),
    aws_resource("kinesis_stream", "Kinesis stream", "kinesis list-streams", "StreamNames"),
    aws_resource("firehose_stream", "Firehose stream", "firehose list-delivery-streams",
                 "DeliveryStreamNames", "--limit", "10000"),
    aws_resource("msk_cluster", "MSK cluster", "kafka list-clusters-v2",
                 "ClusterInfoList[].{id: ClusterName, name: ClusterName, type: ClusterType}",
                 fields=["type"]),
    aws_resource("eventbridge_rule", "EventBridge rule", "events list-rules",
                 "Rules[].{id: Name, name: Name, state: State}",
                 fields=["state"]),

    # Developer tools
    aws_resource("codebuild_project", "CodeBuild project", "codebuild list-projects", "projects"),
    aws_resource("codepipeline_pipeline", "CodePipeline pipeline", "codepipeline list-pipelines",
                 "pipelines[].{id: name, name: name}"),
    aws_resource("codeartifact_domain", "CodeArtifact domain", "codeartifact list-domains",
                 "domains[].{id: name, name: name, status: status}",
                 fields=["status"]),
    aws_resource("cloudformation_stack", "CloudFormation stack", "cloudformation describe-stacks",
                 "Stacks[].{id: StackName, name: StackName, status: StackStatus}",
                 fields=["status"]),

    # Security, identity and logging
    aws_resource("kms_key", "KMS key", "kms list-keys", "Keys[].KeyId"),
    aws_resource("secret", "Secrets Manager secret", "secretsmanager list-secrets",
                 "SecretList[].{id: Name, name: Name, rotation: RotationEnabled}",
                 fields=["rotation"]),
    aws_resource("cloudtrail_trail", "CloudTrail trail", "cloudtrail describe-trails",
                 "trailList[].{id: Name, name: Name, multi_region: IsMultiRegionTrail, home_region: HomeRegion}",
                 "--no-include-shadow-trails",
                 fields=["multi_region", "home_region"]),
    aws_resource("cloudwatch_alarm", "CloudWatch alarm", "cloudwatch describe-alarms",
                 "MetricAlarms[].{id: AlarmName, name: AlarmName, state: StateValue}",
                 fields=["state"], summary=by("state")),
    aws_resource("log_group", "CloudWatch log group", "logs describe-log-groups",
                 "logGroups[].{id: logGroupName, name: logGroupName, retention_days: retentionInDays}",
                 fields=["retention_days"]),
    aws_resource("config_recorder", "Config recorder", "configservice describe-configuration-recorders",
                 "ConfigurationRecorders[].{id: name, name: name}"),
    aws_resource("guardduty_detector", "GuardDuty detector", "guardduty list-detectors", "DetectorIds"),
    aws_resource("securityhub_hub", "Security Hub", "securityhub describe-hub",
                 "[{id: HubArn, name: HubArn, subscribed_at: SubscribedAt}]",
                 fields=["subscribed_at"]),
    aws_resource("inspector", "Inspector", "inspector2 batch-get-account-status",
                 "accounts[].{id: accountId, name: accountId, status: state.status, "
                 "ec2: resourceState.ec2.status, ecr: resourceState.ecr.status, "
                 "lambda: resourceState.lambda.status}",
                 fields=["status", "ec2", "ecr", "lambda"], off_when=_inspector_off),
    aws_resource("macie", "Macie", "macie2 get-macie-session",
                 "[{id: serviceRole, name: status, finding_frequency: findingPublishingFrequency}]",
                 fields=["finding_frequency"]),
    aws_resource("access_analyzer", "IAM Access Analyzer", "accessanalyzer list-analyzers",
                 "analyzers[].{id: name, name: name, type: type, status: status}",
                 fields=["type", "status"]),
    aws_resource("identity_center_instance", "IAM Identity Center instance", "sso-admin list-instances",
                 "Instances[].{id: InstanceArn, name: IdentityStoreId}"),
]

# --------------------------------------------------------------------------- #
# Layer 1, global: listed once. IAM users are people, so they are counted.
# --------------------------------------------------------------------------- #
GLOBAL = [
    aws_resource("iam_user", "IAM user", "iam list-users", "Users[].UserName", count_only=True),
    aws_resource("iam_role", "IAM role", "iam list-roles",
                 "Roles[].{id: RoleName, name: RoleName, "
                 "service_linked: starts_with(Path, '/aws-service-role/')}",
                 fields=["service_linked"], summary=by("service_linked")),
    aws_resource("iam_group", "IAM group", "iam list-groups", "Groups[].{id: GroupName, name: GroupName}"),
    aws_resource("iam_policy", "IAM customer-managed policy", "iam list-policies",
                 "Policies[].{id: PolicyName, name: PolicyName, attachments: AttachmentCount}",
                 "--scope", "Local", fields=["attachments"]),
    aws_resource("s3_bucket", "S3 bucket", "s3api list-buckets",
                 "Buckets[].{id: Name, name: Name, region: BucketRegion, created: CreationDate}",
                 fields=["region", "created"], summary=by("region")),
    aws_resource("route53_hosted_zone", "Route 53 hosted zone", "route53 list-hosted-zones",
                 "HostedZones[].{id: Id, name: Name, private: Config.PrivateZone, "
                 "records: ResourceRecordSetCount}",
                 fields=["private", "records"]),
    aws_resource("cloudfront_distribution", "CloudFront distribution", "cloudfront list-distributions",
                 "DistributionList.Items[].{id: Id, name: DomainName, enabled: Enabled}",
                 fields=["enabled"]),
    aws_resource("waf_web_acl_cloudfront", "WAF web ACL (CloudFront)", "wafv2 list-web-acls",
                 "WebACLs[].{id: Id, name: Name}", "--scope", "CLOUDFRONT", region="us-east-1"),
    aws_resource("global_accelerator", "Global Accelerator", "globalaccelerator list-accelerators",
                 "Accelerators[].{id: AcceleratorArn, name: Name, enabled: Enabled}",
                 region="us-west-2", fields=["enabled"]),
    aws_resource("shield_advanced", "Shield Advanced subscription", "shield get-subscription-state",
                 "[{id: 'shield-advanced', name: SubscriptionState}]",
                 region="us-east-1", off_when=_shield_off),
    aws_resource("organization", "AWS Organization", "organizations describe-organization",
                 "[{id: Organization.Id, name: Organization.Id, feature_set: Organization.FeatureSet}]",
                 fields=["feature_set"]),
]


# Where a CLI service name differs from the name AWS publishes its regional
# availability under (/aws/service/global-infrastructure/services/<name>).
_AVAILABILITY_NAME = {"elbv2": "elb", "s3api": "s3", "opensearch": "es", "kafka": "msk", "sso-admin": "sso"}
_offered_lock = threading.Lock()
_offered: Dict[str, Optional[frozenset]] = {}


def _offered_in(service: str, home: str) -> Optional[frozenset]:
    """The regions AWS says offer `service`, or None if that could not be read."""
    with _offered_lock:
        if service in _offered:
            return _offered[service]
    name = _AVAILABILITY_NAME.get(service, service)
    try:
        regions = _aws("ssm get-parameters-by-path",
                       ("--path", f"/aws/service/global-infrastructure/services/{name}/regions"),
                       "Parameters[].Value", home)
        result = frozenset(regions) if regions else None
    except CallFailed:
        result = None
    with _offered_lock:
        _offered[service] = result
    return result


def pages_in(region: str, home: str):
    def pages(resource: Resource) -> Iterator[List[Any]]:
        params = resource.params
        where = params.get("region") or region
        try:
            data = _aws(resource.path, tuple(params["extra"]), params["query"], where)
        except CallFailed as e:
            # No endpoint in a region is either a network failure or a service
            # AWS does not offer there; the error text is identical. AWS's own
            # published availability tells them apart. Only a confirmed "not
            # offered" becomes not_enabled; anything else stays an error.
            if e.status == "error" and "Could not connect to the endpoint URL" in e.reason:
                service = resource.path.split()[0]
                offered = _offered_in(service, home)
                if offered is not None and where not in offered:
                    raise CallFailed("not_enabled", f"{service} is not offered in {where}") from e
            raise
        # A query over an absent list returns null; that is an empty list, not a failure.
        rows = data if isinstance(data, list) else ([] if data is None else [data])
        off = params.get("off_when")
        if off and (why := off(rows)):
            raise CallFailed("not_enabled", why)
        yield rows

    return pages


# --------------------------------------------------------------------------- #
# Layer 2: everything else, from Resource Explorer.
# --------------------------------------------------------------------------- #
EVERYTHING = Resource(
    "resource_explorer_type", "resource-explorer-2 search",
    id="type", name="type", fields=["service", "resources"],
    source='aws resource-explorer-2 search --query-string ""',
    label="Resource type (Resource Explorer)",
    note=("Everything Resource Explorer has indexed, counted by type. Regions without an index "
          "were not searched, so this is not a complete inventory of those regions; the types "
          "above are read directly in every region."),
    summary=lambda rows: {"resources_by_service": _sum_by(rows, "service", "resources")},
)


def _sum_by(rows: List[dict], key: str, value: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in rows:
        out[str(r.get(key))] = out.get(str(r.get(key)), 0) + int(r.get(value) or 0)
    return out


def _type_counts(rows: List[dict]) -> List[dict]:
    """[{type, region, service}] -> one record per resource type with its count."""
    counts: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        t = r.get("type") or "unknown"
        rec = counts.setdefault(t, {"type": t, "service": r.get("service") or t.split(":")[0], "resources": 0})
        rec["resources"] += 1
    return sorted(counts.values(), key=lambda rec: (-rec["resources"], rec["type"]))


def explorer_entries(home: str, regions: List[str]) -> List[dict]:
    """One entry per region: the resource types Resource Explorer found there.

    With an aggregator index, one search covers every indexed region; otherwise
    each region with a local index is searched on its own. A region with no
    index is not_enabled. Resource Explorer returns at most 1,000 resources per
    search, so a search that hit the cap marks its regions truncated.
    """
    try:
        indexes = _aws("resource-explorer-2 list-indexes", (), "Indexes[].{region: Region, type: Type}", home) or []
    except CallFailed as e:
        # Bound as a default: an except variable is unset once the block ends.
        return [enumerate_resource(EVERYTHING, lambda _r, err=e: _raise(err), {"region": r}) for r in regions]

    indexed = {i["region"] for i in indexes}
    aggregator = next((i["region"] for i in indexes if i["type"] == "AGGREGATOR"), None)
    query = "{complete: Count.Complete, rows: Resources[].{type: ResourceType, region: Region, service: Service}}"

    def search(region: str) -> Dict[str, Any]:
        return _aws("resource-explorer-2 search", ("--query-string", ""), query, region) or {}

    by_region: Dict[str, Tuple[List[dict], bool]] = {}
    failed: Dict[str, CallFailed] = {}
    if aggregator:
        try:
            result = search(aggregator)
            for r in indexed:
                by_region[r] = ([row for row in result.get("rows") or [] if row.get("region") == r],
                                result.get("complete") is not False)
        except CallFailed as e:
            failed = {r: e for r in indexed}
    else:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for r, outcome in zip(sorted(indexed), pool.map(_try(search), sorted(indexed))):
                if isinstance(outcome, CallFailed):
                    failed[r] = outcome
                else:
                    by_region[r] = (outcome.get("rows") or [], outcome.get("complete") is not False)

    entries = []
    for r in sorted(set(regions) | indexed):
        if r in failed:
            entries.append(enumerate_resource(EVERYTHING, lambda _res, e=failed[r]: _raise(e), {"region": r}))
        elif r in by_region:
            rows, complete = by_region[r]
            if complete:
                entry = enumerate_resource(EVERYTHING, lambda _res, rows=rows: iter([_type_counts(rows)]),
                                           {"region": r})
            else:
                entry = enumerate_resource(EVERYTHING, lambda _res, rows=rows: _partial(_type_counts(rows)),
                                           {"region": r})
                entry["reason"] = "Resource Explorer returns at most 1,000 resources per search; counts are a lower bound"
            entries.append(entry)
        else:
            entries.append(enumerate_resource(
                EVERYTHING,
                lambda _res: _raise(CallFailed("not_enabled", "no Resource Explorer index in this region")),
                {"region": r},
            ))
    return entries


def _raise(e: CallFailed) -> Iterator[List[Any]]:
    raise e


def _partial(rows: List[dict]) -> Iterator[List[Any]]:
    yield rows
    raise CallFailed("error", "Resource Explorer returns at most 1,000 resources per search")


def _try(fn: Callable[[str], Any]) -> Callable[[str], Any]:
    def call(arg: str) -> Any:
        try:
            return fn(arg)
        except CallFailed as e:
            return e
    return call


def target_id() -> str:
    """The filename suffix: the profile when one is set, else "ambient".
    Same rule as aws_target_id in fetchers/aws/_shared/aws.sh."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", os.environ.get("AWS_PROFILE") or "ambient")


def main() -> int:
    setup_logging(FETCHER)
    home = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"

    # Identity first: credentials that cannot say who they are fail the run.
    try:
        ident = _aws("sts get-caller-identity", (), "{arn: Arn, account: Account}", home)
    except CallFailed as e:
        code = "auth_failed" if _BAD_CREDENTIALS.search(e.reason) else None
        report_failure(f"cannot establish the AWS identity: {e.reason}", code)
        return 1

    wanted = [r.strip() for r in os.environ.get("AWS_DISCOVERY_REGIONS", "").split(",") if r.strip()]
    if wanted:
        regions = wanted
    else:
        try:
            regions = sorted(_aws("ec2 describe-regions", (), "Regions[].RegionName", home) or [])
        except CallFailed as e:
            report_failure(f"cannot list the account's regions: {e.reason}", None)
            return 1

    logger.info("enumerating account %s as %s in %d regions", ident["account"], ident["arn"], len(regions))

    jobs: List[Tuple[Resource, str, Optional[Dict[str, str]]]] = [
        (res, home, None) for res in GLOBAL
    ] + [
        (res, region, {"region": region}) for res in REGIONAL for region in regions
    ]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        entries = list(pool.map(lambda job: enumerate_resource(job[0], pages_in(job[1], home), job[2]), jobs))
    entries += explorer_entries(home, regions)

    return write(
        platform="aws",
        output_name=f"{FETCHER}_{target_id()}.json",
        entries=entries,
        identity=ident["arn"],
        scope={"account": ident["account"], "regions": len(regions)},
    )


if __name__ == "__main__":
    sys.exit(main())
