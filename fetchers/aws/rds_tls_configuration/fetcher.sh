#!/bin/bash
# Collects RDS instance TLS/SSL configuration and available CA certificates.
# Output: $EVIDENCE_DIR/aws_rds_tls_configuration.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

# Identity/region come from the AWS CLI credential chain. A manifest target may
# set AWS_PROFILE/AWS_DEFAULT_REGION (multi-account / multi-region fanout); when
# unset, the CLI uses the ambient identity/region. The helper sets PROFILE/REGION
# (for metadata) and provides aws_target_id (for the output filename).
source "$(dirname "$0")/../_shared/aws.sh"

# Per-target output filename (profile+region) so multi-target runs don't overwrite.
_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_rds_tls_configuration_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_rds_tls_configuration.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_rds_tls_configuration_fail.XXXXXX)"
_INSTANCES_JSON="$(mktemp -t aws_rds_tls_configuration_instances.XXXXXX.json)"
_PG_NAMES="$(mktemp -t aws_rds_tls_configuration_pg_names.XXXXXX)"
_PG_PARAMS="$(mktemp -t aws_rds_tls_configuration_pg_params.XXXXXX.json)"
_CERTS_JSON="$(mktemp -t aws_rds_tls_configuration_certs.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_INSTANCES_JSON" "$_PG_NAMES" "$_PG_PARAMS" "$_CERTS_JSON"' EXIT

log_info() { printf '%s INFO aws_rds_tls_configuration %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_rds_tls_configuration %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
  --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
  --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream) ---

# 1. Get all RDS instances
instances_raw=$(aws rds describe-db-instances \
    \
    --query 'DBInstances[*].{
        id:DBInstanceIdentifier,
        engine:Engine,
        engine_version:EngineVersion,
        ca_cert:CACertificateIdentifier,
        param_group:DBParameterGroups[0].DBParameterGroupName,
        param_status:DBParameterGroups[0].ParameterApplyStatus,
        status:DBInstanceStatus
    }' \
    --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws rds describe-db-instances failed (exit=$ec)" >> "$_FAILURE_LOG"
    instances_raw='[]'
fi

# Get unique parameter groups in use
param_groups=$(echo "$instances_raw" | jq -r '[.[].param_group] | unique[]')

# 2/3. For each parameter group, fetch TLS-related parameters. MySQL uses
# require_secure_transport (including RDS for MySQL 8.4+), while PostgreSQL and
# SQL Server use rds.force_ssl.
#
# The parameters of each group are appended in order and every record is built
# in the one jq pass below. The per-group and per-instance jq extractions this
# replaced cost about 8 processes per group plus 7 per instance and one per
# (instance, group) pair for the lookup, and the final --argjson carried every
# group's raw parameters: past a few dozen instances that overflowed Linux's
# 128 KiB argv limit and the evidence file was written empty.
for pg in $param_groups; do
    pg_params=$(aws rds describe-db-parameters \
        --db-parameter-group-name "$pg" \
        \
        --query 'Parameters[?ParameterName==`ssl_min_protocol_version` || ParameterName==`ssl_max_protocol_version` || ParameterName==`rds.force_ssl` || ParameterName==`require_secure_transport`].{name:ParameterName,value:ParameterValue,source:Source,apply_method:ApplyMethod,allowed_values:AllowedValues}' \
        --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ] || [ -z "$pg_params" ]; then
        [ $ec -ne 0 ] && echo "aws rds describe-db-parameters failed for $pg (exit=$ec)" >> "$_FAILURE_LOG"
        pg_params='[]'
    fi
    printf '%s\n' "$pg" >> "$_PG_NAMES"
    printf '%s\n' "$pg_params" >> "$_PG_PARAMS"
done

# 5. Get CA certificates
certs_raw=$(aws rds describe-certificates \
    \
    --query 'Certificates[*].{id:CertificateIdentifier,type:CertificateType,valid_from:ValidFrom,valid_till:ValidTill}' \
    --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws rds describe-certificates failed (exit=$ec)" >> "$_FAILURE_LOG"
    certs_raw='[]'
fi
printf '%s' "$instances_raw" > "$_INSTANCES_JSON"
printf '%s' "$certs_raw" > "$_CERTS_JSON"

# 4. Build parameter-group and instance results, and the summary.
# Field semantics are those of the `jq -r` + --arg extraction this replaced: a
# scalar renders as text (a null instance field is the string "null"), and a
# parameter absent from the group is "" -- "unknown" only when it is present
# with no value.
jq -n \
    --arg profile "$PROFILE" \
    --arg region "$REGION" \
    --arg datetime "$DATETIME" \
    --arg account_id "$ACCOUNT_ID" \
    --arg arn "$ARN" \
    --slurpfile instances_doc "$_INSTANCES_JSON" \
    --rawfile pg_names "$_PG_NAMES" \
    --slurpfile pg_params "$_PG_PARAMS" \
    --slurpfile certificates_doc "$_CERTS_JSON" \
    '
    def param($params; $name; $field; $default):
        first($params[] | select(.name == $name) | (.[$field] // $default) | tostring) // "";
    def secure_transport_on($v): (($v | ascii_downcase) == "on" or $v == "1" or ($v | ascii_downcase) == "true");
    ($pg_names | split("\n")) as $names
    | [range(0; $pg_params | length) as $i | $pg_params[$i] as $params
        | param($params; "rds.force_ssl"; "value"; "unknown") as $force_ssl
        | param($params; "require_secure_transport"; "value"; "unknown") as $require_secure_transport
        | param($params; "ssl_max_protocol_version"; "value"; "") as $ssl_max
        | {
            parameter_group_name: $names[$i],
            force_ssl: ($force_ssl == "1"),
            force_ssl_source: param($params; "rds.force_ssl"; "source"; "unknown"),
            require_secure_transport: secure_transport_on($require_secure_transport),
            require_secure_transport_source: param($params; "require_secure_transport"; "source"; "unknown"),
            ssl_enforced: (($force_ssl == "1") or secure_transport_on($require_secure_transport)),
            ssl_min_protocol_version: param($params; "ssl_min_protocol_version"; "value"; "unknown"),
            ssl_min_source: param($params; "ssl_min_protocol_version"; "source"; "unknown"),
            ssl_max_protocol_version: (if $ssl_max == "" then "unrestricted" else $ssl_max end),
            raw_parameters: $params
        }] as $parameter_groups
    | ($instances_doc[0] // []) as $raw_instances
    | [$raw_instances[] | (.param_group | tostring) as $pg
        | {
            instance_id: (.id | tostring),
            engine: (.engine | tostring),
            engine_version: (.engine_version | tostring),
            ca_certificate: (.ca_cert | tostring),
            parameter_group: $pg,
            parameter_group_sync_status: (.param_status | tostring),
            instance_status: (.status | tostring),
            tls_configuration: (first($parameter_groups[] | select(.parameter_group_name == $pg)) // {})
        }] as $instances
    | def count(f): [$instances[] | select(f)] | length;
    {
        metadata: {
            profile: $profile,
            region: $region,
            datetime: $datetime,
            account_id: $account_id,
            arn: $arn
        },
        results: {
            instances: $instances,
            parameter_groups: $parameter_groups,
            ca_certificates: $certificates_doc[0],
            summary: {
                total_instances: ($raw_instances | length),
                force_ssl_enabled: count(.tls_configuration.force_ssl == true),
                require_secure_transport_enabled: count(.tls_configuration.require_secure_transport == true),
                ssl_enforced: count(.tls_configuration.ssl_enforced == true),
                tls_1_2_minimum_enforced: count(.tls_configuration.ssl_min_protocol_version == "TLSv1.2"),
                parameter_groups_in_sync: count(.parameter_group_sync_status == "in-sync")
            }
        }
    }' > "$OUTPUT_JSON"

aws_finish
