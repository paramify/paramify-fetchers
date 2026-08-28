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
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

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

# 2/3. For each parameter group, fetch TLS-related parameters
pg_results=()
for pg in $param_groups; do
    pg_params=$(aws rds describe-db-parameters \
        --db-parameter-group-name "$pg" \
        \
        --query 'Parameters[?ParameterName==`ssl_min_protocol_version` || ParameterName==`ssl_max_protocol_version` || ParameterName==`rds.force_ssl`].{name:ParameterName,value:ParameterValue,source:Source,apply_method:ApplyMethod,allowed_values:AllowedValues}' \
        --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ]; then
        echo "aws rds describe-db-parameters failed for $pg (exit=$ec)" >> "$_FAILURE_LOG"
        pg_params='[]'
    fi

    force_ssl=$(echo "$pg_params" | jq -r '.[] | select(.name=="rds.force_ssl") | .value // "unknown"')
    ssl_min=$(echo "$pg_params" | jq -r '.[] | select(.name=="ssl_min_protocol_version") | .value // "unknown"')
    ssl_max=$(echo "$pg_params" | jq -r '.[] | select(.name=="ssl_max_protocol_version") | .value // ""')
    force_ssl_source=$(echo "$pg_params" | jq -r '.[] | select(.name=="rds.force_ssl") | .source // "unknown"')
    ssl_min_source=$(echo "$pg_params" | jq -r '.[] | select(.name=="ssl_min_protocol_version") | .source // "unknown"')

    pg_results+=("$(jq -n \
        --arg pg "$pg" \
        --arg force_ssl "$force_ssl" \
        --arg force_ssl_source "$force_ssl_source" \
        --arg ssl_min "$ssl_min" \
        --arg ssl_min_source "$ssl_min_source" \
        --arg ssl_max "$ssl_max" \
        --argjson raw_params "$pg_params" \
        '{
            parameter_group_name: $pg,
            force_ssl: ($force_ssl == "1"),
            force_ssl_source: $force_ssl_source,
            ssl_min_protocol_version: $ssl_min,
            ssl_min_source: $ssl_min_source,
            ssl_max_protocol_version: (if $ssl_max == "" then "unrestricted" else $ssl_max end),
            raw_parameters: $raw_params
        }')")
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

# 4. Build instance results enriched with parameter group TLS data
instance_results=()
while IFS= read -r instance; do
    instance_id=$(echo "$instance" | jq -r '.id')
    instance_pg=$(echo "$instance" | jq -r '.param_group')
    instance_status=$(echo "$instance" | jq -r '.status')
    instance_param_status=$(echo "$instance" | jq -r '.param_status')
    instance_engine=$(echo "$instance" | jq -r '.engine')
    instance_engine_version=$(echo "$instance" | jq -r '.engine_version')
    instance_ca=$(echo "$instance" | jq -r '.ca_cert')

    # Find matching param group data
    pg_data="{}"
    for pg_entry in "${pg_results[@]}"; do
        if [ "$(echo "$pg_entry" | jq -r '.parameter_group_name')" = "$instance_pg" ]; then
            pg_data="$pg_entry"
            break
        fi
    done

    instance_results+=("$(jq -n \
        --arg id "$instance_id" \
        --arg engine "$instance_engine" \
        --arg version "$instance_engine_version" \
        --arg ca "$instance_ca" \
        --arg pg "$instance_pg" \
        --arg pg_sync "$instance_param_status" \
        --arg status "$instance_status" \
        --argjson pg_tls "$pg_data" \
        '{
            instance_id: $id,
            engine: $engine,
            engine_version: $version,
            ca_certificate: $ca,
            parameter_group: $pg,
            parameter_group_sync_status: $pg_sync,
            instance_status: $status,
            tls_configuration: $pg_tls
        }')")
done < <(echo "$instances_raw" | jq -c '.[]')

# Summary counts
total_instances=$(echo "$instances_raw" | jq 'length')
if [ ${#instance_results[@]} -gt 0 ]; then
    force_ssl_enabled=$(printf '%s\n' "${instance_results[@]}" | jq -s '[.[] | select(.tls_configuration.force_ssl == true)] | length')
    tls12_min=$(printf '%s\n' "${instance_results[@]}" | jq -s '[.[] | select(.tls_configuration.ssl_min_protocol_version == "TLSv1.2")] | length')
    params_in_sync=$(printf '%s\n' "${instance_results[@]}" | jq -s '[.[] | select(.parameter_group_sync_status == "in-sync")] | length')
    instances_arr="[$(IFS=,; echo "${instance_results[*]}")]"
else
    force_ssl_enabled=0
    tls12_min=0
    params_in_sync=0
    instances_arr="[]"
fi

if [ ${#pg_results[@]} -gt 0 ]; then
    pg_arr="[$(IFS=,; echo "${pg_results[*]}")]"
else
    pg_arr="[]"
fi

# Combine all results (preserve metadata block, write results object)
results_json=$(jq -n \
    --arg profile "$PROFILE" \
    --arg region "$REGION" \
    --arg datetime "$DATETIME" \
    --arg account_id "$ACCOUNT_ID" \
    --arg arn "$ARN" \
    --argjson instances "$instances_arr" \
    --argjson parameter_groups "$pg_arr" \
    --argjson certificates "$certs_raw" \
    --argjson total "$total_instances" \
    --argjson force_ssl_count "$force_ssl_enabled" \
    --argjson tls12_count "$tls12_min" \
    --argjson in_sync_count "$params_in_sync" \
    '{
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
            ca_certificates: $certificates,
            summary: {
                total_instances: $total,
                force_ssl_enabled: $force_ssl_count,
                tls_1_2_minimum_enforced: $tls12_count,
                parameter_groups_in_sync: $in_sync_count
            }
        }
    }')

echo "$results_json" > "$OUTPUT_JSON"

failure_count=$(wc -l < "$_FAILURE_LOG" 2>/dev/null | tr -d ' ')
failure_count=${failure_count:-0}
if [ "$failure_count" -gt 0 ]; then
    # Report WHICH calls failed before the log is discarded on exit; the count
    # alone cannot be acted on. See aws_report_failures in ../_shared/aws.sh.
    aws_report_failures "$_FAILURE_LOG" "$failure_count"
    log_error "Encountered $failure_count AWS API failures during collection"
    exit 1
fi

log_info "Evidence saved to $OUTPUT_JSON"
