#!/bin/bash
# Collects API Gateway REST API endpoint configuration, stage-level security,
# and custom domain name TLS minimum version (securityPolicy). Maps to KSI-SVC-SIN.
# Output: $EVIDENCE_DIR/aws_apigateway_tls_enforcement_<target>.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_apigateway_tls_enforcement_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_apigateway_tls_enforcement.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_apigateway_tls_enforcement_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_apigateway_tls_enforcement %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_apigateway_tls_enforcement %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"rest_apis": [], "custom_domain_names": []}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from prowler apigateway_service) ---

# 1. List REST APIs with endpoint configuration (PRIVATE vs public).
rest_apis_raw=$(aws apigateway get-rest-apis \
    --query 'items[*].{id:id,name:name,endpoint_types:endpointConfiguration.types,disable_execute_api_endpoint:disableExecuteApiEndpoint,minimum_compression_size:minimumCompressionSize}' \
    --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws apigateway get-rest-apis failed (exit=$ec)" >> "$_FAILURE_LOG"
    rest_apis_raw='[]'
fi

# 2. For each REST API, fetch stages and their TLS/security-relevant settings.
while IFS= read -r api; do
    [ -z "$api" ] && continue
    api_id=$(echo "$api" | jq -r '.id')

    stages_raw=$(aws apigateway get-stages \
        --rest-api-id "$api_id" \
        --query 'item[*].{name:stageName,client_certificate_id:clientCertificateId,web_acl_arn:webAclArn,tracing_enabled:tracingEnabled,cache_cluster_enabled:cacheClusterEnabled,method_settings:methodSettings}' \
        --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ]; then
        echo "aws apigateway get-stages failed for $api_id (exit=$ec)" >> "$_FAILURE_LOG"
        stages_raw='[]'
    fi

    # Normalize stage security flags (client cert / WAF / logging / cache encryption).
    stages_json=$(echo "$stages_raw" | jq '[.[] | {
        name: .name,
        client_certificate: (.client_certificate_id != null),
        waf_acl_arn: .web_acl_arn,
        tracing_enabled: (.tracing_enabled == true),
        cache_enabled: (.cache_cluster_enabled == true),
        logging_enabled: ([(.method_settings // {}) | .[] | select((.loggingLevel // "OFF") != "OFF")] | length > 0),
        cache_data_encrypted: ([(.method_settings // {}) | .[] | select(.cacheDataEncrypted == true)] | length > 0)
    }]')

    api_entry=$(echo "$api" | jq --argjson stages "$stages_json" '{
        id: .id,
        name: .name,
        endpoint_types: (.endpoint_types // []),
        public_endpoint: ((.endpoint_types // []) != ["PRIVATE"]),
        disable_execute_api_endpoint: (.disable_execute_api_endpoint // false),
        stages: $stages
    }')

    jq --argjson data "$api_entry" '.results.rest_apis += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
done < <(echo "$rest_apis_raw" | jq -c '.[]')

# 3. Custom domain names: securityPolicy is the TLS minimum version (e.g. TLS_1_2).
domains_raw=$(aws apigateway get-domain-names \
    --query 'items[*].{domain_name:domainName,security_policy:securityPolicy,endpoint_types:endpointConfiguration.types,domain_name_status:domainNameStatus}' \
    --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws apigateway get-domain-names failed (exit=$ec)" >> "$_FAILURE_LOG"
    domains_raw='[]'
fi

jq --argjson domains "$domains_raw" '.results.custom_domain_names = $domains' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
