#!/bin/bash
#
# AWS — CloudFront Distribution Security
#
# Lists CloudFront distributions and, for each, records the viewer protocol
# policy (HTTPS enforcement), minimum TLS version, WAF (web ACL) association,
# and access logging state. Maps to KSI-SVC-SIN.
#
# Output: $EVIDENCE_DIR/aws_cloudfront_distribution_security.json
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

# CloudFront is a GLOBAL service: its API lives in us-east-1 regardless of the
# target region, so we pin --region us-east-1 on every cloudfront call and the
# filename stays profile-scoped (no region suffix). Account attribution lives in
# the evidence metadata via aws sts get-caller-identity.
_TARGET_ID="$(aws_target_id)"
OUTPUT_JSON="$OUTPUT_DIR/aws_cloudfront_distribution_security_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_cloudfront_distribution_security.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_cloudfront_distribution_security_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_cloudfront_distribution_security %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_cloudfront_distribution_security %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": []}' \
  > "$OUTPUT_JSON"

# List distributions (global API, pinned to us-east-1). The list summary already
# carries the WebACLId, ViewerCertificate (incl. MinimumProtocolVersion), and the
# DefaultCacheBehavior ViewerProtocolPolicy; get-distribution-config supplies the
# Logging.Enabled flag.
#
# The summaries come from ONE list call. Each distribution used to re-run the
# whole paginated list-distributions just to pick out its own summary, so the
# list was fetched N+1 times. get-distribution-config has no bulk form and stays
# one call per distribution; its responses are streamed to a file (null for a
# failed call) and joined in the single jq pass below.
_DISTS_JSON="$(mktemp -t aws_cloudfront_distribution_security_dists.XXXXXX.json)"
_CONFIGS_JSON="$(mktemp -t aws_cloudfront_distribution_security_configs.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_DISTS_JSON" "$_CONFIGS_JSON"' EXIT
aws cloudfront list-distributions --region us-east-1 \
    --query 'DistributionList.Items[*]' --output json > "$_DISTS_JSON" 2>/dev/null
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws cloudfront list-distributions failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list CloudFront distributions"
else
    while read -r dist_id; do
        [ -z "$dist_id" ] && continue
        config=$(aws cloudfront get-distribution-config --id "$dist_id" --region us-east-1 --output json 2>/dev/null)
        config_exit=$?
        if [ $config_exit -ne 0 ] || [ -z "$config" ]; then
            echo "aws cloudfront get-distribution-config ($dist_id) failed (exit=$config_exit)" >> "$_FAILURE_LOG"
            config='null'
        fi
        printf '%s\n' "$config" >> "$_CONFIGS_JSON"
    done < <(jq -r '.[]?.Id' "$_DISTS_JSON")

    jq --slurpfile dists "$_DISTS_JSON" --slurpfile configs "$_CONFIGS_JSON" '
        .results += [($dists[0] // []) | to_entries[] | .key as $i | .value
            | {
               "Id": .Id,
               "ARN": .ARN,
               "DomainName": .DomainName,
               "Enabled": .Enabled,
               "ViewerProtocolPolicy": (.DefaultCacheBehavior.ViewerProtocolPolicy // null),
               "MinimumProtocolVersion": (.ViewerCertificate.MinimumProtocolVersion // null),
               "CloudFrontDefaultCertificate": (.ViewerCertificate.CloudFrontDefaultCertificate // null),
               "WebACLId": (.WebACLId // ""),
               "WafEnabled": ((.WebACLId // "") != ""),
               "LoggingEnabled": ($configs[$i].DistributionConfig.Logging.Enabled // null)
             }]
    ' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

aws_finish
