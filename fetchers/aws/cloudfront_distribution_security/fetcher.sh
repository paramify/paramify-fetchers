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
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

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
dist_ids=$(aws cloudfront list-distributions --region us-east-1 \
    --query 'DistributionList.Items[*].Id' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws cloudfront list-distributions failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list CloudFront distributions"
else
    for dist_id in $(aws_text_list "$dist_ids"); do
        summary=$(aws cloudfront list-distributions --region us-east-1 \
            --query "DistributionList.Items[?Id=='$dist_id'] | [0]" --output json 2>/dev/null)
        summary_exit=$?
        if [ $summary_exit -ne 0 ]; then
            echo "aws cloudfront list-distributions ($dist_id) failed (exit=$summary_exit)" >> "$_FAILURE_LOG"
            continue
        fi

        logging_enabled="null"
        config=$(aws cloudfront get-distribution-config --id "$dist_id" --region us-east-1 --output json 2>/dev/null)
        config_exit=$?
        if [ $config_exit -ne 0 ]; then
            echo "aws cloudfront get-distribution-config ($dist_id) failed (exit=$config_exit)" >> "$_FAILURE_LOG"
        else
            logging_enabled=$(echo "$config" | jq -c '.DistributionConfig.Logging.Enabled // null')
        fi

        dist_record=$(echo "$summary" | jq \
            --arg id "$dist_id" --argjson logging "$logging_enabled" \
            '{
               "Id": $id,
               "ARN": .ARN,
               "DomainName": .DomainName,
               "Enabled": .Enabled,
               "ViewerProtocolPolicy": (.DefaultCacheBehavior.ViewerProtocolPolicy // null),
               "MinimumProtocolVersion": (.ViewerCertificate.MinimumProtocolVersion // null),
               "CloudFrontDefaultCertificate": (.ViewerCertificate.CloudFrontDefaultCertificate // null),
               "WebACLId": (.WebACLId // ""),
               "WafEnabled": ((.WebACLId // "") != ""),
               "LoggingEnabled": $logging
             }')

        jq --argjson data "$dist_record" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

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
