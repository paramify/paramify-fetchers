#!/bin/bash
# AWS — Component SSL/TLS Enforcement Status
# Checks S3 bucket policies for an aws:SecureTransport HTTPS-deny statement and
# RDS DB parameter groups for rds.force_ssl=1.
# Output: $EVIDENCE_DIR/aws_component_ssl_enforcement_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_component_ssl_enforcement_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_component_ssl_enforcement_status.XXXXXX.json)"
_S3_DETAILS="$(mktemp -t aws_component_ssl_enforcement_status_s3.XXXXXX.json)"
_RDS_DETAILS="$(mktemp -t aws_component_ssl_enforcement_status_rds.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_component_ssl_enforcement_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_S3_DETAILS" "$_RDS_DETAILS" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_component_ssl_enforcement_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_component_ssl_enforcement_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn},
    "results": {"s3": [], "rds": []},
    "summary": {}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream) ---

# 1. S3 Bucket SSL Enforcement
s3_buckets=$(aws s3api list-buckets 2>/dev/null | jq -r '.Buckets[].Name')
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws s3api list-buckets failed (exit=$ec)" >> "$_FAILURE_LOG"
fi
s3_total=0
s3_ssl_enforced=0

echo "[]" > "$_S3_DETAILS"

for bucket in $s3_buckets; do
    s3_total=$((s3_total+1))
    # get-bucket-policy errors (NoSuchBucketPolicy) when a bucket has no policy;
    # upstream treats that as valid evidence (ssl not enforced), not a failure.
    policy=$(aws s3api get-bucket-policy --bucket "$bucket" 2>/dev/null || echo "")
    enforced="false"
    snippet=""
    if [[ -n "$policy" ]]; then
        # Check for aws:SecureTransport deny
        found=$(echo "$policy" | jq -e '.Policy | fromjson | .Statement[]? | select(.Effect=="Deny" and .Condition.Bool."aws:SecureTransport"=="false")' 2>/dev/null || echo "")
        if [[ -n "$found" ]]; then
            enforced="true"
            s3_ssl_enforced=$((s3_ssl_enforced+1))
            snippet=$(echo "$found" | jq -c '.')
        fi
    fi
    # Add to JSON array using jq
    jq --arg bucket "$bucket" --arg enforced "$enforced" --arg snippet "$snippet" \
       '. += [{"bucket": $bucket, "ssl_enforced": ($enforced == "true"), "policy_snippet": ($snippet | fromjson? // null)}]' \
       "$_S3_DETAILS" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$_S3_DETAILS"
done

# Update main JSON with S3 details
jq --slurpfile s3 "$_S3_DETAILS" '.results.s3 = $s3[0]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

# 2. RDS SSL Enforcement
rds_instances=$(aws rds describe-db-instances 2>/dev/null | jq -r '.DBInstances[].DBInstanceIdentifier')
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws rds describe-db-instances failed (exit=$ec)" >> "$_FAILURE_LOG"
fi
rds_total=0
rds_ssl_enforced=0

echo "[]" > "$_RDS_DETAILS"

for db in $rds_instances; do
    rds_total=$((rds_total+1))
    pgroups=$(aws rds describe-db-instances --db-instance-identifier "$db" 2>/dev/null | jq -r '.DBInstances[0].DBParameterGroups[].DBParameterGroupName')
    ec=$?
    if [ $ec -ne 0 ]; then
        echo "aws rds describe-db-instances ($db) failed (exit=$ec)" >> "$_FAILURE_LOG"
    fi
    enforced="false"
    for pg in $pgroups; do
        param=$(aws rds describe-db-parameters --db-parameter-group-name "$pg" 2>/dev/null | jq -r '.Parameters[] | select(.ParameterName=="rds.force_ssl") | .ParameterValue')
        ec=$?
        if [ $ec -ne 0 ]; then
            echo "aws rds describe-db-parameters ($pg) failed (exit=$ec)" >> "$_FAILURE_LOG"
        fi
        if [[ "$param" == "1" ]]; then
            enforced="true"
            rds_ssl_enforced=$((rds_ssl_enforced+1))
            break
        fi
    done
    # Convert parameter groups to JSON array
    pg_json=$(echo "$pgroups" | jq -R -s 'split("\n") | map(select(length > 0))')
    # Add to JSON array using jq
    jq --arg db "$db" --arg enforced "$enforced" --argjson pgroups "$pg_json" \
       '. += [{"db_instance": $db, "ssl_enforced": ($enforced == "true"), "parameter_groups": $pgroups}]' \
       "$_RDS_DETAILS" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$_RDS_DETAILS"
done

# Update main JSON with RDS details
jq --slurpfile rds "$_RDS_DETAILS" '.results.rds = $rds[0]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

# Summary
jq --arg s3_total "$s3_total" --arg s3_ssl_enforced "$s3_ssl_enforced" \
   --arg rds_total "$rds_total" --arg rds_ssl_enforced "$rds_ssl_enforced" \
   '.summary = {
      s3_total: ($s3_total|tonumber),
      s3_ssl_enforced: ($s3_ssl_enforced|tonumber),
      rds_total: ($rds_total|tonumber),
      rds_ssl_enforced: ($rds_ssl_enforced|tonumber),
      formatted_summary: ("S3 Buckets: " + $s3_total + ", SSL Enforced: " + $s3_ssl_enforced + "\n" +
                         "RDS Instances: " + $rds_total + ", SSL Enforced: " + $rds_ssl_enforced + "\n")
   }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

log_info "$(jq -r '.summary.formatted_summary' "$OUTPUT_JSON")"

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
