#!/bin/bash
#
# AWS — S3 Encryption at Rest
#
# For each S3 bucket in the account, reports server-side encryption config.
# Aggregates an encryption-coverage percentage.
#
# Output: $EVIDENCE_DIR/aws_s3_encryption_status.json
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
REGION="${REGION:-us-east-1}"
export AWS_DEFAULT_REGION="$REGION"

# Per-account output filename (profile) — global service, region not part of identity.
_TARGET_ID="$(aws_target_id)"
OUTPUT_JSON="$OUTPUT_DIR/aws_s3_encryption_status_${_TARGET_ID}.json"
_FAILURE_LOG="$(mktemp -t aws_s3_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_s3_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_s3_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# get-bucket-encryption has no batch form, so each bucket still costs one call.
# What the loop no longer does is spawn jq: each bucket's name and raw response
# (or null when the call failed) are appended in order, and one jq pass below
# builds every record. That pass reads files, not --argjson: every bucket on
# one command line overflows Linux's 128 KiB argv limit at around 700 buckets.
_BUCKET_NAMES="$(mktemp -t aws_s3_encryption_status_names.XXXXXX)"
_BUCKET_RESPONSES="$(mktemp -t aws_s3_encryption_status_responses.XXXXXX.json)"
trap 'rm -f "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_BUCKET_NAMES" "$_BUCKET_RESPONSES"' EXIT

bucket_names=$(aws s3api list-buckets --query "Buckets[*].Name" --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws s3api list-buckets failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list S3 buckets"
else
    for bucket in $bucket_names; do
        # Note: a bucket with no encryption configured is the data point, not a
        # failure -- it is recorded as unencrypted (null here).
        if ! encryption_config=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null) || [ -z "$encryption_config" ]; then
            encryption_config='null'
        fi
        printf '%s\n' "$bucket" >> "$_BUCKET_NAMES"
        printf '%s\n' "$encryption_config" >> "$_BUCKET_RESPONSES"
    done
fi

jq -n \
    --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
    --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
    --rawfile names "$_BUCKET_NAMES" --slurpfile responses "$_BUCKET_RESPONSES" \
    '($names | split("\n")) as $names
    | [range(0; $responses | length) as $i | $responses[$i] as $config
        | if $config == null then
            {name: $names[$i], type: "s3", encrypted: false, encryption_type: "None", kms_key_id: "None", bucket_key_enabled: false}
          else
            $config.ServerSideEncryptionConfiguration.Rules[0] as $rule
            | {name: $names[$i], type: "s3", encrypted: true,
               encryption_type: ($rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm // "None" | tostring),
               kms_key_id: ($rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID // "None" | tostring),
               bucket_key_enabled: ($rule.BucketKeyEnabled // false)}
          end] as $buckets
    | ($buckets | length) as $total
    | ([$buckets[] | select(.encrypted)] | length) as $encrypted
    | {
        metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn},
        results: {
            storage_inventory: {object: $buckets},
            summary: {
                total_storage: $total,
                encrypted_storage: $encrypted,
                encryption_percentage: (if $total > 0 then ($encrypted * 100 / $total | floor) else 0 end)
            }
        }
    }' > "$OUTPUT_JSON"

aws_finish
