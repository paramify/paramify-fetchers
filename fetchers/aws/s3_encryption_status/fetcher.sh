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
trap 'rm -f "$_FAILURE_LOG"' EXIT

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

total_buckets=0
encrypted_buckets=0
s3_results=()

bucket_names=$(aws s3api list-buckets --query "Buckets[*].Name" --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws s3api list-buckets failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list S3 buckets"
else
    for bucket in $(aws_text_list "$bucket_names"); do
        total_buckets=$((total_buckets + 1))

        if encryption_config=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null); then
            sse_algorithm=$(echo "$encryption_config" | jq -r '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm // "None"')
            kms_key_id=$(echo "$encryption_config" | jq -r '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID // "None"')
            bucket_key_enabled=$(echo "$encryption_config" | jq -r '.ServerSideEncryptionConfiguration.Rules[0].BucketKeyEnabled // false')

            s3_results+=("$(jq -n \
                --arg name "$bucket" --arg type "s3" \
                --arg sse "$sse_algorithm" --arg kms "$kms_key_id" \
                --argjson key_enabled "$bucket_key_enabled" \
                '{name: $name, type: $type, encrypted: true, encryption_type: $sse, kms_key_id: $kms, bucket_key_enabled: $key_enabled}')")
            encrypted_buckets=$((encrypted_buckets + 1))
        else
            # Note: a bucket with no encryption configured is the data point, not a failure.
            s3_results+=("$(jq -n \
                --arg name "$bucket" --arg type "s3" \
                '{name: $name, type: $type, encrypted: false, encryption_type: "None", kms_key_id: "None", bucket_key_enabled: false}')")
        fi
    done
fi

percentage=0
if [ $total_buckets -gt 0 ]; then
    percentage=$(( (encrypted_buckets * 100) / total_buckets ))
fi

jq -n \
    --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
    --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
    --argjson buckets "[$(IFS=,; echo "${s3_results[*]}")]" \
    --arg total "$total_buckets" --arg encrypted "$encrypted_buckets" --arg percentage "$percentage" \
    '{
        metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn},
        results: {
            storage_inventory: {object: $buckets},
            summary: {
                total_storage: ($total | tonumber),
                encrypted_storage: ($encrypted | tonumber),
                encryption_percentage: ($percentage | tonumber)
            }
        }
    }' > "$OUTPUT_JSON"

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
