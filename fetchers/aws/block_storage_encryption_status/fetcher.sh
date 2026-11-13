#!/bin/bash
#
# AWS — Block Storage Encryption at Rest
#
# Reports EBS encryption defaults + per-volume EBS encryption + per-EFS
# encryption. Aggregates a coverage percentage.
#
# Output: $EVIDENCE_DIR/aws_block_storage_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_block_storage_encryption_status_${_TARGET_ID}.json"
_FAILURE_LOG="$(mktemp -t aws_block_storage_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_block_storage_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_block_storage_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# --output text renders the API's boolean as `True`/`False`, not `true`/`false`,
# so the comparison below downcases before testing it.
ebs_encryption_default=$(aws ec2 get-ebs-encryption-by-default --query "EbsEncryptionByDefault" --output text 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws ec2 get-ebs-encryption-by-default failed" >> "$_FAILURE_LOG"
    ebs_encryption_default="unknown"
fi
ebs_default_kms_key=$(aws ec2 get-ebs-default-kms-key-id --query "KmsKeyId" --output text 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws ec2 get-ebs-default-kms-key-id failed" >> "$_FAILURE_LOG"
    ebs_default_kms_key="unknown"
fi

# One describe per service. The per-item describe-volumes --volume-ids /
# describe-file-systems --file-system-id calls this replaced re-fetched fields the
# list call already returns, one CLI process per volume.
_EBS_JSON="$(mktemp -t aws_block_storage_encryption_status_ebs.XXXXXX.json)"
_EFS_JSON="$(mktemp -t aws_block_storage_encryption_status_efs.XXXXXX.json)"
trap 'rm -f "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_EBS_JSON" "$_EFS_JSON"' EXIT

if ! aws ec2 describe-volumes --query "Volumes[*].{VolumeId:VolumeId,Encrypted:Encrypted,KmsKeyId:KmsKeyId,State:State,Size:Size}" --output json > "$_EBS_JSON" 2>/dev/null \
   || ! jq -e 'type == "array"' "$_EBS_JSON" >/dev/null 2>&1; then
    echo "aws ec2 describe-volumes (list) failed" >> "$_FAILURE_LOG"
    log_error "Failed to list EBS volumes"
    echo '[]' > "$_EBS_JSON"
fi

if ! aws efs describe-file-systems --query "FileSystems[*].{FileSystemId:FileSystemId,Encrypted:Encrypted,KmsKeyId:KmsKeyId}" --output json > "$_EFS_JSON" 2>/dev/null \
   || ! jq -e 'type == "array"' "$_EFS_JSON" >/dev/null 2>&1; then
    echo "aws efs describe-file-systems (list) failed" >> "$_FAILURE_LOG"
    log_error "Failed to list EFS file systems"
    echo '[]' > "$_EFS_JSON"
fi

jq -n \
    --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
    --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
    --slurpfile vols "$_EBS_JSON" --slurpfile fss "$_EFS_JSON" \
    --arg ebs_default "$ebs_encryption_default" --arg ebs_kms "$ebs_default_kms_key" \
    '[$vols[0][] | {name: .VolumeId, type: "ebs", encrypted: .Encrypted, kms_key_id: (.KmsKeyId // "None"), state: (.State | tostring), size_gb: .Size}] as $ebs
    | [$fss[0][] | {name: .FileSystemId, type: "efs", encrypted: .Encrypted, kms_key_id: (.KmsKeyId // "None")}] as $efs
    | (($ebs + $efs) | length) as $total
    | ([($ebs + $efs)[] | select(.encrypted == true)] | length) as $encrypted
    | {
        metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn},
        results: {
            ebs_default_settings: {
                encryption_enabled_by_default: (($ebs_default | ascii_downcase) == "true"),
                default_kms_key_id: $ebs_kms
            },
            storage_inventory: {ebs: $ebs, efs: $efs},
            summary: {
                total_storage: $total,
                encrypted_storage: $encrypted,
                encryption_percentage: (if $total > 0 then ($encrypted * 100 / $total | floor) else 0 end)
            }
        }
    }' > "$OUTPUT_JSON"

aws_finish
