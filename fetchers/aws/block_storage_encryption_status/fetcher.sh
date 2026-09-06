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

total_storage=0
encrypted_storage=0
ebs_results=()
efs_results=()

volume_ids=$(aws ec2 describe-volumes --query "Volumes[*].VolumeId" --output text 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws ec2 describe-volumes (list) failed" >> "$_FAILURE_LOG"
    log_error "Failed to list EBS volumes"
else
    for volume in $volume_ids; do
        total_storage=$((total_storage + 1))
        volume_details=$(aws ec2 describe-volumes --volume-ids "$volume" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws ec2 describe-volumes ($volume) failed" >> "$_FAILURE_LOG"
            continue
        fi
        encrypted=$(echo "$volume_details" | jq -r '.Volumes[0].Encrypted')
        kms_key_id=$(echo "$volume_details" | jq -r '.Volumes[0].KmsKeyId // "None"')
        state=$(echo "$volume_details" | jq -r '.Volumes[0].State')
        size=$(echo "$volume_details" | jq -r '.Volumes[0].Size')

        ebs_results+=("$(jq -n --arg name "$volume" --arg type "ebs" \
            --argjson enc "$encrypted" --arg kms "$kms_key_id" --arg st "$state" --arg sz "$size" \
            '{name: $name, type: $type, encrypted: $enc, kms_key_id: $kms, state: $st, size_gb: ($sz | tonumber)}')")
        [ "$encrypted" = "true" ] && encrypted_storage=$((encrypted_storage + 1))
    done
fi

fs_ids=$(aws efs describe-file-systems --query "FileSystems[*].FileSystemId" --output text 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws efs describe-file-systems (list) failed" >> "$_FAILURE_LOG"
    log_error "Failed to list EFS file systems"
else
    for fs in $fs_ids; do
        total_storage=$((total_storage + 1))
        fs_details=$(aws efs describe-file-systems --file-system-id "$fs" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws efs describe-file-systems ($fs) failed" >> "$_FAILURE_LOG"
            continue
        fi
        encrypted=$(echo "$fs_details" | jq -r '.FileSystems[0].Encrypted')
        kms_key_id=$(echo "$fs_details" | jq -r '.FileSystems[0].KmsKeyId // "None"')

        efs_results+=("$(jq -n --arg name "$fs" --arg type "efs" \
            --argjson enc "$encrypted" --arg kms "$kms_key_id" \
            '{name: $name, type: $type, encrypted: $enc, kms_key_id: $kms}')")
        [ "$encrypted" = "true" ] && encrypted_storage=$((encrypted_storage + 1))
    done
fi

percentage=0
[ $total_storage -gt 0 ] && percentage=$(( (encrypted_storage * 100) / total_storage ))

jq -n \
    --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
    --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
    --argjson ebs "[$(IFS=,; echo "${ebs_results[*]}")]" \
    --argjson efs "[$(IFS=,; echo "${efs_results[*]}")]" \
    --arg total "$total_storage" --arg encrypted "$encrypted_storage" --arg percentage "$percentage" \
    --arg ebs_default "$ebs_encryption_default" --arg ebs_kms "$ebs_default_kms_key" \
    '{
        metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn},
        results: {
            ebs_default_settings: {
                encryption_enabled_by_default: (($ebs_default | ascii_downcase) == "true"),
                default_kms_key_id: $ebs_kms
            },
            storage_inventory: {ebs: $ebs, efs: $efs},
            summary: {
                total_storage: ($total | tonumber),
                encrypted_storage: ($encrypted | tonumber),
                encryption_percentage: ($percentage | tonumber)
            }
        }
    }' > "$OUTPUT_JSON"

aws_finish
