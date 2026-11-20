#!/bin/bash
# Lists AWS Backup vaults and their KMS encryption key configuration to confirm
# backup data is encrypted at rest.
# Output: $EVIDENCE_DIR/aws_backup_vault_encryption.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

source "$(dirname "$0")/../_shared/aws.sh"

_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_backup_vault_encryption_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_backup_vault_encryption.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_backup_vault_encryption_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info()  { printf '%s INFO  aws_backup_vault_encryption %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_backup_vault_encryption %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata":{"profile":$profile,"region":$region,"datetime":$datetime,"account_id":$account_id,"arn":$arn},"results":{"vaults":[],"summary":{}}}' \
  > "$OUTPUT_JSON"

log_info "Collecting Backup vault list"

# list-backup-vaults already returns EncryptionKeyArn; no per-vault describe needed.
vaults=$(aws backup list-backup-vaults \
    --query 'BackupVaultList[*].{BackupVaultName:BackupVaultName,BackupVaultArn:BackupVaultArn,EncryptionKeyArn:EncryptionKeyArn,NumberOfRecoveryPoints:NumberOfRecoveryPoints,CreationDate:CreationDate}' \
    --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws backup list-backup-vaults failed" >> "$_FAILURE_LOG"
    vaults='[]'
fi

total_count=$(echo "$vaults" | jq 'length')
# AWS always encrypts vaults; the meaningful split is customer-managed vs the
# default aws/backup key. A CMK ARN does not contain "aws/backup".
cmk_count=$(echo "$vaults" | jq '[.[] | select(.EncryptionKeyArn != null and (.EncryptionKeyArn | contains("aws/backup") | not))] | length')
default_key_count=$(echo "$vaults" | jq '[.[] | select(.EncryptionKeyArn != null and (.EncryptionKeyArn | contains("aws/backup")))] | length')

_VAULTS_JSON="$(mktemp -t aws_backup_vaults.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_VAULTS_JSON"' EXIT
printf '%s' "$vaults" > "$_VAULTS_JSON"

jq --slurpfile vaults "$_VAULTS_JSON" \
   --arg total       "$total_count" \
   --arg cmk         "$cmk_count" \
   --arg default_key "$default_key_count" \
   '.results = {
       "vaults": ($vaults[0] // []),
       "summary": {
         "total_vaults":               ($total       | tonumber),
         "customer_managed_key_vaults": ($cmk         | tonumber),
         "aws_managed_key_vaults":      ($default_key | tonumber)
       }
   }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

log_info "Evidence saved to $OUTPUT_JSON (vaults: $total_count, CMK: $cmk_count, AWS-managed key: $default_key_count)"

aws_finish
