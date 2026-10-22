#!/bin/bash
# Validates backup posture across RDS (retention, window, cross-region replication,
# encryption, deletion protection), S3 (versioning, replication, encryption), and
# AWS Backup (vaults and recovery points), with coverage summaries.
# Honors BUCKETS_TO_INCLUDE (space-separated) to limit which S3 buckets are processed.
# Output: $EVIDENCE_DIR/aws_backup_validation.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Optional env: BUCKETS_TO_INCLUDE
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
OUTPUT_JSON="$OUTPUT_DIR/aws_backup_validation_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_backup_validation.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_backup_validation_fail.XXXXXX)"
_S3_NAMES="$(mktemp -t aws_backup_validation_s3_names.XXXXXX)"
_S3_RESPONSES="$(mktemp -t aws_backup_validation_s3.XXXXXX.json)"
_VAULT_RESPONSES="$(mktemp -t aws_backup_validation_vaults.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_S3_NAMES" "$_S3_RESPONSES" "$_VAULT_RESPONSES"' EXIT

log_info() { printf '%s INFO aws_backup_validation %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_backup_validation %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

# No explicit --profile/--region: the CLI reads AWS_PROFILE/AWS_DEFAULT_REGION
# from the env (set by the runner from a target, or ambient). Kept as an (empty)
# array so the existing "${AWS_ARGS[@]}" call sites are unchanged.
AWS_ARGS=()
COMPONENT="aws_backup_validation"

CALLER_IDENTITY=$(aws sts get-caller-identity "${AWS_ARGS[@]}" --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Set BUCKETS_TO_INCLUDE for specific s3 buckets to include (space-separated string).
if [ -n "${BUCKETS_TO_INCLUDE:-}" ]; then
    buckets_to_include=($BUCKETS_TO_INCLUDE)
else
    buckets_to_include=() # If empty, all available buckets will be included in the output
fi

jq -n \
  --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
  --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": [], "summary": {}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream) ---

# 1. RDS Backup Validation
rds_instances=$(aws rds describe-db-instances "${AWS_ARGS[@]}" --query 'DBInstances[*]' --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws rds describe-db-instances failed (exit=$ec)" >> "$_FAILURE_LOG"
    rds_instances='[]'
fi
if [ -z "$rds_instances" ] || ! echo "$rds_instances" | jq . >/dev/null 2>&1; then
    rds_instances='[]'
fi

if [ "$(echo "$rds_instances" | jq -r 'length')" -gt 0 ]; then
    log_info "Found $(echo "$rds_instances" | jq -r 'length') RDS instances"
    # Build all RDS_Backup results in one jq pass (transform JSON, merge once)
    rds_results_json="$(echo "$rds_instances" | jq -c '
      map(
        . as $inst
        | {
            Type: "RDS_Backup",
            InstanceId: $inst.DBInstanceIdentifier,
            BackupEnabled: (($inst.BackupRetentionPeriod // 0) > 0),
            BackupRetentionPeriod: ($inst.BackupRetentionPeriod // 0),
            BackupWindow: ($inst.PreferredBackupWindow // ""),
            BackupTarget: ($inst.BackupTarget // "region"),
            LatestRestorableTime: ($inst.LatestRestorableTime // "N/A"),
            CrossRegionReplication: (($inst.DBInstanceAutomatedBackupsReplications // []) | length > 0),
            ReplicationDestination: (
              ($inst.DBInstanceAutomatedBackupsReplications // [])[0].DBInstanceAutomatedBackupsArn?
              | if . then (split(":")[3] // "") else "" end
            ),
            StorageEncrypted: ($inst.StorageEncrypted == true),
            DeletionProtection: ($inst.DeletionProtection == true),
            KmsKeyId: ($inst.KmsKeyId // "N/A"),
            InstanceInfo: $inst
          }
      )
    ')"

    # On stdin, not --argjson: InstanceInfo carries each instance whole, and a
    # few dozen instances overflow Linux's 128 KiB argv limit.
    tmp_out="$(mktemp "${OUTPUT_DIR%/}/.${COMPONENT}.rds_merge.XXXXXX")"
    printf '%s' "$rds_results_json" | jq --slurpfile rds /dev/stdin '.results += $rds[0]' "$OUTPUT_JSON" > "$tmp_out" \
      && mv "$tmp_out" "$OUTPUT_JSON" \
      || {
        rm -f "$tmp_out" 2>/dev/null || true
        echo "failed to merge RDS results into $OUTPUT_JSON" >> "$_FAILURE_LOG"
        log_error "Failed to merge RDS results into $OUTPUT_JSON"
      }
else
    log_info "No RDS instances found"
fi

# 2. S3 Backup Validation
s3_buckets=$(aws s3api list-buckets "${AWS_ARGS[@]}" --query 'Buckets[*].Name' --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws s3api list-buckets failed (exit=$ec)" >> "$_FAILURE_LOG"
    s3_buckets='[]'
fi
if [ -z "$s3_buckets" ] || ! echo "$s3_buckets" | jq . >/dev/null 2>&1; then
    s3_buckets='[]'
fi

if [ "$(echo "$s3_buckets" | jq -r 'length')" -gt 0 ]; then
    log_info "Found $(echo "$s3_buckets" | jq -r 'length') S3 buckets"
    while read -r bucket_name; do
        [ -z "$bucket_name" ] && continue

        if [ ${#buckets_to_include[@]} -eq 0 ] || [[ " ${buckets_to_include[@]} " =~ " ${bucket_name} " ]]; then
            # Get bucket versioning status (empty / not configured is valid evidence)
            versioning_status=$(aws s3api get-bucket-versioning "${AWS_ARGS[@]}" --bucket "$bucket_name" --output json 2>/dev/null)
            # Get cross-region replication status (NoSuchReplicationConfiguration is valid -> no replication)
            replication_status=$(aws s3api get-bucket-replication "${AWS_ARGS[@]}" --bucket "$bucket_name" --output json 2>/dev/null)
            # Get bucket encryption (no encryption config is valid evidence)
            encryption_status=$(aws s3api get-bucket-encryption "${AWS_ARGS[@]}" --bucket "$bucket_name" --output json 2>/dev/null)

            # Ensure valid JSON
            versioning_status=${versioning_status:-'{}'}
            replication_status=${replication_status:-'{}'}
            encryption_status=${encryption_status:-'{}'}

            # Appended in order; the records are built in one jq pass after the
            # loop -- no jq process or output rewrite per bucket.
            printf '%s\n' "$bucket_name" >> "$_S3_NAMES"
            printf '%s\n%s\n%s\n' "$versioning_status" "$replication_status" "$encryption_status" >> "$_S3_RESPONSES"
        else
            log_info "Skipping bucket: $bucket_name"
        fi
    done < <(echo "$s3_buckets" | jq -r '.[]')

    # VersioningEnabled / ReplicationEnabled / EncryptionEnabled are the
    # truthiness tests the per-bucket `jq -e` checks made.
    jq --rawfile names "$_S3_NAMES" --slurpfile responses "$_S3_RESPONSES" '
        ($names | split("\n")) as $names
        | .results += [range(0; ($responses | length) / 3) as $i
            | $responses[3 * $i] as $versioning
            | $responses[3 * $i + 1] as $replication
            | $responses[3 * $i + 2] as $encryption
            | {"Type": "S3_Backup", "BucketName": $names[$i],
               "VersioningEnabled": ($versioning.Status == "Enabled"),
               "ReplicationEnabled": (if $replication.ReplicationConfiguration then true else false end),
               "ReplicationDestination": (if $replication.ReplicationConfiguration
                    then ($replication.ReplicationConfiguration.Rules[0].Destination.Bucket // "N/A" | tostring) else "" end),
               "EncryptionEnabled": (if $encryption.ServerSideEncryptionConfiguration then true else false end),
               "VersioningInfo": $versioning, "ReplicationInfo": $replication, "EncryptionInfo": $encryption}]
    ' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
else
    log_info "No S3 buckets found"
fi

# 3. AWS Backup Validation
backup_vaults=$(aws backup list-backup-vaults "${AWS_ARGS[@]}" --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws backup list-backup-vaults failed (exit=$ec)" >> "$_FAILURE_LOG"
    backup_vaults='{"BackupVaultList": []}'
fi
if [ -z "$backup_vaults" ] || ! echo "$backup_vaults" | jq . >/dev/null 2>&1; then
    backup_vaults='{"BackupVaultList": []}'
fi

if [ "$(echo "$backup_vaults" | jq -r '.BackupVaultList | length')" -gt 0 ]; then
    log_info "Found $(echo "$backup_vaults" | jq -r '.BackupVaultList | length') backup vaults"
    while read -r vault; do
        vault_name=$(echo "$vault" | jq -r '.BackupVaultName')

        # Get recovery points for this vault (empty list is valid evidence)
        recovery_points=$(aws backup list-recovery-points-by-backup-vault "${AWS_ARGS[@]}" --backup-vault-name "$vault_name" --output json 2>/dev/null)
        ec=$?
        if [ $ec -ne 0 ]; then
            echo "aws backup list-recovery-points-by-backup-vault ($vault_name) failed (exit=$ec)" >> "$_FAILURE_LOG"
            recovery_points='{"RecoveryPoints": []}'
        fi
        if [ -z "$recovery_points" ] || ! echo "$recovery_points" | jq . >/dev/null 2>&1; then
            recovery_points='{"RecoveryPoints": []}'
        fi

        # Appended and merged once after the loop. A vault under an AWS Backup
        # plan holds thousands of recovery points: as --argjson that overflowed
        # Linux's 128 KiB argv limit and the vault silently fell out.
        printf '%s\n%s\n' "$vault" "$recovery_points" >> "$_VAULT_RESPONSES"
    done < <(echo "$backup_vaults" | jq -c '.BackupVaultList[]')

    jq --slurpfile responses "$_VAULT_RESPONSES" '
        .results += [range(0; ($responses | length) / 2) as $i
            | $responses[2 * $i] as $vault
            | {"Type": "AWS_Backup_Vault", "VaultName": $vault.BackupVaultName, "VaultArn": $vault.BackupVaultArn,
               "CreationDate": $vault.CreationDate, "RecoveryPoints": $responses[2 * $i + 1]}]
    ' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
else
    log_info "No AWS Backup vaults found"
fi

# Generate summary (one pass over the results)
tmp_summary="$(mktemp "${OUTPUT_DIR%/}/.${COMPONENT}.summary.XXXXXX")"
jq 'def count(f): [.results[] | select(f)] | length;
    count(.Type == "RDS_Backup") as $total_rds
    | count(.Type == "S3_Backup") as $total_s3
    | .summary = {
       "rds_backup_coverage": {"with_backups": count(.Type == "RDS_Backup" and .BackupEnabled == true), "total": $total_rds},
       "rds_replication_coverage": {"with_replication": count(.Type == "RDS_Backup" and .CrossRegionReplication == true), "total": $total_rds},
       "rds_encryption_coverage": {"with_encryption": count(.Type == "RDS_Backup" and .StorageEncrypted == true), "total": $total_rds},
       "rds_deletion_protection": {"with_protection": count(.Type == "RDS_Backup" and .DeletionProtection == true), "total": $total_rds},
       "s3_versioning_coverage": {"with_versioning": count(.Type == "S3_Backup" and .VersioningEnabled == true), "total": $total_s3},
       "s3_replication_coverage": {"with_replication": count(.Type == "S3_Backup" and .ReplicationEnabled == true), "total": $total_s3},
       "s3_encryption_coverage": {"with_encryption": count(.Type == "S3_Backup" and .EncryptionEnabled == true), "total": $total_s3},
       "backup_vaults": count(.Type == "AWS_Backup_Vault")
   }' "$OUTPUT_JSON" > "$tmp_summary" && mv "$tmp_summary" "$OUTPUT_JSON"

aws_finish
