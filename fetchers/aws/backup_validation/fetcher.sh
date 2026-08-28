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
_RDS_RESULTS="$(mktemp -t aws_backup_validation_rds.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_RDS_RESULTS"' EXIT

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
    # Written to a file, NOT a shell variable: each element embeds the entire
    # describe-db-instances object as InstanceInfo, so the array runs to hundreds
    # of KB in an account with a few dozen instances. Passing that to jq through
    # --argjson puts it in argv, which blows the kernel's per-argument limit
    # (MAX_ARG_STRLEN, 128 KiB) and fails the merge with "Argument list too long"
    # — losing every RDS result while the rest of the scan appears to succeed.
    # --slurpfile below reads it from the file, which has no size limit.
    echo "$rds_instances" | jq -c '
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
    ' > "$_RDS_RESULTS"

    tmp_out="$(mktemp "${OUTPUT_DIR%/}/.${COMPONENT}.rds_merge.XXXXXX")"
    jq --slurpfile rds "$_RDS_RESULTS" '.results += ($rds[0] // [])' "$OUTPUT_JSON" > "$tmp_out" \
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

            # Check if versioning is enabled
            versioning_enabled="false"
            if echo "$versioning_status" | jq -e '.Status == "Enabled"' > /dev/null; then
                versioning_enabled="true"
            fi

            # Check if replication is configured
            replication_enabled="false"
            replication_destination=""
            if echo "$replication_status" | jq -e '.ReplicationConfiguration' > /dev/null; then
                replication_enabled="true"
                replication_destination=$(echo "$replication_status" | jq -r '.ReplicationConfiguration.Rules[0].Destination.Bucket // "N/A"')
            fi

            # Check if encryption is enabled
            encryption_enabled="false"
            if echo "$encryption_status" | jq -e '.ServerSideEncryptionConfiguration' > /dev/null; then
                encryption_enabled="true"
            fi

            # Add to JSON
            tmp_out="$(mktemp "${OUTPUT_DIR%/}/.${COMPONENT}.XXXXXX")"
            jq --argjson versioning "$versioning_status" \
               --argjson replication "$replication_status" \
               --argjson encryption "$encryption_status" \
               --arg bucket "$bucket_name" \
               --arg v_enabled "$versioning_enabled" \
               --arg r_enabled "$replication_enabled" \
               --arg r_destination "$replication_destination" \
               --arg e_enabled "$encryption_enabled" \
               '.results += [{"Type": "S3_Backup", "BucketName": $bucket, "VersioningEnabled": ($v_enabled == "true"), "ReplicationEnabled": ($r_enabled == "true"), "ReplicationDestination": $r_destination, "EncryptionEnabled": ($e_enabled == "true"), "VersioningInfo": $versioning, "ReplicationInfo": $replication, "EncryptionInfo": $encryption}]' \
               "$OUTPUT_JSON" > "$tmp_out" && mv "$tmp_out" "$OUTPUT_JSON"
        else
            log_info "Skipping bucket: $bucket_name"
        fi
    done < <(echo "$s3_buckets" | jq -r '.[]')
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

        # Add to JSON
        tmp_out="$(mktemp "${OUTPUT_DIR%/}/.${COMPONENT}.XXXXXX")"
        jq --argjson vault "$vault" \
           --argjson points "$recovery_points" \
           '.results += [{"Type": "AWS_Backup_Vault", "VaultName": $vault.BackupVaultName, "VaultArn": $vault.BackupVaultArn, "CreationDate": $vault.CreationDate, "RecoveryPoints": $points}]' \
           "$OUTPUT_JSON" > "$tmp_out" && mv "$tmp_out" "$OUTPUT_JSON"
    done < <(echo "$backup_vaults" | jq -c '.BackupVaultList[]')
else
    log_info "No AWS Backup vaults found"
fi

# Generate summary
rds_with_backups=$(jq '.results[] | select(.Type == "RDS_Backup" and .BackupEnabled == true) | .InstanceId' "$OUTPUT_JSON" 2>/dev/null | wc -l)
total_rds=$(jq '.results[] | select(.Type == "RDS_Backup") | .InstanceId' "$OUTPUT_JSON" 2>/dev/null | wc -l)
rds_with_replication=$(jq '.results[] | select(.Type == "RDS_Backup" and .CrossRegionReplication == true) | .InstanceId' "$OUTPUT_JSON" 2>/dev/null | wc -l)
rds_with_encryption=$(jq '.results[] | select(.Type == "RDS_Backup" and .StorageEncrypted == true) | .InstanceId' "$OUTPUT_JSON" 2>/dev/null | wc -l)
rds_with_deletion_protection=$(jq '.results[] | select(.Type == "RDS_Backup" and .DeletionProtection == true) | .InstanceId' "$OUTPUT_JSON" 2>/dev/null | wc -l)
s3_with_versioning=$(jq '.results[] | select(.Type == "S3_Backup" and .VersioningEnabled == true) | .BucketName' "$OUTPUT_JSON" 2>/dev/null | wc -l)
total_s3=$(jq '.results[] | select(.Type == "S3_Backup") | .BucketName' "$OUTPUT_JSON" 2>/dev/null | wc -l)
s3_with_replication=$(jq '.results[] | select(.Type == "S3_Backup" and .ReplicationEnabled == true) | .BucketName' "$OUTPUT_JSON" 2>/dev/null | wc -l)
s3_with_encryption=$(jq '.results[] | select(.Type == "S3_Backup" and .EncryptionEnabled == true) | .BucketName' "$OUTPUT_JSON" 2>/dev/null | wc -l)
total_vaults=$(jq '.results[] | select(.Type == "AWS_Backup_Vault") | .VaultName' "$OUTPUT_JSON" 2>/dev/null | wc -l)

# Update summary in JSON
tmp_summary="$(mktemp "${OUTPUT_DIR%/}/.${COMPONENT}.summary.XXXXXX")"
jq --arg rds_backups "$rds_with_backups" \
   --arg total_rds "$total_rds" \
   --arg rds_replication "$rds_with_replication" \
   --arg rds_encryption "$rds_with_encryption" \
   --arg rds_protection "$rds_with_deletion_protection" \
   --arg s3_versioning "$s3_with_versioning" \
   --arg total_s3 "$total_s3" \
   --arg s3_replication "$s3_with_replication" \
   --arg s3_encryption "$s3_with_encryption" \
   --arg vaults "$total_vaults" \
   '.summary = {
       "rds_backup_coverage": {"with_backups": ($rds_backups|tonumber), "total": ($total_rds|tonumber)},
       "rds_replication_coverage": {"with_replication": ($rds_replication|tonumber), "total": ($total_rds|tonumber)},
       "rds_encryption_coverage": {"with_encryption": ($rds_encryption|tonumber), "total": ($total_rds|tonumber)},
       "rds_deletion_protection": {"with_protection": ($rds_protection|tonumber), "total": ($total_rds|tonumber)},
       "s3_versioning_coverage": {"with_versioning": ($s3_versioning|tonumber), "total": ($total_s3|tonumber)},
       "s3_replication_coverage": {"with_replication": ($s3_replication|tonumber), "total": ($total_s3|tonumber)},
       "s3_encryption_coverage": {"with_encryption": ($s3_encryption|tonumber), "total": ($total_s3|tonumber)},
       "backup_vaults": ($vaults|tonumber)
   }' "$OUTPUT_JSON" > "$tmp_summary" && mv "$tmp_summary" "$OUTPUT_JSON"

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
