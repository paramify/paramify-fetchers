#!/bin/bash
#
# AWS — DynamoDB Point-in-Time Recovery (PITR) Status
#
# Lists DynamoDB tables and reports each table's point-in-time recovery /
# continuous-backups status (recovery-point backup evidence).
#
# Output: $EVIDENCE_DIR/aws_dynamodb_pitr_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_dynamodb_pitr_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_dynamodb_pitr_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_dynamodb_pitr_status_fail.XXXXXX)"
_TABLE_NAMES="$(mktemp -t aws_dynamodb_pitr_status_names.XXXXXX)"
_TABLE_BACKUPS="$(mktemp -t aws_dynamodb_pitr_status_backups.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_TABLE_NAMES" "$_TABLE_BACKUPS"' EXIT

log_info() { printf '%s INFO aws_dynamodb_pitr_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_dynamodb_pitr_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# List all DynamoDB table names in the target region.
table_names=$(aws dynamodb list-tables --query 'TableNames[*]' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws dynamodb list-tables failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list DynamoDB tables"
else
    # describe-continuous-backups has no batch form, so each table still costs
    # one call. Responses are appended in order and the records built in one jq
    # pass, instead of four jq processes and an output rewrite per table.
    for table_name in $(aws_text_list "$table_names"); do
        # describe-continuous-backups carries the PITR status for the table.
        backups=$(aws dynamodb describe-continuous-backups --table-name "$table_name" --output json 2>/dev/null)
        desc_exit=$?
        if [ $desc_exit -ne 0 ] || [ -z "$backups" ]; then
            echo "aws dynamodb describe-continuous-backups ($table_name) failed (exit=$desc_exit)" >> "$_FAILURE_LOG"
            continue
        fi
        printf '%s\n' "$table_name" >> "$_TABLE_NAMES"
        printf '%s\n' "$backups" >> "$_TABLE_BACKUPS"
    done

    jq --rawfile names "$_TABLE_NAMES" --slurpfile backups "$_TABLE_BACKUPS" '
        ($names | split("\n")) as $names
        | .results += [range(0; $backups | length) as $i
            | $backups[$i].ContinuousBackupsDescription as $d
            | ($d.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus // "DISABLED" | tostring) as $pitr_status
            | {"TableName": $names[$i], "PITREnabled": ($pitr_status == "ENABLED"), "PointInTimeRecoveryStatus": $pitr_status,
               "ContinuousBackupsStatus": ($d.ContinuousBackupsStatus // "DISABLED" | tostring),
               "EarliestRestorableDateTime": ($d.PointInTimeRecoveryDescription.EarliestRestorableDateTime // "N/A" | tostring),
               "LatestRestorableDateTime": ($d.PointInTimeRecoveryDescription.LatestRestorableDateTime // "N/A" | tostring)}]
    ' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

aws_finish
