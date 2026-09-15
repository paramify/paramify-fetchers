#!/bin/bash
#
# AWS — S3 Glacier Vault Encryption and Lock
#
# Lists S3 Glacier vaults in the account/region and, for each, reports the
# vault access policy and the vault lock policy (lock state + policy document).
#
# Output: $EVIDENCE_DIR/aws_glacier_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_glacier_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_glacier_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_glacier_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_glacier_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_glacier_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

_LIST_ERR="$(mktemp -t aws_glacier_encryption_status_list.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_LIST_ERR" "$_AWS_ERR_LOG"' EXIT
vault_names=$(aws glacier list-vaults --account-id - --query 'VaultList[*].VaultName' --output text 2>"$_LIST_ERR")
list_exit=$?
if [ $list_exit -ne 0 ]; then
    if aws_service_unavailable "$_LIST_ERR"; then
        # Glacier not subscribed / not in use for this account+region. Valid evidence.
        log_info "S3 Glacier not in use (not subscribed/enabled); recording not-enabled status"
        jq '.results += [{"status": "not_enabled", "detail": "S3 Glacier is not subscribed or not in use for this account/region (list-vaults returned a not-subscribed/not-enabled error)."}]' \
            "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    else
        echo "aws glacier list-vaults (list) failed (exit=$list_exit): $(cat "$_LIST_ERR")" >> "$_FAILURE_LOG"
        log_error "Failed to list Glacier vaults"
    fi
else
    for vault_name in $(aws_text_list "$vault_names"); do
        vault_arn=$(aws glacier list-vaults --account-id - \
            --query "VaultList[?VaultName=='$vault_name'].VaultARN | [0]" --output text 2>/dev/null)

        # Vault access policy — absent when no policy is set (ResourceNotFoundException).
        access_policy=$(aws glacier get-vault-access-policy --account-id - --vault-name "$vault_name" \
            --query 'policy.Policy' --output text 2>/dev/null)
        ap_exit=$?
        if [ $ap_exit -ne 0 ]; then
            access_policy_json='{}'
        else
            access_policy_json=$(echo "$access_policy" | jq -c '.' 2>/dev/null) || access_policy_json='{}'
        fi

        # Vault lock policy — lock state and policy document (immutability / compliance lock).
        lock=$(aws glacier get-vault-lock --account-id - --vault-name "$vault_name" --output json 2>/dev/null)
        lock_exit=$?
        if [ $lock_exit -ne 0 ]; then
            lock_state="None"
            lock_policy_json='{}'
        else
            lock_state=$(echo "$lock" | jq -r '.State // "None"')
            lock_policy_json=$(echo "$lock" | jq -r '.Policy // "{}"' | jq -c '.' 2>/dev/null) || lock_policy_json='{}'
        fi

        vault_data=$(jq -n \
            --arg name "$vault_name" --arg arn "$vault_arn" \
            --argjson access_policy "$access_policy_json" \
            --arg lock_state "$lock_state" --argjson lock_policy "$lock_policy_json" \
            '{name: $name, arn: $arn, access_policy: $access_policy, vault_lock: {state: $lock_state, policy: $lock_policy}}')

        jq --argjson data "$vault_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
