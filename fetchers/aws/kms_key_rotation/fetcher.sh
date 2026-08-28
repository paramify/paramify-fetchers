#!/bin/bash
#
# AWS — KMS Key Rotation
#
# For each KMS key, reports rotation status, state/usage, and policy.
# Includes the AWS Config rule compliance for cmk-backing-key-rotation-enabled.
#
# Output: $EVIDENCE_DIR/aws_kms_key_rotation.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq
#
# NOTE: The Config rule name is hardcoded to a Paramify-specific conformance
# pack rule (`cmk-backing-key-rotation-enabled-conformance-pack-j3wepwlkw`).
# Customers running outside that account should expect the config_compliance
# section to be empty or fail.

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
OUTPUT_JSON="$OUTPUT_DIR/aws_kms_key_rotation_${_TARGET_ID}.json"
_FAILURE_LOG="$(mktemp -t aws_kms_key_rotation_fail.XXXXXX)"
trap 'rm -f "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_kms_key_rotation %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_kms_key_rotation %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

config_rule_name="cmk-backing-key-rotation-enabled-conformance-pack-j3wepwlkw"
config_compliance=$(aws configservice describe-compliance-by-config-rule --config-rule-name "$config_rule_name" 2>/dev/null)
if [ $? -ne 0 ]; then
    # Treat as a soft signal — the rule may not exist outside Paramify's account.
    config_compliance='{"ComplianceByConfigRules": []}'
fi

total_keys=0
rotated_keys=0
kms_results=()

key_ids=$(aws kms list-keys --query "Keys[*].KeyId" --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws kms list-keys failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list KMS keys"
else
    for key_id in $(aws_text_list "$key_ids"); do
        [ -z "$key_id" ] && continue
        total_keys=$((total_keys + 1))

        key_details=$(aws kms describe-key --key-id "$key_id" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws kms describe-key ($key_id) failed" >> "$_FAILURE_LOG"
            key_details='{"KeyMetadata": {}}'
        fi
        key_rotation_status=$(aws kms get-key-rotation-status --key-id "$key_id" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws kms get-key-rotation-status ($key_id) failed" >> "$_FAILURE_LOG"
            key_rotation_status='{"KeyRotationEnabled": false}'
        fi

        key_arn=$(echo "$key_details" | jq -r '.KeyMetadata.Arn // "Unknown"')
        key_state=$(echo "$key_details" | jq -r '.KeyMetadata.KeyState // "Unknown"')
        key_usage=$(echo "$key_details" | jq -r '.KeyMetadata.KeyUsage // "Unknown"')
        is_rotated=$(echo "$key_rotation_status" | jq -r '.KeyRotationEnabled // false')

        if [ "$is_rotated" = "true" ]; then
            rotated_keys=$((rotated_keys + 1))
        fi

        key_policy=$(aws kms get-key-policy --key-id "$key_id" --policy-name default 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws kms get-key-policy ($key_id) failed" >> "$_FAILURE_LOG"
            key_policy='{}'
        fi

        kms_results+=("$(jq -n \
            --arg id "$key_id" --arg arn "$key_arn" --arg state "$key_state" --arg usage "$key_usage" \
            --argjson rotated "$is_rotated" --argjson policy "$key_policy" \
            '{key_id: $id, key_arn: $arn, key_state: $state, key_usage: $usage, rotation_enabled: $rotated, key_policy: $policy}')")
    done
fi

percentage=0
[ $total_keys -gt 0 ] && percentage=$(( (rotated_keys * 100) / total_keys ))

jq -n \
    --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
    --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
    --argjson keys "[$(IFS=,; echo "${kms_results[*]}")]" \
    --argjson config "$config_compliance" \
    --arg total "$total_keys" --arg rotated "$rotated_keys" --arg percentage "$percentage" \
    '{
        metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn},
        results: {
            kms_keys: {object: $keys},
            config_rule: $config,
            summary: {
                total_keys: ($total | tonumber),
                rotated_keys: ($rotated | tonumber),
                rotation_percentage: ($percentage | tonumber)
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
