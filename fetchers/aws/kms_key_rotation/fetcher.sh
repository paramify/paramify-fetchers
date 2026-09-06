#!/bin/bash
#
# AWS — KMS Key Rotation
#
# For each KMS key, reports rotation status, state/usage, and policy.
# Includes the AWS Config rule compliance for cmk-backing-key-rotation-enabled.
#
# A key whose policy denies the collecting identity is reported with
# rotation_status "unreadable" and a collection_error, and is left out of the
# rotation coverage denominator -- it does not fail the run. Only list-keys, the
# caller identity, or every key being unreadable fails collection (GH #44).
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
_CALL_ERR="$(mktemp -t aws_kms_key_rotation_err.XXXXXX)"
trap 'rm -f "$_FAILURE_LOG" "$_CALL_ERR" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_kms_key_rotation %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_kms_key_rotation %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

# key_call_error <label> -- one-line reason for a failed per-key call, read from
# $_CALL_ERR. Prefers the AWS error code botocore names ("AccessDeniedException")
# and falls back to the trimmed stderr, so the note on the key says what the API
# actually refused rather than just that something went wrong.
key_call_error() {
    local label="$1" code text
    code=$(sed -n 's/.*An error occurred (\([A-Za-z]*\)).*/\1/p' "$_CALL_ERR" | head -1)
    if [ -z "$code" ]; then
        text=$(tr '\n\r\t' '   ' < "$_CALL_ERR" | tr -s ' ' | sed 's/^ *//;s/ *$//' | cut -c1-200)
        code="${text:-call failed}"
    fi
    printf '%s on %s' "$code" "$label"
}

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
readable_keys=0
rotated_keys=0
unreadable_keys=0
kms_results=()

key_ids=$(aws kms list-keys --query "Keys[*].KeyId" --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws kms list-keys failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list KMS keys"
else
    for key_id in $key_ids; do
        [ -z "$key_id" ] && continue
        total_keys=$((total_keys + 1))

        # A key's own policy can deny the collecting identity -- an AWS-managed
        # key such as alias/aws/acm, or a customer key whose policy scopes out
        # the readonly role. That is a property of the key, not a failure of the
        # run: the reason is recorded on the key and the other keys still
        # collect. Only list-keys and the caller identity fail the fetcher.
        key_error=""

        key_details=$(aws kms describe-key --key-id "$key_id" 2>"$_CALL_ERR")
        if [ $? -ne 0 ]; then
            key_error="${key_error:+$key_error; }$(key_call_error DescribeKey)"
            key_details='{"KeyMetadata": {}}'
        fi

        # rotation_enabled stays null when the status could not be read. The old
        # `false` fallback asserted "not rotated" about a key never actually
        # read, and dragged down the coverage percentage with it.
        rotation_status="unreadable"
        is_rotated="null"
        key_rotation_status=$(aws kms get-key-rotation-status --key-id "$key_id" 2>"$_CALL_ERR")
        if [ $? -ne 0 ]; then
            key_error="${key_error:+$key_error; }$(key_call_error GetKeyRotationStatus)"
            unreadable_keys=$((unreadable_keys + 1))
        else
            readable_keys=$((readable_keys + 1))
            if [ "$(echo "$key_rotation_status" | jq -r '.KeyRotationEnabled // false')" = "true" ]; then
                rotation_status="enabled"
                is_rotated="true"
                rotated_keys=$((rotated_keys + 1))
            else
                rotation_status="disabled"
                is_rotated="false"
            fi
        fi

        key_arn=$(echo "$key_details" | jq -r '.KeyMetadata.Arn // "Unknown"')
        key_state=$(echo "$key_details" | jq -r '.KeyMetadata.KeyState // "Unknown"')
        key_usage=$(echo "$key_details" | jq -r '.KeyMetadata.KeyUsage // "Unknown"')

        key_policy=$(aws kms get-key-policy --key-id "$key_id" --policy-name default 2>"$_CALL_ERR")
        if [ $? -ne 0 ]; then
            key_error="${key_error:+$key_error; }$(key_call_error GetKeyPolicy)"
            key_policy='{}'
        fi

        kms_results+=("$(jq -n \
            --arg id "$key_id" --arg arn "$key_arn" --arg state "$key_state" --arg usage "$key_usage" \
            --argjson rotated "$is_rotated" --arg rotation_status "$rotation_status" \
            --argjson policy "$key_policy" --arg collection_error "$key_error" \
            '{key_id: $id, key_arn: $arn, key_state: $state, key_usage: $usage,
              rotation_enabled: $rotated, rotation_status: $rotation_status,
              key_policy: $policy}
             + (if $collection_error == "" then {} else {collection_error: $collection_error} end)')")
    done
fi

# Keys exist but not one rotation status could be read: the rotation evidence is
# empty, which is a problem with the collecting identity rather than a per-key
# quirk. Fail rather than report 0-of-0 coverage as a clean run.
if [ "$total_keys" -gt 0 ] && [ "$readable_keys" -eq 0 ]; then
    echo "aws kms get-key-rotation-status failed for all $total_keys key(s)" >> "$_FAILURE_LOG"
    log_error "Could not read rotation status for any of the $total_keys KMS key(s)"
fi

percentage=0
[ $readable_keys -gt 0 ] && percentage=$(( (rotated_keys * 100) / readable_keys ))

jq -n \
    --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
    --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
    --argjson keys "[$(IFS=,; echo "${kms_results[*]}")]" \
    --argjson config "$config_compliance" \
    --arg total "$total_keys" --arg readable "$readable_keys" --arg unreadable "$unreadable_keys" \
    --arg rotated "$rotated_keys" --arg percentage "$percentage" \
    '{
        metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn},
        results: {
            kms_keys: {object: $keys},
            config_rule: $config,
            summary: {
                total_keys: ($total | tonumber),
                readable_keys: ($readable | tonumber),
                unreadable_keys: ($unreadable | tonumber),
                rotated_keys: ($rotated | tonumber),
                rotation_percentage: ($percentage | tonumber)
            }
        }
    }' > "$OUTPUT_JSON"

aws_finish
