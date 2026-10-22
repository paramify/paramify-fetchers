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
_KEY_IDS="$(mktemp -t aws_kms_key_rotation_ids.XXXXXX)"
_KEY_ERRORS="$(mktemp -t aws_kms_key_rotation_errors.XXXXXX)"
_KEY_RESPONSES="$(mktemp -t aws_kms_key_rotation_responses.XXXXXX.json)"
_CONFIG_JSON="$(mktemp -t aws_kms_key_rotation_config.XXXXXX.json)"
trap 'rm -f "$_FAILURE_LOG" "$_CALL_ERR" "$_AWS_ERR_LOG" "$_KEY_IDS" "$_KEY_ERRORS" "$_KEY_RESPONSES" "$_CONFIG_JSON"' EXIT

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

# There is no batch form of describe-key, get-key-rotation-status or
# get-key-policy, so each key still costs three calls. What the loop no longer
# does is spawn jq: each key's raw responses are appended in a fixed order
# (details, rotation status or null, policy) and its error note as one line,
# and a single jq pass below builds every record. That pass reads files, not
# --argjson: every key policy on one command line overflows Linux's 128 KiB
# argv limit at around 60 keys.
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
        if [ $? -ne 0 ] || [ -z "$key_details" ]; then
            key_error="${key_error:+$key_error; }$(key_call_error DescribeKey)"
            key_details='{"KeyMetadata": {}}'
        fi

        # rotation_enabled stays null when the status could not be read. The old
        # `false` fallback asserted "not rotated" about a key never actually
        # read, and dragged down the coverage percentage with it.
        key_rotation_status=$(aws kms get-key-rotation-status --key-id "$key_id" 2>"$_CALL_ERR")
        if [ $? -ne 0 ] || [ -z "$key_rotation_status" ]; then
            key_error="${key_error:+$key_error; }$(key_call_error GetKeyRotationStatus)"
            key_rotation_status='null'
        else
            readable_keys=$((readable_keys + 1))
        fi

        key_policy=$(aws kms get-key-policy --key-id "$key_id" --policy-name default 2>"$_CALL_ERR")
        if [ $? -ne 0 ] || [ -z "$key_policy" ]; then
            key_error="${key_error:+$key_error; }$(key_call_error GetKeyPolicy)"
            key_policy='{}'
        fi

        printf '%s\n' "$key_id" >> "$_KEY_IDS"
        printf '%s\n' "$key_error" >> "$_KEY_ERRORS"
        printf '%s\n%s\n%s\n' "$key_details" "$key_rotation_status" "$key_policy" >> "$_KEY_RESPONSES"
    done
fi

# Keys exist but not one rotation status could be read: the rotation evidence is
# empty, which is a problem with the collecting identity rather than a per-key
# quirk. Fail rather than report 0-of-0 coverage as a clean run.
if [ "$total_keys" -gt 0 ] && [ "$readable_keys" -eq 0 ]; then
    echo "aws kms get-key-rotation-status failed for all $total_keys key(s)" >> "$_FAILURE_LOG"
    log_error "Could not read rotation status for any of the $total_keys KMS key(s)"
fi

printf '%s' "$config_compliance" > "$_CONFIG_JSON"

jq -n \
    --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
    --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
    --rawfile ids "$_KEY_IDS" --rawfile errors "$_KEY_ERRORS" \
    --slurpfile responses "$_KEY_RESPONSES" --slurpfile config "$_CONFIG_JSON" \
    '($ids | split("\n")) as $ids
    | ($errors | split("\n")) as $errors
    | [range(0; ($responses | length) / 3) as $i
        | $responses[3 * $i] as $details
        | $responses[3 * $i + 1] as $rotation
        | (if $rotation == null then null
           elif ($rotation.KeyRotationEnabled // false) == true then true
           else false end) as $rotated
        | {key_id: $ids[$i],
           key_arn: ($details.KeyMetadata.Arn // "Unknown"),
           key_state: ($details.KeyMetadata.KeyState // "Unknown"),
           key_usage: ($details.KeyMetadata.KeyUsage // "Unknown"),
           rotation_enabled: $rotated,
           rotation_status: (if $rotated == null then "unreadable" elif $rotated then "enabled" else "disabled" end),
           key_policy: $responses[3 * $i + 2]}
          + (if $errors[$i] == "" then {} else {collection_error: $errors[$i]} end)
      ] as $keys
    | ($keys | length) as $total
    | ([$keys[] | select(.rotation_enabled != null)] | length) as $readable
    | ([$keys[] | select(.rotation_enabled == true)] | length) as $rotated
    | {
        metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn},
        results: {
            kms_keys: {object: $keys},
            config_rule: $config[0],
            summary: {
                total_keys: $total,
                readable_keys: $readable,
                unreadable_keys: ($total - $readable),
                rotated_keys: $rotated,
                rotation_percentage: (if $readable > 0 then ($rotated * 100 / $readable | floor) else 0 end)
            }
        }
    }' > "$OUTPUT_JSON"

aws_finish
