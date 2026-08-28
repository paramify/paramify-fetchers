#!/bin/bash
# Verifies the new-resource detection pipeline: AWS Config recorders, the
# New-Resource-Launched-Alert-Rule EventBridge rule (targets/schedule), the
# New_AWS_Resource_Launch_Detected SNS topic/subscriptions, and that the
# monitoring interval is 5 minutes or less.
# Output: $EVIDENCE_DIR/aws_detect_new_aws_resource.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_detect_new_aws_resource_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_detect_new_aws_resource.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_detect_new_aws_resource_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_detect_new_aws_resource %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_detect_new_aws_resource %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"aws_config": {"recorders": [], "status": [], "delivery_channels": []}, "eventbridge": {"rules": {}}, "sns": {"topics": {}}, "validation_results": {"interval_checks": {}}}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream) ---

# 1. Check AWS Config setup. Empty arrays are valid evidence (not configured).
log_info "Checking AWS Config setup"
config_recorders=$(aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[*]' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws configservice describe-configuration-recorders failed" >> "$_FAILURE_LOG"
    config_recorders='[]'
fi
recorder_status=$(aws configservice describe-configuration-recorder-status --query 'ConfigurationRecordersStatus[*]' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws configservice describe-configuration-recorder-status failed" >> "$_FAILURE_LOG"
    recorder_status='[]'
fi
delivery_channels=$(aws configservice describe-delivery-channels --query 'DeliveryChannels[*]' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws configservice describe-delivery-channels failed" >> "$_FAILURE_LOG"
    delivery_channels='[]'
fi

jq --argjson recorders "$config_recorders" \
   --argjson status "$recorder_status" \
   --argjson channels "$delivery_channels" \
   '.results.aws_config = {
       "recorders": ($recorders // []),
       "status": ($status // []),
       "delivery_channels": ($channels // [])
   }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

# 2. Check EventBridge rule for new resource detection.
log_info "Checking EventBridge rules"
rules=$(aws events list-rules --name "New-Resource-Launched-Alert-Rule" --query 'Rules[*]' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws events list-rules failed" >> "$_FAILURE_LOG"
    rules='[]'
fi

# Absence of the rule is valid evidence (control not in place) -> not a failure.
if [ "$(echo "$rules" | jq 'length')" -gt 0 ]; then
    echo "$rules" | jq -c '.[]' | while read -r rule; do
        rule_name=$(echo "$rule" | jq -r '.Name')

        # Get rule targets
        targets=$(aws events list-targets-by-rule --rule "$rule_name" --query 'Targets[*]' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws events list-targets-by-rule ($rule_name) failed" >> "$_FAILURE_LOG"
            targets='[]'
        fi

        # Get rule details including schedule
        rule_details=$(aws events describe-rule --name "$rule_name" --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws events describe-rule ($rule_name) failed" >> "$_FAILURE_LOG"
            rule_details='{}'
        fi
        schedule=$(echo "$rule_details" | jq -r '.ScheduleExpression // empty')

        jq --arg name "$rule_name" \
           --argjson targets "$targets" \
           --arg schedule "$schedule" \
           --argjson rule "$rule" \
           '.results.eventbridge.rules[$name] = {
               "rule": $rule,
               "targets": ($targets // []),
               "schedule": $schedule
           }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
else
    log_info "No EventBridge rule found with name 'New-Resource-Launched-Alert-Rule'"
fi

# 3. Check SNS topics and subscriptions.
log_info "Checking SNS topics"
topics=$(aws sns list-topics --query 'Topics[*]' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sns list-topics failed" >> "$_FAILURE_LOG"
    topics='[]'
fi

# Absence of the target topic is valid evidence -> not a failure.
if [ "$(echo "$topics" | jq 'length')" -gt 0 ]; then
    echo "$topics" | jq -c '.[]' | while read -r topic; do
        topic_arn=$(echo "$topic" | jq -r '.TopicArn')
        topic_name=$(echo "$topic_arn" | awk -F':' '{print $NF}')

        # Only process the specific topic
        if [[ "$topic_name" == "New_AWS_Resource_Launch_Detected" ]]; then
            subscriptions=$(aws sns list-subscriptions-by-topic --topic-arn "$topic_arn" --query 'Subscriptions[*]' --output json 2>/dev/null)
            if [ $? -ne 0 ]; then
                echo "aws sns list-subscriptions-by-topic ($topic_name) failed" >> "$_FAILURE_LOG"
                subscriptions='[]'
            fi

            jq --arg name "$topic_name" \
               --argjson topic "$topic" \
               --argjson subs "$subscriptions" \
               '.results.sns.topics[$name] = {
                   "topic": $topic,
                   "subscriptions": ($subs // [])
               }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
        fi
    done
else
    log_info "No SNS topics found"
fi

# 4. Verify monitoring interval (schedule must be 5 minutes or less).
log_info "Verifying monitoring intervals"
if [ "$(jq -r '.results.eventbridge.rules | length' "$OUTPUT_JSON")" -gt 0 ]; then
    jq -r '.results.eventbridge.rules | keys[]' "$OUTPUT_JSON" | while read -r rule_name; do
        schedule=$(jq -r --arg name "$rule_name" '.results.eventbridge.rules[$name].schedule' "$OUTPUT_JSON")

        if [[ "$schedule" == *"rate(5 minutes)"* ]] || [[ "$schedule" == *"rate(1 minute)"* ]] || [[ "$schedule" == *"rate(2 minutes)"* ]] || [[ "$schedule" == *"rate(3 minutes)"* ]] || [[ "$schedule" == *"rate(4 minutes)"* ]]; then
            interval_check="PASS"
        else
            interval_check="FAIL"
        fi

        jq --arg name "$rule_name" \
           --arg check "$interval_check" \
           --arg schedule "$schedule" \
           '.results.validation_results.interval_checks[$name] = {
               "status": $check,
               "schedule": $schedule
           }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
else
    log_info "No EventBridge rules found to check intervals"
fi

# Summary (informational)
config_recording=$(jq -r '.results.aws_config.status[0].recording // "false"' "$OUTPUT_JSON")
rule_state=$(jq -r '.results.eventbridge.rules["New-Resource-Launched-Alert-Rule"].rule.State // "DISABLED"' "$OUTPUT_JSON")
sns_topic_count=$(jq -r '.results.sns.topics | length' "$OUTPUT_JSON")
log_info "Config recording: $config_recording; EventBridge rule state: $rule_state; matching SNS topics: $sns_topic_count"

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
