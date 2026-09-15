#!/bin/bash
# Verifies the new-resource detection pipeline: AWS Config recorders, the
# configured EventBridge rule (targets/schedule), the configured
# SNS topic/subscriptions, and the event-driven or scheduled trigger.
# Scheduled rules must run every 5 minutes or less.
# Output: $EVIDENCE_DIR/aws_detect_new_aws_resource.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

EVENTBRIDGE_RULE_NAME="${AWS_DETECT_NEW_RESOURCE_RULE_NAME:-New-Resource-Launched-Alert-Rule}"
SNS_TOPIC_NAME="${AWS_DETECT_NEW_RESOURCE_TOPIC_NAME:-New_AWS_Resource_Launch_Detected}"

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
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

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
rules=$(aws events list-rules --query 'Rules[*]' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws events list-rules failed" >> "$_FAILURE_LOG"
    rules='[]'
fi

rules=$(echo "$rules" | jq --arg name "$EVENTBRIDGE_RULE_NAME" '[.[] | select(.Name == $name)]')

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
    log_info "No EventBridge rule found with name '$EVENTBRIDGE_RULE_NAME'"
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
        if [[ "$topic_name" == "$SNS_TOPIC_NAME" ]]; then
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

# 4. Validate the trigger and its connection to the configured SNS topic.
log_info "Verifying EventBridge trigger and SNS target"
if jq --arg rule_name "$EVENTBRIDGE_RULE_NAME" \
      --arg topic_name "$SNS_TOPIC_NAME" \
      -f "$(dirname "$0")/validate.jq" "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON"; then
    mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
else
    echo "EventBridge validation failed" >> "$_FAILURE_LOG"
fi

# Summary (informational)
config_recording=$(jq -r '.results.aws_config.status[0].recording // "false"' "$OUTPUT_JSON")
rule_state=$(jq -r --arg name "$EVENTBRIDGE_RULE_NAME" '.results.eventbridge.rules[$name].rule.State // "DISABLED"' "$OUTPUT_JSON")
sns_topic_count=$(jq -r '.results.sns.topics | length' "$OUTPUT_JSON")
log_info "Config recording: $config_recording; EventBridge rule state: $rule_state; matching SNS topics: $sns_topic_count"

aws_finish
