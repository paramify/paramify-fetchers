#!/bin/bash
# Checks AWS Config setup (configuration recorders, recorder status, delivery
# channels) and summarizes recording/health state.
# Output: $EVIDENCE_DIR/aws_config_monitoring.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_config_monitoring_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_config_monitoring.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_config_monitoring_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_config_monitoring %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_config_monitoring %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"configuration_recorders": [], "recorder_status": [], "delivery_channels": [], "summary": {}}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream) ---

log_info "Checking AWS Config setup"

# Get configuration recorder status. Empty arrays are valid evidence (Config
# not set up in this region) -> not logged as failures.
recorder_status=$(aws configservice describe-configuration-recorder-status --query 'ConfigurationRecordersStatus[*]' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws configservice describe-configuration-recorder-status failed" >> "$_FAILURE_LOG"
    recorder_status='[]'
fi

config_recorders=$(aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[*]' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws configservice describe-configuration-recorders failed" >> "$_FAILURE_LOG"
    config_recorders='[]'
fi

delivery_channels=$(aws configservice describe-delivery-channels --query 'DeliveryChannels[*]' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws configservice describe-delivery-channels failed" >> "$_FAILURE_LOG"
    delivery_channels='[]'
fi

# Compute summary values from API responses (before single jq write so summary is never missing)
recording_status=$(echo "$recorder_status" | jq -r 'if .[0].recording == true then "true" else "false" end')
recorder_count=$(echo "$config_recorders" | jq 'length')
channel_count=$(echo "$delivery_channels" | jq 'length')
all_resources=$(echo "$config_recorders" | jq -r '.[0].recordingGroup.allSupported // false')
global_resources=$(echo "$config_recorders" | jq -r '.[0].recordingGroup.includeGlobalResourceTypes // .[0].recordingGroup.includeGlobalResources // false')
last_status=$(echo "$recorder_status" | jq -r '.[0].lastStatus // "N/A"')
last_error=$(echo "$recorder_status" | jq -r '.[0].lastErrorCode // "NONE"')
s3_bucket=$(echo "$delivery_channels" | jq -r '.[0].s3BucketName // "N/A"')
sns_topic=$(echo "$delivery_channels" | jq -r '.[0].snsTopicARN // "N/A"')
delivery_freq=$(echo "$delivery_channels" | jq -r '.[0].configSnapshotDeliveryProperties.deliveryFrequency // "N/A"')

# Write results and summary in a single jq so validation (recording_enabled + HEALTHY) always sees summary
jq --argjson status "$recorder_status" \
   --argjson recorders "$config_recorders" \
   --argjson channels "$delivery_channels" \
   --arg rec_status "$recording_status" \
   --arg ch_count "$channel_count" \
   --arg rec_count "$recorder_count" \
   --arg all_res "$all_resources" \
   --arg global_res "$global_resources" \
   --arg last_stat "$last_status" \
   --arg last_err "$last_error" \
   --arg s3 "$s3_bucket" \
   --arg sns "$sns_topic" \
   --arg freq "$delivery_freq" \
   '.results = {
       "configuration_recorders": ($recorders // []),
       "recorder_status": ($status // []),
       "delivery_channels": ($channels // []),
       "summary": {
         "basic_status": {
           "recording_enabled": $rec_status,
           "delivery_channels_configured": $ch_count
         },
         "configuration_details": {
           "recorder_count": $rec_count,
           "all_resources_recorded": $all_res,
           "global_resources_included": $global_res
         },
         "status_details": {
           "last_status": $last_stat,
           "last_error": $last_err
         },
         "delivery_details": {
           "s3_bucket": $s3,
           "sns_topic": $sns,
           "delivery_frequency": $freq
         },
         "health_assessment": {
           "status": (if $rec_status == "true" and $ch_count != "0" then "HEALTHY" else "REQUIRES_ATTENTION" end),
           "issues": (if $rec_status != "true" then ["recording_disabled"] else [] end + if $ch_count == "0" then ["no_delivery_channel"] else [] end)
         }
       }
   }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

log_info "Recording status: $recording_status; recorders: $recorder_count; delivery channels: $channel_count"

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
