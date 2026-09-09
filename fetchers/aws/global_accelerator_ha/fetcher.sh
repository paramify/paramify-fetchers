#!/bin/bash
#
# AWS — Global Accelerator High Availability
#
# Lists Global Accelerator accelerators and, per accelerator, their listeners
# and endpoint groups (multi-region HA posture).
#
# Output: $EVIDENCE_DIR/aws_global_accelerator_ha.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq
#
# Global Accelerator is a global service; the AWS CLI must target us-west-2 to
# work with accelerators, so these calls pin --region us-west-2 regardless of
# the ambient region. The output filename is profile-scoped (no region suffix).

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

# Identity/region come from the AWS CLI credential chain. A manifest target may
# set AWS_PROFILE/AWS_DEFAULT_REGION (multi-account fanout); when unset, the CLI
# uses the ambient identity. The helper sets PROFILE/REGION (for metadata) and
# provides aws_target_id (for the output filename).
source "$(dirname "$0")/../_shared/aws.sh"

# Global Accelerator API endpoint lives in us-west-2; pin it on every call.
GA_REGION="us-west-2"

# Global service: profile-scoped filename (no region suffix) so a multi-account
# fanout stays distinct while regional duplication is avoided.
_TARGET_ID="$(aws_target_id)"
OUTPUT_JSON="$OUTPUT_DIR/aws_global_accelerator_ha_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_global_accelerator_ha.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_global_accelerator_ha_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_global_accelerator_ha %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_global_accelerator_ha %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

_LIST_ERR="$(mktemp -t aws_global_accelerator_ha_lerr.XXXXXX)"
accelerators=$(aws globalaccelerator list-accelerators --region "$GA_REGION" --query 'Accelerators[*]' --output json 2>"$_LIST_ERR")
acc_exit=$?
if [ $acc_exit -ne 0 ] && aws_service_unavailable "$_LIST_ERR"; then
    # Global Accelerator is not subscribed/enabled for this account. This is a
    # valid "service not in use" evidence outcome, not a collection failure.
    log_info "Global Accelerator is not subscribed for this account; recording not-subscribed status"
    jq '.results += [{"Type": "ServiceStatus", "Service": "GlobalAccelerator", "Status": "NotSubscribed", "Detail": "ListAccelerators reported the service as unavailable to this account (not subscribed or not enabled)."}]' \
       "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    rm -f "$_LIST_ERR"
elif [ $acc_exit -ne 0 ]; then
    echo "aws globalaccelerator list-accelerators failed (exit=$acc_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list accelerators"
    rm -f "$_LIST_ERR"
else
    rm -f "$_LIST_ERR"
    echo "$accelerators" | jq -c '.[]' | while read -r accelerator; do
        accelerator_arn=$(echo "$accelerator" | jq -r '.AcceleratorArn')

        listeners=$(aws globalaccelerator list-listeners --accelerator-arn "$accelerator_arn" --region "$GA_REGION" --query 'Listeners[*]' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws globalaccelerator list-listeners ($accelerator_arn) failed" >> "$_FAILURE_LOG"
            listeners='[]'
        fi

        listeners_with_groups=$(echo "$listeners" | jq -c '.[]' | while read -r listener; do
            listener_arn=$(echo "$listener" | jq -r '.ListenerArn')

            endpoint_groups=$(aws globalaccelerator list-endpoint-groups --listener-arn "$listener_arn" --region "$GA_REGION" --query 'EndpointGroups[*]' --output json 2>/dev/null)
            if [ $? -ne 0 ]; then
                echo "aws globalaccelerator list-endpoint-groups ($listener_arn) failed" >> "$_FAILURE_LOG"
                endpoint_groups='[]'
            fi

            echo "$listener" | jq --argjson groups "$endpoint_groups" '. + {"EndpointGroups": $groups}'
        done | jq -s '.')

        jq --argjson acc "$accelerator" --argjson listeners "$listeners_with_groups" \
           '.results += [{"Type": "Accelerator", "AcceleratorInfo": $acc, "Listeners": $listeners}]' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
