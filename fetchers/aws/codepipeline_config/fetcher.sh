#!/bin/bash
#
# AWS — CodePipeline Configuration
#
# Lists CodePipeline pipelines and records each pipeline's stages, source
# action providers, and artifact-store KMS encryption.
#
# Output: $EVIDENCE_DIR/aws_codepipeline_config.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_codepipeline_config_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_codepipeline_config.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_codepipeline_config_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_codepipeline_config %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_codepipeline_config %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# List pipelines in the target region. An empty list is valid evidence (no
# pipelines in this region) -> not logged as a failure.
pipeline_names=$(aws codepipeline list-pipelines --query 'pipelines[*].name' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws codepipeline list-pipelines (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list pipelines"
else
    for pipeline_name in $(aws_text_list "$pipeline_names"); do
        pipeline_def=$(aws codepipeline get-pipeline --name "$pipeline_name" --output json 2>/dev/null)
        get_exit=$?
        if [ $get_exit -ne 0 ]; then
            echo "aws codepipeline get-pipeline ($pipeline_name) failed" >> "$_FAILURE_LOG"
            continue
        fi

        # Keep only the fields that demonstrate change-management config:
        # stages (with per-action source providers) and artifact-store KMS
        # encryption.
        pipeline_data=$(echo "$pipeline_def" | jq '{
            "name": .pipeline.name,
            "pipelineType": .pipeline.pipelineType,
            "stages": [.pipeline.stages[]? | {
                "name": .name,
                "actions": [.actions[]? | {
                    "name": .name,
                    "category": .actionTypeId.category,
                    "provider": .actionTypeId.provider,
                    "owner": .actionTypeId.owner
                }]
            }],
            "source_providers": [.pipeline.stages[]?.actions[]?
                | select(.actionTypeId.category == "Source")
                | .actionTypeId.provider],
            "artifactStore": (.pipeline.artifactStore // null),
            "artifactStores": (.pipeline.artifactStores // null),
            "encryption": {
                "artifactStore": (.pipeline.artifactStore.encryptionKey // null),
                "artifactStores": (
                    (.pipeline.artifactStores // {})
                    | to_entries
                    | map({"region": .key, "encryptionKey": (.value.encryptionKey // null)})
                )
            }
        }')

        jq --argjson data "$pipeline_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

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
