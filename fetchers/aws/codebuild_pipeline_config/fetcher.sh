#!/bin/bash
#
# AWS — CodeBuild Pipeline Configuration
#
# Lists CodeBuild projects and collects each project's source, environment,
# logging configuration, and artifact encryption for change-management evidence.
#
# Output: $EVIDENCE_DIR/aws_codebuild_pipeline_config_<target>.json
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
# CodeBuild is a regional service, so the region is part of the target id.
_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_codebuild_pipeline_config_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_codebuild_pipeline_config.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_codebuild_pipeline_config_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_codebuild_pipeline_config %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_codebuild_pipeline_config %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# --- per-script data collection (ported from prowler codebuild_service) ---

# List all project names in this region. An empty list is valid evidence
# (no CodeBuild projects) -> not logged as a failure.
project_names=$(aws codebuild list-projects --query 'projects[*]' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws codebuild list-projects failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list CodeBuild projects"
else
    for project_name in $(aws_text_list "$project_names"); do
        # batch-get-projects returns the full project config; keep only the
        # KSI-CMT-VTD fields: source, environment, logging, artifact encryption.
        project_info=$(aws codebuild batch-get-projects \
            --names "$project_name" \
            --query 'projects[0]' \
            --output json 2>/dev/null)
        get_exit=$?
        if [ $get_exit -ne 0 ]; then
            echo "aws codebuild batch-get-projects ($project_name) failed (exit=$get_exit)" >> "$_FAILURE_LOG"
            continue
        fi

        project_data=$(echo "$project_info" | jq '{
            name: .name,
            arn: .arn,
            serviceRole: .serviceRole,
            projectVisibility: .projectVisibility,
            source: {
                type: (.source.type // null),
                location: (.source.location // null),
                buildspec: (.source.buildspec // null),
                gitCloneDepth: (.source.gitCloneDepth // null)
            },
            environment: {
                type: (.environment.type // null),
                image: (.environment.image // null),
                computeType: (.environment.computeType // null),
                privilegedMode: (.environment.privilegedMode),
                imagePullCredentialsType: (.environment.imagePullCredentialsType // null)
            },
            artifacts: {
                type: (.artifacts.type // null),
                location: (.artifacts.location // null),
                encryptionDisabled: (.artifacts.encryptionDisabled)
            },
            encryptionKey: (.encryptionKey // null),
            logsConfig: {
                cloudWatchLogs: {
                    status: (.logsConfig.cloudWatchLogs.status // "DISABLED"),
                    groupName: (.logsConfig.cloudWatchLogs.groupName // null),
                    streamName: (.logsConfig.cloudWatchLogs.streamName // null)
                },
                s3Logs: {
                    status: (.logsConfig.s3Logs.status // "DISABLED"),
                    location: (.logsConfig.s3Logs.location // null),
                    encryptionDisabled: (.logsConfig.s3Logs.encryptionDisabled)
                }
            }
        }')

        jq --argjson data "$project_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
