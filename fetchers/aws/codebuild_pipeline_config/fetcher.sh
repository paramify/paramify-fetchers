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

_PROJECTS_JSON="$(mktemp -t aws_codebuild_pipeline_config_projects.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_PROJECTS_JSON"' EXIT

# List all project names in this region. An empty list is valid evidence
# (no CodeBuild projects) -> not logged as a failure.
project_names=$(aws codebuild list-projects --query 'projects[*]' --output json 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws codebuild list-projects failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list CodeBuild projects"
else
    # batch-get-projects takes up to 100 names per call; it was being called with
    # one name at a time. A failed batch skips its projects, as a failed
    # single-name call skipped one.
    while read -r batch; do
        [ -z "$batch" ] && continue
        # shellcheck disable=SC2086  # batch is space-separated project names (no spaces allowed in them)
        batch_info=$(aws codebuild batch-get-projects --names $batch --query 'projects' --output json 2>/dev/null)
        get_exit=$?
        if [ $get_exit -ne 0 ]; then
            echo "aws codebuild batch-get-projects ($batch) failed (exit=$get_exit)" >> "$_FAILURE_LOG"
            continue
        fi
        printf '%s\n' "$batch_info" >> "$_PROJECTS_JSON"
    done < <(printf '%s' "$project_names" | jq -r '[.[]?] | _nwise(100) | join(" ")')

    # batch-get-projects returns the full project config; keep only the
    # KSI-CMT-VTD fields: source, environment, logging, artifact encryption.
    # Rows follow list-projects order, whatever order a batch came back in.
    printf '%s' "$project_names" | jq --slurpfile names /dev/stdin --slurpfile batches "$_PROJECTS_JSON" '
        (reduce ($batches | add // [])[] as $p ({}; .[$p.name] = $p)) as $by_name
        | .results += [$names[0][]? | $by_name[.] | select(. != null) | {
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
        }]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

aws_finish
