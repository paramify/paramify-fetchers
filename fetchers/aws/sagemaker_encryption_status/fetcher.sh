#!/bin/bash
#
# AWS — SageMaker Encryption
#
# For each SageMaker notebook instance, training job, and endpoint config in the
# account/region, reports KMS volume encryption and inter-container traffic
# encryption.
#
# Output: $EVIDENCE_DIR/aws_sagemaker_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_sagemaker_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_sagemaker_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_sagemaker_encryption_status_fail.XXXXXX)"
# Describe responses are appended per resource type and turned into records in
# one jq pass at the end, instead of a jq process and an output rewrite per
# resource. An ML account's training-job history is never pruned, so that
# rewrite ran over thousands of jobs.
_NOTEBOOKS_JSON="$(mktemp -t aws_sagemaker_encryption_status_nb.XXXXXX.json)"
_TRAINING_JSON="$(mktemp -t aws_sagemaker_encryption_status_tj.XXXXXX.json)"
_ENDPOINTS_JSON="$(mktemp -t aws_sagemaker_encryption_status_ec.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_NOTEBOOKS_JSON" "$_TRAINING_JSON" "$_ENDPOINTS_JSON"' EXIT

log_info() { printf '%s INFO aws_sagemaker_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_sagemaker_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"notebook_instances": [], "training_jobs": [], "endpoint_configs": []}}' \
  > "$OUTPUT_JSON"

# --- Notebook instances: KMS volume encryption ---
notebooks=$(aws sagemaker list-notebook-instances --query 'NotebookInstances[*].NotebookInstanceName' --output text 2>/dev/null)
nb_list_exit=$?
if [ $nb_list_exit -ne 0 ]; then
    echo "aws sagemaker list-notebook-instances (list) failed (exit=$nb_list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list SageMaker notebook instances"
else
    for notebook in $(aws_text_list "$notebooks"); do
        details=$(aws sagemaker describe-notebook-instance --notebook-instance-name "$notebook" 2>/dev/null)
        if [ $? -ne 0 ] || [ -z "$details" ]; then
            echo "aws sagemaker describe-notebook-instance ($notebook) failed" >> "$_FAILURE_LOG"
            continue
        fi
        printf '%s\n' "$details" >> "$_NOTEBOOKS_JSON"
    done
fi

# --- Training jobs: KMS volume encryption + inter-container traffic encryption ---
training_jobs=$(aws sagemaker list-training-jobs --query 'TrainingJobSummaries[*].TrainingJobName' --output text 2>/dev/null)
tj_list_exit=$?
if [ $tj_list_exit -ne 0 ]; then
    echo "aws sagemaker list-training-jobs (list) failed (exit=$tj_list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list SageMaker training jobs"
else
    for job in $(aws_text_list "$training_jobs"); do
        details=$(aws sagemaker describe-training-job --training-job-name "$job" 2>/dev/null)
        if [ $? -ne 0 ] || [ -z "$details" ]; then
            echo "aws sagemaker describe-training-job ($job) failed" >> "$_FAILURE_LOG"
            continue
        fi
        printf '%s\n' "$details" >> "$_TRAINING_JSON"
    done
fi

# --- Endpoint configs: KMS volume encryption at rest ---
endpoint_configs=$(aws sagemaker list-endpoint-configs --query 'EndpointConfigs[*].EndpointConfigName' --output text 2>/dev/null)
ec_list_exit=$?
if [ $ec_list_exit -ne 0 ]; then
    echo "aws sagemaker list-endpoint-configs (list) failed (exit=$ec_list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list SageMaker endpoint configs"
else
    for config in $(aws_text_list "$endpoint_configs"); do
        details=$(aws sagemaker describe-endpoint-config --endpoint-config-name "$config" 2>/dev/null)
        if [ $? -ne 0 ] || [ -z "$details" ]; then
            echo "aws sagemaker describe-endpoint-config ($config) failed" >> "$_FAILURE_LOG"
            continue
        fi
        printf '%s\n' "$details" >> "$_ENDPOINTS_JSON"
    done
fi

jq --slurpfile notebooks "$_NOTEBOOKS_JSON" --slurpfile training "$_TRAINING_JSON" --slurpfile endpoints "$_ENDPOINTS_JSON" '
    .results.notebook_instances += [$notebooks[] | {
        name: .NotebookInstanceName,
        type: "notebook_instance",
        arn: .NotebookInstanceArn,
        kms_key_id: (.KmsKeyId // "None"),
        volume_encrypted: (.KmsKeyId != null)
    }]
    | .results.training_jobs += [$training[] | {
        name: .TrainingJobName,
        type: "training_job",
        arn: .TrainingJobArn,
        volume_kms_key_id: (.ResourceConfig.VolumeKmsKeyId // "None"),
        volume_encrypted: (.ResourceConfig.VolumeKmsKeyId != null),
        inter_container_encryption: (.EnableInterContainerTrafficEncryption // false)
    }]
    | .results.endpoint_configs += [$endpoints[] | {
        name: .EndpointConfigName,
        type: "endpoint_config",
        arn: .EndpointConfigArn,
        kms_key_id: (.KmsKeyId // "None"),
        volume_encrypted: (.KmsKeyId != null)
    }]
' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
