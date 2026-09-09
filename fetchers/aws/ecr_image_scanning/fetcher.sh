#!/bin/bash
# KSI-SCR-MON: Lists AWS ECR repositories with their image scan-on-push configuration,
# the registry scanning type/frequency, and a summary of the latest image scan findings.
#
# Output: $EVIDENCE_DIR/aws_ecr_image_scanning.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_ecr_image_scanning_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_ecr_image_scanning.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_ecr_image_scanning_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_ecr_image_scanning %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_ecr_image_scanning %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"registry_scanning": {}, "repositories": []}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from prowler ecr_service.py) ---

# Registry-level scanning configuration: scan type (BASIC/ENHANCED) and rules
# (scan frequency + filters). A disabled feature surfaces as a ValidationException;
# Prowler treats that as scan_type=BASIC with no rules rather than a failure.
_SCAN_ERR="$(mktemp -t aws_ecr_image_scanning_scan.XXXXXX)"
scanning_config=$(aws ecr get-registry-scanning-configuration --output json 2>"$_SCAN_ERR")
ec=$?
if [ $ec -ne 0 ]; then
    if grep -q 'ValidationException' "$_SCAN_ERR"; then
        log_info "Registry scanning configuration unavailable in $REGION (defaulting to BASIC)"
        scanning_config='{"scanningConfiguration":{"scanType":"BASIC","rules":[]}}'
    else
        echo "aws ecr get-registry-scanning-configuration failed (exit=$ec): $(tr '\n' ' ' < "$_SCAN_ERR")" >> "$_FAILURE_LOG"
        scanning_config='{"scanningConfiguration":{"scanType":"BASIC","rules":[]}}'
    fi
fi
rm -f "$_SCAN_ERR"

registry_scanning=$(echo "$scanning_config" | jq '{
    scan_type: (.scanningConfiguration.scanType // "BASIC"),
    rules: [ (.scanningConfiguration.rules // [])[] | {
        scan_frequency: .scanFrequency,
        scan_filters: (.repositoryFilters // [])
    } ]
}')
jq --argjson rs "$registry_scanning" '.results.registry_scanning = $rs' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

# List repositories with their per-repository image scanning configuration.
repositories=$(aws ecr describe-repositories --output json 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws ecr describe-repositories (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list ECR repositories"
else
    echo "$repositories" | jq -c '.repositories[]?' | while read -r repo; do
        repo_name=$(echo "$repo" | jq -r '.repositoryName')
        scan_on_push=$(echo "$repo" | jq -r '.imageScanningConfiguration.scanOnPush // false')

        repo_data=$(echo "$repo" | jq '{
            name: .repositoryName,
            arn: .repositoryArn,
            registry_id: .registryId,
            scan_on_push: (.imageScanningConfiguration.scanOnPush // false),
            immutability: (.imageTagMutability // "MUTABLE"),
            latest_image_scan: null
        }')

        # Only inspect scan findings when scan-on-push is enabled (Prowler skips
        # repositories that are not scanning pushed images).
        if [ "$scan_on_push" = "true" ]; then
            # Identify the most recently pushed image to summarize its scan findings.
            latest_digest=$(aws ecr describe-images \
                --repository-name "$repo_name" \
                --query 'reverse(sort_by(imageDetails,&imagePushedAt))[0].imageDigest' \
                --output text 2>/dev/null)
            img_exit=$?
            if [ $img_exit -ne 0 ]; then
                echo "aws ecr describe-images ($repo_name) failed (exit=$img_exit)" >> "$_FAILURE_LOG"
            elif [ -n "$latest_digest" ] && [ "$latest_digest" != "None" ]; then
                _FIND_ERR="$(mktemp -t aws_ecr_image_scanning_find.XXXXXX)"
                findings=$(aws ecr describe-image-scan-findings \
                    --repository-name "$repo_name" \
                    --image-id imageDigest="$latest_digest" \
                    --output json 2>"$_FIND_ERR")
                find_exit=$?
                if [ $find_exit -ne 0 ]; then
                    # No completed scan for the image is meaningful evidence, not a failure.
                    if grep -qE 'ScanNotFoundException|ImageNotFoundException' "$_FIND_ERR"; then
                        scan_summary=$(jq -n --arg d "$latest_digest" '{
                            image_digest: $d, scan_status: "NOT_SCANNED",
                            severity_counts: {critical: 0, high: 0, medium: 0}
                        }')
                    else
                        echo "aws ecr describe-image-scan-findings ($repo_name) failed (exit=$find_exit): $(tr '\n' ' ' < "$_FIND_ERR")" >> "$_FAILURE_LOG"
                        scan_summary=null
                    fi
                else
                    scan_summary=$(echo "$findings" | jq '{
                        image_digest: .imageId.imageDigest,
                        scan_status: (.imageScanStatus.status // null),
                        severity_counts: {
                            critical: (.imageScanFindings.findingSeverityCounts.CRITICAL // 0),
                            high: (.imageScanFindings.findingSeverityCounts.HIGH // 0),
                            medium: (.imageScanFindings.findingSeverityCounts.MEDIUM // 0)
                        }
                    }')
                fi
                rm -f "$_FIND_ERR"
                repo_data=$(echo "$repo_data" | jq --argjson scan "$scan_summary" '.latest_image_scan = $scan')
            fi
        fi

        jq --argjson data "$repo_data" '.results.repositories += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
