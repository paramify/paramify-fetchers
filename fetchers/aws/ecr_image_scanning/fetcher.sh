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
_REPOS_STREAM="$(mktemp -t aws_ecr_image_scanning_repos.XXXXXX.json)"
_CONFIG_STREAM="$(mktemp -t aws_ecr_image_scanning_config.XXXXXX.json)"
_CONFIG_ERR="$(mktemp -t aws_ecr_image_scanning_config_err.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_REPOS_STREAM" "$_CONFIG_STREAM" "$_CONFIG_ERR"' EXIT

log_info() { printf '%s INFO aws_ecr_image_scanning %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_ecr_image_scanning %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
if ! echo "$CALLER_IDENTITY" | jq -e '.Account | type == "string" and test("^[0-9]{12}$")' >/dev/null; then
    echo "aws sts get-caller-identity returned invalid identity" >> "$_FAILURE_LOG"
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

# Registry scanning configuration is independent of the existence of scan results.
_SCAN_ERR="$(mktemp -t aws_ecr_image_scanning_scan.XXXXXX)"
scanning_config=$(aws ecr get-registry-scanning-configuration --output json 2>"$_SCAN_ERR")
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws ecr get-registry-scanning-configuration failed (exit=$ec): $(tr '\n' ' ' < "$_SCAN_ERR")" >> "$_FAILURE_LOG"
    scanning_config='{}'
fi
if ! echo "$scanning_config" | jq -e '.scanningConfiguration.scanType | . == "BASIC" or . == "ENHANCED"' >/dev/null; then
    echo "aws ecr get-registry-scanning-configuration returned no scanning configuration" >> "$_FAILURE_LOG"
    scanning_config='{}'
fi
rm -f "$_SCAN_ERR"

registry_scanning=$(echo "$scanning_config" | jq '{
    scan_type: (.scanningConfiguration.scanType // null),
    rules: [ (.scanningConfiguration.rules // [])[] | {
        scan_frequency: .scanFrequency,
        scan_filters: (.repositoryFilters // [])
    } ]
}')
jq --argjson rs "$registry_scanning" '.results.registry_scanning = $rs' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

# List repositories with their per-repository image scanning configuration.
repositories=$(aws ecr describe-repositories --output json 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ] || ! echo "$repositories" | jq -e '.repositories | type == "array"' >/dev/null; then
    echo "aws ecr describe-repositories (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list ECR repositories"
else
    # AWS resolves overlapping registry filters; batch requests accept 25 names.
    echo "$repositories" | jq -c '[.repositories[].repositoryName] | range(0; length; 25) as $i | {repositoryNames: .[$i:$i+25]}' | while read -r batch; do
        config=$(aws ecr batch-get-repository-scanning-configuration --cli-input-json "$batch" --output json 2>"$_CONFIG_ERR")
        if [ $? -ne 0 ]; then
            echo "aws ecr batch-get-repository-scanning-configuration failed for $batch: $(tr '\n' ' ' < "$_CONFIG_ERR")" >> "$_FAILURE_LOG"
        elif ! echo "$config" | jq -e '(.scanningConfigurations | type == "array") and (.failures // [] | type == "array")' >/dev/null; then
            echo "aws ecr batch-get-repository-scanning-configuration returned invalid data for $batch: $config" >> "$_FAILURE_LOG"
        else
            echo "$config" | jq -cr '.failures[]? | "aws ecr batch-get-repository-scanning-configuration: \(tojson)"' >> "$_FAILURE_LOG"
            echo "$config" | jq -c '.scanningConfigurations[]' >> "$_CONFIG_STREAM"
        fi
    done
    # Join configs once, rather than parsing/searching the full stream per repo.
    echo "$repositories" | jq -c --slurpfile configs "$_CONFIG_STREAM" '
        (reduce $configs[] as $c ({}; .[$c.repositoryName] = $c)) as $by_name
        | .repositories[]?
        | . + {effective_scanning: ($by_name[.repositoryName] // null), scan_collection_status: "empty_repository"}
    ' | while read -r repo; do
        repo_name=$(echo "$repo" | jq -r '.repositoryName')
        if ! echo "$repo" | jq -e '.effective_scanning != null' >/dev/null; then
            echo "No effective scanning configuration returned for $repo_name" >> "$_FAILURE_LOG"
        fi

        # null = no scan recorded (latest_image_scan stays null); otherwise the
        # NOT_SCANNED summary, or {"findings": <describe-image-scan-findings>}.
        scan='null'

        # Enhanced continuous and completed manual scans do not require scanOnPush.
        # Use JSON so the CLI selects the newest image AFTER combining all pages.
        # Identify the most recently pushed image to summarize its scan findings.
        latest_digest=$(aws ecr describe-images \
            --repository-name "$repo_name" \
            --query 'reverse(sort_by(imageDetails,&imagePushedAt))[0].imageDigest' \
            --output json 2>/dev/null)
        img_exit=$?
        if [ $img_exit -ne 0 ]; then
            echo "aws ecr describe-images ($repo_name) failed (exit=$img_exit)" >> "$_FAILURE_LOG"
            repo=$(echo "$repo" | jq '.scan_collection_status = "error"')
        elif [ -n "$latest_digest" ] && [ "$latest_digest" != "null" ]; then
            latest_digest=$(echo "$latest_digest" | jq -er 'select(type == "string" and length > 0)')
            if [ $? -ne 0 ]; then
                echo "aws ecr describe-images ($repo_name) returned an invalid digest" >> "$_FAILURE_LOG"
                repo=$(echo "$repo" | jq '.scan_collection_status = "error"')
                printf '%s\n%s\n' "$repo" "$scan" >> "$_REPOS_STREAM"
                continue
            fi
            # Read every page. With enhanced (Inspector) scanning,
            # findingSeverityCounts covers only the findings on the returned
            # page, so counts come from enhancedFindings itself. BASIC scans
            # keep AWS's findingSeverityCounts, which is the image total.
            # The raw response goes to a file (it can be tens of MB) and is
            # reduced to the summary below before it joins the stream.
            _FIND_ERR="$(mktemp -t aws_ecr_image_scanning_find.XXXXXX)"
            _FIND_OUT="$(mktemp -t aws_ecr_image_scanning_find_out.XXXXXX)"
            aws ecr describe-image-scan-findings \
                --repository-name "$repo_name" \
                --image-id imageDigest="$latest_digest" \
                --output json >"$_FIND_OUT" 2>"$_FIND_ERR"
            find_exit=$?
            findings=''
            if [ $find_exit -eq 0 ]; then
                findings=$(jq -c '{
                    imageId, imageScanStatus,
                    imageScanFindings: ((.imageScanFindings // {}) | {
                        imageScanCompletedAt, vulnerabilitySourceUpdatedAt,
                        findingSeverityCounts: (if has("enhancedFindings")
                            then reduce (.enhancedFindings // [])[] as $f ({}; .[$f.severity // "UNTRIAGED"] += 1)
                            else .findingSeverityCounts end)
                    })
                }' "$_FIND_OUT" 2>/dev/null)
            fi
            rm -f "$_FIND_OUT"
            if [ $find_exit -ne 0 ]; then
                # No completed scan for the image is meaningful evidence, not a failure.
                if grep -q 'ScanNotFoundException' "$_FIND_ERR"; then
                    scan=$(jq -n --arg d "$latest_digest" '{
                        image_digest: $d, scan_status: "NOT_SCANNED",
                        severity_counts: null
                    }')
                    repo=$(echo "$repo" | jq '.scan_collection_status = "not_scanned"')
                elif grep -q 'ImageNotFoundException' "$_FIND_ERR"; then
                    # A concurrent deletion is neither a failed API permission
                    # nor proof of a clean scan. Retain the selected digest.
                    scan=$(jq -n --arg d "$latest_digest" '{
                        image_digest: $d, scan_status: "IMAGE_NOT_FOUND",
                        severity_counts: null
                    }')
                    repo=$(echo "$repo" | jq '.scan_collection_status = "image_deleted"')
                else
                    echo "aws ecr describe-image-scan-findings ($repo_name) failed (exit=$find_exit): $(tr '\n' ' ' < "$_FIND_ERR")" >> "$_FAILURE_LOG"
                    repo=$(echo "$repo" | jq '.scan_collection_status = "error"')
                fi
            elif echo "$findings" | jq -e '.imageScanStatus.status | type == "string"' >/dev/null; then
                scan="{\"findings\": $findings}"
                repo=$(echo "$repo" | jq '.scan_collection_status = "collected"')
            else
                echo "aws ecr describe-image-scan-findings ($repo_name) returned invalid scan data" >> "$_FAILURE_LOG"
                repo=$(echo "$repo" | jq '.scan_collection_status = "error"')
            fi
            rm -f "$_FIND_ERR"
        fi

        printf '%s\n%s\n' "$repo" "$scan" >> "$_REPOS_STREAM"
    done

    jq --slurpfile stream "$_REPOS_STREAM" '
        .results.repositories += [range(0; ($stream | length) / 2) as $i
            | $stream[2 * $i] as $repo | $stream[2 * $i + 1] as $scan
            | {
                name: $repo.repositoryName,
                arn: $repo.repositoryArn,
                registry_id: $repo.registryId,
                scan_on_push: ($repo.imageScanningConfiguration.scanOnPush // false),
                immutability: ($repo.imageTagMutability // "MUTABLE"),
                latest_image_scan: (if $scan == null then null
                    elif ($scan | has("findings")) then ($scan.findings | {
                        image_digest: .imageId.imageDigest,
                        scan_status: (.imageScanStatus.status // null),
                        severity_counts: (if (.imageScanStatus.status == "COMPLETE" or .imageScanStatus.status == "ACTIVE")
                            and (.imageScanFindings.findingSeverityCounts | type == "object") then {
                            critical: (.imageScanFindings.findingSeverityCounts.CRITICAL // 0),
                            high: (.imageScanFindings.findingSeverityCounts.HIGH // 0),
                            medium: (.imageScanFindings.findingSeverityCounts.MEDIUM // 0),
                            low: (.imageScanFindings.findingSeverityCounts.LOW // 0),
                            informational: (.imageScanFindings.findingSeverityCounts.INFORMATIONAL // 0),
                            untriaged: (.imageScanFindings.findingSeverityCounts.UNTRIAGED // 0)
                        } else null end),
                        scan_completed_at: (.imageScanFindings.imageScanCompletedAt // null),
                        vulnerability_source_updated_at: (.imageScanFindings.vulnerabilitySourceUpdatedAt // null)
                    })
                    else $scan end),
                scan_frequency: ($repo.effective_scanning.scanFrequency // null),
                applied_scan_filters: ($repo.effective_scanning.appliedScanFilters // []),
                scan_collection_status: $repo.scan_collection_status
            }]
    ' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

aws_finish
