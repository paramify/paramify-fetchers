#!/bin/bash
#
# AWS — Resource Inventory (KSI-PIY-GIV)
#
# Collects AWS Resource Explorer indexes and views as an asset inventory:
# index ARN/region/type and view ARN/name/filters, plus the default view.
# Falls back to a Resource Explorer resource count when no index is enabled.
#
# Output: $EVIDENCE_DIR/aws_resource_inventory.json
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

# Resource Explorer is account-global (one aggregator index across regions), so
# the filename is profile-scoped: pass no region to aws_target_id. The CLI still
# reads AWS_DEFAULT_REGION from env to pick the endpoint region.
_TARGET_ID="$(aws_target_id)"
OUTPUT_JSON="$OUTPUT_DIR/aws_resource_inventory_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_resource_inventory.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_resource_inventory_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_resource_inventory %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_resource_inventory %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"indexes": [], "views": [], "default_view_arn": null, "resource_count": null}}' \
  > "$OUTPUT_JSON"

# 1. Resource Explorer indexes (the asset-inventory aggregator index per region).
#    This is the primary enablement call: if it fails because Resource Explorer
#    is simply not in use for this account (not enabled / no default view /
#    ResourceNotFoundException / not subscribed), that is valid "not enabled"
#    evidence, so we record a not-enabled status, skip the dependent calls, and
#    exit 0 rather than logging a collection failure.
log_info "Listing Resource Explorer indexes"
_ERR="$(mktemp -t aws_resource_inventory_err.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_ERR"' EXIT
indexes=$(aws resource-explorer-2 list-indexes --query 'Indexes[*].{Arn:Arn,Region:Region,Type:Type}' --output json 2>"$_ERR")
if [ $? -ne 0 ]; then
    if aws_service_unavailable "$_ERR"; then
        log_info "Resource Explorer is not in use for this account; recording not-enabled evidence"
        jq '.results.status = "not_enabled"' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
        log_info "Evidence saved to $OUTPUT_JSON"
        exit 0
    fi
    echo "aws resource-explorer-2 list-indexes failed" >> "$_FAILURE_LOG"
    indexes='[]'
fi
echo "$indexes" | jq -c '.[]' | while read -r index; do
    jq --argjson index "$index" '.results.indexes += [$index]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
done

# 2. Resource Explorer views (the saved searchable inventory definitions).
log_info "Listing Resource Explorer views"
view_arns=$(aws resource-explorer-2 list-views --query 'Views[*]' --output text 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws resource-explorer-2 list-views failed" >> "$_FAILURE_LOG"
    view_arns=""
fi
for view_arn in $(aws_text_list "$view_arns"); do
    view=$(aws resource-explorer-2 get-view --view-arn "$view_arn" \
        --query 'View.{ViewArn:ViewArn,Filters:Filters,IncludedProperties:IncludedProperties}' \
        --output json 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "aws resource-explorer-2 get-view ($view_arn) failed" >> "$_FAILURE_LOG"
        continue
    fi
    jq --argjson view "$view" '.results.views += [$view]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
done

# 3. Default view ARN (the inventory the account searches by default). When
#    Resource Explorer is not enabled there is no default view and the API
#    returns ResourceNotFoundException; that absence is valid evidence (Explorer
#    off), so it is not a collection failure.
log_info "Resolving default Resource Explorer view"
default_view=$(aws resource-explorer-2 get-default-view --query 'ViewArn' --output text 2>/dev/null)
if [ $? -ne 0 ]; then
    log_info "No default Resource Explorer view available (Explorer may not be enabled)"
    default_view=""
fi
if [ -n "$default_view" ] && [ "$default_view" != "None" ]; then
    jq --arg arn "$default_view" '.results.default_view_arn = $arn' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

# 4. Fallback: when no index is enabled, record a Resource Explorer resource
#    count so the inventory still carries a size signal. Absence of an index is
#    valid evidence (Explorer not enabled), so this is not a collection failure.
index_count=$(jq -r '.results.indexes | length' "$OUTPUT_JSON")
if [ "$index_count" -eq 0 ]; then
    log_info "No Resource Explorer index enabled; collecting resource count fallback"
    resource_count=$(aws resource-explorer-2 search --query-string "*" --max-results 1 --query 'Count.TotalResources' --output text 2>/dev/null)
    if [ $? -ne 0 ]; then
        # Search needs an enabled index/view; with Explorer off it errors. That
        # is the expected state here (we only reach this branch when no index
        # exists), so it is valid evidence, not a collection failure.
        log_info "Resource count fallback unavailable (Resource Explorer not enabled)"
    elif [ -n "$resource_count" ] && [ "$resource_count" != "None" ]; then
        jq --argjson count "$resource_count" '.results.resource_count = $count' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    fi
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
