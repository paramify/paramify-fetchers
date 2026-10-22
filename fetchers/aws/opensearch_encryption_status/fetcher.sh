#!/bin/bash
#
# AWS — OpenSearch Encryption Status
#
# For each OpenSearch/Elasticsearch domain in the account/region, reports
# encryption at rest, node-to-node encryption, and enforced-HTTPS endpoint
# settings (KSI-SVC-SIN).
#
# Output: $EVIDENCE_DIR/aws_opensearch_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_opensearch_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_opensearch_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_opensearch_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_opensearch_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_opensearch_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

_DOMAINS_JSON="$(mktemp -t aws_opensearch_encryption_status_domains.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_DOMAINS_JSON"' EXIT

domains=$(aws opensearch list-domain-names --query 'DomainNames[*].DomainName' --output json 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws opensearch list-domain-names (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list OpenSearch domains"
else
    # describe-domains takes up to five names per call, so domains are described
    # in batches rather than one describe-domain process each. A failed batch
    # skips its domains, as a failed describe-domain skipped one.
    while read -r batch; do
        [ -z "$batch" ] && continue
        # shellcheck disable=SC2086  # batch is space-separated domain names (no spaces allowed in them)
        if ! aws opensearch describe-domains --domain-names $batch --query 'DomainStatusList' --output json >> "$_DOMAINS_JSON" 2>/dev/null; then
            echo "aws opensearch describe-domains ($batch) failed" >> "$_FAILURE_LOG"
        fi
    done < <(printf '%s' "$domains" | jq -r '[.[]?] | _nwise(5) | join(" ")')

    # Rows follow list-domain-names order, whatever order each batch came back in.
    printf '%s' "$domains" | jq --slurpfile names /dev/stdin --slurpfile batches "$_DOMAINS_JSON" '
        (reduce ($batches | add // [])[] as $d ({}; .[$d.DomainName] = $d)) as $by_name
        | .results += [$names[0][]? | $by_name[.] | select(. != null) | {
            name: .DomainName,
            arn: .ARN,
            engine_version: (.EngineVersion // null),
            encryption_at_rest: (.EncryptionAtRestOptions.Enabled // false),
            node_to_node_encryption: (.NodeToNodeEncryptionOptions.Enabled // false),
            enforce_https: (.DomainEndpointOptions.EnforceHTTPS // false)
        }]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

aws_finish
