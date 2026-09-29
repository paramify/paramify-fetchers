#!/bin/bash
# Lists WAFv2 REGIONAL Web ACLs and captures rate-based and DoS-related managed rule groups for each WebACL.
# Output: $EVIDENCE_DIR/aws_waf_dos_rules.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_waf_dos_rules_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_waf_dos_rules.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_waf_dos_rules_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_waf_dos_rules %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_waf_dos_rules %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# --- per-script data collection (ported from upstream) ---

# List all WAFv2 REGIONAL Web ACLs in the region
web_acls=$(aws wafv2 list-web-acls --scope REGIONAL --query 'WebACLs[*].[Id, Name]' --output text 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws wafv2 list-web-acls failed (exit=$ec)" >> "$_FAILURE_LOG"
    web_acls=""
fi

# An account with no Web ACLs is valid evidence, not a failure.
if [ -z "$web_acls" ]; then
    log_info "No Web ACLs found in region $REGION (empty result treated as valid evidence)"
fi

# get-web-acl has no bulk form and stays one call per Web ACL. Each response is
# streamed to a file and every ACL's rules are filtered in one jq pass at the
# end; the old per-rule loop spawned several jq processes per rule and
# re-serialized the growing rule list each time.
_ACLS_JSON="$(mktemp -t aws_waf_dos_rules_acls.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_ACLS_JSON"' EXIT

if [ -n "$web_acls" ]; then
    # Process each Web ACL
    while IFS=$'\t' read -r acl_id acl_name; do
        # Extract ID from ARN if necessary (ARN format: arn:partition:wafv2:region:account:scope/webacl/name/id)
        # The ID is the last segment after the final slash
        if [[ "$acl_id" == arn:* ]]; then
            acl_id=$(echo "$acl_id" | awk -F'/' '{print $NF}')
        fi

        # Skip if we don't have both ID and name
        if [ -z "$acl_id" ] || [ -z "$acl_name" ]; then
            log_info "Skipping invalid entry: id='$acl_id', name='$acl_name'"
            continue
        fi

        # Get detailed ACL configuration
        acl_details=$(aws wafv2 get-web-acl --scope REGIONAL --name "$acl_name" --id "$acl_id" --output json 2>/dev/null)
        ec=$?
        if [ $ec -ne 0 ]; then
            echo "aws wafv2 get-web-acl failed for $acl_name ($acl_id) (exit=$ec)" >> "$_FAILURE_LOG"
            continue
        fi

        printf '%s\n' "$acl_details" >> "$_ACLS_JSON"
    done <<< "$web_acls"
fi

# Keep ALL WebACL metadata, but only the DoS-related rules: a top-level
# rate-based statement, or an AWS managed rule group whose name contains
# DDoS / DoS / RateLimit / AWSManagedRulesATPRuleSet / AWSManagedRulesBotControlRuleSet
# (case-sensitive, as the bash glob was). An ACL with no rules is stored whole.
jq --slurpfile acls "$_ACLS_JSON" '
    .results += [$acls[] | .WebACL
        | if (.Rules | length) == 0 then . else
            .Rules = [.Rules[] | select(
                (.Statement.RateBasedStatement | . != null and . != false)
                or ((.Statement.ManagedRuleGroupStatement | . != null and . != false)
                    and (.Statement.ManagedRuleGroupStatement.Name | tostring
                         | test("DDoS|DoS|RateLimit|AWSManagedRulesATPRuleSet|AWSManagedRulesBotControlRuleSet"))))]
          end]
' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
