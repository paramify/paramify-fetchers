#!/bin/bash
#
# AWS — Organizations Service Control Policies (SCPs)
#
# Lists AWS Organizations service control policies with their JSON content and
# the OUs/accounts they attach to, plus the organization and its roots.
#
# Output: $EVIDENCE_DIR/aws_organizations_scp.json
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
REGION="${REGION:-us-east-1}"
export AWS_DEFAULT_REGION="$REGION"

# Per-account output filename (profile) — global service, region not part of identity.
_TARGET_ID="$(aws_target_id)"
OUTPUT_JSON="$OUTPUT_DIR/aws_organizations_scp_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_organizations_scp.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_organizations_scp_fail.XXXXXX)"
_ORG_JSON="$(mktemp -t aws_organizations_scp_org.XXXXXX)"
_ITEMS_JSON="$(mktemp -t aws_organizations_scp_policies.XXXXXX)"
_TARGETS_JSON="$(mktemp -t aws_organizations_scp_targets.XXXXXX)"
_SUMMARIES_JSON="$(mktemp -t aws_organizations_scp_summaries.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_ORG_JSON" "$_ITEMS_JSON" "$_TARGETS_JSON" "$_SUMMARIES_JSON"' EXIT

log_info() { printf '%s INFO aws_organizations_scp %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_organizations_scp %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# Organization summary (id/arn/master account) — context for the SCPs. A standalone
# account that is not a member of an AWS Organization is valid evidence ("no SCPs
# apply"), NOT a collection failure: describe-organization errors with
# AWSOrganizationsNotInUseException (and the dependent list-roots / list-policies /
# describe-policy / list-targets calls would all fail the same way). Capture stderr
# so the shared helper can tell that case apart from a genuinely unexpected error;
# only the latter goes to the failure log (exit 1).
_ORG_ERR="$(mktemp -t aws_organizations_scp_org.XXXXXX)"
organization=$(aws organizations describe-organization --query 'Organization' --output json 2>"$_ORG_ERR")
ec=$?
if [ $ec -ne 0 ]; then
    if aws_service_unavailable "$_ORG_ERR"; then
        log_info "AWS Organizations not in use for this account (account not a member of an AWS Organization) — recording as valid evidence (no SCPs apply) and skipping dependent calls"
        rm -f "$_ORG_ERR"
        org_data=$(jq -n \
            '{"Organization": {}, "Roots": [], "ServiceControlPolicies": [],
              "OrganizationsInUse": false,
              "Note": "account not a member of an AWS Organization (no SCPs apply)"}')
        jq --argjson data "$org_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
        log_info "Evidence saved to $OUTPUT_JSON"
        exit 0
    fi
    echo "aws organizations describe-organization failed (exit=$ec): $(tr '\n' ' ' < "$_ORG_ERR")" >> "$_FAILURE_LOG"
    organization='{}'
fi
rm -f "$_ORG_ERR"

# Organization roots — top of the OU tree SCPs attach to.
roots=$(aws organizations list-roots --query 'Roots' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws organizations list-roots failed" >> "$_FAILURE_LOG"
    roots='[]'
fi

org_data=$(jq -n --argjson org "$organization" --argjson roots "$roots" \
    '{"Organization": $org, "Roots": $roots, "ServiceControlPolicies": []}')

policies=$(aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[*].[Id,Arn,Name,AwsManaged]' --output json 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws organizations list-policies (SERVICE_CONTROL_POLICY) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list service control policies"
else
    # describe-policy and list-targets-for-policy are genuinely one call each per
    # SCP (no batch form). Responses are appended raw, in list order, and every
    # SCP is built in the one jq pass below -- not a jq process and a re-parse of
    # the whole organization record per SCP.
    while read -r policy_id; do
        policy_doc=$(aws organizations describe-policy --policy-id "$policy_id" --query 'Policy' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws organizations describe-policy ($policy_id) failed" >> "$_FAILURE_LOG"
            policy_doc='{}'
        fi
        [ -n "$policy_doc" ] || policy_doc='{}'

        targets=$(aws organizations list-targets-for-policy --policy-id "$policy_id" --query 'Targets' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws organizations list-targets-for-policy ($policy_id) failed" >> "$_FAILURE_LOG"
            targets='[]'
        fi
        [ -n "$targets" ] || targets='[]'

        printf '%s\n' "$policy_doc" >> "$_ITEMS_JSON"
        printf '%s\n' "$targets" >> "$_TARGETS_JSON"
    done < <(echo "$policies" | jq -r '.[] | .[0]' 2>/dev/null)
    printf '%s' "$policies" > "$_SUMMARIES_JSON"
fi

# One SCP that cannot be read must not cost the others. Content that does not
# parse is recorded as null, and an SCP whose describe-policy failed keeps the
# Id / Arn / Name / AwsManaged list-policies already returned. (The per-SCP
# version built Content with `fromjson?`, which on a parse failure produced no
# object at all -- and that emptied the whole organization record.)
printf '%s' "$org_data" > "$_ORG_JSON"
[ -s "$_SUMMARIES_JSON" ] || echo '[]' > "$_SUMMARIES_JSON"
jq --slurpfile org "$_ORG_JSON" --slurpfile docs "$_ITEMS_JSON" --slurpfile targets "$_TARGETS_JSON" \
   --slurpfile summaries "$_SUMMARIES_JSON" '
    ($summaries[0] // []) as $listed
    | [range(0; $docs | length) as $i | $docs[$i] as $policy | ($listed[$i] // []) as $row
        | {
            "Id": ($policy.PolicySummary.Id // $row[0]),
            "Arn": ($policy.PolicySummary.Arn // $row[1]),
            "Name": ($policy.PolicySummary.Name // $row[2]),
            "Type": ($policy.PolicySummary.Type // "SERVICE_CONTROL_POLICY"),
            "AwsManaged": (if $policy.PolicySummary.AwsManaged == null then $row[3] else $policy.PolicySummary.AwsManaged end),
            "Content": (try ($policy.Content | fromjson) catch null),
            "Targets": $targets[$i]
        }] as $scps
    | .results += [$org[0] | .ServiceControlPolicies += $scps]
' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
