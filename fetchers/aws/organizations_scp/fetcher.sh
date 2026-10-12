#!/bin/bash
#
# AWS — Organizations Service Control Policies (SCPs)
#
# Lists AWS Organizations service control policies with their JSON content and
# the OUs/accounts they attach to, plus the organization and its roots.
# Optionally, for each account named in SCP_EFFECTIVE_ACCOUNTS, walks from the
# account up to the root and records the SCPs attached at every level — the
# SCPs that apply to that account.
#
# A read that failed is never shown as "no SCPs": `PolicyRead.Status` says
# whether the SCP data was read (ok / not_enabled / denied / error), and a list
# that could not be read is null, not []. Only the management account or a
# delegated administrator can list SCPs; see fetchers/aws/README.md.
#
# Output: $EVIDENCE_DIR/aws_organizations_scp.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Optional env: SCP_EFFECTIVE_ACCOUNTS — comma-separated account IDs, or `all`
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
_CALL_ERR="$(mktemp -t aws_organizations_scp_err.XXXXXX)"
_EFFECTIVE_JSON="$(mktemp -t aws_organizations_scp_effective.XXXXXX)"
_CACHE_DIR="$(mktemp -d -t aws_organizations_scp_cache.XXXXXX)"
trap 'rm -rf "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_ORG_JSON" "$_ITEMS_JSON" "$_TARGETS_JSON" "$_SUMMARIES_JSON" "$_CALL_ERR" "$_EFFECTIVE_JSON" "$_CACHE_DIR"' EXIT

log_info() { printf '%s INFO aws_organizations_scp %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_organizations_scp %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

# Read status vocabulary, shared with the discovery documents (PR #142):
#   ok          read in full
#   not_enabled the platform said there is nothing to read (no Organization)
#   denied      the credentials may not read it
#   error       anything else (expired credentials, throttling, bad input)
# denied and error are gaps, never "there are none" — the lists they cover are
# null. The run still exits 1 through aws_finish, exactly as before.

# _read_status <stderr-file> -- denied or error, for a call that failed.
_read_status() {
    if [ "$(aws_classify_code "$1")" = "not_authorized" ]; then printf 'denied'; else printf 'error'; fi
}

# _read_reason <operation> <stderr-file> -- "<operation>: <AWS error, one line>".
_read_reason() {
    local msg
    msg="$(tr '\n\r\t' '   ' < "$2" 2>/dev/null | tr -s ' ' | sed -e 's/^ //' -e 's/ $//' | cut -c1-300)"
    printf '%s: %s' "$1" "${msg:-failed with no error output}"
}

# _policy_read_failed <operation> <stderr-file> -- record a failed SCP read. The
# first failure names PolicyRead's status and reason: it is usually the cause,
# and every later call fails the same way.
POLICY_READ_STATUS="ok"
POLICY_READ_REASON=""
_policy_read_failed() {
    echo "aws organizations $1 failed" >> "$_FAILURE_LOG"
    if [ "$POLICY_READ_STATUS" = "ok" ]; then
        POLICY_READ_STATUS="$(_read_status "$2")"
        POLICY_READ_REASON="$(_read_reason "$1" "$2")"
    fi
}

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Effective-SCP mode: off unless SCP_EFFECTIVE_ACCOUNTS is set. Whitespace is
# ignored so "111122223333, 444455556666" works as typed.
EFFECTIVE_SPEC="$(printf '%s' "${SCP_EFFECTIVE_ACCOUNTS:-}" | tr -d '[:space:]')"

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
#
# Note describe-organization succeeds from ANY member account, so a successful
# call here says nothing about whether the SCP reads below will be allowed.
_ORG_ERR="$(mktemp -t aws_organizations_scp_org.XXXXXX)"
organization=$(aws organizations describe-organization --query 'Organization' --output json 2>"$_ORG_ERR")
ec=$?
if [ $ec -ne 0 ]; then
    if aws_service_unavailable "$_ORG_ERR"; then
        log_info "AWS Organizations not in use for this account (account not a member of an AWS Organization) — recording as valid evidence (no SCPs apply) and skipping dependent calls"
        rm -f "$_ORG_ERR"
        org_data=$(jq -n --arg effective "$EFFECTIVE_SPEC" \
            '{"Organization": {}, "Roots": [], "ServiceControlPolicies": [],
              "OrganizationsInUse": false,
              "Note": "account not a member of an AWS Organization (no SCPs apply)",
              "ScpsEnabled": false,
              "PolicyRead": {"Status": "not_enabled", "Reason": "account not a member of an AWS Organization"}}
             + (if $effective == "" then {} else
                 {"EffectiveScpsRead": {"Status": "not_enabled", "Reason": "account not a member of an AWS Organization"},
                  "EffectiveScps": []} end)')
        jq --argjson data "$org_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
        log_info "Evidence saved to $OUTPUT_JSON"
        exit 0
    fi
    echo "aws organizations describe-organization failed (exit=$ec): $(tr '\n' ' ' < "$_ORG_ERR")" >> "$_FAILURE_LOG"
    organization='null'
fi
rm -f "$_ORG_ERR"
[ -n "$organization" ] || organization='null'

# Organization roots — top of the OU tree SCPs attach to. Each root's
# PolicyTypes says whether the SCP policy type is enabled there.
roots=$(aws organizations list-roots --query 'Roots' --output json 2>"$_CALL_ERR")
if [ $? -ne 0 ]; then
    _policy_read_failed "list-roots" "$_CALL_ERR"
    roots='null'
fi
[ -n "$roots" ] || roots='null'

SCPS_LISTED=false
policies=$(aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[*].[Id,Arn,Name,AwsManaged]' --output json 2>"$_CALL_ERR")
if [ $? -ne 0 ]; then
    _policy_read_failed "list-policies (SERVICE_CONTROL_POLICY)" "$_CALL_ERR"
    log_error "Failed to list service control policies: $POLICY_READ_REASON"
else
    SCPS_LISTED=true
    # describe-policy and list-targets-for-policy are genuinely one call each per
    # SCP (no batch form). Responses are appended raw, in list order, and every
    # SCP is built in the one jq pass below -- not a jq process and a re-parse of
    # the whole organization record per SCP.
    while read -r policy_id; do
        policy_doc=$(aws organizations describe-policy --policy-id "$policy_id" --query 'Policy' --output json 2>"$_CALL_ERR")
        if [ $? -ne 0 ]; then
            _policy_read_failed "describe-policy ($policy_id)" "$_CALL_ERR"
            policy_doc='{}'
        fi
        [ -n "$policy_doc" ] || policy_doc='{}'

        targets=$(aws organizations list-targets-for-policy --policy-id "$policy_id" --query 'Targets' --output json 2>"$_CALL_ERR")
        if [ $? -ne 0 ]; then
            _policy_read_failed "list-targets-for-policy ($policy_id)" "$_CALL_ERR"
            targets='null'
        fi
        [ -n "$targets" ] || targets='null'

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
#
# Keys are only ever appended: Organization, Roots and ServiceControlPolicies
# keep their place, and what was learned about the read follows them.
jq -n --argjson org "$organization" --argjson roots "$roots" > "$_ORG_JSON" \
    '{"Organization": $org, "Roots": $roots}'
[ -s "$_SUMMARIES_JSON" ] || echo '[]' > "$_SUMMARIES_JSON"
jq --slurpfile org "$_ORG_JSON" --slurpfile docs "$_ITEMS_JSON" --slurpfile targets "$_TARGETS_JSON" \
   --slurpfile summaries "$_SUMMARIES_JSON" --argjson listed_ok "$SCPS_LISTED" \
   --arg read_status "$POLICY_READ_STATUS" --arg read_reason "$POLICY_READ_REASON" '
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
    | $org[0] as $o
    | .results += [$o + {
        "ServiceControlPolicies": (if $listed_ok then $scps else null end),
        "OrganizationsInUse": (if $o.Organization == null then null else true end),
        "ScpsEnabled": (if $o.Roots == null then null
                        else any($o.Roots[]?.PolicyTypes[]?; .Type == "SERVICE_CONTROL_POLICY" and .Status == "ENABLED") end),
        "PolicyRead": {"Status": $read_status, "Reason": (if $read_reason == "" then null else $read_reason end)}
      }]
' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

# --------------------------------------------------------------------------- #
# Effective SCPs per account (SCP_EFFECTIVE_ACCOUNTS)
#
# DescribeEffectivePolicy does not support SCPs, so an account's effective SCPs
# are the ones attached to the account itself, to each OU above it, and to the
# root: walk list-parents up to the root and collect the SCPs at every level.
#
# The SCPs attached at a level come from the list-targets-for-policy results
# already collected above when every SCP read succeeded, so a full read costs
# only the list-parents walk. Otherwise each level is asked directly with
# list-policies-for-target. Parents and per-level answers are cached by id, so
# an OU shared by 500 accounts is looked up once.
#
# One account that cannot be read does not cost the others: it gets its own
# Status/Reason and null Path/Policies, and the run still exits 1.
# --------------------------------------------------------------------------- #
if [ -n "$EFFECTIVE_SPEC" ]; then
    # Account ids are split on whitespace below; never let an entry glob.
    set -f
    EFFECTIVE_STATUS="ok"
    EFFECTIVE_REASON=""
    EFFECTIVE_LISTED=true
    MANAGEMENT_ACCOUNT_ID="$(echo "$organization" | jq -r '.MasterAccountId // ""' 2>/dev/null)"

    # Every SCP's targets were read, so "which SCPs are attached to X" can be
    # answered from them: {target id: [{Id, Name}]}.
    USE_TARGET_MAP=false
    if [ "$POLICY_READ_STATUS" = "ok" ] && [ "$SCPS_LISTED" = "true" ]; then
        USE_TARGET_MAP=true
        jq -c '.results[-1].ServiceControlPolicies
               | reduce .[] as $p ({}; reduce ($p.Targets // [])[] as $t (.;
                   .[$t.TargetId] += [{"Id": $p.Id, "Name": $p.Name}]))' \
            "$OUTPUT_JSON" > "$_CACHE_DIR/target_map.json"
    fi

    # _effective_failed <account> <status> <reason> -- first failure names the
    # summary's status and reason.
    _effective_failed() {
        if [ "$EFFECTIVE_STATUS" = "ok" ]; then
            EFFECTIVE_STATUS="$2"
            EFFECTIVE_REASON="$1: $3"
        fi
    }

    accounts=""
    case "$(printf '%s' "$EFFECTIVE_SPEC" | tr '[:upper:]' '[:lower:]')" in
        all)
            # The CLI follows NextToken itself. JSON, not text: --output json
            # applies --query to the merged result, while text applies it per
            # page and can print "None" for an empty page mid-listing.
            listed=$(aws organizations list-accounts --query 'Accounts[].Id' --output json 2>"$_CALL_ERR")
            if [ $? -ne 0 ]; then
                echo "aws organizations list-accounts failed" >> "$_FAILURE_LOG"
                EFFECTIVE_STATUS="$(_read_status "$_CALL_ERR")"
                EFFECTIVE_REASON="$(_read_reason "list-accounts" "$_CALL_ERR")"
                EFFECTIVE_LISTED=false
            else
                accounts="$(printf '%s' "$listed" | jq -r '.[]?' 2>/dev/null)"
            fi
            ;;
        *)
            accounts="$(printf '%s' "$EFFECTIVE_SPEC" | tr ',' ' ')"
            ;;
    esac

    for acct in $(printf '%s\n' $accounts | awk 'NF && !seen[$0]++'); do
        status="ok"
        reason=""
        levels="[]"
        if ! printf '%s' "$acct" | grep -qE '^[0-9]{12}$'; then
            status="error"
            reason="not a 12-digit AWS account ID"
            echo "SCP_EFFECTIVE_ACCOUNTS entry '$acct' is not a 12-digit AWS account ID" >> "$_FAILURE_LOG"
            # So aws_finish classifies it as bad_config, not a generic partial failure.
            echo "InvalidInput: SCP_EFFECTIVE_ACCOUNTS entry '$acct' is not a 12-digit AWS account ID" >> "$_AWS_ERR_LOG"
        else
            # Path: the account, each OU above it, the root.
            path_ids="$acct"
            path_types="ACCOUNT"
            cur="$acct"
            reached_root=false
            # OUs nest at most five deep under the root, so ten levels is a guard
            # against a malformed answer, not a limit anyone will reach.
            for _ in 1 2 3 4 5 6 7 8 9 10; do
                cache="$_CACHE_DIR/parent_$cur"
                if [ ! -f "$cache" ]; then
                    parent=$(aws organizations list-parents --child-id "$cur" --query 'Parents[0].[Id,Type]' --output text 2>"$_CALL_ERR")
                    if [ $? -ne 0 ] || [ -z "$(aws_text_list "$parent")" ]; then
                        echo "aws organizations list-parents ($cur) failed" >> "$_FAILURE_LOG"
                        status="$(_read_status "$_CALL_ERR")"
                        reason="$(_read_reason "list-parents ($cur)" "$_CALL_ERR")"
                        break
                    fi
                    printf '%s\n' "$parent" > "$cache"
                fi
                read -r parent_id parent_type < "$cache"
                path_ids="$path_ids $parent_id"
                path_types="$path_types $parent_type"
                if [ "$parent_type" = "ROOT" ]; then reached_root=true; break; fi
                cur="$parent_id"
            done
            if [ "$status" = "ok" ] && [ "$reached_root" != "true" ]; then
                status="error"
                reason="list-parents: no root within 10 levels above $acct"
                echo "aws organizations list-parents ($acct) never reached the root" >> "$_FAILURE_LOG"
            fi

            # The SCPs attached at each level of the path.
            if [ "$status" = "ok" ]; then
                set -- $path_types
                levels="["
                sep=""
                for level_id in $path_ids; do
                    level_type="$1"; shift
                    cache="$_CACHE_DIR/policies_$level_id"
                    if [ ! -f "$cache" ]; then
                        if [ "$USE_TARGET_MAP" = "true" ]; then
                            jq -c --arg id "$level_id" '.[$id] // []' "$_CACHE_DIR/target_map.json" > "$cache"
                        else
                            attached=$(aws organizations list-policies-for-target --target-id "$level_id" --filter SERVICE_CONTROL_POLICY --query 'Policies[].{Id: Id, Name: Name}' --output json 2>"$_CALL_ERR")
                            if [ $? -ne 0 ]; then
                                echo "aws organizations list-policies-for-target ($level_id) failed" >> "$_FAILURE_LOG"
                                status="$(_read_status "$_CALL_ERR")"
                                reason="$(_read_reason "list-policies-for-target ($level_id)" "$_CALL_ERR")"
                                break
                            fi
                            printf '%s\n' "${attached:-[]}" > "$cache"
                        fi
                    fi
                    levels="${levels}${sep}{\"Type\":\"${level_type}\",\"Id\":\"${level_id}\",\"Policies\":$(cat "$cache")}"
                    sep=","
                done
                levels="${levels}]"
            fi
        fi
        [ "$status" = "ok" ] || _effective_failed "$acct" "$status" "$reason"

        jq -cn --arg acct "$acct" --arg mgmt "$MANAGEMENT_ACCOUNT_ID" --arg status "$status" \
              --arg reason "$reason" --argjson levels "$levels" '
            {"AccountId": $acct,
             "IsManagementAccount": (if $mgmt == "" then null else ($acct == $mgmt) end),
             "Status": $status,
             "Reason": (if $reason == "" then null else $reason end),
             "Path": (if $status == "ok" then [$levels[] | {Type, Id}] else null end),
             "Policies": (if $status == "ok"
                          then [$levels[] as $l | $l.Policies[] | {Id, Name, "AttachedToType": $l.Type, "AttachedToId": $l.Id}]
                          else null end)}' >> "$_EFFECTIVE_JSON"
    done

    jq --slurpfile accts "$_EFFECTIVE_JSON" --argjson listed "$EFFECTIVE_LISTED" \
       --arg status "$EFFECTIVE_STATUS" --arg reason "$EFFECTIVE_REASON" '
        .results[-1] += {
            "EffectiveScpsRead": {"Status": $status, "Reason": (if $reason == "" then null else $reason end)},
            "EffectiveScps": (if $listed then $accts else null end)
        }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

aws_finish
