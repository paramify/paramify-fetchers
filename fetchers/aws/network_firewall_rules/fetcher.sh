#!/bin/bash
#
# AWS — Network Firewall Rules
#
# Lists AWS Network Firewall firewalls and, for each, the firewall policy's
# default actions and the stateless/stateful rule groups it references (with
# per-group rule counts). Maps to KSI-CNA-RNT.
#
# Output: $EVIDENCE_DIR/aws_network_firewall_rules_<target>.json
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

# Network Firewall is a regional service, so the output filename includes the
# region (profile+region) so multi-target runs don't overwrite.
_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_network_firewall_rules_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_network_firewall_rules.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_network_firewall_rules_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_network_firewall_rules %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_network_firewall_rules %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

_ERR="$(mktemp -t aws_network_firewall_rules_err.XXXXXX)"
firewall_arns=$(aws network-firewall list-firewalls --query 'Firewalls[*].FirewallArn' --output text 2>"$_ERR")
list_exit=$?
if [ $list_exit -ne 0 ] && aws_service_unavailable "$_ERR"; then
    log_info "Network Firewall not in use for this account (not subscribed / not enabled); recording not-enabled status"
    jq '.results += [{"Status": "not-enabled", "Detail": "AWS Network Firewall is not subscribed/enabled for this account"}]' \
      "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    rm -f "$_ERR"
elif [ $list_exit -ne 0 ]; then
    echo "aws network-firewall list-firewalls (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list network firewalls"
    rm -f "$_ERR"
else
    rm -f "$_ERR"
    for fw_arn in $(aws_text_list "$firewall_arns"); do
        firewall=$(aws network-firewall describe-firewall --firewall-arn "$fw_arn" --output json 2>/dev/null)
        fw_exit=$?
        if [ $fw_exit -ne 0 ]; then
            echo "aws network-firewall describe-firewall ($fw_arn) failed" >> "$_FAILURE_LOG"
            continue
        fi

        fw_data=$(echo "$firewall" | jq '{
            "FirewallArn": .Firewall.FirewallArn,
            "FirewallName": .Firewall.FirewallName,
            "VpcId": .Firewall.VpcId,
            "FirewallPolicyArn": .Firewall.FirewallPolicyArn,
            "DeleteProtection": (.Firewall.DeleteProtection // false),
            "SubnetMappings": [.Firewall.SubnetMappings[]? | {"SubnetId": .SubnetId, "IPAddressType": (.IPAddressType // "IPV4")}],
            "FirewallPolicy": {}
        }')

        policy_arn=$(echo "$firewall" | jq -r '.Firewall.FirewallPolicyArn // empty')
        if [ -n "$policy_arn" ]; then
            policy=$(aws network-firewall describe-firewall-policy --firewall-policy-arn "$policy_arn" --output json 2>/dev/null)
            policy_exit=$?
            if [ $policy_exit -ne 0 ]; then
                echo "aws network-firewall describe-firewall-policy ($policy_arn) failed" >> "$_FAILURE_LOG"
            else
                policy_data=$(echo "$policy" | jq '{
                    "StatelessDefaultActions": (.FirewallPolicy.StatelessDefaultActions // []),
                    "StatelessFragmentDefaultActions": (.FirewallPolicy.StatelessFragmentDefaultActions // []),
                    "StatelessRuleGroups": [.FirewallPolicy.StatelessRuleGroupReferences[]?.ResourceArn],
                    "StatefulRuleGroups": [.FirewallPolicy.StatefulRuleGroupReferences[]?.ResourceArn]
                }')

                rg_arns=$(echo "$policy" | jq -r '[.FirewallPolicy.StatelessRuleGroupReferences[]?.ResourceArn, .FirewallPolicy.StatefulRuleGroupReferences[]?.ResourceArn] | .[]')
                for rg_arn in $rg_arns; do
                    rule_group=$(aws network-firewall describe-rule-group --rule-group-arn "$rg_arn" --output json 2>/dev/null)
                    rg_exit=$?
                    if [ $rg_exit -ne 0 ]; then
                        echo "aws network-firewall describe-rule-group ($rg_arn) failed" >> "$_FAILURE_LOG"
                        continue
                    fi
                    rg_data=$(echo "$rule_group" | jq '{
                        "RuleGroupArn": .RuleGroupResponse.RuleGroupArn,
                        "RuleGroupName": .RuleGroupResponse.RuleGroupName,
                        "Type": .RuleGroupResponse.Type,
                        "Capacity": .RuleGroupResponse.Capacity,
                        "StatefulRuleCount": (.RuleGroup.RulesSource.StatefulRules | length? // 0),
                        "StatelessRuleCount": (.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules | length? // 0)
                    }')
                    policy_data=$(echo "$policy_data" | jq --argjson rg "$rg_data" '.RuleGroups += [$rg]')
                done

                fw_data=$(echo "$fw_data" | jq --argjson p "$policy_data" '.FirewallPolicy = $p')
            fi
        fi

        jq --argjson data "$fw_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
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
