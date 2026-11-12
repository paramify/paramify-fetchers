#!/bin/bash
#
# AWS — Route 53 Resolver DNS Security
#
# Per VPC: Resolver DNSSEC validation, DNS Firewall associations and rule actions,
# and Resolver query logging. Maps to KSI-SVC-VCM, KSI-CNA-RNT, KSI-MLA-LET.
#
# Output: $EVIDENCE_DIR/aws_route53_resolver_dns_security_<target>.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

source "$(dirname "$0")/../_shared/aws.sh"

_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_route53_resolver_dns_security_${_TARGET_ID}.json"
_TMP="$(mktemp -d -t aws_r53_dns_sec.XXXXXX)"
_FAILURE_LOG="$_TMP/failures"
: > "$_FAILURE_LOG"
trap 'rm -rf "$_TMP" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_route53_resolver_dns_security %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_route53_resolver_dns_security %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

fail() {
    echo "$1" >> "$_FAILURE_LOG"
    log_error "$1"
}

if ! CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null); then
    fail "aws sts get-caller-identity failed"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# collect <name> <description> <aws args...> -- writes $_TMP/<name>.json; on failure
# writes [] plus $_TMP/<name>.failed, so the fields it feeds read null, not "off".
collect() {
    local name="$1" desc="$2"; shift 2
    if ! aws "$@" --output json > "$_TMP/$name.json" 2>/dev/null; then
        fail "$desc failed"
        echo '[]' > "$_TMP/$name.json"
        : > "$_TMP/$name.failed"
    fi
}
read_ok() { [ -e "$_TMP/$1.failed" ] && echo false || echo true; }

collect vpcs   "aws ec2 describe-vpcs" \
    ec2 describe-vpcs --query "Vpcs[*].{Id:VpcId,IsDefault:IsDefault,Name:Tags[?Key=='Name']|[0].Value}"
collect dnssec "aws route53resolver list-resolver-dnssec-configs" \
    route53resolver list-resolver-dnssec-configs --query "ResolverDnssecConfigs[*].{Id:Id,ResourceId:ResourceId,ValidationStatus:ValidationStatus}"
collect fwa    "aws route53resolver list-firewall-rule-group-associations" \
    route53resolver list-firewall-rule-group-associations --query "FirewallRuleGroupAssociations[*].{VpcId:VpcId,RuleGroupId:FirewallRuleGroupId,Name:Name,Priority:Priority,Status:Status,MutationProtection:MutationProtection}"
collect lists  "aws route53resolver list-firewall-domain-lists" \
    route53resolver list-firewall-domain-lists --query "FirewallDomainLists[*].{Id:Id,Name:Name,ManagedOwnerName:ManagedOwnerName}"
collect qla    "aws route53resolver list-resolver-query-log-config-associations" \
    route53resolver list-resolver-query-log-config-associations --query "ResolverQueryLogConfigAssociations[*].{ResourceId:ResourceId,ConfigId:ResolverQueryLogConfigId,Status:Status,Error:Error}"

# Rules per associated rule group, keyed by group id. A group whose rules could not
# be read is left out, so its Rules read null rather than an empty list.
echo '{}' > "$_TMP/rules.json"
for rg in $(jq -r '[(. // [])[].RuleGroupId] | unique | .[]' "$_TMP/fwa.json"); do
    if aws route53resolver list-firewall-rules --firewall-rule-group-id "$rg" \
         --query "FirewallRules[*].{Name:Name,Priority:Priority,Action:Action,BlockResponse:BlockResponse,DomainListId:FirewallDomainListId,FirewallThreatProtectionId:FirewallThreatProtectionId,DnsThreatProtection:DnsThreatProtection,ConfidenceThreshold:ConfidenceThreshold}" \
         --output json > "$_TMP/rg.json" 2>/dev/null \
       && jq --arg rg "$rg" --slurpfile r "$_TMP/rg.json" '.[$rg] = ($r[0] // [])' "$_TMP/rules.json" > "$_TMP/rules.new"; then
        mv "$_TMP/rules.new" "$_TMP/rules.json"
    else
        fail "aws route53resolver list-firewall-rules ($rg) failed"
    fi
done

if ! jq -n \
  --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
  --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
  --argjson vpcs_ok "$(read_ok vpcs)" --argjson dnssec_ok "$(read_ok dnssec)" \
  --argjson fwa_ok "$(read_ok fwa)" --argjson qla_ok "$(read_ok qla)" \
  --slurpfile vpcs "$_TMP/vpcs.json" --slurpfile dnssec "$_TMP/dnssec.json" \
  --slurpfile fwa "$_TMP/fwa.json" --slurpfile lists "$_TMP/lists.json" \
  --slurpfile qla "$_TMP/qla.json" --slurpfile rules "$_TMP/rules.json" '
  ($vpcs[0] // []) as $vpcs | ($dnssec[0] // []) as $dnssec | ($fwa[0] // []) as $fwa
  | ($qla[0] // []) as $qla | ($rules[0] // {}) as $rules
  | (($lists[0] // []) | map({(.Id): .Name}) | add // {}) as $list_names
  | ($vpcs | map(.Id)) as $vpc_ids
  | {
      metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn},
      results: [
        $vpcs[] as $v
        | ([$dnssec[] | select(.ResourceId == $v.Id)][0]) as $d
        | ([$fwa[] | select(.VpcId == $v.Id)]) as $assoc
        | ([$qla[] | select(.ResourceId == $v.Id)]) as $ql
        | {
            Id: $v.Id,
            Name: ($v.Name // ""),
            Default: $v.IsDefault,
            DnssecValidation: (if $dnssec_ok then ($d.ValidationStatus // "NOT_CONFIGURED") else null end),
            DnsFirewall: (if $fwa_ok then {
              Associated: ([$assoc[] | select(.Status == "COMPLETE")] | length > 0),
              RuleGroups: [$assoc[] | {
                Id: .RuleGroupId, Name, Priority, Status, MutationProtection,
                Rules: ($rules[.RuleGroupId] | if . == null then null else map(
                  . + {DomainListName: (if .DomainListId == null then null
                                        else ($list_names[.DomainListId] // "unknown") end)}) end)
              }]
            } else {Associated: null, RuleGroups: null} end),
            QueryLogging: (if $qla_ok then {
              Enabled: ([$ql[] | select(.Status == "ACTIVE")] | length > 0),
              Associations: [$ql[] | {ConfigId, Status, Error}]
            } else {Enabled: null, Associations: null} end)
          }
      ],
      OrphanedDnssecConfigs: (if $vpcs_ok and $dnssec_ok
        then [$dnssec[] | select(.ResourceId as $r | $vpc_ids | index($r) | not)]
        else null end)
    }' > "$_TMP/out.json"; then
    fail "building the evidence JSON failed"
    jq -n --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
        --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
        '{metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn},
          results: [], OrphanedDnssecConfigs: null}' > "$_TMP/out.json"
fi
mv "$_TMP/out.json" "$OUTPUT_JSON"

aws_finish
