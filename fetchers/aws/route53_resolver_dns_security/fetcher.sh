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

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# collect <name> <description> <aws args...> -- writes $_TMP/<name>.json, or [] and a failure line.
collect() {
    local name="$1" desc="$2"; shift 2
    if ! aws "$@" --output json > "$_TMP/$name.json" 2>/dev/null; then
        echo "$desc failed" >> "$_FAILURE_LOG"
        log_error "$desc failed"
        echo '[]' > "$_TMP/$name.json"
    fi
}

collect vpcs   "aws ec2 describe-vpcs" \
    ec2 describe-vpcs --query "Vpcs[*].{Id:VpcId,IsDefault:IsDefault,Name:Tags[?Key=='Name']|[0].Value}"
collect dnssec "aws route53resolver list-resolver-dnssec-configs" \
    route53resolver list-resolver-dnssec-configs --query "ResolverDnssecConfigs[*].{Id:Id,ResourceId:ResourceId,ValidationStatus:ValidationStatus}"
collect fwa    "aws route53resolver list-firewall-rule-group-associations" \
    route53resolver list-firewall-rule-group-associations --query "FirewallRuleGroupAssociations[*].{VpcId:VpcId,RuleGroupId:FirewallRuleGroupId,Name:Name,Priority:Priority,Status:Status,MutationProtection:MutationProtection}"
collect lists  "aws route53resolver list-firewall-domain-lists" \
    route53resolver list-firewall-domain-lists --query "FirewallDomainLists[*].{Id:Id,Name:Name,ManagedOwnerName:ManagedOwnerName}"
collect qla    "aws route53resolver list-resolver-query-log-config-associations" \
    route53resolver list-resolver-query-log-config-associations --query "ResolverQueryLogConfigAssociations[*].{ResourceId:ResourceId,ConfigId:ResolverQueryLogConfigId,Status:Status}"

# Rules per associated rule group, keyed by group id.
echo '{}' > "$_TMP/rules.json"
for rg in $(jq -r '[.[].RuleGroupId] | unique | .[]' "$_TMP/fwa.json"); do
    if aws route53resolver list-firewall-rules --firewall-rule-group-id "$rg" \
         --query "FirewallRules[*].{Name:Name,Priority:Priority,Action:Action,BlockResponse:BlockResponse,DomainListId:FirewallDomainListId}" \
         --output json > "$_TMP/rg.json" 2>/dev/null; then
        jq --arg rg "$rg" --slurpfile r "$_TMP/rg.json" '.[$rg] = $r[0]' "$_TMP/rules.json" > "$_TMP/rules.new" \
            && mv "$_TMP/rules.new" "$_TMP/rules.json"
    else
        echo "aws route53resolver list-firewall-rules ($rg) failed" >> "$_FAILURE_LOG"
    fi
done

jq -n \
  --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
  --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
  --slurpfile vpcs "$_TMP/vpcs.json" --slurpfile dnssec "$_TMP/dnssec.json" \
  --slurpfile fwa "$_TMP/fwa.json" --slurpfile lists "$_TMP/lists.json" \
  --slurpfile qla "$_TMP/qla.json" --slurpfile rules "$_TMP/rules.json" '
  ($lists[0] | map({(.Id): .Name}) | add // {}) as $list_names
  | ($vpcs[0] | map(.Id)) as $vpc_ids
  | {
      metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn},
      results: [
        $vpcs[0][] as $v
        | ([$dnssec[0][] | select(.ResourceId == $v.Id)][0]) as $d
        | ([$fwa[0][] | select(.VpcId == $v.Id)]) as $assoc
        | ([$qla[0][] | select(.ResourceId == $v.Id)]) as $ql
        | {
            Id: $v.Id,
            Name: ($v.Name // ""),
            Default: $v.IsDefault,
            DnssecValidation: ($d.ValidationStatus // "NOT_CONFIGURED"),
            DnsFirewall: {
              Associated: ([$assoc[] | select(.Status == "COMPLETE")] | length > 0),
              RuleGroups: [$assoc[] | {
                Id: .RuleGroupId, Name, Priority, Status, MutationProtection,
                Rules: [($rules[0][.RuleGroupId] // [])[] | . + {DomainListName: ($list_names[.DomainListId] // "unknown")}]
              }]
            },
            QueryLogging: {
              Enabled: ([$ql[] | select(.Status == "ACTIVE")] | length > 0),
              ConfigIds: [$ql[] | .ConfigId]
            }
          }
      ],
      OrphanedDnssecConfigs: [$dnssec[0][] | select(.ResourceId as $r | $vpc_ids | index($r) | not)]
    }' > "$OUTPUT_JSON"

aws_finish
