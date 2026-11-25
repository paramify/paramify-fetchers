#!/bin/bash
#
# AWS — Client VPN endpoints
#
# Per endpoint: split tunnel, VPC and subnet associations, authorization rules
# and pushed routes. Does not read active client sessions.
#
# Output: $EVIDENCE_DIR/aws_client_vpn_endpoints_<target>.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

source "$(dirname "$0")/../_shared/aws.sh"

_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_client_vpn_endpoints_${_TARGET_ID}.json"
_TMP="$(mktemp -d -t aws_client_vpn.XXXXXX)"
_FAILURE_LOG="$_TMP/failures"
: > "$_FAILURE_LOG"
trap 'rm -rf "$_TMP" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_client_vpn_endpoints %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_client_vpn_endpoints %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# collect <name> <description> <aws args...> — writes $_TMP/<name>.json; on failure
# writes [] plus $_TMP/<name>.failed, so the fields it feeds read null, not empty.
collect() {
    local name="$1" desc="$2"; shift 2
    if ! aws "$@" --output json > "$_TMP/$name.json" 2>/dev/null; then
        fail "$desc failed"
        echo '[]' > "$_TMP/$name.json"
        : > "$_TMP/$name.failed"
    fi
}
read_ok() { [ -e "$_TMP/$1.failed" ] && echo false || echo true; }

collect endpoints "aws ec2 describe-client-vpn-endpoints" \
    ec2 describe-client-vpn-endpoints --query "ClientVpnEndpoints[*].{
      Id:ClientVpnEndpointId,
      Name:Tags[?Key=='Name']|[0].Value,
      Description:Description,
      Status:Status.Code,
      StatusMessage:Status.Message,
      SplitTunnel:SplitTunnel,
      VpnProtocol:VpnProtocol,
      TransportProtocol:TransportProtocol,
      VpnPort:VpnPort,
      ClientCidrBlock:ClientCidrBlock,
      DnsServers:DnsServers,
      DnsName:DnsName,
      VpcId:VpcId,
      SecurityGroupIds:SecurityGroupIds,
      ServerCertificateArn:ServerCertificateArn,
      Authentication:AuthenticationOptions[*].{
        Type:Type,
        DirectoryId:ActiveDirectory.DirectoryId,
        ClientRootCertificateChainArn:MutualAuthentication.ClientRootCertificateChainArn,
        SamlProviderArn:FederatedAuthentication.SamlProviderArn,
        SelfServiceSamlProviderArn:FederatedAuthentication.SelfServiceSamlProviderArn
      },
      ConnectionLogging:{
        Enabled:ConnectionLogOptions.Enabled,
        LogGroup:ConnectionLogOptions.CloudwatchLogGroup,
        LogStream:ConnectionLogOptions.CloudwatchLogStream
      },
      SessionTimeoutHours:SessionTimeoutHours,
      SelfServicePortal:SelfServicePortal,
      ClientConnectEnabled:ClientConnectOptions.Enabled,
      RouteEnforcement:ClientRouteEnforcementOptions.Enforced,
      DisconnectOnSessionTimeout:DisconnectOnSessionTimeout
    }"

# One object per child call, keyed by endpoint id. A failed call leaves the key
# out, so that list reads null rather than an empty array.
echo '{}' > "$_TMP/networks.json"
echo '{}' > "$_TMP/rules.json"
echo '{}' > "$_TMP/routes.json"
if [ "$(read_ok endpoints)" = true ]; then
    for id in $(jq -r '[(. // [])[].Id] | .[]' "$_TMP/endpoints.json"); do
        if aws ec2 describe-client-vpn-target-networks --client-vpn-endpoint-id "$id" \
             --query "ClientVpnTargetNetworks[*].{AssociationId:AssociationId,VpcId:VpcId,SubnetId:TargetNetworkId,Status:Status.Code,SecurityGroupIds:SecurityGroups}" \
             --output json > "$_TMP/one.json" 2>/dev/null \
           && jq --arg id "$id" --slurpfile r "$_TMP/one.json" '.[$id] = ($r[0] // [])' "$_TMP/networks.json" > "$_TMP/new"; then
            mv "$_TMP/new" "$_TMP/networks.json"
        else
            fail "aws ec2 describe-client-vpn-target-networks ($id) failed"
        fi
        if aws ec2 describe-client-vpn-authorization-rules --client-vpn-endpoint-id "$id" \
             --query "AuthorizationRules[*].{DestinationCidr:DestinationCidr,AuthorizeAllGroups:AccessAll,AccessGroupId:GroupId,Description:Description,Status:Status.Code}" \
             --output json > "$_TMP/one.json" 2>/dev/null \
           && jq --arg id "$id" --slurpfile r "$_TMP/one.json" '.[$id] = ($r[0] // [])' "$_TMP/rules.json" > "$_TMP/new"; then
            mv "$_TMP/new" "$_TMP/rules.json"
        else
            fail "aws ec2 describe-client-vpn-authorization-rules ($id) failed"
        fi
        if aws ec2 describe-client-vpn-routes --client-vpn-endpoint-id "$id" \
             --query "Routes[*].{DestinationCidr:DestinationCidr,TargetSubnet:TargetSubnet,Origin:Origin,Type:Type,Status:Status.Code,Description:Description}" \
             --output json > "$_TMP/one.json" 2>/dev/null \
           && jq --arg id "$id" --slurpfile r "$_TMP/one.json" '.[$id] = ($r[0] // [])' "$_TMP/routes.json" > "$_TMP/new"; then
            mv "$_TMP/new" "$_TMP/routes.json"
        else
            fail "aws ec2 describe-client-vpn-routes ($id) failed"
        fi
    done
fi

if ! jq -n \
  --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
  --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
  --argjson endpoints_ok "$(read_ok endpoints)" \
  --slurpfile endpoints "$_TMP/endpoints.json" \
  --slurpfile networks "$_TMP/networks.json" \
  --slurpfile rules "$_TMP/rules.json" \
  --slurpfile routes "$_TMP/routes.json" '
  ($endpoints[0] // []) as $endpoints
  | ($networks[0] // {}) as $networks
  | ($rules[0] // {}) as $rules
  | ($routes[0] // {}) as $routes
  | {
      metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn},
      results: (if $endpoints_ok then [
        $endpoints[] | . + {
          Name: (.Name // ""),
          TargetNetworks: $networks[.Id],
          AuthorizationRules: $rules[.Id],
          Routes: $routes[.Id]
        }
      ] else [] end)
    }' > "$_TMP/out.json"; then
    fail "building the evidence JSON failed"
    jq -n --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
        --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
        '{metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn}, results: []}' \
        > "$_TMP/out.json"
fi
mv "$_TMP/out.json" "$OUTPUT_JSON"

aws_finish
