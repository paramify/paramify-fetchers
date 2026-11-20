#!/bin/bash
# Lists Client VPN endpoints and their TLS authentication and transport security
# configuration to confirm admin VPN enforces strong encryption.
# Output: $EVIDENCE_DIR/aws_client_vpn_tls.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

source "$(dirname "$0")/../_shared/aws.sh"

_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_client_vpn_tls_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_client_vpn_tls.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_client_vpn_tls_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info()  { printf '%s INFO  aws_client_vpn_tls %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_client_vpn_tls %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata":{"profile":$profile,"region":$region,"datetime":$datetime,"account_id":$account_id,"arn":$arn},"results":{"client_vpn_endpoints":[],"summary":{}}}' \
  > "$OUTPUT_JSON"

log_info "Collecting Client VPN endpoint configurations"

# Retrieve endpoint details. TLS is always on for Client VPN (OpenVPN only),
# so the useful fields are auth type, connection logging, and split-tunnel.
endpoints=$(aws ec2 describe-client-vpn-endpoints \
    --query 'ClientVpnEndpoints[*].{ClientVpnEndpointId:ClientVpnEndpointId,Description:Description,Status:Status,ServerCertificateArn:ServerCertificateArn,AuthenticationOptions:AuthenticationOptions,ConnectionLogOptions:ConnectionLogOptions,SplitTunnel:SplitTunnel,TransportProtocol:TransportProtocol,VpnProtocol:VpnProtocol,DnsName:DnsName,CreationTime:CreationTime}' \
    --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws ec2 describe-client-vpn-endpoints failed" >> "$_FAILURE_LOG"
    endpoints='[]'
fi

total_count=$(echo "$endpoints" | jq 'length')
# Auth type breakdown: certificate-authentication, directory-service-authentication, or federated-authentication (SAML).
cert_auth_count=$(echo "$endpoints" | jq '[.[] | select(.AuthenticationOptions[]?.Type == "certificate-authentication")] | length')
saml_auth_count=$(echo "$endpoints" | jq '[.[] | select(.AuthenticationOptions[]?.Type == "federated-authentication")] | length')
ad_auth_count=$(echo "$endpoints"   | jq '[.[] | select(.AuthenticationOptions[]?.Type == "directory-service-authentication")] | length')
logging_count=$(echo "$endpoints"   | jq '[.[] | select(.ConnectionLogOptions.Enabled == true)] | length')
split_tunnel_count=$(echo "$endpoints" | jq '[.[] | select(.SplitTunnel == true)] | length')

_ENDPOINTS_JSON="$(mktemp -t aws_client_vpn_endpoints.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_ENDPOINTS_JSON"' EXIT
printf '%s' "$endpoints" > "$_ENDPOINTS_JSON"

jq --slurpfile endpoints "$_ENDPOINTS_JSON" \
   --arg total        "$total_count" \
   --arg cert_auth    "$cert_auth_count" \
   --arg saml_auth    "$saml_auth_count" \
   --arg ad_auth      "$ad_auth_count" \
   --arg logging      "$logging_count" \
   --arg split_tunnel "$split_tunnel_count" \
   '.results = {
       "client_vpn_endpoints": ($endpoints[0] // []),
       "summary": {
         "total_endpoints":              ($total        | tonumber),
         "certificate_auth_endpoints":   ($cert_auth    | tonumber),
         "saml_auth_endpoints":          ($saml_auth    | tonumber),
         "ad_auth_endpoints":            ($ad_auth      | tonumber),
         "connection_logging_enabled":   ($logging      | tonumber),
         "split_tunnel_enabled":         ($split_tunnel | tonumber)
       }
   }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

log_info "Evidence saved to $OUTPUT_JSON (endpoints: $total_count)"

aws_finish
