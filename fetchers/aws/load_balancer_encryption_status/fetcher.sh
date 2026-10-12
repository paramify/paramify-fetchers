#!/bin/bash
# AWS — Load Balancer Encryption Status
# Inspects ELBv2 application and network load balancers and their listener SSL
# policies to report which enforce in-transit encryption.
# Output: $EVIDENCE_DIR/aws_load_balancer_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_load_balancer_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_load_balancer_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_load_balancer_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_load_balancer_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_load_balancer_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn},
    "results": {"load_balancers": {"alb": {"total": 0, "encrypted": 0, "details": []}, "nlb": {"total": 0, "encrypted": 0, "details": []}}},
    "summary": {}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream) ---

log_info "Checking load balancer encryption"

# Get all load balancers
load_balancers=$(aws elbv2 describe-load-balancers 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws elbv2 describe-load-balancers failed (exit=$ec)" >> "$_FAILURE_LOG"
    load_balancers='{"LoadBalancers":[]}'
fi

# One describe-listeners per ALB/NLB (there is no bulk form), read for both the
# encryption check and the reported ssl_policy -- it used to be called twice per
# load balancer. Each response is streamed to a file after a small header
# ({arn, type}); a failed call is streamed as null. One jq pass then applies the
# rules the per-LB shell code did:
#   encrypted  -- some HTTPS/TLS listener's SslPolicy contains FIPS, TLS13 or
#                 TLS-1-2 (false when the call failed);
#   ssl_policy -- the FIRST listener's SslPolicy, whatever its protocol, "none"
#                 when absent, and "" when the call failed (the old pipe into jq
#                 printed nothing on empty input).
_LISTENERS_JSON="$(mktemp -t aws_load_balancer_encryption_status_listeners.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_LISTENERS_JSON"' EXIT
while IFS=$'\t' read -r arn type; do
    [[ "$type" == "application" || "$type" == "network" ]] || continue
    listeners=$(aws elbv2 describe-listeners --load-balancer-arn "$arn" \
        --query "Listeners[*].{Port:Port,Protocol:Protocol,SslPolicy:SslPolicy}" \
        --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ] || [ -z "$listeners" ]; then
        echo "aws elbv2 describe-listeners ($arn) failed (exit=$ec)" >> "$_FAILURE_LOG"
        listeners='null'
    fi
    printf '{"arn":"%s","type":"%s"}\n%s\n' "$arn" "$type" "$listeners" >> "$_LISTENERS_JSON"
done < <(echo "$load_balancers" | jq -r '.LoadBalancers[] | [.LoadBalancerArn, .Type] | @tsv')

jq --slurpfile stream "$_LISTENERS_JSON" '
    [range(0; $stream | length; 2) as $i | $stream[$i] + {listeners: $stream[$i + 1]}] as $lbs
    | def details($t): [$lbs[] | select(.type == $t) | {
        arn: .arn,
        encrypted: (if .listeners == null then false else
            any(.listeners[] | select(.Protocol == "HTTPS" or .Protocol == "TLS") | (.SslPolicy | tostring);
                test("FIPS|TLS13|TLS-1-2")) end),
        ssl_policy: (if .listeners == null then "" else (.listeners[0].SslPolicy // "none") end)
      }];
      details("application") as $alb | details("network") as $nlb
    | ($alb | length) as $alb_count | ([$alb[] | select(.encrypted)] | length) as $alb_encrypted
    | ($nlb | length) as $nlb_count | ([$nlb[] | select(.encrypted)] | length) as $nlb_encrypted
    | .results.load_balancers.alb.total = $alb_count
    | .results.load_balancers.alb.encrypted = $alb_encrypted
    | .results.load_balancers.alb.details = $alb
    | .results.load_balancers.nlb.total = $nlb_count
    | .results.load_balancers.nlb.encrypted = $nlb_encrypted
    | .results.load_balancers.nlb.details = $nlb
    | .summary = {
        alb_total: $alb_count,
        alb_encrypted: $alb_encrypted,
        nlb_total: $nlb_count,
        nlb_encrypted: $nlb_encrypted,
        formatted_summary: ("ALB: \($alb_encrypted)/\($alb_count), NLB: \($nlb_encrypted)/\($nlb_count)")
      }
' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

log_info "$(jq -r '.summary.formatted_summary' "$OUTPUT_JSON")"

aws_finish
