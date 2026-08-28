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
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

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

# Function to check load balancer encryption
check_load_balancer_encryption() {
    local lb_arn=$1
    local lb_type=$2

    # Get listeners with their SSL policies
    local listeners
    listeners=$(aws elbv2 describe-listeners --load-balancer-arn "$lb_arn" \
        --query "Listeners[*].{Port:Port,Protocol:Protocol,SslPolicy:SslPolicy}" \
        2>/dev/null)
    local ec=$?
    if [ $ec -ne 0 ]; then
        echo "aws elbv2 describe-listeners ($lb_arn) failed (exit=$ec)" >> "$_FAILURE_LOG"
    fi

    # Check if any listener uses HTTPS/SSL with secure policy
    local is_encrypted=false

    # Use a for loop to avoid subshell issues
    local ssl_policies
    ssl_policies=$(echo "$listeners" | jq -r '.[] | select(.Protocol == "HTTPS" or .Protocol == "TLS") | .SslPolicy')
    for ssl_policy in $ssl_policies; do
        if [[ -n "$ssl_policy" ]]; then
            if [[ "$ssl_policy" == *"FIPS"* ]] || [[ "$ssl_policy" == *"TLS13"* ]] || [[ "$ssl_policy" == *"TLS-1-2"* ]]; then
                is_encrypted=true
                break
            fi
        fi
    done

    echo "$is_encrypted"
}

log_info "Checking load balancer encryption"

# Get all load balancers
load_balancers=$(aws elbv2 describe-load-balancers 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws elbv2 describe-load-balancers failed (exit=$ec)" >> "$_FAILURE_LOG"
    load_balancers='{"LoadBalancers":[]}'
fi

# Process ALBs
alb_count=0
alb_encrypted=0
alb_details=()

# Process NLBs
nlb_count=0
nlb_encrypted=0
nlb_details=()

# Process each load balancer
while IFS=$'\t' read -r arn type; do
    if [[ "$type" == "application" ]]; then
        alb_count=$((alb_count + 1))
        is_encrypted=$(check_load_balancer_encryption "$arn" "application")
        if [[ "$is_encrypted" == "true" ]]; then
            alb_encrypted=$((alb_encrypted + 1))
        fi
        # Get SSL policy details for the output
        ssl_policy=$(aws elbv2 describe-listeners --load-balancer-arn "$arn" \
            --query "Listeners[*].{Port:Port,Protocol:Protocol,SslPolicy:SslPolicy}" \
            2>/dev/null | jq -r '.[0].SslPolicy // "none"')
        alb_details+=("{\"arn\":\"$arn\",\"encrypted\":$is_encrypted,\"ssl_policy\":\"$ssl_policy\"}")
    elif [[ "$type" == "network" ]]; then
        nlb_count=$((nlb_count + 1))
        is_encrypted=$(check_load_balancer_encryption "$arn" "network")
        if [[ "$is_encrypted" == "true" ]]; then
            nlb_encrypted=$((nlb_encrypted + 1))
        fi
        # Get SSL policy details for the output
        ssl_policy=$(aws elbv2 describe-listeners --load-balancer-arn "$arn" \
            --query "Listeners[*].{Port:Port,Protocol:Protocol,SslPolicy:SslPolicy}" \
            2>/dev/null | jq -r '.[0].SslPolicy // "none"')
        nlb_details+=("{\"arn\":\"$arn\",\"encrypted\":$is_encrypted,\"ssl_policy\":\"$ssl_policy\"}")
    fi
done < <(echo "$load_balancers" | jq -r '.LoadBalancers[] | [.LoadBalancerArn, .Type] | @tsv')

# Update JSON with load balancer information
jq --arg alb_count "$alb_count" --arg alb_encrypted "$alb_encrypted" \
   --arg nlb_count "$nlb_count" --arg nlb_encrypted "$nlb_encrypted" \
   --argjson alb_details "[$(IFS=,; echo "${alb_details[*]}")]" \
   --argjson nlb_details "[$(IFS=,; echo "${nlb_details[*]}")]" \
   '.results.load_balancers.alb.total = ($alb_count | tonumber) |
    .results.load_balancers.alb.encrypted = ($alb_encrypted | tonumber) |
    .results.load_balancers.alb.details = $alb_details |
    .results.load_balancers.nlb.total = ($nlb_count | tonumber) |
    .results.load_balancers.nlb.encrypted = ($nlb_encrypted | tonumber) |
    .results.load_balancers.nlb.details = $nlb_details' \
   "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

# Update summary in JSON
jq --arg alb_count "$alb_count" --arg alb_encrypted "$alb_encrypted" \
   --arg nlb_count "$nlb_count" --arg nlb_encrypted "$nlb_encrypted" \
   '.summary = {
      alb_total: ($alb_count | tonumber),
      alb_encrypted: ($alb_encrypted | tonumber),
      nlb_total: ($nlb_count | tonumber),
      nlb_encrypted: ($nlb_encrypted | tonumber),
      formatted_summary: ("ALB: " + $alb_encrypted + "/" + $alb_count + ", NLB: " + $nlb_encrypted + "/" + $nlb_count)
   }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

log_info "$(jq -r '.summary.formatted_summary' "$OUTPUT_JSON")"

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
