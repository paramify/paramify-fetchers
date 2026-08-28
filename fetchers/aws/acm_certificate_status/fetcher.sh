#!/bin/bash
#
# AWS — ACM Certificate Status
#
# For each ACM certificate in the target region, reports validation status,
# expiry (NotAfter / days remaining), key algorithm, renewal eligibility, and
# the resources currently using the certificate. Maps to KSI-SVC-ASM.
#
# Output: $EVIDENCE_DIR/aws_acm_certificate_status_<profile>_<region>.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_acm_certificate_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_acm_certificate_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_acm_certificate_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_acm_certificate_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_acm_certificate_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# `aws acm list-certificates` defaults to returning only RSA_1024/RSA_2048
# certificates; EC and larger-RSA certs are silently omitted. Pass the full
# keyTypes filter (matching Prowler's ACM service) so KSI-SVC-ASM sees every
# certificate's key algorithm, not just the RSA defaults.
cert_arns=$(aws acm list-certificates \
    --includes keyTypes=RSA_1024,RSA_2048,RSA_3072,RSA_4096,EC_prime256v1,EC_secp384r1,EC_secp521r1 \
    --query 'CertificateSummaryList[*].CertificateArn' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws acm list-certificates failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list ACM certificates"
else
    for cert_arn in $(aws_text_list "$cert_arns"); do
        [ -z "$cert_arn" ] && continue

        cert_details=$(aws acm describe-certificate --certificate-arn "$cert_arn" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws acm describe-certificate ($cert_arn) failed" >> "$_FAILURE_LOG"
            continue
        fi

        cert_data=$(echo "$cert_details" | jq '{
            certificate_arn: .Certificate.CertificateArn,
            domain_name: .Certificate.DomainName,
            type: .Certificate.Type,
            status: .Certificate.Status,
            key_algorithm: .Certificate.KeyAlgorithm,
            not_after: .Certificate.NotAfter,
            renewal_eligibility: .Certificate.RenewalEligibility,
            in_use: ((.Certificate.InUseBy | length) > 0),
            in_use_by: (.Certificate.InUseBy // [])
        }')

        jq --argjson data "$cert_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
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
