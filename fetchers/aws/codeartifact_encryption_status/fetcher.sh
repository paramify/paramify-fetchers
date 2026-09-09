#!/bin/bash
#
# AWS — CodeArtifact Domain Encryption at Rest
#
# For each CodeArtifact domain in the account/region, reports the KMS
# encryption key used to encrypt domain assets at rest.
#
# Output: $EVIDENCE_DIR/aws_codeartifact_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_codeartifact_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_codeartifact_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_codeartifact_encryption_status_fail.XXXXXX)"

log_info() { printf '%s INFO aws_codeartifact_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_codeartifact_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

_ERR="$(mktemp -t aws_codeartifact_encryption_status_err.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_ERR" "$_AWS_ERR_LOG"' EXIT

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

domains=$(aws codeartifact list-domains --query 'domains[*].name' --output text 2>"$_ERR")
list_exit=$?
if [ $list_exit -ne 0 ] && aws_service_unavailable "$_ERR"; then
    log_info "CodeArtifact is not in use for this account/region (not subscribed / not enabled); recording not-enabled status"
    record=$(jq -n '{name: "None", arn: "None", owner: "None", encrypted: false, kms_key_arn: "None", status: "not-enabled"}')
    jq --argjson data "$record" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
elif [ $list_exit -ne 0 ]; then
    echo "aws codeartifact list-domains (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list CodeArtifact domains"
else
    for domain in $(aws_text_list "$domains"); do
        domain_details=$(aws codeartifact describe-domain --domain "$domain" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws codeartifact describe-domain ($domain) failed" >> "$_FAILURE_LOG"
            continue
        fi

        name=$(echo "$domain_details" | jq -r '.domain.name')
        arn=$(echo "$domain_details" | jq -r '.domain.arn // "None"')
        owner=$(echo "$domain_details" | jq -r '.domain.owner // "None"')
        kms_key_arn=$(echo "$domain_details" | jq -r '.domain.encryptionKey // "None"')
        encrypted=false
        [ "$kms_key_arn" != "None" ] && [ -n "$kms_key_arn" ] && encrypted=true

        record=$(jq -n --arg name "$name" --arg arn "$arn" --arg owner "$owner" \
            --argjson enc "$encrypted" --arg kms "$kms_key_arn" \
            '{name: $name, arn: $arn, owner: $owner, encrypted: $enc, kms_key_arn: $kms}')

        jq --argjson data "$record" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
