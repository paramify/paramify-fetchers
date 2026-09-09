#!/bin/bash
# Collects federated identity providers (SAML/OIDC IAM providers) and IAM
# Identity Center configuration (instances, identity providers, permission sets).
# Output: $EVIDENCE_DIR/aws_iam_identity_center.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_iam_identity_center_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_iam_identity_center.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_iam_identity_center_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_iam_identity_center %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_iam_identity_center %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"iam_providers": {"saml": [], "oidc": []}, "identity_center": {"instances": [], "identity_providers": [], "permission_sets": []}}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream) ---

# A. Get IAM SAML Identity Providers
log_info "Retrieving SAML providers"
saml_providers=$(aws iam list-saml-providers --query 'SAMLProviderList[*]' --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws iam list-saml-providers failed (exit=$ec)" >> "$_FAILURE_LOG"
    saml_providers='[]'
fi
echo "$saml_providers" | jq -c '.[]' | while read -r provider; do
    provider_arn=$(echo "$provider" | jq -r '.Arn')

    # Get SAML provider details
    provider_details=$(aws iam get-saml-provider --saml-provider-arn "$provider_arn" --query 'SAMLProviderDocument' --output json 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "aws iam get-saml-provider ($provider_arn) failed" >> "$_FAILURE_LOG"
        provider_details='null'
    fi

    jq --arg arn "$provider_arn" --argjson details "$provider_details" '.results.iam_providers.saml += [{"Arn": $arn, "Details": $details}]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
done

# A. Get IAM OIDC Identity Providers
log_info "Retrieving OpenID Connect providers"
oidc_providers=$(aws iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[*]' --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws iam list-open-id-connect-providers failed (exit=$ec)" >> "$_FAILURE_LOG"
    oidc_providers='[]'
fi
echo "$oidc_providers" | jq -c '.[]' | while read -r provider; do
    provider_arn=$(echo "$provider" | jq -r '.Arn')

    # Get OIDC provider details
    provider_details=$(aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$provider_arn" --query 'OpenIDConnectProviderDocument' --output json 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "aws iam get-open-id-connect-provider ($provider_arn) failed" >> "$_FAILURE_LOG"
        provider_details='null'
    fi

    jq --arg arn "$provider_arn" --argjson details "$provider_details" '.results.iam_providers.oidc += [{"Arn": $arn, "Details": $details}]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
done

# B. Get Identity Center Information
log_info "Retrieving Identity Center instances"
instances=$(aws sso-admin list-instances --query 'Instances[*]' --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws sso-admin list-instances failed (exit=$ec)" >> "$_FAILURE_LOG"
    instances='[]'
fi

# No Identity Center instances is valid evidence (not configured) -> not a failure.
if [ "$(echo "$instances" | jq 'length')" -eq 0 ]; then
    log_info "No IAM Identity Center instances found in this account/region"
else
    echo "$instances" | jq -c '.[]' | while read -r instance; do
        instance_arn=$(echo "$instance" | jq -r '.InstanceArn')
        instance_id=$(echo "$instance" | jq -r '.InstanceId')

        if [ "$instance_id" = "null" ] || [ -z "$instance_id" ]; then
            log_info "Instance found without ID - checking next instance"
            continue
        fi

        # Add instance to results
        jq --argjson instance "$instance" '.results.identity_center.instances += [$instance]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

        # Get Identity Providers for this instance
        identity_providers=$(aws sso-admin list-identity-providers --instance-arn "$instance_arn" --query 'IdentityProviders[*]' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws sso-admin list-identity-providers ($instance_id) failed" >> "$_FAILURE_LOG"
            identity_providers='[]'
        fi

        echo "$identity_providers" | jq -c '.[]' | while read -r provider; do
            provider_id=$(echo "$provider" | jq -r '.IdentityProviderId')

            if [ "$provider_id" = "null" ] || [ -z "$provider_id" ]; then
                log_info "Provider found without ID - checking next provider"
                continue
            fi

            jq --argjson provider "$provider" '.results.identity_center.identity_providers += [$provider]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
        done

        # Get Permission Sets for this instance
        permission_sets=$(aws sso-admin list-permission-sets --instance-arn "$instance_arn" --query 'PermissionSets[*]' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws sso-admin list-permission-sets ($instance_id) failed" >> "$_FAILURE_LOG"
            permission_sets='[]'
        fi

        echo "$permission_sets" | jq -c '.[]' | while read -r permission_set_arn; do
            if [ "$permission_set_arn" = "null" ] || [ -z "$permission_set_arn" ]; then
                log_info "Permission set found without ARN - checking next permission set"
                continue
            fi

            # Get Permission Set details
            permission_set_details=$(aws sso-admin describe-permission-set --instance-arn "$instance_arn" --permission-set-arn "$permission_set_arn" --query 'PermissionSet' --output json 2>/dev/null)
            if [ $? -eq 0 ] && [ -n "$permission_set_details" ]; then
                jq --argjson ps "$permission_set_details" '.results.identity_center.permission_sets += [$ps]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
            else
                echo "aws sso-admin describe-permission-set ($permission_set_arn) failed" >> "$_FAILURE_LOG"
            fi
        done
    done
fi

aws_finish
