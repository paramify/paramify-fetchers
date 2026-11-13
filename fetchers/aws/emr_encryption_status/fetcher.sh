#!/bin/bash
#
# AWS — EMR Encryption (at rest / in transit)
#
# For each EMR cluster in the account/region, reports the at-rest and in-transit
# encryption settings from its associated security configuration.
#
# Output: $EVIDENCE_DIR/aws_emr_encryption_status_<target>.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_emr_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_emr_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_emr_encryption_status_fail.XXXXXX)"
_ERR="$(mktemp -t aws_emr_encryption_status_err.XXXXXX)"
_IDS_TXT="$(mktemp -t aws_emr_encryption_status_ids.XXXXXX)"
_ITEMS_JSON="$(mktemp -t aws_emr_encryption_status_clusters.XXXXXX)"
_SEC_JSON="$(mktemp -t aws_emr_encryption_status_security_configs.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_ERR" "$_AWS_ERR_LOG" "$_IDS_TXT" "$_ITEMS_JSON" "$_SEC_JSON"' EXIT

log_info() { printf '%s INFO aws_emr_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_emr_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

cluster_ids=$(aws emr list-clusters --active --query 'Clusters[*].Id' --output text 2>"$_ERR")
list_exit=$?
if [ $list_exit -ne 0 ]; then
    if aws_service_unavailable "$_ERR"; then
        log_info "EMR is not in use for this account/region (not subscribed / not enabled); recording not-enabled status"
        jq '.results += [{"service": "emr", "status": "not_enabled"}]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    else
        echo "aws emr list-clusters (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
        log_error "Failed to list EMR clusters"
    fi
else
    # describe-cluster is genuinely one call per cluster: list-clusters has no
    # SecurityConfiguration. The security configuration a cluster names is
    # described once per distinct name (a failed describe is re-reported for
    # each cluster that names it, as before). Responses are appended raw, in
    # cluster order, and every record is built in the one jq pass below -- one
    # jq process per cluster instead of seven, and no output rewrite per cluster.
    _sec_names=()
    _sec_values=()
    for cluster_id in $(aws_text_list "$cluster_ids"); do
        cluster_details=$(aws emr describe-cluster --cluster-id "$cluster_id" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws emr describe-cluster ($cluster_id) failed" >> "$_FAILURE_LOG"
            continue
        fi
        [ -n "$cluster_details" ] || cluster_details='{}'  # keeps the lists aligned

        security_config_name=$(printf '%s' "$cluster_details" | jq -r '.Cluster.SecurityConfiguration // ""')

        # null = no configuration named, or its describe failed.
        security_config='null'
        if [ -n "$security_config_name" ]; then
            cached=""
            for k in "${!_sec_names[@]}"; do
                if [ "${_sec_names[$k]}" = "$security_config_name" ]; then
                    cached="${_sec_values[$k]}"
                    break
                fi
            done
            if [ -z "$cached" ]; then
                cached=$(aws emr describe-security-configuration --name "$security_config_name" 2>/dev/null)
                [ $? -eq 0 ] || cached="FAILED"
                [ -n "$cached" ] || cached='null'
                _sec_names+=("$security_config_name")
                _sec_values+=("$cached")
            fi
            if [ "$cached" = "FAILED" ]; then
                echo "aws emr describe-security-configuration ($security_config_name) failed" >> "$_FAILURE_LOG"
            else
                security_config="$cached"
            fi
        fi

        printf '%s\n' "$cluster_id" >> "$_IDS_TXT"
        printf '%s\n' "$cluster_details" >> "$_ITEMS_JSON"
        printf '%s\n' "$security_config" >> "$_SEC_JSON"
    done

    # `raw` reproduces the old `jq -r` -> --arg read; the encryption flags are
    # read from the configuration's JSON string, null when it does not parse.
    jq --rawfile ids "$_IDS_TXT" --slurpfile clusters "$_ITEMS_JSON" --slurpfile secs "$_SEC_JSON" '
        def raw: (if type == "string" then . else tojson end) | sub("\n+$"; "");
        def flag($f): if . == null then null
            else (.SecurityConfiguration // "{}" | raw) | try (fromjson | .EncryptionConfiguration[$f] // false) catch null end;
        ($ids | split("\n")) as $id
        | .results += [range(0; $clusters | length) as $i | $clusters[$i] as $c | $secs[$i] as $sc | {
            id: $id[$i],
            name: ($c.Cluster.Name // "unknown" | raw),
            arn: ($c.Cluster.ClusterArn // "unknown" | raw),
            state: ($c.Cluster.Status.State // "unknown" | raw),
            security_configuration: ($c.Cluster.SecurityConfiguration // "" | raw),
            at_rest_encryption: ($sc | flag("EnableAtRestEncryption")),
            in_transit_encryption: ($sc | flag("EnableInTransitEncryption"))
        }]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

aws_finish
