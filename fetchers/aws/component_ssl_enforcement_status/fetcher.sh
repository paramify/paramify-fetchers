#!/bin/bash
# AWS — Component SSL/TLS Enforcement Status
# Checks S3 bucket policies for an aws:SecureTransport HTTPS-deny statement and
# RDS DB parameter groups for rds.force_ssl=1 or require_secure_transport=ON.
# Output: $EVIDENCE_DIR/aws_component_ssl_enforcement_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_component_ssl_enforcement_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_component_ssl_enforcement_status.XXXXXX.json)"
_S3_NAMES="$(mktemp -t aws_component_ssl_enforcement_status_s3_names.XXXXXX)"
_S3_POLICIES="$(mktemp -t aws_component_ssl_enforcement_status_s3_policies.XXXXXX.json)"
_RDS_ROWS="$(mktemp -t aws_component_ssl_enforcement_status_rds_rows.XXXXXX)"
_FAILURE_LOG="$(mktemp -t aws_component_ssl_enforcement_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_S3_NAMES" "$_S3_POLICIES" "$_RDS_ROWS" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_component_ssl_enforcement_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_component_ssl_enforcement_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
    "results": {"s3": [], "rds": []},
    "summary": {}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream) ---

# 1. S3 Bucket SSL Enforcement
s3_buckets=$(aws s3api list-buckets 2>/dev/null | jq -r '.Buckets[].Name')
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws s3api list-buckets failed (exit=$ec)" >> "$_FAILURE_LOG"
fi
# get-bucket-policy has no batch form, so each bucket still costs one call. The
# policies are appended in order (null for no policy) and checked in the one jq
# pass below, instead of three jq processes and a rewrite per bucket.
for bucket in $s3_buckets; do
    # get-bucket-policy errors (NoSuchBucketPolicy) when a bucket has no policy;
    # upstream treats that as valid evidence (ssl not enforced), not a failure.
    policy=$(aws s3api get-bucket-policy --bucket "$bucket" 2>/dev/null || echo "")
    printf '%s\n' "$bucket" >> "$_S3_NAMES"
    printf '%s\n' "${policy:-null}" >> "$_S3_POLICIES"
done

# 2. RDS SSL Enforcement
# The first describe already carries each instance's parameter groups, so the
# per-instance describe this replaced re-read them. describe-db-parameters is
# asked once per group rather than once per (instance, group), and its answer
# reused.
rds_lines=$(aws rds describe-db-instances 2>/dev/null | jq -r '.DBInstances[] | [.DBInstanceIdentifier, (.DBParameterGroups[]?.DBParameterGroupName)] | join(" ")')
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws rds describe-db-instances failed (exit=$ec)" >> "$_FAILURE_LOG"
fi

pg_seen=" "
pg_enforcing=" "
while read -r db pgroups; do
    [ -z "$db" ] && continue
    enforced="false"
    for pg in $pgroups; do
        if [[ "$pg_seen" != *" $pg "* ]]; then
            # MySQL (including 8.4+) uses require_secure_transport; other engines
            # such as PostgreSQL and SQL Server use rds.force_ssl.
            param=$(aws rds describe-db-parameters --db-parameter-group-name "$pg" 2>/dev/null | jq -r '
                any(.Parameters[]?;
                    (.ParameterName == "rds.force_ssl" and .ParameterValue == "1") or
                    (.ParameterName == "require_secure_transport" and
                        (((.ParameterValue // "") | ascii_downcase) == "on" or
                         .ParameterValue == "1" or
                         ((.ParameterValue // "") | ascii_downcase) == "true")))
            ')
            ec=$?
            if [ $ec -ne 0 ]; then
                echo "aws rds describe-db-parameters ($pg) failed (exit=$ec)" >> "$_FAILURE_LOG"
            fi
            pg_seen="$pg_seen$pg "
            [[ "$param" == "true" ]] && pg_enforcing="$pg_enforcing$pg "
        fi
        if [[ "$pg_enforcing" == *" $pg "* ]]; then
            enforced="true"
            break
        fi
    done
    printf '%s\t%s\t%s\n' "$db" "$enforced" "$pgroups" >> "$_RDS_ROWS"
done <<< "$rds_lines"

# One pass builds both lists and the summary. The S3 test is the per-bucket
# `jq -e` it replaced, down to its edges: matching statements are those the
# stream emitted before any error, and policy_snippet is null unless exactly
# one statement matched (two compact objects did not parse as one).
jq --rawfile names "$_S3_NAMES" --slurpfile policies "$_S3_POLICIES" --rawfile rds_rows "$_RDS_ROWS" '
    ($names | split("\n")) as $names
    | [range(0; $policies | length) as $i | $policies[$i] as $policy
        | (if $policy == null then []
           else ([try ($policy.Policy | fromjson | .Statement[]?
                        | try (select(.Effect == "Deny" and .Condition.Bool."aws:SecureTransport" == "false"))
                          catch {"__error": true})
                  catch {"__error": true}]
                 | (map(type == "object" and has("__error")) | index(true)) as $stop
                 | if $stop == null then . else .[:$stop] end)
           end) as $found
        | {"bucket": $names[$i], "ssl_enforced": ($found | length > 0),
           "policy_snippet": (if ($found | length) == 1 then $found[0] else null end)}] as $s3
    | [$rds_rows | split("\n")[] | select(length > 0) | split("\t")
        | {"db_instance": .[0], "ssl_enforced": (.[1] == "true"),
           "parameter_groups": (.[2] | split(" ") | map(select(length > 0)))}] as $rds
    | ($s3 | length | tostring) as $s3_total
    | ([$s3[] | select(.ssl_enforced)] | length | tostring) as $s3_ssl_enforced
    | ($rds | length | tostring) as $rds_total
    | ([$rds[] | select(.ssl_enforced)] | length | tostring) as $rds_ssl_enforced
    | .results.s3 = $s3
    | .results.rds = $rds
    | .summary = {
      s3_total: ($s3_total|tonumber),
      s3_ssl_enforced: ($s3_ssl_enforced|tonumber),
      rds_total: ($rds_total|tonumber),
      rds_ssl_enforced: ($rds_ssl_enforced|tonumber),
      formatted_summary: ("S3 Buckets: " + $s3_total + ", SSL Enforced: " + $s3_ssl_enforced + "\n" +
                         "RDS Instances: " + $rds_total + ", SSL Enforced: " + $rds_ssl_enforced + "\n")
   }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

log_info "$(jq -r '.summary.formatted_summary' "$OUTPUT_JSON")"

aws_finish
