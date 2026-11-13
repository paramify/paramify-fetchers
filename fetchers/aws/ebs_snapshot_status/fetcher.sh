#!/bin/bash
#
# AWS — EBS Snapshot Status
#
# Lists EBS volumes in the target region and whether each has at least one
# snapshot, plus per-snapshot encryption, age, and public-exposure status.
# Maps to KSI-RPL-ABO.
#
# Output: $EVIDENCE_DIR/aws_ebs_snapshot_status_<target>.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_ebs_snapshot_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_ebs_snapshot_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_ebs_snapshot_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_ebs_snapshot_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_ebs_snapshot_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# --- per-script data collection (ported from Prowler EC2 service) ---

# Snapshots owned by this account: id, volume, encryption, age (StartTime).
# Prowler: _describe_snapshots paginates describe_snapshots with OwnerIds=["self"].
snapshots=$(aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[*].{SnapshotId:SnapshotId,VolumeId:VolumeId,Encrypted:Encrypted,StartTime:StartTime}' --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws ec2 describe-snapshots failed (exit=$ec)" >> "$_FAILURE_LOG"
    snapshots='[]'
fi
if [ -z "$snapshots" ] || ! echo "$snapshots" | jq . >/dev/null 2>&1; then
    snapshots='[]'
fi

# Public snapshots, in ONE call. Prowler's _determine_public_snapshots asks
# describe_snapshot_attribute per snapshot whether createVolumePermission has
# Group == "all"; --restorable-by-user-ids all is that same predicate evaluated
# server-side, so an account with thousands of snapshots costs one paginated call
# instead of one CLI process per snapshot (which ran past the runner's timeout).
# Skipped when there are no snapshots to mark, as the per-snapshot loop was.
public_ids='[]'
if [ "$(echo "$snapshots" | jq 'length')" -gt 0 ]; then
    public_ids=$(aws ec2 describe-snapshots --owner-ids self --restorable-by-user-ids all --query 'Snapshots[].SnapshotId' --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ]; then
        echo "aws ec2 describe-snapshots (public) failed (exit=$ec)" >> "$_FAILURE_LOG"
        public_ids='[]'
    fi
    if [ -z "$public_ids" ] || ! echo "$public_ids" | jq . >/dev/null 2>&1; then
        public_ids='[]'
    fi
fi

# Volumes in the region, with whether each has at least one owned snapshot.
# Prowler: _describe_volumes (id, encrypted) + volumes_with_snapshots map.
volumes=$(aws ec2 describe-volumes --query 'Volumes[*].{VolumeId:VolumeId,Encrypted:Encrypted}' --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws ec2 describe-volumes failed (exit=$ec)" >> "$_FAILURE_LOG"
    volumes='[]'
fi
if [ -z "$volumes" ] || ! echo "$volumes" | jq . >/dev/null 2>&1; then
    volumes='[]'
fi

# One jq pass joins volumes, snapshots and the public set. The inputs go through
# files, not --argjson: thousands of snapshots overflow the argv limit.
_SNAPS_JSON="$(mktemp -t aws_ebs_snapshot_status_snaps.XXXXXX.json)"
_VOLS_JSON="$(mktemp -t aws_ebs_snapshot_status_vols.XXXXXX.json)"
_PUBLIC_JSON="$(mktemp -t aws_ebs_snapshot_status_public.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_SNAPS_JSON" "$_VOLS_JSON" "$_PUBLIC_JSON"' EXIT
printf '%s' "$snapshots" > "$_SNAPS_JSON"
printf '%s' "$volumes" > "$_VOLS_JSON"
printf '%s' "$public_ids" > "$_PUBLIC_JSON"

jq --slurpfile snaps "$_SNAPS_JSON" --slurpfile vols "$_VOLS_JSON" --slurpfile pub "$_PUBLIC_JSON" '
    (reduce $pub[0][] as $id ({}; .[$id] = true)) as $public
    | (reduce $snaps[0][] as $s ({};
        .[$s.VolumeId | tostring] += [$s + {"Public": ($public[$s.SnapshotId] // false)}])) as $by_vol
    | .results = [$vols[0][] | ($by_vol[.VolumeId | tostring] // []) as $vs
        | {"VolumeId": .VolumeId, "Encrypted": .Encrypted, "HasSnapshot": ($vs | length > 0), "Snapshots": $vs}]
' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
