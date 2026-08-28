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
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

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

# Determine public snapshots: Prowler _determine_public_snapshots checks
# describe_snapshot_attribute createVolumePermission for a Group == "all".
snapshots_enriched='[]'
while read -r snap; do
    [ -z "$snap" ] && continue
    snap_id=$(echo "$snap" | jq -r '.SnapshotId')

    is_public="false"
    perms=$(aws ec2 describe-snapshot-attribute --attribute createVolumePermission --snapshot-id "$snap_id" --query 'CreateVolumePermissions' --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ]; then
        echo "aws ec2 describe-snapshot-attribute ($snap_id) failed (exit=$ec)" >> "$_FAILURE_LOG"
    elif echo "${perms:-[]}" | jq -e 'any(.[]?; .Group == "all")' >/dev/null 2>&1; then
        is_public="true"
    fi

    snapshots_enriched=$(echo "$snapshots_enriched" | jq --argjson snap "$snap" --arg public "$is_public" \
        '. += [$snap + {"Public": ($public == "true")}]')
done < <(echo "$snapshots" | jq -c '.[]')

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

while read -r vol; do
    [ -z "$vol" ] && continue
    vol_id=$(echo "$vol" | jq -r '.VolumeId')

    vol_snapshots=$(echo "$snapshots_enriched" | jq -c --arg vid "$vol_id" '[.[] | select(.VolumeId == $vid)]')
    has_snapshot=$(echo "$vol_snapshots" | jq 'length > 0')

    jq --argjson vol "$vol" \
       --argjson snaps "$vol_snapshots" \
       --argjson has_snapshot "$has_snapshot" \
       '.results += [{"VolumeId": $vol.VolumeId, "Encrypted": $vol.Encrypted, "HasSnapshot": $has_snapshot, "Snapshots": $snaps}]' \
       "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
done < <(echo "$volumes" | jq -c '.[]')

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
