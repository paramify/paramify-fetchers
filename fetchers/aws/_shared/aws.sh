#!/usr/bin/env bash
# Shared helpers for the AWS fetchers (SOURCED, not executed).
#
# Credential + region resolution is the AWS CLI's job, via its own provider
# chain. The runner sets AWS_PROFILE / AWS_DEFAULT_REGION from a manifest target
# when one is given; when a target omits them — or there are no targets at all —
# they stay unset and the CLI uses the AMBIENT identity/region ("collect where
# deployed"). So fetchers do NOT pass --profile/--region; they just run `aws ...`
# and let the CLI read the env vars (or fall through to IRSA / instance role /
# SSO / ~/.aws). A profile-bearing target still scopes the run for fanout.
#
# Usage in a fetcher.sh:
#   source "$(dirname "$0")/../_shared/aws.sh"
#   _TARGET_ID="$(aws_target_id)"

# Recorded in evidence metadata only (the CLI reads the env itself). Empty is a
# valid value = ambient.
PROFILE="${AWS_PROFILE:-}"
REGION="${AWS_DEFAULT_REGION:-}"

# Retry policy for every AWS CLI call a fetcher makes. The CLI's default
# (standard mode, 3 attempts) is tuned for interactive use; a fetcher sweeps a
# whole account, so in a large environment the per-resource describe calls
# throttle and come back as `Throttling: Rate exceeded` (exit 254) — which the
# fetcher can only record as an opaque API failure. Adaptive mode adds
# client-side rate limiting and 10 attempts absorbs the bursts, which is the
# difference between a partial scan and a complete one.
#
# `:=` means an operator's own value always wins: set AWS_RETRY_MODE /
# AWS_MAX_ATTEMPTS in the runner environment (both are in the category's
# passthrough_env) to tune this per account.
: "${AWS_RETRY_MODE:=adaptive}"
: "${AWS_MAX_ATTEMPTS:=10}"
export AWS_RETRY_MODE AWS_MAX_ATTEMPTS

# aws_target_id [REGION] — id for unique output filenames across a fanout: the
# profile when set, else "ambient", with the region appended only when passed.
# Regional fetchers pass "$REGION"; global fetchers (IAM, Route53, S3 naming)
# pass nothing so their filename stays account/profile-scoped. Account
# attribution always lives in the evidence metadata (account_id from
# `aws sts get-caller-identity`), so an ambient run is still traceable.
aws_target_id() {
  local id="${PROFILE:-ambient}"
  [ -n "${1:-}" ] && id="${id}_${1}"
  printf '%s' "$id" | tr -c 'A-Za-z0-9._-' '_'
}

# aws_service_unavailable <stderr-file> — true (exit 0) when the captured AWS CLI
# error means the service is simply NOT IN USE for this account. That is valid
# evidence ("not enabled / not subscribed / not applicable"), NOT a collection
# failure, so the caller should record a not-enabled result and exit 0 rather than
# logging a failure. Covers: service not subscribed / not opted-in, Security Hub /
# Macie not enabled, account not a member of an Organization, Resource Explorer /
# resource not found, and the generic "needs a subscription for the service"
# message. Use it ONLY at a fetcher's primary enablement / top-level list call to
# decide not-enabled (exit 0) vs. a real failure (exit 1). Genuine AccessDenied
# (without the subscription message), throttling, and endpoint errors are NOT
# matched here and stay real failures.
aws_service_unavailable() {
  [ -s "${1:-/dev/null}" ] || return 1
  grep -qiE 'SubscriptionRequiredException|OptInRequired|needs a subscription for the service|InvalidAccessException|AWSOrganizationsNotInUseException|not a member of an organization|is not enabled|ResourceNotFoundException' "$1"
}

# aws_text_list <output> — echoes an AWS CLI `--output text` list back UNLESS it is
# the empty-list sentinel the CLI prints for an absent/null field (the literal
# "None", or whitespace only). Prevents the classic bug where
# `for x in $(aws ... --query 'Items[].Id' --output text)` iterates once over the
# string "None" and then fails a per-item call. Usage:
#   for x in $(aws_text_list "$ids"); do ...
aws_text_list() {
  case "$1" in
    None|"") return 0 ;;
    *) printf '%s' "$1" ;;
  esac
}

# aws_report_failures <failure-log> [count] — report WHICH API calls failed through
# the runner's status channel.
#
# Every AWS fetcher appends one line per failed call to a temp $_FAILURE_LOG
# ("aws ec2 describe-volumes (vol-0f23c982…) failed"), deletes it on exit, and
# reports only the COUNT to stderr. An operator is then left with "Encountered 2
# AWS API failures during collection" and no way to learn which two — the detail
# existed and was thrown away. In a 628-volume account that is the difference
# between "two volumes were deleted mid-scan, the evidence is good" and an
# unexplained failed run.
#
# $FETCHER_STATUS_FILE is the runner's channel for exactly this: what lands here
# becomes metadata.error on the evidence envelope, IN PREFERENCE to the tail of
# stderr (which otherwise reports whatever happened to be logged last). This is
# the bash counterpart of azure_common.write_status().
#
# `code` uses the contract's closed set (docs/fetcher_contract.md): per-call
# failures inside an otherwise complete sweep are partial_failure. The exit code
# stays binary and is still the fetcher's to decide — this only explains it.
#
# Never fails the run: a fetcher that cannot report its status must still exit
# with the code it meant to.
aws_report_failures() {
  local log="${1:-}" count="${2:-}" detail reason
  [ -n "${FETCHER_STATUS_FILE:-}" ] || return 0
  [ -s "$log" ] || return 0

  if [ -z "$count" ]; then
    count="$(wc -l < "$log" 2>/dev/null | tr -d ' ')"
    count="${count:-0}"
  fi

  # metadata.error is capped at 4000 chars and a large-account sweep can fail on
  # hundreds of resources, so send a bounded sample: the first 20 show the
  # pattern (one bad region? one denied key? volumes vanishing?) and the count
  # carries the true scale.
  detail="$(head -n 20 "$log" | tr '\n' '|' | sed 's/|$//; s/|/ | /g')"
  if [ "$count" -gt 20 ] 2>/dev/null; then
    detail="${detail} | +$((count - 20)) more"
  fi
  reason="${count} AWS API failure(s) during collection: ${detail}"

  jq -n --arg error "$reason" '{error: $error, code: "partial_failure"}' \
    > "$FETCHER_STATUS_FILE" 2>/dev/null || true
}
