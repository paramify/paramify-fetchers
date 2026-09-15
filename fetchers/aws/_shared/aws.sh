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

# Failure reporting. Re-exported, NOT reimplemented (docs/fetcher_contract.md
# § Output): every AWS fetcher already sources this file, so sourcing the shared
# helper here gives all 80 `report_failure` without a per-fetcher source line.
# BASH_SOURCE[0] is this file, so the path holds whatever the caller's cwd is.
source "$(dirname "${BASH_SOURCE[0]}")/../../_lib/status.sh"

# Recorded in evidence metadata only (the CLI reads the env itself). Empty is a
# valid value = ambient.
PROFILE="${AWS_PROFILE:-}"
REGION="${AWS_DEFAULT_REGION:-}"

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

# --------------------------------------------------------------------------- #
# Failure classification
#
# The problem this solves: 250 of the AWS CLI calls in this tree run as
# `aws ... 2>/dev/null`, and the matching failure-log line records only a label
# ("aws ec2 describe-security-groups (list) failed"). So a triager learned WHICH
# call broke but never WHY -- expired credentials, a missing IAM permission and
# throttling all looked identical, while being three unrelated fixes.
#
# Rewriting those 250 call sites was the obvious approach and the wrong one. The
# `aws` below is a shell FUNCTION that shadows the CLI, so every existing call
# site keeps its exact text and still gets its stderr captured. That works only
# because no fetcher reaches the binary another way -- no `command aws`, no
# absolute path, no `xargs aws`. Keep it that way, or those calls go unclassified.
# --------------------------------------------------------------------------- #

# One line per failed call, accumulated across the run. A FILE, not a variable:
# every call site is `out=$(aws ...)`, which runs the function in a subshell, so
# a variable assignment would be discarded with it. Created here rather than in
# each fetcher so no per-fetcher line is needed; the fetchers' own EXIT traps
# remove it.
_AWS_ERR_LOG="$(mktemp -t aws_shared_err.XXXXXX)"

# aws ... -- the real CLI with stderr captured for classification. stdout, stderr
# and the exit code all reach the caller unchanged, so `2>/dev/null`,
# `2>"$_ERR"` + grep (the not-enabled check), and `$?` all behave exactly as
# before. Only failures are recorded; a successful call writes nothing.
aws() {
  local _err _ec
  _err="$(mktemp -t aws_call_err.XXXXXX)" || { command aws "$@"; return $?; }
  command aws "$@" 2>"$_err"
  _ec=$?
  if [ "$_ec" -ne 0 ] && [ -s "$_err" ]; then
    # printf '%s\n', not a bare pipe: `tr` turns the trailing newline into a
    # space, so the text would arrive unterminated and successive failures would
    # concatenate onto ONE line -- making any `wc -l` of this file read 0.
    printf '%s\n' "$(tr '\n\r\t' '   ' < "$_err" | tr -s ' ' | cut -c1-500)" >> "$_AWS_ERR_LOG"
  fi
  # Hand the caller its stderr back, synchronously, so a grep on the line after
  # the call still sees it. Not `tee`/process substitution, which races.
  cat "$_err" >&2
  rm -f "$_err"
  return $_ec
}

# aws_classify_code [file] -- echoes the contract `code` for the AWS error text
# in <file> (default $_AWS_ERR_LOG), else "partial_failure". Ordered
# most-specific-first and matched against the whole file, so a run whose real
# problem is an expired credential is not reported as a generic partial failure
# just because a later call also 403'd.
#
# Deliberately no "not_enabled": it is not in the contract's closed set, because
# a service that is not in use is valid evidence and exits 0 -- see
# aws_service_unavailable, which is checked BEFORE this and short-circuits.
aws_classify_code() {
  local f="${1:-$_AWS_ERR_LOG}"
  [ -s "$f" ] || { printf 'partial_failure'; return 0; }
  if grep -qiE 'ExpiredToken|InvalidClientTokenId|UnrecognizedClientException|SignatureDoesNotMatch|Unable to locate credentials|The security token included in the request is (expired|invalid)|NoCredentialProviders|sso session .* is expired' "$f"; then
    printf 'auth_failed'
  elif grep -qiE 'AccessDenied|UnauthorizedOperation|not authorized to perform|AuthorizationError|explicit deny|\(403\)' "$f"; then
    printf 'not_authorized'
  elif grep -qiE 'Throttling|ThrottlingException|TooManyRequests|RequestLimitExceeded|SlowDown|Rate exceeded|\(429\)' "$f"; then
    printf 'rate_limited'
  elif grep -qiE 'Could not connect to the endpoint URL|EndpointConnectionError|ConnectTimeoutError|ReadTimeoutError|Connection was closed|Name or service not known|[Tt]emporary failure in name resolution|\(50[34]\)' "$f"; then
    printf 'target_unreachable'
  elif grep -qiE 'InvalidParameterValue|ValidationError|ValidationException|MalformedPolicyDocument|Invalid region|Invalid( |-)?ARN|InvalidInput' "$f"; then
    printf 'bad_config'
  else
    printf 'partial_failure'
  fi
}

# aws_report_failures <count> <label-reasons> -- report a partial collection to
# the runner: the caller's call labels, the AWS error text behind them, and a
# classified code. Replaces a hardcoded `partial_failure` at the 80 call sites.
#
# Both halves are included on purpose. The labels say which call broke and are
# always present; the error text says why and is present whenever the CLI wrote
# anything to stderr. Reporting only the second would lose attribution on a call
# that failed silently.
aws_report_failures() {
    local count="$1" reasons="$2" detail=""
    if [ -s "$_AWS_ERR_LOG" ]; then
        detail="$(head -n 3 "$_AWS_ERR_LOG" | awk '{printf "%s%s", sep, $0; sep=" | "}')"
        detail=" -- ${detail}"
    fi
    report_failure "$count AWS API failure(s); first: ${reasons}${detail}" \
        "$(aws_classify_code)"
}

# aws_finish -- the end of every AWS fetcher: summarize $_FAILURE_LOG, report a
# partial collection if there is one, otherwise log where the evidence landed.
#
# This was nine lines pasted identically into all 80 fetchers -- byte for byte,
# once the fetcher name was normalized out. One copy means a change to how a
# partial collection is summarized lands everywhere at once, instead of in the
# subset someone remembered to update.
#
# Exits 1 on any recorded failure, so it is the LAST line of a fetcher. The
# three-reason cap and the "(+N more)" suffix are the behaviour the 80 copies
# had; they are kept exactly, because the runner surfaces this string and the
# uploader stores it.
#
# Usage (last line of the fetcher):
#   aws_finish
aws_finish() {
    local count reasons
    count=$(wc -l < "$_FAILURE_LOG" 2>/dev/null | tr -d ' ')
    count=${count:-0}
    if [ "$count" -gt 0 ]; then
        reasons="$(head -n 3 "$_FAILURE_LOG" | awk '{printf "%s%s", sep, $0; sep="; "}')"
        [ "$count" -gt 3 ] && reasons="${reasons}(+$((count - 3)) more)"
        aws_report_failures "$count" "$reasons"
        exit 1
    fi

    log_info "Evidence saved to $OUTPUT_JSON"
}
