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
# Failure reporting -- $FETCHER_STATUS_FILE
#
# Every AWS fetcher accumulates failures in a $_FAILURE_LOG temp file, counts the
# lines, and exits 1. The COUNT reaches the runner (as an ERROR log line); the
# recorded causes do not -- the temp file is dropped by the EXIT trap. So the
# envelope's metadata.error falls back to the tail of stderr, which is that
# count, and a triager learns "3 API failures" and nothing about which call or
# why. These helpers hand the runner the causes instead.
#
# The runner redacts every injected secret out of what it reads here
# (framework/runner/executor.py:_read_status_file), which is why raw AWS stderr
# is safe to pass through -- that was the concern that motivated 2>/dev/null.
# --------------------------------------------------------------------------- #

# The contract's closed set of `code` values (docs/fetcher_contract.md).
# Deliberately no "not_enabled": a service that is not in use is valid evidence
# and exits 0 (see aws_service_unavailable), so it never reports a failure code.

# aws_classify_code <file> -- echoes the contract `code` for the AWS error text in
# <file>, else "partial_failure". Ordered most-specific-first and matched against
# the whole file, so a run whose real problem is an expired credential is not
# reported as a generic partial failure just because a later call also 403'd.
aws_classify_code() {
  local f="${1:-/dev/null}"
  [ -s "$f" ] || { printf 'partial_failure'; return 0; }
  if grep -qiE 'ExpiredToken|InvalidClientTokenId|UnrecognizedClientException|SignatureDoesNotMatch|InvalidUserID\.NotFound|Unable to locate credentials|The security token included in the request is (expired|invalid)|NoCredentialProviders|sso session .* is expired' "$f"; then
    printf 'auth_failed'
  elif grep -qiE 'AccessDenied|UnauthorizedOperation|not authorized to perform|AuthorizationError|explicit deny|\(403\)' "$f"; then
    printf 'not_authorized'
  elif grep -qiE 'Throttling|ThrottlingException|TooManyRequests|RequestLimitExceeded|SlowDown|Rate exceeded|\(429\)' "$f"; then
    printf 'rate_limited'
  elif grep -qiE 'Could not connect to the endpoint URL|EndpointConnectionError|ConnectTimeoutError|ReadTimeoutError|Connection was closed|Name or service not known|temporary failure in name resolution|\(50[34]\)' "$f"; then
    printf 'target_unreachable'
  elif grep -qiE 'InvalidParameterValue|ValidationError|ValidationException|MalformedPolicyDocument|Invalid region|Could not connect to the endpoint URL for|Invalid( |-)?ARN|InvalidInput' "$f"; then
    printf 'bad_config'
  else
    printf 'partial_failure'
  fi
}

# aws_status_write <error> [code] -- report the failure reason to the runner.
# A no-op when the runner set no status file. Never fails the run: the exit code
# stays authoritative, so a missing jq or an unwritable path is swallowed, the
# same guarantee the Python helpers give (azure_common.write_status).
aws_status_write() {
  local error="$1" code="${2:-}" path="${FETCHER_STATUS_FILE:-}"
  [ -n "$path" ] || return 0
  command -v jq >/dev/null 2>&1 || return 0
  # Collapse to one line: AWS errors wrap, and `error` is a single-line field.
  error="$(printf '%s' "$error" | tr '\n\r\t' '   ' | tr -s ' ' | sed 's/^ *//;s/ *$//')"
  [ -n "$error" ] || error="collection failed"
  if [ -n "$code" ]; then
    jq -n --arg e "$error" --arg c "$code" '{error:$e, code:$c}' > "$path" 2>/dev/null || return 0
  else
    jq -n --arg e "$error" '{error:$e}' > "$path" 2>/dev/null || return 0
  fi
}

# aws_report_failures <failure-log> [max-lines] -- classify what is in the log,
# write it to the status file, and echo the human count. The caller keeps its
# own log_error/exit; this only adds the machine-readable channel.
# Reports the FIRST failures, not the last: the first is usually the cause and
# the rest its consequences (a failed list call makes every per-item call fail).
aws_report_failures() {
  local log="${1:-/dev/null}" max="${2:-3}" n first
  n=$(wc -l < "$log" 2>/dev/null | tr -d ' '); n=${n:-0}
  [ "$n" -gt 0 ] || return 0
  # awk, not `tr '\n' ';'`: tr maps one char to one char, so it cannot emit the
  # "; " separator, and it leaves a trailing one before the "(+N more)" suffix.
  first="$(head -n "$max" "$log" | awk '{printf "%s%s", sep, $0; sep="; "}')"
  [ "$n" -gt "$max" ] && first="${first}; (+$((n - max)) more)"
  aws_status_write "$n AWS API failure(s); first: $first" "$(aws_classify_code "$log")"
}

# aws_call <failure-log> <label> -- run an AWS CLI command with stderr CAPTURED
# rather than discarded: stdout passes through, and on a non-zero exit the
# stderr text is appended to <failure-log> under <label>. Replaces the
# `cmd 2>/dev/null` / `echo "<label> failed" >> "$_FAILURE_LOG"` pair, which
# recorded that a call failed but never why. Returns the command's exit code.
#   out=$(aws_call "$_FAILURE_LOG" "s3api list-buckets" aws s3api list-buckets)
aws_call() {
  local log="$1" label="$2"; shift 2
  local err ec
  err="$(mktemp -t aws_call_err.XXXXXX)"
  "$@" 2>"$err"
  ec=$?
  if [ $ec -ne 0 ]; then
    printf '%s failed (exit=%s): %s\n' \
      "$label" "$ec" "$(tr '\n\r\t' '   ' < "$err" | tr -s ' ' | cut -c1-500)" >> "$log"
  fi
  rm -f "$err"
  return $ec
}
