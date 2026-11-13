#!/usr/bin/env bash
# The one place a bash fetcher reports WHY it failed. SOURCED, not executed:
#
#   source "$(dirname "$0")/../../_lib/status.sh"
#   ...
#   if [ "$failure_count" -gt 0 ]; then
#       report_failure "$failure_count API failures during collection" partial_failure
#       exit 1
#   fi
#
# See docs/fetcher_contract_guide.md, step 6. The Python twin is fetcher_status.py in
# this directory; keep the two behaviours identical.

# _fetcher_label <path-to-entry-script> -- "<category>_<name>", matching the
# `name:` in fetcher.yaml. Every entry script in the tree is called `fetcher.sh`,
# so a basename is always the useless string "fetcher"; the identity is in the two
# enclosing directory names (fetchers/<category>/<name>/fetcher.sh). Falls back to
# a basename for anything not shaped like a fetcher, so sourcing this from a test
# or a one-off script still logs something.
_fetcher_label() {
  local dir name cat
  dir="$(cd "$(dirname "${1:-$0}")" 2>/dev/null && pwd)" || { basename "${1:-$0}" .sh; return; }
  name="$(basename "$dir")"
  cat="$(basename "$(dirname "$dir")")"
  if [ -n "$name" ] && [ -n "$cat" ] && [ "$cat" != "/" ] && [ "$cat" != "." ]; then
    printf '%s_%s' "$cat" "$name"
  else
    basename "${1:-$0}" .sh
  fi
}

# _normalize_reason <text> -- one line, with separator noise collapsed. Callers
# build a reason by joining a failure log with `tr '\n' ';'`, which leaves a
# dangling separator and turns a blank line into an empty `;;` segment. Cleaning
# it here means 100+ call sites don't each have to get the joining exactly right.
_normalize_reason() {
  printf '%s' "$1" \
    | tr '\n\r\t' '   ' \
    | tr -s ' ' \
    | sed -e 's/;[[:space:]]*;/;/g' -e 's/;[[:space:]]*;/;/g' \
          -e 's/[[:space:]]*;[[:space:]]*$//' -e 's/^[[:space:]]*;[[:space:]]*//' \
          -e 's/^ *//' -e 's/ *$//'
}

# report_failure <reason> [code] -- log the reason to stderr AND report it to the
# runner via $FETCHER_STATUS_FILE. This is the whole failure path: callers do not
# also need a log_error. Logging here is what guarantees the reason is the LAST
# thing on stderr, which matters because the runner's fallback takes the stderr
# *tail* -- a fetcher that logs its error before its "Evidence saved" INFO line
# reports that success message as its failure reason (issue #24).
#
# A no-op on the status file when the runner set no $FETCHER_STATUS_FILE, or when
# jq is unavailable. Never fails the run: the exit code is the authoritative
# failure signal, so a status-file problem must not mask or manufacture one.
# Returns 0 always, so `report_failure ... && exit 1` and `set -e` both behave.
report_failure() {
  local reason code one_line path
  reason="${1:-collection failed}"
  code="${2:-}"

  # One line, separator noise collapsed: API errors wrap, and `error` is a
  # single-line field.
  one_line="$(_normalize_reason "$reason")"
  [ -n "$one_line" ] || one_line="collection failed"
  # Match the Python twin's bound so the two channels can't disagree.
  if [ "${#one_line}" -gt 2000 ]; then
    one_line="$(printf '%s' "$one_line" | cut -c1-2000) ..."
  fi

  printf '%s ERROR %s %s\n' \
    "$(date -u +'%Y-%m-%d %H:%M:%S')" \
    "${FETCHER:-$(_fetcher_label "${BASH_SOURCE[1]:-$0}")}" \
    "$one_line" >&2

  # Only the contract's closed set is allowed through; anything else is dropped
  # rather than written, so a typo can't invent a category downstream code reads.
  case "$code" in
    auth_failed|not_authorized|target_unreachable|rate_limited|bad_config|partial_failure|internal_error|input_failed) ;;
    "") ;;
    *)
      printf '%s WARNING %s dropping unrecognized status code %s\n' \
        "$(date -u +'%Y-%m-%d %H:%M:%S')" "${FETCHER:-report_failure}" "$code" >&2
      code=""
      ;;
  esac

  path="${FETCHER_STATUS_FILE:-}"
  [ -n "$path" ] || return 0
  command -v jq >/dev/null 2>&1 || return 0

  if [ -n "$code" ]; then
    jq -n --arg e "$one_line" --arg c "$code" '{error:$e, code:$c}' > "$path" 2>/dev/null || true
  else
    jq -n --arg e "$one_line" '{error:$e}' > "$path" 2>/dev/null || true
  fi
  return 0
}
