#!/bin/bash
#
# KnowBe4 — Developer-Specific Training Validation
#
# Checks completion of the campaign(s) named in KNOWBE4_DEVELOPER_CAMPAIGNS for the
# members of the groups named in KNOWBE4_DEVELOPER_GROUPS.
#
# Group and campaign names come from config, never from this file: hardcoding them
# made the fetcher report a confident 0% on any tenant that named things
# differently. Names are matched EXACTLY — the substring matching this replaced let
# a group named "Dev" pull in anything containing "Dev".
#
# A name that matches nothing in the tenant is NOT a fetcher failure — one typo must
# not turn a whole run red — so it exits 0 and reports every metric it could not
# measure as null, with results.config_resolution naming what did not resolve.
# null means "not measured"; 0 means "measured, and it is zero".
#
# Output: $EVIDENCE_DIR/knowbe4_developer_specific_training.json
# Required env: KNOWBE4_API_KEY, KNOWBE4_REGION,
#               KNOWBE4_DEVELOPER_GROUPS, KNOWBE4_DEVELOPER_CAMPAIGNS

set -o pipefail

# Interim v0.x: load .env if present. Runner + secret resolver replaces this.
[ -f .env ] && { set -a; . .env; set +a; }

FETCHER=knowbe4_developer_specific_training

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"
OUTPUT_JSON="$OUTPUT_DIR/${FETCHER}.json"

_FAILURE_LOG="$(mktemp -t ${FETCHER}_fail.XXXXXX)"
# Large jq inputs go in by FILE, never as an argv string: Linux caps a single
# argument at MAX_ARG_STRLEN (128KB), so --argjson with a full enrollments or
# members array fails execve with E2BIG and jq never runs — leaving an empty
# evidence file. macOS has no per-argument cap, which is exactly how this hid
# during local dev.
_TMP_ENROLLMENTS="$(mktemp -t ${FETCHER}_enroll.XXXXXX)"
_TMP_MEMBERS="$(mktemp -t ${FETCHER}_members.XXXXXX)"
_TMP_MATCHED_GROUPS="$(mktemp -t ${FETCHER}_mgroups.XXXXXX)"
_TMP_MATCHED_CAMPAIGNS="$(mktemp -t ${FETCHER}_mcamps.XXXXXX)"
_TMP_GROUPS_PRESENT="$(mktemp -t ${FETCHER}_gpresent.XXXXXX)"
_TMP_CAMPAIGNS_PRESENT="$(mktemp -t ${FETCHER}_cpresent.XXXXXX)"
_TMP_GROUP_RES="$(mktemp -t ${FETCHER}_gres.XXXXXX)"
_TMP_CAMPAIGN_RES="$(mktemp -t ${FETCHER}_cres.XXXXXX)"
trap 'rm -f "$_FAILURE_LOG" "$_TMP_ENROLLMENTS" "$_TMP_MEMBERS" \
      "$_TMP_MATCHED_GROUPS" "$_TMP_MATCHED_CAMPAIGNS" "$_TMP_GROUPS_PRESENT" \
      "$_TMP_CAMPAIGNS_PRESENT" "$_TMP_GROUP_RES" "$_TMP_CAMPAIGN_RES"' EXIT

log_info()  { printf '%s INFO %s %s\n'  "$(date -u +'%Y-%m-%d %H:%M:%S')" "$FETCHER" "$*" >&2; }
log_warn()  { printf '%s WARN %s %s\n'  "$(date -u +'%Y-%m-%d %H:%M:%S')" "$FETCHER" "$*" >&2; }
log_error() { printf '%s ERROR %s %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$FETCHER" "$*" >&2; }

# The shared failure path: report_failure logs the reason AND writes it to
# $FETCHER_STATUS_FILE, so the runner reports why instead of the stderr tail.
source "$(dirname "$0")/../../_lib/status.sh"

if [ -z "${KNOWBE4_API_KEY:-}" ]; then
    report_failure "KNOWBE4_API_KEY is not set" bad_config
    exit 1
fi
if [ -z "${KNOWBE4_REGION:-}" ]; then
    report_failure "KNOWBE4_REGION is not set" bad_config
    exit 1
fi

# Split a comma-separated config value into _SPLIT[], trimming surrounding
# whitespace and dropping empty elements. `read -ra`, not an unquoted expansion,
# so a name containing a glob character is never pathname-expanded.
split_config() {
    local raw="$1" item
    local -a parts=()
    _SPLIT=()
    IFS=',' read -ra parts <<< "$raw"
    for item in "${parts[@]}"; do
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        [ -n "$item" ] && _SPLIT+=("$item")
    done
}

# printf '%s', never echo: bash's echo leaves backslashes alone but sh's and zsh's
# do not, and KnowBe4 group and campaign titles are free text.
make_api_call() {
    local endpoint=$1
    local url="https://${KNOWBE4_REGION}.api.knowbe4.com/v1/${endpoint}"
    local response
    if ! response=$(curl -sf -H "Authorization: Bearer ${KNOWBE4_API_KEY}" \
                         -H "Content-Type: application/json" "${url}"); then
        printf 'GET %s\n' "$endpoint" >> "$_FAILURE_LOG"
        printf '%s' '[]'
        return 1
    fi
    # Anything that is not a JSON array is an error body, not a page. Recording it
    # rather than treating it as data is what stops pagination looping forever on a
    # 200-with-error-payload.
    if ! printf '%s' "$response" | jq -e 'type == "array"' >/dev/null 2>&1; then
        printf 'GET %s (response was not a JSON array)\n' "$endpoint" >> "$_FAILURE_LOG"
        printf '%s' '[]'
        return 1
    fi
    printf '%s' "$response"
}

_MAX_PAGES=1000

make_paginated_api_call() {
    local endpoint="$1"
    local page=1 all_results="[]" response count separator
    if [[ "$endpoint" == *\?* ]]; then separator="&"; else separator="?"; fi

    while [ "$page" -le "$_MAX_PAGES" ]; do
        if ! response=$(make_api_call "${endpoint}${separator}page=${page}"); then
            break
        fi
        count=$(printf '%s' "$response" | jq 'length')
        [ "$count" -eq 0 ] && break
        all_results=$(jq -s '.[0] + .[1]' \
            <(printf '%s' "$all_results") <(printf '%s' "$response"))
        page=$((page + 1))
    done
    if [ "$page" -gt "$_MAX_PAGES" ]; then
        printf 'GET %s (stopped at the %s-page cap)\n' "$endpoint" "$_MAX_PAGES" >> "$_FAILURE_LOG"
    fi
    printf '%s' "$all_results"
}

# Requested vs present, computed by jq from data. The names are never spliced into
# a jq program, so quotes, backslashes and $ in a title are just text.
resolve_names() {
    local present_json="$1"; shift
    jq -n -c --argjson present "$present_json" --args '
        ($ARGS.positional) as $req
        | {
            requested: $req,
            matched:   [ $req[] | select(. as $n | $present | any(. == $n)) ],
            unmatched: [ $req[] | select(. as $n | $present | any(. == $n) | not) ]
          }
    ' -- "$@"
}

split_config "${KNOWBE4_DEVELOPER_GROUPS:-}"
requested_groups=("${_SPLIT[@]}")
split_config "${KNOWBE4_DEVELOPER_CAMPAIGNS:-}"
requested_campaigns=("${_SPLIT[@]}")

[ "${#requested_groups[@]}" -eq 0 ] && \
    log_warn "KNOWBE4_DEVELOPER_GROUPS is empty — there is no population to measure"
[ "${#requested_campaigns[@]}" -eq 0 ] && \
    log_warn "KNOWBE4_DEVELOPER_CAMPAIGNS is empty — there is no campaign to measure"

campaigns_response=$(make_paginated_api_call "training/campaigns")
groups_response=$(make_paginated_api_call "groups")
enrollments_response=$(make_paginated_api_call \
    "training/enrollments?exclude_archived_users=true&include_campaign_id=true")

campaigns_present=$(printf '%s' "$campaigns_response" | jq -c '[.[].name] | unique')
groups_present=$(printf '%s' "$groups_response" | jq -c '[.[].name] | unique')
campaign_res=$(resolve_names "$campaigns_present" "${requested_campaigns[@]}")
group_res=$(resolve_names "$groups_present" "${requested_groups[@]}")

matched_campaign_objs=$(jq -c --argjson res "$campaign_res" \
    '[ .[] | select(.name as $n | $res.matched | any(. == $n)) ]' <<< "$campaigns_response")
matched_groups=$(jq -c --argjson res "$group_res" \
    '[ .[] | select(.name as $n | $res.matched | any(. == $n)) | {id: (.id|tostring), name: .name} ]' \
    <<< "$groups_response")

# Members of the matched groups only — an unmatched name costs no API call.
# `while read` over a process substitution, so the array survives (a pipeline
# would run the loop in a subshell and silently discard it).
members="[]"
while read -r group_id; do
    [ -z "$group_id" ] && continue
    page=$(make_paginated_api_call "groups/${group_id}/members")
    members=$(jq -s '.[0] + .[1]' <(printf '%s' "$members") <(printf '%s' "$page"))
done < <(printf '%s' "$matched_groups" | jq -r '.[].id')

# One jq pass builds the whole document. The previous version re-ran jq over the
# growing output file once per record, which was quadratic.
printf '%s' "$enrollments_response"   > "$_TMP_ENROLLMENTS"
printf '%s' "$members"                > "$_TMP_MEMBERS"
printf '%s' "$matched_groups"         > "$_TMP_MATCHED_GROUPS"
printf '%s' "$matched_campaign_objs"  > "$_TMP_MATCHED_CAMPAIGNS"
printf '%s' "$campaigns_present"      > "$_TMP_CAMPAIGNS_PRESENT"
printf '%s' "$groups_present"         > "$_TMP_GROUPS_PRESENT"
printf '%s' "$campaign_res"           > "$_TMP_CAMPAIGN_RES"
printf '%s' "$group_res"              > "$_TMP_GROUP_RES"

jq -n \
   --slurpfile enrollments_in "$_TMP_ENROLLMENTS" \
   --slurpfile members_in "$_TMP_MEMBERS" \
   --slurpfile matched_groups_in "$_TMP_MATCHED_GROUPS" \
   --slurpfile matched_campaigns_in "$_TMP_MATCHED_CAMPAIGNS" \
   --slurpfile campaign_res_in "$_TMP_CAMPAIGN_RES" \
   --slurpfile group_res_in "$_TMP_GROUP_RES" \
   --slurpfile campaigns_present_in "$_TMP_CAMPAIGNS_PRESENT" \
   --slurpfile groups_present_in "$_TMP_GROUPS_PRESENT" '
    # --slurpfile wraps the contents of each file in an array; [0] unwraps it.
    ($enrollments_in[0]) as $enrollments
    | ($members_in[0]) as $members
    | ($matched_groups_in[0]) as $matched_groups
    | ($matched_campaigns_in[0]) as $matched_campaigns
    | ($campaign_res_in[0]) as $campaign_res
    | ($group_res_in[0]) as $group_res
    | ($campaigns_present_in[0]) as $campaigns_present
    | ($groups_present_in[0]) as $groups_present
    | ($campaign_res.matched) as $mc
    | ($group_res.matched) as $mg
    # Measurable needs both dimensions: a population to measure and a campaign to
    # measure it against. Nothing downstream of an unmatched name may be a number.
    | ((($mc | length) > 0) and (($mg | length) > 0)) as $measurable
    | (if $measurable | not then "unresolved"
       elif (($campaign_res.unmatched | length) == 0
             and ($group_res.unmatched | length) == 0) then "resolved"
       else "partial" end) as $status
    | ( [ $members[] | select(.status == "active") ] | unique_by(.id) ) as $users
    | [ $enrollments[] | select(.campaign_name as $c | $mc | any(. == $c)) ] as $scoped
    | ( $users | map(
          . as $u
          | ( [ $scoped[] | select(.user.id == $u.id) ] ) as $ue
          | {
              email: $u.email,
              status: (
                if   ($ue | length) == 0                    then "not_started"
                elif ($ue | all(.status == "Passed"))       then "completed"
                elif ($ue | any(.status == "Past Due"))     then "past_due"
                elif ($ue | any(.status == "In Progress"))  then "in_progress"
                else "not_started" end)
            } ) ) as $rows
    | ($rows | map(select(.status == "completed"))   | length) as $completed
    | ($rows | map(select(.status == "in_progress")) | length) as $in_progress
    | ($rows | map(select(.status == "past_due"))    | length) as $past_due
    | ($rows | map(select(.status == "not_started")) | length) as $not_started
    | ($users | length) as $total_users
    | {
        results: {
          config_resolution: (
            {
              status: $status,
              measurable: $measurable,
              groups: $group_res,
              campaigns: $campaign_res
            }
            # Only when something failed to match, so a healthy run stays terse.
            + (if ($group_res.unmatched | length) > 0
               then { groups_present_in_tenant: $groups_present } else {} end)
            + (if ($campaign_res.unmatched | length) > 0
               then { campaigns_present_in_tenant: $campaigns_present } else {} end)
          ),
          developer_users: [ $users[] | {id, email, status} ],
          developer_groups: $matched_groups,
          developer_campaigns: $matched_campaigns,
          enrollments: [ $scoped[] | del(.policy_acknowledged) ],
          user_training_status: (
            if $measurable then ($rows | map({key: .email, value: .status}) | from_entries)
            else {} end),
          summary: {
            # Discovered counts stay real: 0 groups matched is an accurate 0.
            total_developer_users: $total_users,
            total_groups: ($mg | length),
            total_campaigns: ($mc | length),
            # Compliance metrics are null unless they were actually measurable.
            completed_training: (if $measurable then $completed   else null end),
            in_progress:        (if $measurable then $in_progress else null end),
            past_due:           (if $measurable then $past_due    else null end),
            not_started:        (if $measurable then $not_started  else null end),
            completion_rate: (
              if $measurable | not then null
              elif $total_users == 0 then 0
              else (($completed * 100 / $total_users) | floor) end)
          }
        }
      }
' > "$OUTPUT_JSON"

if [ ! -s "$OUTPUT_JSON" ]; then
    report_failure "failed to assemble the evidence document" internal_error
    exit 1
fi

# A failed API call is still a failure. Only *config* that does not resolve is
# reported as evidence instead of raised as an error.
failure_count=$(wc -l < "$_FAILURE_LOG" 2>/dev/null | tr -d ' ')
failure_count=${failure_count:-0}
if [ "$failure_count" -gt 0 ]; then
    report_failure "encountered $failure_count API failure(s) during collection" partial_failure
    exit 1
fi

status=$(jq -r '.results.config_resolution.status' "$OUTPUT_JSON")
if [ "$status" != "resolved" ]; then
    log_warn "config_resolution.status=${status} — unmeasurable metrics are reported as null, not 0"
    log_warn "group name(s) not found in tenant: $(jq -r '.results.config_resolution.groups.unmatched | join(", ")' "$OUTPUT_JSON")"
    log_warn "campaign name(s) not found in tenant: $(jq -r '.results.config_resolution.campaigns.unmatched | join(", ")' "$OUTPUT_JSON")"
    log_warn "groups present in tenant: $(jq -r '.results.config_resolution.groups_present_in_tenant // [] | join(", ")' "$OUTPUT_JSON")"
    log_warn "campaigns present in tenant: $(jq -r '.results.config_resolution.campaigns_present_in_tenant // [] | join(", ")' "$OUTPUT_JSON")"
fi

log_info "Evidence saved to $OUTPUT_JSON"
exit 0
