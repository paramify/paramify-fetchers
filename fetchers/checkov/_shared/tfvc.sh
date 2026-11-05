#!/bin/bash
# Shared helper for the checkov "scanner" fetchers: download an Azure DevOps TFVC
# folder through the REST API, pinned to one changeset. Source it from a fetcher:
#
#   . "$(dirname "$0")/../_shared/tfvc.sh"
#   checkov_fetch_tfvc "$PROJECT_URL" "$TFVC_PATH" "$VERSION" "$TOKEN" || ...
#       VERSION is "latest" or a changeset number (123 or C123)
#       on success sets globals: CLONE_DIR, CHANGESET, CHANGESET_DATE   (return 0)
#       on failure sets TFVC_ERROR and TFVC_ERROR_CODE (a report_failure code), returns 1
#
# The token reaches curl only as an Authorization header on stdin, never in argv or logs.

CHECKOV_TFVC_API_VERSION="7.1"

# GET url into a file; prints the HTTP status ("000" when curl could not connect).
_tfvc_get() {
    local url="$1" accept="$2" out="$3" auth="$4"
    { [ -n "$auth" ] && printf 'header = "Authorization: Basic %s"\n' "$auth"; } |
        curl -sS --config - --max-time 900 --retry 2 -H "Accept: $accept" -o "$out" -w '%{http_code}' "$url" 2>"$out.err"
}

_tfvc_fail() { TFVC_ERROR="$1"; TFVC_ERROR_CODE="${2:-internal_error}"; return 1; }

_tfvc_http_error() {
    local what="$1" code="$2" out="$3" detail
    detail="$(jq -r '.message // empty' "$out" 2>/dev/null | head -c 300)"
    case "$code" in
        000) _tfvc_fail "$what: could not reach Azure DevOps ($(tr '\n' ' ' < "$out.err" | head -c 300))" target_unreachable ;;
        # A rejected or missing PAT can come back 203 with the HTML sign-in page, or 302 to it.
        203|302|401)
            if [ "$_TFVC_HAS_TOKEN" = true ]; then _tfvc_fail "$what: HTTP $code, the token was not accepted (it needs Code (Read))" auth_failed
            else _tfvc_fail "$what: HTTP $code, sign-in required and no tfvc_token was set (a PAT with Code (Read))" auth_failed; fi ;;
        403) _tfvc_fail "$what: HTTP 403, the token cannot read this project's code (it needs Code (Read))" not_authorized ;;
        400|404) _tfvc_fail "$what: HTTP $code${detail:+ ($detail)}; check the project URL, the TFVC path and the changeset" bad_config ;;
        429) _tfvc_fail "$what: HTTP 429, rate limited by Azure DevOps" rate_limited ;;
        *) _tfvc_fail "$what: HTTP $code${detail:+ ($detail)}" internal_error ;;
    esac
}

checkov_fetch_tfvc() {
    local project_url="${1%/}" path="$2" version="${3:-latest}" token="$4"
    local api="${1%/}/_apis/tfvc" auth="" enc work code cs_url
    TFVC_ERROR=""; TFVC_ERROR_CODE=""; CHANGESET=""; CHANGESET_DATE=""
    [ -n "$token" ] && auth="$(printf ':%s' "$token" | base64 | tr -d '\n')"
    _TFVC_HAS_TOKEN=false; [ -n "$token" ] && _TFVC_HAS_TOKEN=true
    enc="$(jq -rn --arg p "$path" '$p | @uri')"
    work="$(mktemp -d -t checkov_tfvc.XXXXXX)"

    # "latest" pins the newest changeset, so the folder is read at one version even if a check-in lands mid-run.
    case "$version" in
        latest) cs_url="$api/changesets?%24top=1&api-version=$CHECKOV_TFVC_API_VERSION" ;;
        *)      cs_url="$api/changesets/${version#[Cc]}?api-version=$CHECKOV_TFVC_API_VERSION" ;;
    esac
    code="$(_tfvc_get "$cs_url" application/json "$work/changeset.json" "$auth")"
    if [ "$code" != "200" ]; then
        _tfvc_http_error "changeset lookup ($version)" "$code" "$work/changeset.json"; rm -rf "$work"; return 1
    fi
    CHANGESET="$(jq -r '(if has("value") then .value[0] else . end) // {} | .changesetId // empty' "$work/changeset.json" 2>/dev/null)"
    CHANGESET_DATE="$(jq -r '(if has("value") then .value[0] else . end) // {} | .createdDate // empty' "$work/changeset.json" 2>/dev/null)"
    if ! [[ "$CHANGESET" =~ ^[0-9]+$ ]]; then
        _tfvc_fail "changeset lookup ($version) returned no changeset id; $project_url may have no TFVC history" bad_config
        rm -rf "$work"; return 1
    fi

    code="$(_tfvc_get "$api/items?path=$enc&recursionLevel=Full&versionDescriptor.versionType=changeset&versionDescriptor.version=$CHANGESET&api-version=$CHECKOV_TFVC_API_VERSION" \
        application/zip "$work/source.zip" "$auth")"
    if [ "$code" != "200" ]; then
        _tfvc_http_error "download of $path at changeset $CHANGESET" "$code" "$work/source.zip"; rm -rf "$work"; return 1
    fi
    if ! unzip -tq "$work/source.zip" >/dev/null 2>&1; then
        _tfvc_fail "download of $path at changeset $CHANGESET did not return a zip archive" internal_error
        rm -rf "$work"; return 1
    fi
    CLONE_DIR="$(mktemp -d -t checkov_clone.XXXXXX)"
    if ! unzip -q "$work/source.zip" -d "$CLONE_DIR" >/dev/null 2>&1; then
        _tfvc_fail "could not extract $path at changeset $CHANGESET" internal_error
        rm -rf "$work"; return 1
    fi
    rm -rf "$work"
    return 0
}
