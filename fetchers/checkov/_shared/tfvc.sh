#!/bin/bash
# Shared helper for the checkov "scanner" fetchers: download the .bicep and .json files of an
# Azure DevOps TFVC folder through the REST API, pinned to one changeset. Source it from a fetcher:
#
#   . "$(dirname "$0")/../_shared/tfvc.sh"
#   checkov_fetch_tfvc "$PROJECT_URL" "$TFVC_PATH" "$VERSION" "$TOKEN" || ...
#       VERSION is "latest" or a changeset number (123 or C123)
#       TOKEN is a PAT; without one it signs in as the Entra identity the azure_devops_* fetchers
#       would use (ado_token.py), and without that it sends no credentials (a public project)
#       on success sets globals: CLONE_DIR, CHANGESET, CHANGESET_DATE   (return 0)
#       on failure sets TFVC_ERROR and TFVC_ERROR_CODE (a report_failure code), returns 1
#       either way sets TFVC_AUTH_MODE: pat, entra or anonymous, and TFVC_AUTH_NOTE: why it fell back
#       to anonymous, when it did
#
# Credentials reach curl only as an Authorization header on stdin, never in argv or logs.

CHECKOV_TFVC_API_VERSION="7.1"
_TFVC_SHARED="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Answers Azure DevOps gives in place of a 403 when the caller may not see the thing (as devops_rest.py).
_TFVC_MASKING_CODES='TF14098|TF200016|TF401019|VS800075'

# GET url into a file; prints the HTTP status ("000" when curl could not connect).
# auth is the whole Authorization header value, or empty for none.
_tfvc_get() {
    local url="$1" accept="$2" out="$3" auth="$4"
    { [ -n "$auth" ] && printf 'header = "Authorization: %s"\n' "$auth"; } |
        curl -sS --config - --max-time 900 --retry 2 -H "Accept: $accept" -o "$out" -w '%{http_code}' "$url" 2>"$out.err"
}

# Prints an Entra access token for Azure DevOps; on failure returns non-zero, the reason in $1/entra.err.
_tfvc_entra_token() {
    command -v python3 >/dev/null 2>&1 || { echo "python3 is not on PATH" > "$1/entra.err"; return 1; }
    python3 -I "$_TFVC_SHARED/ado_token.py" 2>"$1/entra.err"
}

_tfvc_fail() { TFVC_ERROR="$1"; TFVC_ERROR_CODE="${2:-internal_error}"; return 1; }

_tfvc_http_error() {
    local what="$1" code="$2" out="$3" detail who
    detail="$(jq -r '.message // empty' "$out" 2>/dev/null | tr '\n' ' ' | head -c 300)"
    case "$TFVC_AUTH_MODE" in
        pat)   who="the token" ;;
        entra) who="the Entra identity" ;;
        *)     who="an anonymous caller (no tfvc_token; $TFVC_AUTH_NOTE)" ;;
    esac
    if [[ "$detail" =~ (^|[^A-Z0-9])($_TFVC_MASKING_CODES)([^0-9]|$) ]]; then
        _tfvc_fail "$what: HTTP $code ($detail); $who cannot see this project or path, or it does not exist (reading it needs Code (Read))" not_authorized
        return
    fi
    case "$code" in
        000) _tfvc_fail "$what: could not reach Azure DevOps ($(tr '\n' ' ' < "$out.err" | head -c 300))" target_unreachable ;;
        # A rejected or missing credential can come back 203 with the HTML sign-in page, or 302 to it.
        203|302|401)
            case "$TFVC_AUTH_MODE" in
                pat)   _tfvc_fail "$what: HTTP $code, the token was not accepted (it needs Code (Read))" auth_failed ;;
                entra) _tfvc_fail "$what: HTTP $code${detail:+ ($detail)}, Azure DevOps did not accept the Entra identity (it must be a member of the organization with Code (Read) on the project), or set tfvc_token" auth_failed ;;
                *)     _tfvc_fail "$what: HTTP $code, sign-in required and no tfvc_token was set (a PAT with Code (Read)); $TFVC_AUTH_NOTE" auth_failed ;;
            esac ;;
        403) _tfvc_fail "$what: HTTP 403${detail:+ ($detail)}, $who cannot read this project's code (it needs Code (Read))" not_authorized ;;
        400|404) _tfvc_fail "$what: HTTP $code${detail:+ ($detail)}; check the project URL, the TFVC path and the changeset" bad_config ;;
        429) _tfvc_fail "$what: HTTP 429, rate limited by Azure DevOps" rate_limited ;;
        *) _tfvc_fail "$what: HTTP $code${detail:+ ($detail)}" internal_error ;;
    esac
}

checkov_fetch_tfvc() {
    local project_url="${1%/}" path="$2" version="${3:-latest}" token="$4"
    local api="${1%/}/_apis/tfvc" auth="" bearer enc work code cs_url pin top item rel
    TFVC_ERROR=""; TFVC_ERROR_CODE=""; CHANGESET=""; CHANGESET_DATE=""; TFVC_AUTH_MODE=anonymous; _TFVC_ENTRA_WHY=""
    TFVC_AUTH_NOTE=""
    enc="$(jq -rn --arg p "$path" '$p | @uri')"
    work="$(mktemp -d -t checkov_tfvc.XXXXXX)"

    # A PAT wins; without one, sign in as the ambient Entra identity; without that, read anonymously.
    if [ -n "$token" ]; then
        auth="Basic $(printf ':%s' "$token" | base64 | tr -d '\n')"; TFVC_AUTH_MODE=pat
    elif bearer="$(_tfvc_entra_token "$work")" && [ -n "$bearer" ]; then
        auth="Bearer $bearer"; TFVC_AUTH_MODE=entra
    else
        _TFVC_ENTRA_WHY="$(tr '\n' ' ' < "$work/entra.err" 2>/dev/null | head -c 300)"
        TFVC_AUTH_NOTE="Entra sign-in was not available: ${_TFVC_ENTRA_WHY:-no reason given}"
    fi

    # "latest" pins the newest changeset, so the folder is read at one version even if a check-in lands mid-run.
    case "$version" in
        latest) cs_url="$api/changesets?%24top=1&api-version=$CHECKOV_TFVC_API_VERSION" ;;
        *)      cs_url="$api/changesets/${version#[Cc]}?api-version=$CHECKOV_TFVC_API_VERSION" ;;
    esac
    code="$(_tfvc_get "$cs_url" application/json "$work/changeset.json" "$auth")"
    # A refused Entra identity fails; it never falls back to anonymous. An anonymous caller sees only the public
    # folders of a project, so the scan would cover a subset and still read as success.
    if [ "$code" != "200" ]; then
        _tfvc_http_error "changeset lookup ($version)" "$code" "$work/changeset.json"; rm -rf "$work"; return 1
    fi
    CHANGESET="$(jq -r '(if has("value") then .value[0] else . end) // {} | .changesetId // empty' "$work/changeset.json" 2>/dev/null)"
    CHANGESET_DATE="$(jq -r '(if has("value") then .value[0] else . end) // {} | .createdDate // empty' "$work/changeset.json" 2>/dev/null)"
    if ! [[ "$CHANGESET" =~ ^[0-9]+$ ]]; then
        _tfvc_fail "changeset lookup ($version) returned no changeset id; $project_url may have no TFVC history" bad_config
        rm -rf "$work"; return 1
    fi

    # A folder takes scopePath (path with recursionLevel Full is a 400), and the API zips no TFVC folder, so
    # list it at that changeset and download each file checkov's bicep and arm frameworks read.
    pin="versionDescriptor.versionType=changeset&versionDescriptor.version=$CHANGESET&api-version=$CHECKOV_TFVC_API_VERSION"
    code="$(_tfvc_get "$api/items?scopePath=$enc&recursionLevel=Full&$pin" application/json "$work/items.json" "$auth")"
    if [ "$code" = "200" ] && ! jq -e '.value | type == "array"' "$work/items.json" >/dev/null 2>&1; then
        _tfvc_fail "listing of $path at changeset $CHANGESET did not return an item list" internal_error
        rm -rf "$work"; return 1
    fi
    # TFVC hides what the caller may not read, so a folder it cannot see is missing, not refused.
    if [ "$code" = "404" ] || { [ "$code" = "200" ] && ! jq -e --arg p "${path%/}" \
            'any(.value[]; (.path // "" | ascii_downcase) == ($p | ascii_downcase))' "$work/items.json" >/dev/null; }; then
        _tfvc_fail "listing of $path at changeset $CHANGESET: HTTP $code without the folder; the identity cannot see this path, or it does not exist (TFVC leaves out folders the identity may not read)" not_authorized
        rm -rf "$work"; return 1
    fi
    if [ "$code" != "200" ]; then
        _tfvc_http_error "listing of $path at changeset $CHANGESET" "$code" "$work/items.json"; rm -rf "$work"; return 1
    fi
    # One line per .bicep/.json file: its server path URL-encoded, a tab, then its path under the folder's own name
    # (empty when the item is outside the folder).
    top="${path%/}"; top="${top##*/}"
    # jq stops at the first item it cannot read, so its exit status guards against scanning a subset.
    if ! jq -r --arg p "${path%/}" --arg top "$top" '
        ($p | ascii_downcase) as $lp
        | .value[] | select((.isFolder // false) | not) | .path
        | select(test("\\.(bicep|json)$"; "i"))
        | [@uri, (if ascii_downcase == $lp then $top
                  elif ascii_downcase | startswith($lp + "/") then $top + "/" + .[($lp | length) + 1:]
                  else "" end)]
        | @tsv' "$work/items.json" > "$work/files.tsv" 2>/dev/null; then
        _tfvc_fail "could not read the listing of $path at changeset $CHANGESET" internal_error
        rm -rf "$work"; return 1
    fi
    CLONE_DIR="$(mktemp -d -t checkov_clone.XXXXXX)"
    while IFS=$'\t' read -r item rel; do
        case "/$rel/" in //|*/../*|*/./*|///*)
            _tfvc_fail "listing of $path at changeset $CHANGESET returned an item outside it" internal_error
            rm -rf "$work"; return 1 ;;
        esac
        code="$(_tfvc_get "$api/items?path=$item&$pin" application/octet-stream "$work/item" "$auth")"
        if [ "$code" != "200" ]; then
            _tfvc_http_error "download of $rel at changeset $CHANGESET" "$code" "$work/item"; rm -rf "$work"; return 1
        fi
        if ! { mkdir -p "$CLONE_DIR/$(dirname "$rel")" && mv "$work/item" "$CLONE_DIR/$rel"; }; then
            _tfvc_fail "could not save $rel" internal_error; rm -rf "$work"; return 1
        fi
    done < "$work/files.tsv"
    rm -rf "$work"
    return 0
}
