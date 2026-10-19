#!/bin/bash
# Shared helpers for the checkov "scanner" fetchers: verify tooling and acquire a
# git repo with provenance. Source this from a fetcher entry script:
#
#   . "$(dirname "$0")/../_shared/clone.sh"
#   checkov_require_tools "$COMPONENT" [tool ...] || exit 1     (default tools: git checkov jq)
#   checkov_clone_repo "$REPO_URL" "$BRANCH" "$TOKEN" "$GIT_USER" "$COMPONENT" || ...
#       on success sets globals: CLONE_DIR, COMMIT_SHA, SCANNED_BRANCH,
#                                BRANCH_FALLBACK (true|false)   (return 0)
#       on failure: returns non-zero (caller reports + exits)
#
# The credentialed clone URL and token are never written to stdout/stderr.

# Verify the external tools the scanner needs are on PATH. Returns 1 if any missing.
checkov_require_tools() {
    local component="$1" missing=0 t
    shift
    [ $# -eq 0 ] && set -- git checkov jq
    for t in "$@"; do
        if ! command -v "$t" >/dev/null 2>&1; then
            printf '%s ERROR %s required tool not found on PATH: %s\n' \
                "$(date -u +'%Y-%m-%d %H:%M:%S')" "$component" "$t" >&2
            missing=1
        fi
    done
    return "$missing"
}

# Inject basic-auth creds into an http(s) URL. Token optional (public repos clone
# as-is). Non-http URLs (ssh/scp-like) pass through untouched.
_checkov_auth_url() {
    local url="$1" user="$2" token="$3"
    if [ -z "$token" ]; then printf '%s' "$url"; return; fi
    case "$url" in
        https://*) printf 'https://%s:%s@%s' "$user" "$token" "${url#https://}" ;;
        http://*)  printf 'http://%s:%s@%s'  "$user" "$token" "${url#http://}"  ;;
        *)         printf '%s' "$url" ;;
    esac
}

# Shallow-clone repo_url into a fresh temp dir. Tries the requested branch first,
# then falls back to the repo's default branch (the branch may not exist).
# Sets CLONE_DIR + COMMIT_SHA on success, plus what was actually checked out:
#   SCANNED_BRANCH   the requested branch, or after a fallback the default branch
#                    read from the clone itself ("unknown" if it cannot be read)
#   BRANCH_FALLBACK  "true" when the requested branch could not be cloned
checkov_clone_repo() {
    local repo_url="$1" branch="${2:-main}" token="$3" user="${4:-oauth2}" component="$5"
    local auth_url; auth_url="$(_checkov_auth_url "$repo_url" "$user" "$token")"

    SCANNED_BRANCH="$branch"; BRANCH_FALLBACK=false
    CLONE_DIR="$(mktemp -d -t checkov_clone.XXXXXX)"
    # stderr discarded so a credentialed URL can never leak into captured logs.
    if ! git clone --depth 1 --branch "$branch" "$auth_url" "$CLONE_DIR" >/dev/null 2>&1; then
        rm -rf "$CLONE_DIR"
        CLONE_DIR="$(mktemp -d -t checkov_clone.XXXXXX)"
        if ! git clone --depth 1 "$auth_url" "$CLONE_DIR" >/dev/null 2>&1; then
            printf '%s ERROR %s git clone failed for %s (branch %s)\n' \
                "$(date -u +'%Y-%m-%d %H:%M:%S')" "$component" "$repo_url" "$branch" >&2
            return 1
        fi
        BRANCH_FALLBACK=true
        SCANNED_BRANCH="$(git -C "$CLONE_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
        case "$SCANNED_BRANCH" in ""|HEAD) SCANNED_BRANCH=unknown ;; esac
        printf '%s WARN %s branch %s could not be cloned; scanned the default branch (%s) instead\n' \
            "$(date -u +'%Y-%m-%d %H:%M:%S')" "$component" "$branch" "$SCANNED_BRANCH" >&2
    fi
    COMMIT_SHA="$(git -C "$CLONE_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
    return 0
}
