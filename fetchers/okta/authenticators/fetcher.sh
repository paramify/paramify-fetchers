#!/bin/bash
#
# Collects Okta authenticator-related evidence:
#   - FIDO2 authenticator configuration + per-config analysis
#   - Okta applications + their per-app authentication policies
#   - Authenticator enrollment policies + rules + phishing-resistant MFA check
#   - Policy-simulation results against test cases
#
# Output: $EVIDENCE_DIR/okta_authenticators.json
# Required env: OKTA_API_TOKEN, OKTA_ORG_URL (set however your environment
# populates env vars — .env, export, secret manager, K8s, etc.)
#
# Exit codes:
#   0 = all curl calls succeeded
#   1 = required env var missing, or any API call failed

set -o pipefail

# The one place a fetcher reports WHY it failed (docs/fetcher_contract_guide.md, step 6).
source "$(dirname "$0")/../../_lib/status.sh"
FETCHER="okta_authenticators"   # attributes report_failure's log line to this fetcher

# Interim v0.x: fetcher loads .env if present. The framework's runner +
# secret resolver will replace this when the framework lands.
[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

if [ -z "${OKTA_API_TOKEN:-}" ]; then
    report_failure "OKTA_API_TOKEN is not set" bad_config
    exit 1
fi
if [ -z "${OKTA_ORG_URL:-}" ]; then
    report_failure "OKTA_ORG_URL is not set" bad_config
    exit 1
fi

OUTPUT_JSON="$OUTPUT_DIR/okta_authenticators.json"
_FETCHER_TMP_JSON="$(mktemp -t okta_authenticators.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t okta_authenticators_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() {
    printf '%s INFO okta_authenticators %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2
}

log_error() {
    printf '%s ERROR okta_authenticators %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2
}

# Failure tracking via a temp file: `... | while` loops run in subshells where
# variable mutations don't persist; appending to a file is global.
okta_curl_get() {
    if ! curl -sf \
        -H "Authorization: SSWS $OKTA_API_TOKEN" \
        -H "Accept: application/json" \
        -H "Content-Type: application/json" \
        "$1"; then
        echo "GET $1" >> "$_FAILURE_LOG"
        echo "[]"
        return 1
    fi
}

okta_curl_post() {
    if ! curl -sf -X POST \
        -H "Authorization: SSWS $OKTA_API_TOKEN" \
        -H "Accept: application/json" \
        -H "Content-Type: application/json" \
        -d "$2" \
        "$1"; then
        echo "POST $1" >> "$_FAILURE_LOG"
        echo "[]"
        return 1
    fi
}

# Initialize output structure.
echo '{"results": {"applications": [], "enrollment_policies": [], "simulation_results": [], "fido2_config": []}}' > "$OUTPUT_JSON"

# --- FIDO2 authenticator configuration ---
fido2_config=$(okta_curl_get "$OKTA_ORG_URL/api/v1/authenticators" | jq '.')

echo "$fido2_config" | jq -c '.[]' | while read -r authenticator; do
    auth_id=$(echo "$authenticator" | jq -r '.id')
    auth_type=$(echo "$authenticator" | jq -r '.type')

    if [[ "$auth_type" == "security_key" || "$auth_type" == "webauthn" ]]; then
        auth_details=$(okta_curl_get "$OKTA_ORG_URL/api/v1/authenticators/$auth_id" | jq '.')

        analysis=$(jq -n --argjson auth "$auth_details" '{
            "status": "PASS",
            "checks": {
                "user_verification": {
                    "required": ($auth.settings.userVerification == "required"),
                    "recommended": true,
                    "description": "User verification should be required for phishing resistance"
                },
                "resident_key": {
                    "required": ($auth.settings.residentKey == "required"),
                    "recommended": true,
                    "description": "Resident keys should be required for better security"
                },
                "attestation": {
                    "required": ($auth.settings.attestation == "required"),
                    "recommended": true,
                    "description": "Attestation should be required to verify authenticator authenticity"
                },
                "timeout": {
                    "within_limits": ($auth.settings.timeout <= 300),
                    "recommended": true,
                    "description": "Timeout should be 300 seconds or less"
                }
            }
        }')

        jq --argjson auth "$auth_details" --argjson analysis "$analysis" \
           '.results.fido2_config += [$auth + {"Analysis": $analysis}]' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    fi
done

# --- Okta applications + per-app authentication policies ---
applications=$(okta_curl_get "$OKTA_ORG_URL/api/v1/apps" | jq '.')

echo "$applications" | jq -c '.[]' | while read -r app; do
    app_id=$(echo "$app" | jq -r '.id')
    app_policies=$(okta_curl_get "$OKTA_ORG_URL/api/v1/apps/$app_id/policies" | jq '.')

    jq --argjson app "$app" --argjson policies "$app_policies" \
       '.results.applications += [$app + {"Policies": $policies}]' \
       "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
done

# --- Authenticator enrollment policies + rules ---
enrollment_policies=$(okta_curl_get "$OKTA_ORG_URL/api/v1/policies?type=AUTHENTICATOR_ENROLLMENT" | jq '.')

echo "$enrollment_policies" | jq -c '.[]' | while read -r policy; do
    policy_id=$(echo "$policy" | jq -r '.id')
    policy_rules=$(okta_curl_get "$OKTA_ORG_URL/api/v1/policies/$policy_id/rules" | jq '.')

    has_phishing_resistant=$(echo "$policy_rules" | jq 'any(.conditions.authenticators[]; select(.type == "security_key" or .type == "webauthn"))')

    jq --argjson policy "$policy" --argjson rules "$policy_rules" --arg has_pr "$has_phishing_resistant" \
       '.results.enrollment_policies += [$policy + {"Rules": $rules, "HasPhishingResistantMFA": ($has_pr | test("true"))}]' \
       "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
done

# --- Policy simulation against test cases ---
test_cases=(
    '{"user": {"id": "test_user"}, "context": {"network": {"ip": "192.168.1.1"}, "device": {"os": "Windows"}}, "authenticators": []}'
    '{"user": {"id": "test_user"}, "context": {"network": {"ip": "192.168.1.1"}, "device": {"os": "Windows"}}, "authenticators": [{"type": "password"}]}'
    '{"user": {"id": "test_user"}, "context": {"network": {"ip": "192.168.1.1"}, "device": {"os": "Windows"}}, "authenticators": [{"type": "password"}, {"type": "security_key"}]}'
)

for test_case in "${test_cases[@]}"; do
    simulation_result=$(okta_curl_post "$OKTA_ORG_URL/api/v1/policies/simulate" "$test_case" | jq '.')

    jq --argjson result "$simulation_result" \
       '.results.simulation_results += [$result]' \
       "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
done

# Tally API failures recorded across all subshells.
failure_count=$(wc -l < "$_FAILURE_LOG" 2>/dev/null | tr -d ' ')
failure_count=${failure_count:-0}

if [ "$failure_count" -gt 0 ]; then
    # The log holds the "<METHOD> <url>" of each failed call -- the first few are
    # the useful reason, so report those rather than only a count.
    _FAILED_CALLS="$(head -n 3 "$_FAILURE_LOG" | sed 's/$/;/' | tr '\n' ' ')"
    report_failure "$failure_count Okta API call(s) failed during collection - $_FAILED_CALLS" partial_failure
    exit 1
fi

log_info "Evidence saved to $OUTPUT_JSON"
