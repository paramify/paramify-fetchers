"""AWS failure classification: `aws_classify_code` and the `aws` wrapper.

Why this file exists: PR #60 got all 80 AWS fetchers reporting *which* call
failed, and the conformance checker went green — while 302 of 310 failure
reports still carried only a call label and every one of the 80 passed a
hardcoded `partial_failure`. A test that asks "did it report?" cannot see that.
These tests ask what the report actually SAYS, so the gap cannot reopen quietly.

The `aws` helper is a shell function shadowing the CLI, so the tests here run
real fetchers against a fake `aws` on PATH rather than mocking the helper.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AWS_FETCHERS = REPO_ROOT / "fetchers" / "aws"
SHARED = AWS_FETCHERS / "_shared" / "aws.sh"

CONTRACT_CODES = {
    "auth_failed",
    "not_authorized",
    "target_unreachable",
    "rate_limited",
    "bad_config",
    "partial_failure",
    "internal_error",
}

# Real botocore/AWS CLI wordings, one per classification the contract allows.
# Kept verbatim rather than paraphrased: the classifier matches on this text, so
# a paraphrase would test the paraphrase.
ERROR_TEXTS = [
    ("auth_failed", "An error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation: The security token included in the request is invalid."),
    ("auth_failed", "An error occurred (ExpiredToken) when calling the ListBuckets operation: The provided token has expired."),
    ("auth_failed", "An error occurred (UnrecognizedClientException) when calling the ListDetectors operation: The security token included in the request is invalid."),
    ("auth_failed", "Unable to locate credentials. You can configure credentials by running \"aws configure\"."),
    ("not_authorized", "An error occurred (AccessDenied) when calling the GetBucketEncryption operation: Access Denied"),
    ("not_authorized", "An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation: You are not authorized to perform this operation."),
    ("not_authorized", "An error occurred (AccessDeniedException) when calling the DescribeStandards operation: User: arn:aws:sts::1:assumed-role/x is not authorized to perform: securityhub:DescribeStandards"),
    ("rate_limited", "An error occurred (Throttling) when calling the GetAccountSummary operation (reached max retries: 4): Rate exceeded"),
    ("rate_limited", "An error occurred (RequestLimitExceeded) when calling the DescribeVolumes operation: Request limit exceeded."),
    ("target_unreachable", 'Could not connect to the endpoint URL: "https://ec2.us-west-3.amazonaws.com/"'),
    ("target_unreachable", "Connect timeout on endpoint URL: \"https://sts.amazonaws.com/\" (ConnectTimeoutError)"),
    ("bad_config", "An error occurred (ValidationException) when calling the DescribeKey operation: InvalidParameterValue: key id must be a valid ARN"),
    ("bad_config", "An error occurred (MalformedPolicyDocument) when calling the PutKeyPolicy operation: Policy contains a syntax error"),
]


def _classify(text: str) -> str:
    """Run aws_classify_code over `text`, the way a fetcher would."""
    script = f'''
        set -e
        source "{SHARED}"
        f="$(mktemp)"
        cat > "$f"
        aws_classify_code "$f"
        rm -f "$f"
    '''
    out = subprocess.run(
        ["bash", "-c", script], input=text, capture_output=True, text=True, check=True
    )
    return out.stdout.strip()


@pytest.mark.parametrize("expected,text", ERROR_TEXTS, ids=[f"{c}-{i}" for i, (c, _) in enumerate(ERROR_TEXTS)])
def test_real_aws_wordings_classify(expected, text):
    assert _classify(text) == expected


def test_classifier_only_ever_emits_contract_codes():
    """Including for text it has no rule for — the fallback must still be legal."""
    for text in ["", "something nobody has ever seen", "\n\n", "kaboom"]:
        assert _classify(text) in CONTRACT_CODES


def test_empty_error_text_is_partial_failure():
    """No captured stderr is not evidence of a cause, so it must not guess one."""
    assert _classify("") == "partial_failure"


def test_credentials_beat_a_later_403():
    """Ordering matters: the first call failing on an expired token makes every
    later call 403 too. The report must name the cause, not the consequence."""
    both = (
        "An error occurred (ExpiredToken) when calling GetCallerIdentity: token expired\n"
        "An error occurred (AccessDenied) when calling DescribeSecurityGroups: Access Denied\n"
    )
    assert _classify(both) == "auth_failed"


def test_not_enabled_is_not_a_code():
    """A service that isn't in use is valid evidence and exits 0, so it must never
    produce a failure code. `not_enabled` is deliberately absent from the set."""
    assert "not_enabled" not in CONTRACT_CODES
    text = "An error occurred (SubscriptionRequiredException) when calling the operation: needs a subscription for the service"
    assert _classify(text) in CONTRACT_CODES


# --------------------------------------------------------------------------- #
# The `aws` wrapper must be transparent
# --------------------------------------------------------------------------- #

FAKE_AWS = """#!/bin/bash
case "$FAKE_MODE" in
  ok)      echo '{"ok":true}'; exit 0 ;;
  fail)    echo "An error occurred (AccessDenied) when calling the operation: Access Denied" >&2; exit 254 ;;
  both)    echo '{"partial":true}'; echo "An error occurred (Throttling): Rate exceeded" >&2; exit 254 ;;
esac
exit 0
"""


@pytest.fixture
def fake_aws(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "aws"
    exe.write_text(FAKE_AWS)
    exe.chmod(0o755)
    return bin_dir


def _wrapped(fake_aws, mode, redirect):
    """Call the wrapper the way a fetcher does and report what the caller saw."""
    script = f'''
        source "{SHARED}"
        out=$(aws sts get-caller-identity {redirect})
        ec=$?
        printf 'EXIT=%s\\n' "$ec"
        printf 'STDOUT=%s\\n' "$out"
        printf 'CAPTURED=%s\\n' "$(wc -l < "$_AWS_ERR_LOG" | tr -d ' ')"
        rm -f "$_AWS_ERR_LOG"
    '''
    env = {**os.environ, "PATH": f"{fake_aws}:{os.environ['PATH']}", "FAKE_MODE": mode}
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    return dict(
        line.split("=", 1) for line in r.stdout.strip().splitlines() if "=" in line
    ), r.stderr


def test_wrapper_passes_stdout_and_exit_zero_through(fake_aws):
    got, _ = _wrapped(fake_aws, "ok", "2>/dev/null")
    assert got["EXIT"] == "0"
    assert got["STDOUT"] == '{"ok":true}'
    assert got["CAPTURED"] == "0", "a successful call must record nothing"


def test_wrapper_preserves_a_nonzero_exit_code(fake_aws):
    got, _ = _wrapped(fake_aws, "fail", "2>/dev/null")
    assert got["EXIT"] == "254"


def test_wrapper_captures_stderr_the_caller_discarded(fake_aws):
    """The whole point: `2>/dev/null` at 250 call sites must still yield a cause."""
    got, _ = _wrapped(fake_aws, "fail", "2>/dev/null")
    assert got["CAPTURED"] == "1"


def test_wrapper_still_hands_stderr_to_a_caller_that_wants_it(fake_aws):
    """The not-enabled check does `2>"$_ERR"` then greps that file on the next
    line. If the wrapper delivered stderr asynchronously, that grep would race."""
    script = f'''
        source "{SHARED}"
        e="$(mktemp)"
        aws macie2 get-macie-session 2>"$e" >/dev/null
        grep -q 'AccessDenied' "$e" && echo GREP_SAW_IT || echo GREP_MISSED
        rm -f "$e" "$_AWS_ERR_LOG"
    '''
    env = {**os.environ, "PATH": f"{fake_aws}:{os.environ['PATH']}", "FAKE_MODE": "fail"}
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    assert "GREP_SAW_IT" in r.stdout


def test_wrapper_records_one_line_per_failure(fake_aws):
    """`tr` turns the trailing newline into a space, so an unterminated write
    would concatenate failures onto one line and make `wc -l` read 0."""
    script = f'''
        source "{SHARED}"
        for i in 1 2 3; do aws sts get-caller-identity >/dev/null 2>/dev/null; done
        wc -l < "$_AWS_ERR_LOG" | tr -d ' '
        rm -f "$_AWS_ERR_LOG"
    '''
    env = {**os.environ, "PATH": f"{fake_aws}:{os.environ['PATH']}", "FAKE_MODE": "fail"}
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    assert r.stdout.strip() == "3"


# --------------------------------------------------------------------------- #
# No fetcher may go back to a hardcoded code
# --------------------------------------------------------------------------- #

def _fetchers():
    return sorted(AWS_FETCHERS.glob("*/fetcher.sh"))


def test_every_aws_fetcher_reports_through_the_shared_reporter():
    """Every fetcher must end with aws_finish, which is what calls the reporter.

    This used to assert the literal `aws_report_failures` appeared in each file,
    back when all 80 pasted the nine-line epilogue inline. The epilogue now
    lives in aws.sh, so the invariant is stated where it actually holds: the
    last statement of every fetcher hands off to the shared summarizer.

    Asserting on the LAST line, not just presence, is deliberate — aws_finish
    exits 1 on any recorded failure, so anything after it would only run on the
    success path, which is a trap rather than a feature.
    """
    assert len(_fetchers()) == 80
    offenders = []
    for p in _fetchers():
        code = [ln.strip() for ln in p.read_text().splitlines()
                if ln.strip() and not ln.strip().startswith("#")]
        if not code or code[-1] != "aws_finish":
            offenders.append(f"{p.parent.name} (ends with {code[-1][:40]!r})" if code else p.parent.name)
    assert not offenders, f"fetchers not ending in aws_finish: {offenders}"


def test_no_aws_fetcher_still_carries_its_own_epilogue():
    """The nine lines aws_finish replaced must not creep back in.

    A copy left behind would run the summary twice: report a partial collection,
    exit 1, and never reach aws_finish — or worse, drift from it.
    """
    offenders = [f"{p.parent.name}" for p in _fetchers()
                 if "failure_count=" in p.read_text()]
    assert not offenders, f"inline epilogue still present: {offenders}"


def test_no_aws_fetcher_hardcodes_a_status_code():
    """A literal code is how all 80 came to report `partial_failure` for every
    failure regardless of cause. The code must be derived, never typed."""
    offenders = []
    for p in _fetchers():
        for n, line in enumerate(p.read_text().splitlines(), 1):
            if "report_failure" not in line or line.lstrip().startswith("#"):
                continue
            if any(f" {c}" in line or f'"{c}"' in line for c in CONTRACT_CODES):
                offenders.append(f"{p.parent.name}:{n}")
    assert not offenders, f"hardcoded status code: {offenders}"


def test_no_fetcher_reaches_the_cli_around_the_wrapper():
    """`aws` is a shell function, so it only sees calls made by that exact name.
    `command aws`, an absolute path, or `xargs aws` would silently go
    unclassified — which is the failure mode this whole file exists to prevent."""
    import re

    bypass = re.compile(r"\bcommand\s+aws\b|/usr/(local/)?bin/aws\b|\bxargs\s+aws\b")
    offenders = [p.parent.name for p in _fetchers() if bypass.search(p.read_text())]
    assert not offenders, f"bypasses the aws wrapper: {offenders}"


def test_not_enabled_branch_never_records_a_failure():
    """A service that isn't in use must exit 0 with no status file. That holds
    only because the `aws_service_unavailable` branch skips $_FAILURE_LOG — the
    wrapper still captures the SubscriptionRequiredException stderr, so if that
    branch ever logged a failure, every account without Macie/Inspector/Shield
    would report a spurious partial_failure."""
    offenders = []
    for p in _fetchers():
        lines = p.read_text().splitlines()
        for n, line in enumerate(lines):
            if "aws_service_unavailable" not in line or line.lstrip().startswith("#"):
                continue
            # The taken branch ends at the next elif/else/fi. `elif` matters:
            # these fetchers spell the real-failure case as `elif`, and that
            # branch SHOULD log — reading past it is what makes a window-based
            # check cry wolf.
            for follow in lines[n + 1 : n + 12]:
                stripped = follow.strip()
                if stripped.startswith(("elif", "else", "fi")):
                    break
                if "_FAILURE_LOG" in follow:
                    offenders.append(f"{p.parent.name}:{n + 1}")
                    break
    assert not offenders, (
        f"not-enabled branch writes to the failure log: {offenders}"
    )


def test_no_aws_fetcher_hand_rolls_service_unavailable_detection():
    """"Service not in use" must be decided by the shared helper, not by grep.

    `aws_service_unavailable` matches eight markers case-insensitively:
    SubscriptionRequiredException, OptInRequired, "is not enabled",
    InvalidAccessException, AWSOrganizationsNotInUseException, "not a member of
    an organization", "needs a subscription for the service", and
    ResourceNotFoundException. Three fetchers used to test one of those eight
    with a case-sensitive `grep -q`, so in a region answering OptInRequired
    instead they reported a hard collection failure where their siblings
    correctly recorded not-enabled and exited 0.

    The point is not the grep — it is that a fetcher must not carry its own
    opinion about what "not enabled" looks like.
    """
    import re

    # A marker tested outside a call to the helper, i.e. someone re-deciding.
    hand_rolled = re.compile(
        r"(grep|=~|case)\b[^\n]*"
        r"(SubscriptionRequiredException|OptInRequired|InvalidAccessException"
        r"|AWSOrganizationsNotInUseException|is not enabled"
        r"|not a member of an organization)",
        re.IGNORECASE,
    )
    offenders = []
    for p in _fetchers():
        for n, line in enumerate(p.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if hand_rolled.search(line):
                offenders.append(f"{p.parent.name}:{n}")
    assert not offenders, (
        "these decide 'service not enabled' themselves instead of calling "
        f"aws_service_unavailable: {offenders}"
    )
