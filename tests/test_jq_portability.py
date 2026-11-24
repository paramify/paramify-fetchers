"""Shell scripts must not call jq builtins that a supported jq release lacks.

The container image ships jq 1.8, while macOS and Debian ship jq 1.7. jq 1.8
removed the private `_nwise` and the deprecated `pow10`. A filter that calls
either does not compile on jq 1.8. When the filter feeds a `while read` loop
through process substitution, the loop gets no input and the fetcher reports
empty evidence instead of an error, so this has to be caught here.
"""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Builtins present in jq 1.7 and gone in 1.8, with what to use instead.
REMOVED_IN_JQ_1_8 = {
    "_nwise": ". as $a | range(0; $a | length; N) | $a[.:.+N]",
    "pow10": "exp10",
}
_CALL = re.compile(r"(?<![\w$])(" + "|".join(REMOVED_IN_JQ_1_8) + r")\b")


def test_no_shell_script_calls_a_jq_builtin_removed_in_jq_1_8():
    offenders = []
    for path in sorted(REPO_ROOT.rglob("*.sh")):
        if any(part in {".git", ".venv", "venv", "node_modules", ".claude"} for part in path.parts):
            continue
        for number, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for match in _CALL.finditer(line):
                name = match.group(1)
                offenders.append(
                    f"{path.relative_to(REPO_ROOT)}:{number}: {name} (use {REMOVED_IN_JQ_1_8[name]})"
                )
    assert not offenders, "jq builtins removed in jq 1.8:\n" + "\n".join(offenders)
