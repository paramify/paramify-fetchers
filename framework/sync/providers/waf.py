"""Strings the production WAF rejects in an upload.

Uploads to the production app pass through managed WAF rules that inspect the
whole request body: the file and the artifact metadata (title and note). A
match is refused at the load balancer with a bare 403 and no request id, so the
uploader cannot say why. Delivery checks each file before it plans the upload
and drops a file that would be blocked.

These signatures were confirmed blocked in production. `$(`, `&&`, `rm -rf`,
`' OR 1=1` and `<b>` were confirmed NOT blocked; do not add them on a hunch.
"""
from __future__ import annotations

# (signature, managed rule it maps to)
SIGNATURES: tuple[tuple[str, str], ...] = (
    ("../", "GenericLFI_BODY (path traversal)"),
    ("/etc/passwd", "GenericLFI_BODY (sensitive file)"),
    ("/bin/sh", "LinuxRuleSet (shell path)"),
    ("/bin/bash", "LinuxRuleSet (shell path)"),
    ("<script", "CrossSiteScripting_BODY"),
)

RULES: dict[str, str] = dict(SIGNATURES)


def scan(content: bytes, note: str, title: str = "") -> list[str]:
    """The signatures found in the file content, the note or the title, in SIGNATURES order."""
    text = "\n".join((content.decode("utf-8", errors="replace"), note, title))
    return [sig for sig, _rule in SIGNATURES if sig in text]
