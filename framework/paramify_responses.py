"""Reading one Paramify refusal the same way in every uploader: "already there".

Three uploaders have to tell "this already exists" apart from a real failure,
and the API gives them no cleaner way than trying the write:

- ``POST /evidence`` has no get-or-create; creating a ``referenceId`` twice is
  refused.
- ``POST /evidence/{id}/associate`` has no read-back; the only way to learn that
  a subject is connected is to CONNECT it again and be refused.

Both refusals were observed on the live API as HTTP 400 with a message naming
the duplicate (2026-08-31), although the spec lists 400 for validation errors.
Spec 0.9.2 then added 409 Conflict to every operation, so the same refusal may
arrive as a 409 carrying the same message. Each uploader used to hold its own
copy of this test and they disagreed (GitHub #83): the scripts uploader
tolerated a repeat CONNECT while the validator syncer raised on it, against the
same endpoint. This module is the one place the rule lives.

The message is required for both codes. A 400 without it is a validation
error. A 409 without it is a conflict this code does not understand, and
raising there is the safe failure: treating an unknown conflict as success
would silently drop an association, and a missing association is invisible:
the API has no read-back that would ever show it.
"""

from __future__ import annotations

# Both known refusals say "already": "already exists" on a repeat create and
# "already connected" on a repeat CONNECT. Bare "exists" / "connected" /
# "associated" are deliberately absent: they also appear in negations such as
# "cannot be associated", which must stay failures.
ALREADY_PRESENT_MARKERS = ("already", "duplicate")

# The two statuses a duplicate refusal has been seen on, or may legally use.
ALREADY_PRESENT_STATUSES = (400, 409)


def already_present(status_code: int, text: str) -> bool:
    """True when a create or CONNECT was refused because the thing is already there.

    ``status_code`` and ``text`` come straight off the response. The caller
    treats True as success (the state it wanted already holds) and anything
    else as the failure it is.
    """
    if status_code not in ALREADY_PRESENT_STATUSES:
        return False
    body = (text or "").lower()
    return any(marker in body for marker in ALREADY_PRESENT_MARKERS)
