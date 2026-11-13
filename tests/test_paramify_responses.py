"""The one shared reading of "already exists / already connected" (GitHub #83).

Three uploaders used to carry their own copy of this test and disagreed; these
pin the rule they now share: the status alone is never enough, the message is.
"""

from __future__ import annotations

import pytest

from framework.paramify_responses import already_present


@pytest.mark.parametrize(
    "status, text",
    [
        (400, "Evidence already exists"),                      # repeat create, as observed live
        (400, '{"statusMessage":"Bad Request","error":{"message":"Script already connected"}}'),
        (409, "Evidence already exists"),                      # same refusal on the code 0.9.2 permits
        (409, '{"statusMessage":"Conflict","error":{"message":"Validator is already associated"}}'),
        (400, "Duplicate referenceId"),
        (409, "DUPLICATE association"),                        # case-insensitive
    ],
)
def test_duplicate_refusals_count_as_already_present(status, text):
    assert already_present(status, text) is True


@pytest.mark.parametrize(
    "status, text",
    [
        (400, "validation: name required"),                    # a 400 is a validation error unless it says otherwise
        (409, '{"statusMessage":"Conflict","error":{"message":"Conflict"}}'),  # a conflict we do not understand stays a failure
        (400, "subject cannot be associated with this evidence"),  # negation: must not read as success
        (400, "evidence set does not exist"),
        (404, "already exists"),                               # only the two statuses a duplicate arrives on
        (500, "already exists"),
        (200, "already exists"),
        (400, ""),
        (409, None),
    ],
)
def test_everything_else_is_not(status, text):
    assert already_present(status, text) is False
