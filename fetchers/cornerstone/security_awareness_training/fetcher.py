#!/usr/bin/env python3
"""
KSI-CED-RAT: General security awareness training (Cornerstone)

Measures completion of the Cornerstone course(s) named in CSOD_SECURITY_AWARENESS_COURSES for
every user in scope. This is the evidence for the KSI-CED-RAT clause
"at least general training for all employees".


Collection and the summary live in ../_shared/training_completion.py; this
file only names the training group. The fetcher reports counts and rates; it
does not decide whether they are acceptable.
"""

import logging
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from csod_client import collect_guarded, run_fetcher  # type: ignore  # noqa: E402
from training_completion import collect_training_group, scopes_for  # type: ignore  # noqa: E402

logger = logging.getLogger("cornerstone_security_awareness_training")

OUTPUT = "cornerstone_security_awareness_training.json"
COURSES_ENV = "CSOD_SECURITY_AWARENESS_COURSES"
POPULATION_ENV = "CSOD_SECURITY_AWARENESS_POPULATION_FILTER"  # override of the shared CSOD_USER_POPULATION_FILTER
GROUP = {
    "key": "security_awareness_training",
    "title": "General security awareness training",
    "ksi": "KSI-CED-RAT",
    "ksi_clause": "at least general training for all employees",
}


def collect():
    body = collect_guarded(
        scopes_for(POPULATION_ENV),
        lambda client: collect_training_group(
            client, group=GROUP, courses_env=COURSES_ENV, population_env=POPULATION_ENV),
    )
    return body()


if __name__ == "__main__":
    sys.exit(run_fetcher(collect, OUTPUT, logger))
