#!/usr/bin/env python3
"""
KSI-CED-RAT: Incident response and disaster recovery training (Cornerstone)

Measures completion of the Cornerstone course(s) named in CSOD_INCIDENT_RESPONSE_COURSES for
users who hold the incident response or contingency course on their transcript. This is the evidence for the KSI-CED-RAT clause
"training for staff involved with incident response or disaster recovery".


Collection and the summary live in ../_shared/training_completion.py; this
file only names the training group. The fetcher reports counts and rates; it
does not decide whether they are acceptable.
"""

import logging
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from csod_client import collect_guarded, run_fetcher  # type: ignore  # noqa: E402
from training_completion import collect_training_group, scopes  # type: ignore  # noqa: E402

logger = logging.getLogger("cornerstone_incident_response_training")

OUTPUT = "cornerstone_incident_response_training.json"
COURSES_ENV = "CSOD_INCIDENT_RESPONSE_COURSES"
POPULATION_ENV = None
GROUP = {
    "key": "incident_response_training",
    "title": "Incident response and disaster recovery training",
    "ksi": "KSI-CED-RAT",
    "ksi_clause": "training for staff involved with incident response or disaster recovery",
}


def collect():
    with_population = bool(POPULATION_ENV and os.environ.get(POPULATION_ENV, "").strip())
    body = collect_guarded(
        scopes(with_population),
        lambda client: collect_training_group(
            client, group=GROUP, courses_env=COURSES_ENV, population_env=POPULATION_ENV),
    )
    return body()


if __name__ == "__main__":
    sys.exit(run_fetcher(collect, OUTPUT, logger))
