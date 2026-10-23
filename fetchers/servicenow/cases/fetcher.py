#!/usr/bin/env python3
"""ServiceNow customer service cases, written as the JSON response."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))

from scripted_rest import Endpoint, run  # noqa: E402

ENDPOINT = Endpoint(
    label="cases",
    output="servicenow_cases.json",
    url_env="SERVICENOW_CASES_API_URL",
    since_env="SERVICENOW_CASES_LAST_RUN",
    since_param="sysparm_last_run",
)

if __name__ == "__main__":
    raise SystemExit(run(ENDPOINT))
