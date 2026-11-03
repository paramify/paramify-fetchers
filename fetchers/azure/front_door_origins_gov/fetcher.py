#!/usr/bin/env python3
"""azure_front_door_origins_gov: azure_front_door_origins for Azure Government.

Runs fetchers/azure/front_door_origins/fetcher.py unchanged, with every Microsoft.Cdn client
pinned to the newest stable API version Azure Government offers. See
_shared/frontdoor_gov.py for why and for the known field gap.
"""

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from frontdoor_gov import run_gov_variant  # noqa: E402

if __name__ == "__main__":
    sys.exit(run_gov_variant("front_door_origins"))
