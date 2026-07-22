#!/usr/bin/env python3
"""Thin run-scaffolding shared by the okta fetchers.

Each okta ``fetcher.py`` owns its evidence-collection logic and delegates the
boilerplate — logging setup, client construction, the optional compatibility
probe, writing the evidence file, and the api-failure exit code — to ``run()``.
This is scaffolding only; no evidence logic lives here.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Callable, Dict

from dotenv import load_dotenv

# Make the category _shared/ importable regardless of the caller's cwd.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from okta_client import OktaAPIClient  # noqa: E402

CollectFn = Callable[[OktaAPIClient], Dict]


def run(collect: CollectFn, *, output_filename: str, logger_name: str) -> int:
    """Run a single okta fetcher end-to-end.

    ``collect`` receives a ready ``OktaAPIClient`` and returns the evidence dict.
    Returns a process exit code (1 if any network-level API failures occurred).
    """
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logger = logging.getLogger(logger_name)

    # Interim v0.x: the fetcher loads .env itself. The framework's runner +
    # secret resolver will pass resolved values in and this goes away.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    client = OktaAPIClient()

    # A best-effort feature probe (populates client.feature_availability and logs
    # which OIE/add-on features are missing). Skippable, like the previous CLI.
    if "--skip-check" not in sys.argv:
        client.run_compatibility_check()

    evidence = collect(client)

    output_path = output_dir / output_filename
    with open(output_path, "w") as fh:
        json.dump(evidence, fh, indent=2)
    logger.info("Evidence saved to %s", output_path)

    if client.api_failures:
        logger.error("Encountered %d API failure(s) during collection", len(client.api_failures))
        return 1
    return 0
