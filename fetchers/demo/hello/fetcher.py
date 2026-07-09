#!/usr/bin/env python3
"""
Demo fetcher: synthetic MFA-policy evidence.

Writes a fixed, plausible-looking evidence payload so a newcomer can run the
whole pipeline — collect, envelope, inspect — without any credentials or network
access. This is NOT real evidence; it exists purely to demonstrate the shape of
a run. See `examples/demo.yaml`.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("demo_hello")


def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    # A fixed, synthetic snapshot — the shape a real fetcher would collect,
    # with obviously fake values.
    evidence = {
        "metadata": {
            "source": "demo",
            "note": "Synthetic evidence — not collected from any real system.",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "results": [
            {
                "policy": "require-phishing-resistant-mfa",
                "enabled": True,
                "applies_to": "all-users",
                "enrolled_users": 42,
                "total_users": 42,
            },
            {
                "policy": "block-legacy-authentication",
                "enabled": True,
                "applies_to": "all-users",
            },
        ],
    }

    output_path = output_dir / "demo_hello.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2)

    logger.info("Synthetic evidence saved to %s", output_path)


if __name__ == "__main__":
    main()
