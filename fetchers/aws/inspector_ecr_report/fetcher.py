#!/usr/bin/env python3
"""Inspector findings converted to CSV for Paramify's existing intake API.

Unlike a native scanner export, this intentionally normalizes ListFindings
responses. See README.md for the versioned column layout and intake mapping.
No S3 export, KMS key, scanner mutation or Paramify credential is needed here.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from inspector_ecr import main

if __name__ == "__main__":
    raise SystemExit(main(report=True))
