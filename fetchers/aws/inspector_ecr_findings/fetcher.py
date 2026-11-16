#!/usr/bin/env python3
"""Detailed ECR vulnerability evidence from the Inspector API."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from inspector_ecr import main

if __name__ == "__main__":
    raise SystemExit(main())
