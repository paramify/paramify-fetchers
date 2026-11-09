"""Prints an Entra access token for Azure DevOps, signed in the way the azure_devops_* fetchers sign in."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Reuse the azure_devops_* fetchers' credential chain and resource id rather than copying them.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "azure" / "_shared"))
from devops_rest import ADO_RESOURCE, entra_credential  # noqa: E402

NO_TOKEN = 3
NO_SDK = 4


def main() -> int:
    # azure-identity logs each failed credential at WARNING; the caller gets one line on stderr instead.
    logging.disable(logging.CRITICAL)
    try:
        credential = entra_credential()
    except ImportError:
        print("the azure-identity package is not installed for this python3", file=sys.stderr)
        return NO_SDK
    try:
        token = credential.get_token(f"{ADO_RESOURCE}/.default").token
    except Exception as exc:  # any sign-in failure means there is no usable Entra identity here
        print(" ".join(f"{type(exc).__name__}: {exc}".split())[:300], file=sys.stderr)
        return NO_TOKEN
    print(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
