"""Prints an Entra access token for Azure DevOps, from the DefaultAzureCredential chain the azure_devops_* fetchers use."""

from __future__ import annotations

import logging
import sys
from typing import Any

# Azure DevOps' first-party application, the audience of an Entra token for it (as in azure/_shared/devops_rest.py).
ADO_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798"
NO_TOKEN = 3
NO_SDK = 4


def entra_credential() -> Any:
    """The ambient Entra identity (service principal, workload or managed identity, az login)."""
    from azure.identity import DefaultAzureCredential  # lazy

    return DefaultAzureCredential()


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
