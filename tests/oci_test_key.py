"""The throwaway signing key shared by the OCI tests and tools/oci_fault_sweep.py.

Request signing runs for real under replay, so something has to sign. The key is
generated per run and never written to the repo: the suite needs no credentials at
all, rather than shipping a fake one. RSA because OCI API signing keys are RSA-only.
"""

from __future__ import annotations


def throwaway_signing_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
