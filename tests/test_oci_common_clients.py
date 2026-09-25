"""Client construction and region selection in `oci_common`."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

oci = pytest.importorskip("oci")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "_shared"))
import oci_common  # noqa: E402


def _key(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = tmp_path / "key.pem"
    key.write_bytes(rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key


def _config_file(tmp_path, region="us-phoenix-1"):
    key = _key(tmp_path)
    path = tmp_path / "config"
    path.write_text(
        "[DEFAULT]\nuser=ocid1.user.oc1..aaaa\nfingerprint=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff\n"
        f"tenancy=ocid1.tenancy.oc1..aaaa\nregion={region}\nkey_file={key}\n")
    return path


@pytest.fixture
def clean_env(monkeypatch):
    for name in ("OCI_REGION", "OCI_CLI_AUTH", "OCI_CLI_PROFILE", "OCI_RESOURCE_PRINCIPAL_VERSION",
                 *oci_common.API_KEY_ENV.values()):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_a_target_region_overrides_the_config_file_region(clean_env, tmp_path):
    """Without this a per-region fanout target collected the profile's region every time."""
    clean_env.setenv("OCI_CONFIG_FILE", str(_config_file(tmp_path)))
    clean_env.setenv("OCI_REGION", "us-ashburn-1")
    auth = oci_common.load_config(oci_common.Collector(oci_common.logging.getLogger("t")))
    assert auth["config"]["region"] == "us-ashburn-1"


def test_oci_config_file_wins_over_an_existing_home_config(clean_env, tmp_path):
    """The SDK falls back to OCI_CONFIG_FILE only when ~/.oci/config is absent.
    A host with both collected as whoever ~/.oci/config names — typically an
    administrator — while the deployment believed it ran as the collector."""
    home = tmp_path / "home"
    (home / ".oci").mkdir(parents=True)
    decoy = _config_file(home / ".oci", region="eu-frankfurt-1")
    decoy.rename(home / ".oci" / "config")
    chosen = tmp_path / "chosen"
    chosen.mkdir()
    clean_env.setenv("HOME", str(home))
    clean_env.setenv("OCI_CONFIG_FILE", str(_config_file(chosen, region="us-sanjose-1")))
    auth = oci_common.load_config(oci_common.Collector(oci_common.logging.getLogger("t")))
    assert auth["config"]["region"] == "us-sanjose-1"


def test_the_config_file_region_is_used_when_no_target_names_one(clean_env, tmp_path):
    clean_env.setenv("OCI_CONFIG_FILE", str(_config_file(tmp_path)))
    auth = oci_common.load_config(oci_common.Collector(oci_common.logging.getLogger("t")))
    assert auth["config"]["region"] == "us-phoenix-1"


def test_every_client_retries_throttling_and_server_errors(clean_env, tmp_path):
    """The SDK's global strategy is None, so no retry unless the client asks."""
    clean_env.setenv("OCI_CONFIG_FILE", str(_config_file(tmp_path)))
    auth = oci_common.load_config(oci_common.Collector(oci_common.logging.getLogger("t")))
    client = oci_common.make_client(oci.identity.IdentityClient, auth)
    assert client.retry_strategy is oci.retry.DEFAULT_RETRY_STRATEGY
