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


# --- a partly-set API-key environment ----------------------------------------
#
# Four of the five variables and a ~/.oci/config on the host: the old code
# returned None for the partial set and fell through to the config file, so the
# run signed in as whoever that file named, often in another tenancy.

def _partial_key_env(env, tmp_path, *, drop):
    key = _key(tmp_path).read_text()
    full = {"OCI_TENANCY_OCID": "ocid1.tenancy.oc1..intended", "OCI_USER_OCID": "ocid1.user.oc1..collector",
            "OCI_FINGERPRINT": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99", "OCI_PRIVATE_KEY": key,
            "OCI_REGION": "us-phoenix-1"}
    for name, value in full.items():
        if name not in drop:
            env.setenv(name, value)
    env.setenv("OCI_CONFIG_FILE", str(_config_file(tmp_path, region="us-ashburn-1")))


@pytest.mark.parametrize("drop", ["OCI_REGION", "OCI_PRIVATE_KEY", "OCI_FINGERPRINT"])
def test_a_partial_api_key_environment_is_refused_not_replaced_by_the_config_file(clean_env, tmp_path, drop):
    _partial_key_env(clean_env, tmp_path, drop={drop})
    with pytest.raises(oci_common.IncompleteApiKeyConfig) as raised:
        oci_common.load_config(None)
    assert drop in str(raised.value)
    assert "BEGIN" not in str(raised.value) and "intended" not in str(raised.value), "names only, never values"
    failure = {"operation": "oci.config.load", "type": type(raised.value).__name__, "message": str(raised.value)}
    assert oci_common._failure_code(failure) == "bad_config"


def test_region_alone_still_selects_the_config_file_path(clean_env, tmp_path):
    """OCI_REGION is also the target region for the principal and config-file paths."""
    clean_env.setenv("OCI_CONFIG_FILE", str(_config_file(tmp_path, region="us-ashburn-1")))
    clean_env.setenv("OCI_REGION", "us-phoenix-1")
    auth = oci_common.load_config(None)
    assert auth["auth_method"] == oci_common.AUTH_CONFIG_FILE
    assert auth["config"]["region"] == "us-phoenix-1"


def test_leftover_key_variables_do_not_block_an_explicit_principal(clean_env, tmp_path, monkeypatch):
    _partial_key_env(clean_env, tmp_path, drop={"OCI_PRIVATE_KEY"})
    clean_env.setenv("OCI_CLI_AUTH", "instance_principal")

    class Signer:
        region, tenancy_id = "us-phoenix-1", "ocid1.tenancy.oc1..fromimds"

    monkeypatch.setattr(oci.auth.signers, "InstancePrincipalsSecurityTokenSigner", Signer)
    assert oci_common.load_config(None)["auth_method"] == oci_common.AUTH_INSTANCE_PRINCIPAL


# --- one file per target -------------------------------------------------------

def test_the_filename_carries_compartment_and_region(clean_env):
    auth = {"tenancy": "ocid1.tenancy.oc1..t", "config": {"region": "us-ashburn-1"}}
    scope = {"compartment_id": "ocid1.compartment.oc1..c"}
    east = oci_common.evidence_filename("oci_vault_keys", auth, scope)
    west = oci_common.evidence_filename("oci_vault_keys", {**auth, "config": {"region": "us-phoenix-1"}}, scope)
    assert east != west and east.endswith("_us-ashburn-1.json")
    assert oci_common.evidence_filename("oci_iam_policies", auth, scope, regional=False).endswith("__c.json")


def test_a_run_that_failed_before_auth_still_names_its_own_file(clean_env):
    clean_env.setenv("OCI_COMPARTMENT_ID", "ocid1.compartment.oc1..c")
    clean_env.setenv("OCI_REGION", "eu-frankfurt-1")
    name = oci_common.evidence_filename("oci_vault_keys", {}, {"compartment_id": None})
    assert name == "oci_vault_keys_ocid1_compartment_oc1__c_eu-frankfurt-1.json"
