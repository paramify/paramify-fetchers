"""Every env var the OCI fetchers read is one the runner can actually set.

This exists because it already went wrong once. `fetchers/_categories/oci.yaml`
declared the credential set under `auth.secrets:`, which reads naturally and
validates — the category schema defines `auth.passthrough_env` and does not
forbid unknown keys — but `config_loader` reads `secrets:` from the TOP level.
The five credentials were therefore invisible to the framework: `paramify
describe oci_*` reported `secrets: []`, and a manifest naming them was rejected
as declaring a secret the fetcher does not take. Nothing failed loudly, because
every local and CI run so far authenticated from an already-exported
environment, where the runner's injection is not the path under test.

So the assertion is the join the fetchers depend on: the names
`oci_common` reads at run time, against the names the manifest layer can
produce — as a declared secret (injected from any source and masked out of
captured output) or as passthrough_env (let through the runner's whitelist when
already set). A var in neither is unreachable in a deployed run.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CATEGORY = REPO_ROOT / "fetchers" / "_categories" / "oci.yaml"
COMMON = REPO_ROOT / "fetchers" / "oci" / "_shared" / "oci_common.py"

# Read from the target/config schema instead, and asserted separately below.
CONFIG_ENV = {"OCI_COMPARTMENT_ID", "OCI_INCLUDE_SUBCOMPARTMENTS", "OCI_ENVIRONMENT"}
# Set by this suite's own replay harness, never by a deployment.
TEST_ONLY_ENV = {"OCI_CASSETTE", "OCI_CASSETTE_MODE"}


@pytest.fixture(scope="module")
def category() -> dict:
    return yaml.safe_load(CATEGORY.read_text())


def env_names_read_by_the_fetchers() -> set[str]:
    """Every OCI_* name the shared credential module reads from the environment."""
    source = COMMON.read_text()
    return set(re.findall(r'os\.environ(?:\.get)?\(\s*"(OCI_[A-Z0-9_]+)"', source)) | set(
        re.findall(r'"(OCI_[A-Z0-9_]+)"', source)
    )


def test_every_env_var_the_fetchers_read_is_reachable_from_a_manifest(category):
    declared = {s["env"] for s in category.get("secrets") or []}
    passthrough = set((category.get("auth") or {}).get("passthrough_env") or [])
    reachable = declared | passthrough | CONFIG_ENV | TEST_ONLY_ENV

    unreachable = env_names_read_by_the_fetchers() - reachable
    assert not unreachable, (
        f"oci_common reads {sorted(unreachable)}, which the runner can never set: "
        "add each to `secrets:` (top level, with an `env:`) or `auth.passthrough_env` "
        "in fetchers/_categories/oci.yaml."
    )


def test_the_credential_set_is_declared_where_the_loader_reads_it(category):
    """The specific mistake: secrets nested under `auth:`, which nothing reads."""
    assert "secrets" not in (category.get("auth") or {}), (
        "fetchers/_categories/oci.yaml declares secrets under `auth:`. "
        "framework/config_loader.py reads `secrets:` from the top level, so these "
        "would be silently ignored."
    )
    assert {s["env"] for s in (category.get("secrets") or [])} >= {
        "OCI_PRIVATE_KEY", "OCI_USER_OCID", "OCI_TENANCY_OCID", "OCI_FINGERPRINT",
    }, "the API-signing-key path needs all four declared to be injectable"


def test_the_framework_actually_offers_the_secrets_to_every_oci_fetcher():
    """The end of the join: what the runner would resolve for each fetcher."""
    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from framework import api

    root = api.find_repo_root()
    fetchers = api.discover_fetchers(root)
    platform = api.discover_platforms(root).get("oci")
    assert platform is not None, "no oci platform spec discovered"

    oci = {name: f for name, f in fetchers.items() if f.category == "oci"}
    assert len(oci) == 17, f"expected 17 OCI fetchers, discovered {len(oci)}"
    for name, fetcher in oci.items():
        envs = {s.env for s in api.effective_secrets(fetcher, platform)}
        assert "OCI_PRIVATE_KEY" in envs, (
            f"{name} advertises no signing key; the runner cannot inject one"
        )


def test_every_secret_is_optional_so_workload_identity_manifests_validate(category):
    """An instance- or resource-principal deployment supplies none of these."""
    required = [s["name"] for s in (category.get("secrets") or [])
                if s.get("required", True)]
    assert not required, (
        f"{required} are declared required, which would fail `paramify validate` for "
        "every manifest that authenticates with an instance or resource principal"
    )


# --- the shipped example manifests -----------------------------------------
#
# Validating them is cheap and catches the authoring mistakes (a targets[] on a
# tenancy-scoped fetcher, a malformed ${env:...} ref). Building the child
# environment from one is the part that matters: it is the step that was broken,
# and it is the only assertion here that fails if the credentials go back to
# being declared somewhere the loader does not read.

EXAMPLES = sorted((REPO_ROOT / "examples").glob("oci_*.yaml"))


def test_the_category_ships_example_manifests():
    assert EXAMPLES, "examples/oci_*.yaml is how a deployer starts; ship at least one"
    covered = set()
    for path in EXAMPLES:
        manifest = yaml.safe_load(path.read_text())
        covered |= {e["use"] for e in manifest["run"]["fetchers"]}
    missing = {
        d.name for d in (REPO_ROOT / "fetchers" / "oci").iterdir()
        if d.is_dir() and not d.name.startswith("_") and (d / "fetcher.py").exists()
    } - {name[len("oci_"):] for name in covered}
    assert not missing, f"no example manifest wires {sorted(missing)}"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_manifest_validates(path):
    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from framework import api

    root = api.find_repo_root()
    problems = api.validate(yaml.safe_load(path.read_text()), root)
    assert not problems, f"{path.name}: {problems}"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_the_runner_injects_the_signing_key_from_an_example_manifest(path, monkeypatch, tmp_path):
    """End of the chain: the PEM reaches the fetcher's own environment.

    The value is a throwaway string, not a key — what is under test is that the
    manifest's ${env:OCI_PRIVATE_KEY} reference resolves and lands in the child
    env, and that the runner marks it for masking out of captured output.
    """
    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from framework import api
    from framework.runner import executor, manifest_loader

    monkeypatch.setenv("OCI_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----\nnot-a-key\n")
    monkeypatch.setenv("OCI_TENANCY_OCID", "ocid1.tenancy.oc1..test")
    monkeypatch.setenv("OCI_USER_OCID", "ocid1.user.oc1..test")
    monkeypatch.setenv("OCI_FINGERPRINT", "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff")
    monkeypatch.setenv("OCI_REGION", "us-phoenix-1")

    root = api.find_repo_root()
    fetchers = api.discover_fetchers(root)
    platforms = api.discover_platforms(root)
    manifest = manifest_loader.load_manifest(path, root)

    for entry in manifest.entries:
        fetcher = fetchers[entry.use]
        target = entry.targets[0] if entry.targets else None
        sink: set = set()
        env = executor._build_env(
            fetcher, entry, target, tmp_path,
            platform_spec=platforms.get("oci"),
            platform_cfg=manifest.platforms.get("oci"),
            secret_sink=sink,
        )
        assert env.get("OCI_PRIVATE_KEY", "").startswith("-----BEGIN"), (
            f"{entry.use}: the signing key never reached the fetcher's environment"
        )
        assert env["OCI_TENANCY_OCID"] == "ocid1.tenancy.oc1..test"
        assert env["OCI_REGION"] == "us-phoenix-1", "passthrough_env did not let the region through"
        assert any(v.startswith("-----BEGIN") for v in sink), (
            f"{entry.use}: the key is not marked for masking out of captured output"
        )
