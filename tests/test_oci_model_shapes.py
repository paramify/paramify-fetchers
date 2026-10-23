"""Facts about OCI's own models that the fetchers depend on being true.

These are not tests of our code. They are assertions about the SDK's generated
models, pinned because each one is a decision a future maintainer would
otherwise have to rediscover the hard way — and in two cases the obvious
"improvement" silently produces empty evidence rather than an error.

If one of these fails, Oracle changed the shape of a response and the
corresponding fetcher needs re-reading, not the test relaxing.
"""

from __future__ import annotations

import pytest

oci = pytest.importorskip("oci", reason="these are assertions about the oci SDK")


def _fields(model) -> set[str]:
    return set(model().swagger_types)


def test_bastion_jit_fields_are_only_on_the_detail_response():
    """`bastion_sessions` must call get_bastion per bastion, and here is why.

    The three fields the just-in-time evidence turns on are absent from the list
    summary, so a fetcher built on list_bastions alone would report every
    bastion with a null TTL and an empty allow-list — which
    `allows_internet([])` correctly reads as UNRESTRICTED, turning a missing
    read into a fabricated finding.
    """
    summary = _fields(oci.bastion.models.BastionSummary)
    detail = _fields(oci.bastion.models.Bastion)

    for field in (
        "max_session_ttl_in_seconds",
        "max_sessions_allowed",
        "client_cidr_block_allow_list",
    ):
        assert field in detail, f"{field} vanished from Bastion"
        assert field not in summary, (
            f"{field} is now on BastionSummary — the per-bastion get_bastion call "
            f"in bastion_sessions may no longer be necessary"
        )


def test_certificate_validity_is_only_on_the_list_summary():
    """`certificates` must NOT call get_certificate per certificate.

    OCI inverts the usual relationship: the validity window lives on the LIST
    summary and is absent from the detail response. A per-certificate get would
    drop every expiry date without raising, because the field is not on that
    model at all.
    """
    summary = _fields(oci.certificates_management.models.CertificateSummary)
    detail = _fields(oci.certificates_management.models.Certificate)

    assert "current_version_summary" in summary
    assert "current_version_summary" not in detail, (
        "Certificate now carries current_version_summary — the comment in "
        "fetchers/oci/certificates/fetcher.py warning against a per-certificate "
        "get_certificate call needs revisiting"
    )




def test_adm_reports_severity_twice_so_suppression_is_visible():
    """The suppression gap `dependency_vulnerabilities` exists to surface.

    Without the `_with_ignored` pair there is no way to tell a project that
    fixed its vulnerabilities from one that suppressed them.
    """
    audit = _fields(oci.adm.models.VulnerabilityAuditSummary)

    for field in (
        "max_observed_severity",
        "max_observed_severity_with_ignored",
        "vulnerable_artifacts_count",
        "vulnerable_artifacts_count_with_ignored",
    ):
        assert field in audit, f"{field} vanished from VulnerabilityAuditSummary"


def test_adm_only_scans_maven_builds():
    """The scope limit stated in the fetcher's docstring and description.

    If Oracle adds a build type, the fetcher's "Maven/Java only" caveat is
    outdated and the KSI-SCR-MIT claim gets correspondingly stronger.
    """
    build_types = {
        value for key, value in vars(oci.adm.models.VulnerabilityAudit).items()
        if key.startswith("BUILD_TYPE_") and isinstance(value, str)
    }
    assert build_types == {"MAVEN", "UNSET"}, (
        f"ADM build types changed to {sorted(build_types)} — the Maven-only scope "
        f"caveat in fetchers/oci/dependency_vulnerabilities/ needs updating"
    )




def test_cloud_guard_target_rules_are_only_on_the_detail_response():
    """`cloud_guard_posture` must call get_target per target.

    TargetSummary carries a recipe_count and no rules, so a list-only fetcher
    would report every target as assessing nothing.
    """
    summary = _fields(oci.cloud_guard.models.TargetSummary)
    detail = _fields(oci.cloud_guard.models.Target)

    for field in ("target_detector_recipes", "target_responder_recipes"):
        assert field in detail, f"{field} vanished from Target"
        assert field not in summary, (
            f"{field} is now on TargetSummary — the per-target get_target call "
            f"in cloud_guard_posture may no longer be necessary"
        )


def test_cloud_guard_targets_misspell_lifecycle_details():
    """Oracle's target models spell it `lifecyle_details`; zones spell it right.

    `target_record` reads the misspelling on purpose. If Oracle fixes it, the
    fetcher must follow or the field reads None on every target.
    """
    models = oci.cloud_guard.models
    for model in (models.Target, models.TargetSummary):
        assert "lifecyle_details" in _fields(model)
        assert "lifecycle_details" not in _fields(model), (
            f"{model.__name__} now spells lifecycle_details correctly — update "
            f"target_record in cloud_guard_posture"
        )
    assert "lifecycle_details" in _fields(models.SecurityZoneSummary)


def test_security_zone_inheritance_is_only_on_the_detail_response():
    """`cloud_guard_posture` reads zones from the list call and so cannot report
    inherited compartments. Pinned so that omission stays a decision."""
    assert "inherited_by_compartments" not in _fields(oci.cloud_guard.models.SecurityZoneSummary)
    assert "inherited_by_compartments" in _fields(oci.cloud_guard.models.SecurityZone)
