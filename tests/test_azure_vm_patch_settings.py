"""vm_hardening_status 0.3.0: OS patch settings on VMs and scale sets. No network."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace as NS

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "azure" / "_shared"))
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))


def _load():
    path = REPO_ROOT / "fetchers" / "azure" / "vm_hardening_status" / "fetcher.py"
    spec = importlib.util.spec_from_file_location("vmh_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vmh = _load()


def os_profile(windows=None, linux=None):
    return NS(windows_configuration=windows, linux_configuration=linux)


def patch(mode, assessment, bypass=None):
    return NS(patch_mode=mode, assessment_mode=assessment,
              automatic_by_platform_settings=NS(bypass_platform_safety_checks_on_user_schedule=bypass))


def test_windows_patch_settings_are_projected():
    p = vmh.project_patch_settings(os_profile(windows=NS(patch_settings=patch("AutomaticByPlatform", "AutomaticByPlatform", True))))
    r = vmh.patch_settings_record(p)
    assert r["os"] == "windows" and r["patch_mode"] == "AutomaticByPlatform"
    assert r["automatic_patching"] is True and r["assessment_automatic"] is True
    assert r["bypass_platform_safety_checks_on_user_schedule"] is True


def test_linux_image_default_is_not_platform_managed():
    p = vmh.project_patch_settings(os_profile(linux=NS(patch_settings=patch("ImageDefault", "ImageDefault"))))
    r = vmh.patch_settings_record(p)
    assert r["os"] == "linux" and r["automatic_patching"] is False and r["assessment_automatic"] is False


def test_missing_patch_settings_read_unknown_not_manual():
    r = vmh.patch_settings_record(vmh.project_patch_settings(os_profile(linux=NS(patch_settings=None))))
    assert r["os"] == "linux" and r["patch_mode"] is None and r["automatic_patching"] is None
    none = vmh.patch_settings_record(vmh.project_patch_settings(None))
    assert none["os"] is None and none["assessment_automatic"] is None
    assert vmh.patch_settings_record(None)["automatic_patching"] is None


def test_patch_summary_counts_unknown_apart():
    def vm(mode, assessment):
        return {"patch_settings": vmh.patch_settings_record({"os": "linux", "patch_mode": mode, "assessment_mode": assessment})}
    vms = [vm("AutomaticByPlatform", "AutomaticByPlatform"), vm("Manual", "ImageDefault"), vm(None, None), vm("AutomaticByOS", None)]
    s = vmh.summarize_patching(vms, [vm("AutomaticByPlatform", "AutomaticByPlatform")])
    assert s["vms_automatic_patching"] == 2 and s["vms_manual_or_image_default_patching"] == 1
    assert s["vms_patch_mode_unknown"] == 1 and s["vms_automatic_patch_assessment"] == 1 and s["vms_patch_assessment_unknown"] == 2
    assert s["vms_patch_modes"] == {"AutomaticByOS": 1, "AutomaticByPlatform": 1, "Manual": 1}
    assert s["scale_sets_automatic_patching"] == 1 and s["scale_sets_patch_mode_unknown"] == 0


def test_empty_patch_mode_is_unknown_not_manual():
    r = vmh.patch_settings_record({"os": "linux", "patch_mode": "", "assessment_mode": ""})
    assert r["patch_mode"] is None and r["automatic_patching"] is None and r["assessment_automatic"] is None
