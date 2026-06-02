"""Regression tests for PhantomAICodeScanner well-known package allowlist.

The noise-reduction fix downgrades broken imports for known popular PyPI
packages from CRITICAL "Broken Import" to LOW "Missing local dep". This
prevents customer reports from being flooded with CRITICAL findings for
torch/transformers/boto3-style deps that simply aren't installed in the
scanning env (typical on Modal/Lambda/Docker deploys where deps live
remotely).
"""

import tempfile
from pathlib import Path

import pytest

from brass.models.finding import Severity
from brass.scanners.phantom_ai_code_scanner import (
    PhantomAICodeScanner,
    _WELL_KNOWN_PYPI_PACKAGES,
)


@pytest.fixture
def scanner():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield PhantomAICodeScanner(tmpdir)


def test_well_known_package_downgraded_to_low(scanner):
    """torch is a popular PyPI dep — should be LOW, not CRITICAL."""
    file_path = scanner.project_path / "train.py"
    finding = scanner._create_broken_import_finding(file_path, "torch", 1)

    assert finding.severity == Severity.LOW
    assert finding.title == "Missing local dep: torch"
    assert finding.impact_score == 0.3
    assert finding.metadata["is_well_known_pypi"] is True
    assert finding.metadata["top_level_module"] == "torch"


def test_well_known_submodule_recognized_by_top_level(scanner):
    """transformers.models.llama → top-level 'transformers' is well-known."""
    file_path = scanner.project_path / "model.py"
    finding = scanner._create_broken_import_finding(
        file_path, "transformers.models.llama", 1
    )

    assert finding.severity == Severity.LOW
    assert finding.metadata["top_level_module"] == "transformers"
    assert finding.metadata["is_well_known_pypi"] is True


def test_unknown_package_stays_critical(scanner):
    """An AI-hallucinated package keeps the original CRITICAL severity."""
    file_path = scanner.project_path / "agent.py"
    finding = scanner._create_broken_import_finding(
        file_path, "totally_made_up_phantom_module_xyz", 1
    )

    assert finding.severity == Severity.CRITICAL
    assert finding.title.startswith("Broken Import:")
    assert finding.impact_score == 0.9
    assert finding.metadata["is_well_known_pypi"] is False


def test_allowlist_covers_ml_and_cloud_categories():
    """The allowlist must cover the categories that drove the noise problem."""
    must_have = {"torch", "transformers", "peft", "trl", "unsloth",
                 "boto3", "fastapi", "django", "flask", "requests"}
    missing = must_have - _WELL_KNOWN_PYPI_PACKAGES
    assert not missing, f"allowlist missing expected entries: {missing}"


def test_allowlist_is_all_lowercase():
    """Lookup applies .lower() to the import top-level. PascalCase entries
    (e.g. 'PIL', 'Crypto') would be dead — guard against regression."""
    bad = [p for p in _WELL_KNOWN_PYPI_PACKAGES if p != p.lower()]
    assert not bad, f"non-lowercase entries are unreachable at lookup: {bad}"


def test_allowlist_excludes_supply_chain_risky_names():
    """Hardcoded blocklist of names that have been considered for the
    allowlist but are unsafe to add. Locks the intent in code so a future
    well-meaning edit (e.g. re-adding 'Crypto' for legacy pycrypto code,
    or 'mock' as a 'common test util') gets caught by CI."""
    forbidden = {
        "crypto",         # legacy pycrypto, abandoned with known CVEs
        "mock",           # stdlib has unittest.mock; PyPI mock has typosquat risk
        "google",         # too broad — would suppress hallucinated google.* submodules
    }
    present = forbidden & {p.lower() for p in _WELL_KNOWN_PYPI_PACKAGES}
    assert not present, f"unsafe entries present in allowlist: {present}"


def test_case_variants_of_dead_entries_stay_critical(scanner):
    """Regression for the .lower() case-mismatch bug: 'PIL'/'Crypto' were
    in the allowlist as PascalCase, but the lookup applies .lower() so
    they never matched. We've removed them, but verify the unreachable
    CRITICAL path keeps firing for the case-sensitive name. (Note: lookup
    lowercases input, so `import PIL` actually checks `pil` — `pillow` is
    on the list as the canonical name; `pil` is not, so it stays CRITICAL.)"""
    file_path = scanner.project_path / "vision.py"
    finding = scanner._create_broken_import_finding(file_path, "PIL", 1)
    assert finding.severity == Severity.CRITICAL
    assert finding.metadata["top_level_module"] == "pil"
