"""Unit tests for the enrichment-mode record (Part A) and its YAML threading (Part B).

Covers:
  - the closed constants + ``is_enriched`` in ``brass.core.enrichment_mode``
  - ``BrassCLI._maybe_apply_enrichment`` setting ``self._enrichment_mode``
    at every exit, including the ``--offline`` fix (no gateway client is
    ever constructed, no "Running AI enrichment" line)
  - ``BrassCLI._generate_output`` threading the mode into
    ``generate_intelligence``
  - ``YAMLOutputGeneratorV2`` grafting ``metadata.enrichment`` into
    ai_instructions.yaml only, omitting it for ``None``, and isolating a
    graft failure from the YAML write

Templates: ``test_phase4_licensing.py`` (LicenseRecord / LicenseStore(path=...)),
``test_cache_clear_cli.py`` (BrassCLI() + capsys).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from brass.core import enrichment_mode as em
from brass.cli.brass_cli import BrassCLI
from brass.models.finding import Finding, FindingType, Severity


# --- fixtures -------------------------------------------------------


def _finding(i: int = 1) -> Finding:
    return Finding(
        id=f"f{i}",
        type=FindingType.SECURITY,
        severity=Severity.HIGH,
        file_path=f"src/mod{i}.py",
        line_number=i,
        title="t",
        description="d",
        confidence=0.9,
        impact_score=0.5,
        detected_by="test",
    )


def _active_record():
    from brass.licensing import LicenseRecord

    moment = datetime.now(timezone.utc).isoformat()
    return LicenseRecord(
        license_key="AAAA-BBBB-CCCC-DDDD",
        instance_id="instance-abc",
        status="active",
        activated_at=moment,
        last_validated_at=moment,
    )


class _ReadCountingStore:
    """LicenseStore stand-in that records whether ``read()`` was called."""

    def __init__(self, record):
        self.record = record
        self.reads = 0

    def read(self):
        self.reads += 1
        return self.record


def _install_store(monkeypatch, record):
    """Route ``LicenseStore.default()`` (imported at call time inside
    ``_maybe_apply_enrichment``) to a counting stand-in."""
    from brass.licensing import LicenseStore

    store = _ReadCountingStore(record)
    monkeypatch.setattr(LicenseStore, "default", classmethod(lambda cls: store))
    return store


class _ExplodingClient:
    """Constructing a gateway client under --offline is the bug being fixed."""

    def __init__(self, *a, **kw):
        raise AssertionError("EnrichmentClient must not be constructed")


class _QuietClient:
    def __init__(self, *a, **kw):
        pass

    def quota(self):
        return SimpleNamespace(monthly_limit=0, monthly_remaining=0)


def _report(n: int):
    return SimpleNamespace(
        input_count=n, output_count=n, duplicates_dropped=0,
        tokens_used=10, quota_remaining=90,
    )


@pytest.fixture
def cli(tmp_path, monkeypatch):
    monkeypatch.delenv("BRASS_OFFLINE", raising=False)
    c = BrassCLI()
    c.project_path = tmp_path
    return c


# --- brass.core.enrichment_mode -------------------------------------


def test_all_modes_is_closed_and_complete():
    assert em.ALL_MODES == frozenset({
        em.ENRICHED,
        em.HEURISTIC_NO_LICENSE,
        em.HEURISTIC_NO_ENRICH_FLAG,
        em.HEURISTIC_FALLBACK,
        em.HEURISTIC_OFFLINE,
    })
    assert len(em.ALL_MODES) == 5


def test_is_enriched_only_for_enriched():
    assert em.is_enriched(em.ENRICHED) is True
    for mode in em.ALL_MODES - {em.ENRICHED}:
        assert em.is_enriched(mode) is False
    assert em.is_enriched(None) is False


def test_enrichment_mode_module_is_dependency_free():
    """The output layer imports this module; it must not drag in
    ``brass.enrichment`` (which imports ``requests`` at import time)."""
    import sys
    import importlib
    importlib.reload(em)
    assert "requests" not in em.__dict__
    assert not any(
        name.startswith("brass.enrichment") for name in vars(em).values()
        if isinstance(name, str)
    )
    assert em.__name__ in sys.modules


# --- BrassCLI._maybe_apply_enrichment: mode at every exit -----------


def test_cli_init_default_mode_is_none():
    assert BrassCLI()._enrichment_mode is None


def test_no_enrich_flag_sets_mode_and_never_reads_license(cli, monkeypatch, capsys):
    store = _install_store(monkeypatch, _active_record())
    findings = [_finding()]
    out = cli._maybe_apply_enrichment(findings, no_enrich=True)
    assert out is findings
    assert cli._enrichment_mode == em.HEURISTIC_NO_ENRICH_FLAG
    assert store.reads == 0
    assert capsys.readouterr().out == ""


def test_offline_with_active_license_skips_before_any_client(cli, monkeypatch, capsys):
    """The --offline bug fix: a licensed --offline scan must not construct
    a gateway client, must not print "Running AI enrichment", and must
    print exactly one ℹ️ skip line."""
    import brass.enrichment as pkg
    _install_store(monkeypatch, _active_record())
    monkeypatch.setattr(pkg, "EnrichmentClient", _ExplodingClient)
    monkeypatch.setattr(
        pkg, "apply_enrichment",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no enrichment")),
    )
    findings = [_finding()]
    out = cli._maybe_apply_enrichment(findings, offline=True)
    assert out is findings
    assert cli._enrichment_mode == em.HEURISTIC_OFFLINE
    printed = capsys.readouterr().out
    assert "Running AI enrichment" not in printed
    assert "⚠️" not in printed
    assert printed.count("--offline: skipping AI enrichment") == 1


def test_offline_without_license_is_silent(cli, monkeypatch, capsys):
    _install_store(monkeypatch, None)
    cli._maybe_apply_enrichment([_finding()], offline=True)
    assert cli._enrichment_mode == em.HEURISTIC_OFFLINE
    assert capsys.readouterr().out == ""


def test_brass_offline_env_alone_yields_offline_mode(tmp_path, monkeypatch, capsys):
    """``_run_analysis_workflow`` ORs ``BRASS_OFFLINE=1`` into ``offline=``;
    verify the OR by driving the same expression the workflow uses."""
    import os
    import brass.enrichment as pkg
    monkeypatch.setenv("BRASS_OFFLINE", "1")
    cli = BrassCLI()
    cli.project_path = tmp_path
    _install_store(monkeypatch, _active_record())
    monkeypatch.setattr(pkg, "EnrichmentClient", _ExplodingClient)
    args = SimpleNamespace(no_enrich=False, offline=False)
    offline = bool(getattr(args, "offline", False)) or os.environ.get("BRASS_OFFLINE") == "1"
    cli._maybe_apply_enrichment([_finding()], no_enrich=args.no_enrich, offline=offline)
    assert cli._enrichment_mode == em.HEURISTIC_OFFLINE
    assert "Running AI enrichment" not in capsys.readouterr().out


def test_no_license_sets_no_license_mode_silently(cli, monkeypatch, capsys):
    _install_store(monkeypatch, None)
    findings = [_finding()]
    out = cli._maybe_apply_enrichment(findings)
    assert out is findings
    assert cli._enrichment_mode == em.HEURISTIC_NO_LICENSE
    assert capsys.readouterr().out == ""


def test_inactive_license_counts_as_no_license(cli, monkeypatch):
    rec = _active_record()
    rec.status = "expired"
    _install_store(monkeypatch, rec)
    cli._maybe_apply_enrichment([_finding()])
    assert cli._enrichment_mode == em.HEURISTIC_NO_LICENSE


@pytest.mark.parametrize("exc_factory", [
    lambda: __import__("brass.enrichment", fromlist=["x"]).EnrichmentUnavailableError("gateway down"),
    lambda: __import__("brass.enrichment", fromlist=["x"]).EnrichmentRateLimitedError("slow down"),
    lambda: __import__("brass.enrichment", fromlist=["x"]).EnrichmentClientError("boom"),
])
def test_soft_fail_sets_fallback_and_returns_identity(cli, monkeypatch, capsys, exc_factory):
    import brass.enrichment as pkg
    _install_store(monkeypatch, _active_record())
    monkeypatch.setattr(pkg, "EnrichmentClient", _QuietClient)

    def _raise(*a, **k):
        raise exc_factory()

    monkeypatch.setattr(pkg, "apply_enrichment", _raise)
    findings = [_finding()]
    out = cli._maybe_apply_enrichment(findings)
    assert out is findings
    assert cli._enrichment_mode == em.HEURISTIC_FALLBACK
    printed = capsys.readouterr().out
    assert "⚠️" in printed
    assert "using heuristic results" in printed


def test_success_sets_enriched(cli, monkeypatch, capsys):
    import brass.enrichment as pkg
    _install_store(monkeypatch, _active_record())
    monkeypatch.setattr(pkg, "EnrichmentClient", _QuietClient)
    enriched = [_finding(2)]
    monkeypatch.setattr(
        pkg, "apply_enrichment", lambda f, p, c: (enriched, _report(len(f))),
    )
    out = cli._maybe_apply_enrichment([_finding()])
    assert out is enriched
    assert cli._enrichment_mode == em.ENRICHED
    assert "Enriched:" in capsys.readouterr().out


def test_success_mode_survives_quota_lookup_failure(cli, monkeypatch, capsys):
    """ENRICHED is set before the quota block so a failing ``client.quota()``
    can never leave the mode unset."""
    import brass.enrichment as pkg
    _install_store(monkeypatch, _active_record())

    class _BadQuota(_QuietClient):
        def quota(self):
            raise pkg.EnrichmentClientError("quota unavailable")

    monkeypatch.setattr(pkg, "EnrichmentClient", _BadQuota)
    monkeypatch.setattr(
        pkg, "apply_enrichment", lambda f, p, c: (f, _report(len(f))),
    )
    cli._maybe_apply_enrichment([_finding()])
    assert cli._enrichment_mode == em.ENRICHED


# --- BrassCLI._generate_output threads the mode ---------------------


def test_generate_output_threads_enrichment_mode(cli, monkeypatch):
    captured = {}

    def _capture(findings, **kw):
        captured.update(kw)
        return {}

    cli.ranker = SimpleNamespace(rank_findings=lambda f: f)
    cli.output_generator = SimpleNamespace(generate_intelligence=_capture)
    cli._enrichment_mode = em.HEURISTIC_NO_LICENSE
    cli._generate_output([_finding()])
    assert captured["enrichment_mode"] == em.HEURISTIC_NO_LICENSE


def test_generate_output_threads_none_when_unset(cli):
    captured = {}
    cli.ranker = SimpleNamespace(rank_findings=lambda f: f)
    cli.output_generator = SimpleNamespace(
        generate_intelligence=lambda f, **kw: captured.update(kw) or {},
    )
    cli._generate_output([_finding()])
    assert "enrichment_mode" in captured
    assert captured["enrichment_mode"] is None


# --- YAMLOutputGeneratorV2: metadata.enrichment graft ---------------


def _generate(tmp_path: Path, mode, findings=None):
    from brass.output.yaml_output_generator_v2 import YAMLOutputGeneratorV2

    gen = YAMLOutputGeneratorV2(str(tmp_path))
    files = gen.generate_intelligence(findings or [_finding()], enrichment_mode=mode)
    assert "ai_instructions" in files
    ai = yaml.safe_load(Path(files["ai_instructions"]).read_text())
    stats = yaml.safe_load(Path(files["statistics"]).read_text())
    return ai, stats


def test_generator_heuristic_mode_grafts_mode_and_note_into_ai_instructions_only(tmp_path):
    from brass.output.yaml_builders.ai_instructions_builder import ENRICHMENT_HEURISTIC_NOTE

    ai, stats = _generate(tmp_path, em.HEURISTIC_NO_LICENSE)
    block = ai["metadata"]["enrichment"]
    assert block == {"mode": em.HEURISTIC_NO_LICENSE, "note": ENRICHMENT_HEURISTIC_NOTE}
    assert "enrichment" not in stats["metadata"]


def test_generator_enriched_mode_emits_mode_only(tmp_path):
    ai, _ = _generate(tmp_path, em.ENRICHED)
    assert ai["metadata"]["enrichment"] == {"mode": em.ENRICHED}


def test_generator_none_mode_omits_block(tmp_path):
    ai, stats = _generate(tmp_path, None)
    assert "enrichment" not in ai["metadata"]
    assert "enrichment" not in stats["metadata"]


def test_generator_glossary_names_metadata_enrichment(tmp_path):
    ai, _ = _generate(tmp_path, em.HEURISTIC_NO_LICENSE)
    assert "metadata.enrichment" in ai["how_to_read_this_file"]["field_glossary"]


def test_generator_graft_failure_is_isolated_from_yaml_write(tmp_path, monkeypatch, caplog):
    import logging
    from brass.output.yaml_builders.ai_instructions_builder import YAMLAIInstructionsBuilder

    def _boom(mode):
        raise RuntimeError("synthetic graft failure")

    monkeypatch.setattr(
        YAMLAIInstructionsBuilder, "_build_enrichment_metadata", staticmethod(_boom),
    )
    with caplog.at_level(logging.WARNING, logger="brass.output.yaml_output_generator_v2"):
        ai, _ = _generate(tmp_path, em.HEURISTIC_NO_LICENSE)
    # File still written and parseable; block dropped; warning logged.
    assert "enrichment" not in ai["metadata"]
    assert "security_critical" in ai or "executive_summary" in ai
    assert any("metadata enrichment skipped" in r.getMessage() for r in caplog.records)
