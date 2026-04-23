from __future__ import annotations

from pathlib import Path

from s19_app.validation.model import CoverageMetrics
from s19_app.tui.models import LoadedFile
from s19_app.tui.services import a2l_service, validation_service


def test_enrich_tags_and_render_merges_check_flags(monkeypatch):
    source_tags = [{"section": "MEASUREMENT", "name": "RPM", "address": 0x1000, "length": 2}]
    checked_tags = [{"section": "MEASUREMENT", "name": "RPM", "schema_ok": True, "in_memory": True}]

    monkeypatch.setattr(a2l_service, "enrich_a2l_tags_with_values", lambda _a2l, _map: source_tags)
    monkeypatch.setattr(a2l_service, "validate_a2l_tags", lambda _tags, _map: checked_tags)
    monkeypatch.setattr(a2l_service, "render_a2l_view", lambda *_args, **_kwargs: "A2L\nSummary")

    merged, summary = a2l_service.enrich_tags_and_render({"tags": source_tags}, {0x1000: 1})
    assert len(merged) == 1
    assert merged[0]["schema_ok"] is True
    assert summary == ["A2L", "Summary"]


def test_build_validation_report_uses_overlap_addresses():
    loaded = LoadedFile(
        path=Path("firmware.s19"),
        file_type="s19",
        mem_map={0x1000: 0x12},
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1004)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data={"sections": [], "errors": [], "tags": [{"name": "RPM", "address": 0x1000, "length": 1}]},
        mac_records=[{"parse_ok": True, "line_number": 1, "name": "RPM", "address": 0x1000}],
        mac_diagnostics=[],
    )

    report, issues, coverage = validation_service.build_validation_report(
        records=loaded.mac_records,
        primary_file=loaded,
        a2l_data=loaded.a2l_data,
        a2l_enriched_tags=[{"name": "RPM", "address": 0x1000, "length": 1}],
        dedupe_issues=lambda items: items,
        overlapped_addresses={0x1000},
    )
    assert report is not None
    assert coverage is not None
    assert any(issue.code == "CROSS_MAC_S19_OVERLAP_AMBIGUOUS" for issue in issues)


def test_build_validation_report_keeps_explicit_empty_enriched_tags(monkeypatch):
    loaded = LoadedFile(
        path=Path("firmware.s19"),
        file_type="s19",
        mem_map={0x1000: 0x12},
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1004)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data={"sections": [], "errors": [], "tags": [{"name": "RAW", "address": 0x1000, "length": 1}]},
        mac_records=[{"parse_ok": True, "line_number": 1, "name": "RPM", "address": 0x1000}],
        mac_diagnostics=[],
    )
    captured: dict[str, list[dict]] = {}

    def _fake_validate_artifact_consistency(**kwargs):
        captured["a2l_tags"] = kwargs["a2l_tags"]
        return validation_service.ValidationReport(issues=[], coverage=CoverageMetrics())

    monkeypatch.setattr(
        validation_service,
        "validate_artifact_consistency",
        _fake_validate_artifact_consistency,
    )
    monkeypatch.setattr(
        validation_service,
        "validate_a2l_internal_issues",
        lambda *_args, **_kwargs: [],
    )

    validation_service.build_validation_report(
        records=loaded.mac_records,
        primary_file=loaded,
        a2l_data=loaded.a2l_data,
        a2l_enriched_tags=[],
        dedupe_issues=lambda items: items,
        overlapped_addresses=set(),
    )

    assert captured["a2l_tags"] == []


def test_build_validation_report_falls_back_to_raw_tags_when_enriched_is_none(monkeypatch):
    loaded = LoadedFile(
        path=Path("firmware.s19"),
        file_type="s19",
        mem_map={0x1000: 0x12},
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1004)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data={"sections": [], "errors": [], "tags": [{"name": "RAW", "address": 0x1000, "length": 1}]},
        mac_records=[{"parse_ok": True, "line_number": 1, "name": "RPM", "address": 0x1000}],
        mac_diagnostics=[],
    )
    captured: dict[str, list[dict]] = {}

    def _fake_validate_artifact_consistency(**kwargs):
        captured["a2l_tags"] = kwargs["a2l_tags"]
        return validation_service.ValidationReport(issues=[], coverage=CoverageMetrics())

    monkeypatch.setattr(
        validation_service,
        "validate_artifact_consistency",
        _fake_validate_artifact_consistency,
    )
    monkeypatch.setattr(
        validation_service,
        "validate_a2l_internal_issues",
        lambda *_args, **_kwargs: [],
    )

    validation_service.build_validation_report(
        records=loaded.mac_records,
        primary_file=loaded,
        a2l_data=loaded.a2l_data,
        a2l_enriched_tags=None,
        dedupe_issues=lambda items: items,
        overlapped_addresses=set(),
    )

    assert captured["a2l_tags"] == loaded.a2l_data["tags"]


def test_build_validation_report_mac_only_emits_duplicate_classification_issue():
    records = [
        {"parse_ok": True, "line_number": 1, "name": "RPM", "address": 0x1000},
        {"parse_ok": True, "line_number": 2, "name": "TORQUE", "address": 0x1000},
    ]
    report, issues, coverage = validation_service.build_validation_report(
        records=records,
        primary_file=None,
        a2l_data=None,
        a2l_enriched_tags=None,
        dedupe_issues=lambda items: items,
        overlapped_addresses=None,
    )
    assert report is not None
    assert coverage is None
    duplicate_issue = next(issue for issue in issues if issue.code == "MAC_DUPLICATE_ADDRESS")
    assert duplicate_issue.details.get("classification") == "alias candidate"
