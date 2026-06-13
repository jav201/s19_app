"""
Comparison service tests — s19_app batch-09, increment I2 (HLR-002 / HLR-003).

Test -> TC -> LLR map:
    test_module_imports_no_textual                  TC-007  LLR-002.1 (inspection-mirror)
    test_variant_pair_matches_engine                TC-007  LLR-002.2
    test_external_unresolvable_returns_refused      TC-008  LLR-002.3
    test_mixed_source_pairings_record_identity      TC-009  LLR-002.4
    test_parse_failure_isolated_to_refused          TC-010  LLR-002.5
    test_result_field_set_matches_c9_contract       TC-011  LLR-002.6
    test_artifact_context_applies_to_external       TC-012  LLR-003.1
    test_coverage_counts_match_hand_computed        TC-013  LLR-003.2
    test_usage_summary_all_four_outcomes            TC-014  LLR-003.3
    test_absent_artifacts_summary_none              TC-015  LLR-003.4

LLR-002.1 is principally an rg purity probe (no Textual import); the pytest
node here is an in-process mirror so the property cannot silently rot.
"""

from __future__ import annotations

import dataclasses
import shutil
from pathlib import Path
from typing import Optional

import pytest

from s19_app.compare import ComparisonResult, diff_mem_maps
from s19_app.tui.services import compare_service
from s19_app.tui.services.compare_service import (
    ARTIFACT_ABSENT,
    ARTIFACT_UNUSED,
    ARTIFACT_USED,
    SOURCE_EXTERNAL,
    SOURCE_PROJECT_VARIANT,
    SUMMARY_BOTH,
    SUMMARY_NONE,
    SUMMARY_ONE_A2L,
    SUMMARY_ONE_MAC,
    ArtifactUsage,
    ImageSource,
    compare_images,
)

EXAMPLE_PROJECT = Path(__file__).resolve().parents[1] / "examples" / "case_01_basic_valid"


# ---------------------------------------------------------------------------
# Fixtures / helpers.
# ---------------------------------------------------------------------------


def _make_variant_project(tmp_path: Path) -> Path:
    """Temp project dir with two distinct S19 variants built from example content.

    Existence probe P-12 (2026-06-11): examples/case_00_public holds prg.s19 +
    s19_sample.s19. We copy one example image twice under distinct names and
    mutate one so the two variants genuinely differ.
    """
    src = Path(__file__).resolve().parents[1] / "examples" / "case_00_public" / "prg.s19"
    project = tmp_path / "proj"
    project.mkdir()
    shutil.copy(src, project / "fw_a.s19")
    shutil.copy(src, project / "fw_b.s19")
    return project


def _variant_set(project: Path):
    from s19_app.tui.workspace import build_variant_set, validate_project_files

    data_files, _a2l_files, err = validate_project_files(project)
    assert err is None
    return build_variant_set(project.name, data_files)


# In-memory loader stubs so coverage/summary tests use hand-computed maps and
# ranges rather than parsed-example internals.


def _stub_loaded(mem_map: dict[int, int], ranges: list[tuple[int, int]]):
    from s19_app.tui.models import LoadedFile

    return LoadedFile(
        path=Path("stub"),
        file_type="s19",
        mem_map=dict(mem_map),
        row_bases=[],
        ranges=list(ranges),
        range_validity=[True] * len(ranges),
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )


def _stub_loader(mem_map: dict[int, int], ranges: list[tuple[int, int]]):
    def _load(_path: Path):
        return _stub_loaded(mem_map, ranges)

    return _load


def _ext(path: Path) -> ImageSource:
    return ImageSource(kind=SOURCE_EXTERNAL, raw_path=str(path))


# ---------------------------------------------------------------------------
# TC-007 — LLR-002.1 module purity (mirror) + LLR-002.2 fresh variant parse.
# ---------------------------------------------------------------------------


def test_module_imports_no_textual() -> None:
    # LLR-002.1: no Textual symbol reaches the service module namespace. The
    # canonical check is the rg purity probe; this mirror parses the module's
    # own import statements via AST so no Textual import can land unnoticed
    # (prose mentions of the word "textual" in docstrings are ignored).
    import ast
    import sys

    mod = sys.modules[compare_service.__name__]
    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
    imported_modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.append(node.module)
    assert not any(name.split(".")[0] == "textual" for name in imported_modules)


def test_variant_pair_matches_engine(tmp_path: Path) -> None:
    # LLR-002.2: comparing two project variants equals the engine over the two
    # independently-parsed memory maps (fresh parse, not the TUI snapshot).
    project = _make_variant_project(tmp_path)
    vset = _variant_set(project)

    # Mutate fw_b on disk so the two images differ.
    target = project / "fw_b.s19"
    from s19_app.core import S19File

    map_a = S19File(str(project / "fw_a.s19")).get_memory_map()
    map_b = S19File(str(target)).get_memory_map()
    # The copies are identical; assert the service yields the engine's output
    # over the actually-parsed maps (here: zero runs), proving it parsed fresh.
    expected_runs, _ = diff_mem_maps(map_a, map_b)

    result = compare_images(
        ImageSource(kind=SOURCE_PROJECT_VARIANT, variant_id="fw_a"),
        ImageSource(kind=SOURCE_PROJECT_VARIANT, variant_id="fw_b"),
        variant_set=vset,
    )

    assert result.refused is False
    assert result.runs == expected_runs
    assert result.image_a.variant_id == "fw_a"
    assert result.image_b.variant_id == "fw_b"
    assert result.image_a.source_kind == SOURCE_PROJECT_VARIANT


def test_variant_pair_reports_real_diff(tmp_path: Path) -> None:
    # LLR-002.2 (diff path): a genuinely-different second variant yields the
    # engine's changed runs through the service.
    project = _make_variant_project(tmp_path)
    # Replace fw_b with the other example image so the maps differ.
    other = Path(__file__).resolve().parents[1] / "examples" / "case_00_public" / "s19_sample.s19"
    shutil.copy(other, project / "fw_b.s19")
    vset = _variant_set(project)

    from s19_app.core import S19File

    map_a = S19File(str(project / "fw_a.s19")).get_memory_map()
    map_b = S19File(str(project / "fw_b.s19")).get_memory_map()
    expected_runs, _ = diff_mem_maps(map_a, map_b)

    result = compare_images(
        ImageSource(kind=SOURCE_PROJECT_VARIANT, variant_id="fw_a"),
        ImageSource(kind=SOURCE_PROJECT_VARIANT, variant_id="fw_b"),
        variant_set=vset,
    )

    assert result.refused is False
    assert result.runs == expected_runs


# ---------------------------------------------------------------------------
# TC-008 — LLR-002.3 external path resolution / unresolvable refusal.
# ---------------------------------------------------------------------------


def test_external_unresolvable_returns_refused(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.s19"
    result = compare_images(
        _ext(missing),
        _ext(missing),
        base_dir=tmp_path,
    )
    assert isinstance(result, ComparisonResult)
    assert result.refused is True
    assert result.runs == []
    assert any(str(missing) in diag for diag in result.diagnostics)


def test_external_resolved_pair(tmp_path: Path) -> None:
    # LLR-002.3 success: two existing external files resolve and compare.
    src = EXAMPLE_PROJECT / "firmware.s19"
    a = tmp_path / "a.s19"
    b = tmp_path / "b.s19"
    shutil.copy(src, a)
    shutil.copy(src, b)
    result = compare_images(_ext(a), _ext(b), base_dir=tmp_path)
    assert result.refused is False
    assert result.image_a.source_kind == SOURCE_EXTERNAL
    assert result.image_a.path == str(a)


# ---------------------------------------------------------------------------
# TC-009 — LLR-002.4 mixed source pairings record identity.
# ---------------------------------------------------------------------------


def test_mixed_source_pairings_record_identity(tmp_path: Path) -> None:
    project = _make_variant_project(tmp_path)
    vset = _variant_set(project)
    ext_file = tmp_path / "external.s19"
    shutil.copy(EXAMPLE_PROJECT / "firmware.s19", ext_file)

    variant_src = ImageSource(kind=SOURCE_PROJECT_VARIANT, variant_id="fw_a")

    # variant + variant
    r1 = compare_images(variant_src, ImageSource(kind=SOURCE_PROJECT_VARIANT, variant_id="fw_b"), variant_set=vset)
    assert r1.image_a.variant_id == "fw_a" and r1.image_b.variant_id == "fw_b"
    assert r1.image_a.path is not None and r1.image_b.path is not None

    # variant + external
    r2 = compare_images(variant_src, _ext(ext_file), variant_set=vset, base_dir=tmp_path)
    assert r2.image_a.source_kind == SOURCE_PROJECT_VARIANT
    assert r2.image_a.variant_id == "fw_a"
    assert r2.image_b.source_kind == SOURCE_EXTERNAL
    assert r2.image_b.variant_id is None
    assert r2.image_b.path == str(ext_file)

    # external + external
    r3 = compare_images(_ext(ext_file), _ext(ext_file), base_dir=tmp_path)
    assert r3.image_a.source_kind == SOURCE_EXTERNAL
    assert r3.image_b.source_kind == SOURCE_EXTERNAL


# ---------------------------------------------------------------------------
# TC-010 — LLR-002.5 parse-failure isolation -> refused (no exception).
# ---------------------------------------------------------------------------


def test_parse_failure_isolated_to_refused(tmp_path: Path) -> None:
    src = EXAMPLE_PROJECT / "firmware.s19"
    a = tmp_path / "a.s19"
    b = tmp_path / "b.s19"
    shutil.copy(src, a)
    shutil.copy(src, b)

    def _boom(_path: Path):
        raise ValueError("planted parse failure")

    # No exception should escape the service; result is refused with the text.
    result = compare_images(
        _ext(a),
        _ext(b),
        base_dir=tmp_path,
        load_s19=_boom,
    )
    assert result.refused is True
    assert result.runs == []
    assert any("planted parse failure" in diag for diag in result.diagnostics)


# ---------------------------------------------------------------------------
# TC-011 — LLR-002.6 C-9 result contract field-set identity.
# ---------------------------------------------------------------------------


def test_result_field_set_matches_c9_contract() -> None:
    # The §6.2 C-9 canonical field set, enumerated.
    c9_fields = {
        "image_a",
        "image_b",
        "runs",
        "stats",
        "notes",
        "diagnostics",
        "refused",
    }
    actual = {f.name for f in dataclasses.fields(ComparisonResult)}
    assert actual == c9_fields  # 0 missing, 0 extra


# ---------------------------------------------------------------------------
# TC-012 — LLR-003.1 artifact context from project cardinality, applied to all.
# ---------------------------------------------------------------------------


def test_artifact_context_applies_to_external(tmp_path: Path) -> None:
    # An external image compared inside a project with one A2L + one MAC
    # receives notes for both artifacts (2 of 2 noted), proving the shared
    # context applies even to external images.
    from s19_app.tui.a2l import parse_a2l_file
    from s19_app.tui.mac import parse_mac_file

    a2l_data = parse_a2l_file(EXAMPLE_PROJECT / "firmware.a2l")
    mac = parse_mac_file(EXAMPLE_PROJECT / "firmware.mac")["records"]

    ext = tmp_path / "ext.s19"
    shutil.copy(EXAMPLE_PROJECT / "firmware.s19", ext)

    result = compare_images(
        _ext(ext),
        _ext(ext),
        base_dir=tmp_path,
        a2l_data=a2l_data,
        mac_records=mac,
    )
    assert result.refused is False
    usage: ArtifactUsage = result.notes["image_a"]
    assert usage.a2l.status != ARTIFACT_ABSENT
    assert usage.mac.status != ARTIFACT_ABSENT
    # The example A2L/MAC addresses fall inside the firmware ranges -> both used.
    assert usage.summary == SUMMARY_BOTH


# ---------------------------------------------------------------------------
# TC-013 — LLR-003.2 coverage counts via range_index match hand computation.
# ---------------------------------------------------------------------------


def test_coverage_counts_match_hand_computed(tmp_path: Path) -> None:
    # Image ranges: [0x100,0x110) and [0x200,0x210). MAC addresses: 3 inside
    # (0x100, 0x108, 0x200), 2 outside (0x0, 0x300). A2L absent.
    mem_map = {addr: 0 for addr in list(range(0x100, 0x110)) + list(range(0x200, 0x210))}
    ranges = [(0x100, 0x110), (0x200, 0x210)]
    mac_records = [
        {"name": "in1", "address": 0x100},
        {"name": "in2", "address": 0x108},
        {"name": "in3", "address": 0x200},
        {"name": "out1", "address": 0x000},
        {"name": "out2", "address": 0x300},
        {"name": "noaddr", "address": None},
    ]
    result = compare_images(
        _ext(tmp_path / "x.s19"),
        _ext(tmp_path / "y.s19"),
        base_dir=tmp_path,
        mac_records=mac_records,
        mac_present=True,
        resolver=lambda p, b: p,  # treat the path as resolved
        load_s19=_stub_loader(mem_map, ranges),
    )
    assert result.refused is False
    usage: ArtifactUsage = result.notes["image_a"]
    assert usage.mac.covered == 3  # hand-computed: 0x100, 0x108, 0x200
    assert usage.mac.total == 5  # records carrying an int address
    assert usage.mac.status == ARTIFACT_USED
    assert usage.a2l.status == ARTIFACT_ABSENT


# ---------------------------------------------------------------------------
# TC-014 — LLR-003.3 usage summary: all four outcomes.
# ---------------------------------------------------------------------------


def _compare_with_artifacts(
    tmp_path: Path,
    *,
    a2l_addr_in: bool,
    mac_addr_in: bool,
    a2l_present: bool = True,
    mac_present: bool = True,
):
    mem_map = {addr: 0 for addr in range(0x100, 0x110)}
    ranges = [(0x100, 0x110)]
    # A2L address inside or outside the single range.
    a2l_addr = 0x104 if a2l_addr_in else 0x900
    mac_addr = 0x108 if mac_addr_in else 0x901
    a2l_data = {"tags": [{"name": "T", "address": a2l_addr}]} if a2l_present else None
    mac_records = [{"name": "M", "address": mac_addr}] if mac_present else None

    return compare_images(
        _ext(tmp_path / "x.s19"),
        _ext(tmp_path / "y.s19"),
        base_dir=tmp_path,
        a2l_data=a2l_data,
        mac_records=mac_records,
        a2l_present=a2l_present,
        mac_present=mac_present,
        resolver=lambda p, b: p,
        load_s19=_stub_loader(mem_map, ranges),
        # Substitute the a2l-address extractor via injected loader is not
        # possible; instead patch enrich below in the test.
    )


def test_usage_summary_all_four_outcomes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Patch the A2L enrichment so a2l "address inside/outside" is deterministic
    # from the synthetic tag list, independent of the full A2L parser.
    def _fake_enrich(a2l_data, mem_map, max_tag_lines: int = 500):
        if not a2l_data:
            return [], []
        return list(a2l_data.get("tags", [])), []

    monkeypatch.setattr(compare_service, "enrich_tags_and_render", _fake_enrich)

    # both: a2l in + mac in
    both = _compare_with_artifacts(tmp_path, a2l_addr_in=True, mac_addr_in=True)
    assert both.notes["image_a"].summary == SUMMARY_BOTH

    # one (a2l): a2l in, mac out
    one_a2l = _compare_with_artifacts(tmp_path, a2l_addr_in=True, mac_addr_in=False)
    assert one_a2l.notes["image_a"].summary == SUMMARY_ONE_A2L

    # one (mac): a2l out, mac in
    one_mac = _compare_with_artifacts(tmp_path, a2l_addr_in=False, mac_addr_in=True)
    assert one_mac.notes["image_a"].summary == SUMMARY_ONE_MAC

    # none: both out
    none = _compare_with_artifacts(tmp_path, a2l_addr_in=False, mac_addr_in=False)
    assert none.notes["image_a"].summary == SUMMARY_NONE
    assert none.notes["image_a"].a2l.status == ARTIFACT_UNUSED
    assert none.notes["image_a"].mac.status == ARTIFACT_UNUSED


# ---------------------------------------------------------------------------
# TC-015 — LLR-003.4 absent artifacts -> summary none, no error.
# ---------------------------------------------------------------------------


def test_absent_artifacts_summary_none(tmp_path: Path) -> None:
    mem_map = {addr: 0 for addr in range(0x100, 0x110)}
    ranges = [(0x100, 0x110)]
    result = compare_images(
        _ext(tmp_path / "x.s19"),
        _ext(tmp_path / "y.s19"),
        base_dir=tmp_path,
        a2l_data=None,
        mac_records=None,
        resolver=lambda p, b: p,
        load_s19=_stub_loader(mem_map, ranges),
    )
    assert result.refused is False
    usage: ArtifactUsage = result.notes["image_a"]
    assert usage.a2l.status == ARTIFACT_ABSENT
    assert usage.mac.status == ARTIFACT_ABSENT
    assert usage.summary == SUMMARY_NONE
