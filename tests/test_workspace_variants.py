"""Batch-07 E5a — multi-variant project model at the workspace + models layer.

Covers:
- LLR-005.1: ``validate_project_files`` accepts N S19/HEX variants in
  deterministic ``(name.lower(), name)`` order while preserving the
  single-MAC and single-A2L rejections.
- LLR-005.2: ``VariantDescriptor`` / ``ProjectVariantSet`` construction and
  the additive ``LoadedFile.variant_id`` default.
- LLR-005.3: single-S19 projects validate exactly as before (equivalence).
- LLR-007.7 (partial): a populated ``reports/`` subdirectory is neutral.
- ``build_variant_set``: ordering, active-id default/override, MAC exclusion.
"""

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from s19_app.tui.models import LoadedFile, ProjectVariantSet, VariantDescriptor
from s19_app.tui.workspace import build_variant_set, validate_project_files


def _make_project(tmp_path: Path, filenames: list[str]) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    for name in filenames:
        (project / name).write_text("S0", encoding="utf-8")
    return project


# ---------------------------------------------------------------------------
# LLR-005.1 — multi-variant acceptance + preserved rejections
# ---------------------------------------------------------------------------


def test_three_s19_variants_accepted_in_deterministic_order(tmp_path: Path):
    # Creation order is deliberately non-alphabetical; the returned order must
    # be (name.lower(), name), not OS iterdir() order.
    project = _make_project(tmp_path, ["zeta.s19", "Alpha.s19", "mid.s19"])

    data_files, a2l_files, error = validate_project_files(project)

    assert error is None, f"3-variant project must validate, got {error!r}"
    assert [item.name for item in data_files] == ["Alpha.s19", "mid.s19", "zeta.s19"]
    assert a2l_files == []


def test_variants_with_two_mac_files_still_rejected(tmp_path: Path):
    project = _make_project(
        tmp_path, ["a.s19", "b.s19", "c.s19", "tags1.mac", "tags2.mac"]
    )

    _, _, error = validate_project_files(project)

    assert error is not None and "MAC" in error


def test_two_a2l_files_still_rejected(tmp_path: Path):
    project = _make_project(tmp_path, ["fw.s19", "one.a2l", "two.a2l"])

    _, _, error = validate_project_files(project)

    assert error is not None and "A2L" in error


# ---------------------------------------------------------------------------
# LLR-005.3 — single-S19 backward compatibility
# ---------------------------------------------------------------------------


def test_single_s19_project_loads_equivalently(tmp_path: Path):
    # Pre-batch contract for a single-S19 project: ([fw.s19], [], None).
    # The relaxation must not change any element of that return, and the
    # derived variant set must be a 1-variant set with that variant active.
    project = _make_project(tmp_path, ["fw.s19"])

    data_files, a2l_files, error = validate_project_files(project)

    assert error is None
    assert [item.name for item in data_files] == ["fw.s19"]
    assert a2l_files == []

    vset = build_variant_set("proj", data_files)
    assert len(vset.variants) == 1
    assert vset.variants[0].variant_id == "fw"
    assert vset.variants[0].path == project / "fw.s19"
    assert vset.variants[0].file_type == "s19"
    assert vset.active_id == "fw"


# ---------------------------------------------------------------------------
# LLR-007.7 (partial) — reports/ storage neutrality
# ---------------------------------------------------------------------------


def test_populated_reports_subdirectory_is_neutral(tmp_path: Path):
    project = _make_project(tmp_path, ["fw.s19", "cal.a2l"])
    reports = project / "reports"
    reports.mkdir()
    (reports / "run-001.md").write_text("# report", encoding="utf-8")
    (reports / "extra.s19").write_text("S0", encoding="utf-8")

    data_files, a2l_files, error = validate_project_files(project)

    assert error is None
    assert [item.name for item in data_files] == ["fw.s19"]
    assert [item.name for item in a2l_files] == ["cal.a2l"]


# ---------------------------------------------------------------------------
# LLR-005.2 — variant dataclasses + LoadedFile compatibility
# ---------------------------------------------------------------------------


def test_variant_descriptor_is_frozen_with_expected_fields():
    descriptor = VariantDescriptor(
        variant_id="fw_a", path=Path("fw_a.s19"), file_type="s19"
    )

    assert descriptor.variant_id == "fw_a"
    assert descriptor.path == Path("fw_a.s19")
    assert descriptor.file_type == "s19"
    with pytest.raises(FrozenInstanceError):
        descriptor.variant_id = "other"


def test_project_variant_set_construction():
    descriptor = VariantDescriptor(
        variant_id="fw", path=Path("fw.hex"), file_type="hex"
    )
    vset = ProjectVariantSet(
        project_name="proj", variants=(descriptor,), active_id="fw"
    )

    assert vset.project_name == "proj"
    assert vset.variants == (descriptor,)
    assert vset.active_id == "fw"


def test_loaded_file_variant_id_defaults_to_none():
    # The pre-batch positional constructor must keep working unchanged, and
    # the new additive field must default to None (LLR-005.2).
    loaded = LoadedFile(
        path=Path("fw.s19"),
        file_type="s19",
        mem_map={},
        row_bases=[],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )

    assert loaded.variant_id is None


# ---------------------------------------------------------------------------
# build_variant_set — ordering, active default/override, filtering
# ---------------------------------------------------------------------------


def test_build_variant_set_orders_variants_and_defaults_active_to_first():
    data_files = [
        Path("zeta.s19"),
        Path("Alpha.hex"),
        Path("tags.mac"),
        Path("mid.s19"),
    ]

    vset = build_variant_set("proj", data_files)

    assert [v.variant_id for v in vset.variants] == ["Alpha", "mid", "zeta"]
    assert [v.file_type for v in vset.variants] == ["hex", "s19", "s19"]
    assert vset.active_id == "Alpha"
    assert vset.project_name == "proj"
    # MAC files are overlays, never variants.
    assert all(v.path.suffix != ".mac" for v in vset.variants)


def test_build_variant_set_honors_explicit_active_id():
    vset = build_variant_set("proj", [Path("a.s19"), Path("b.s19")], active_id="b")

    assert vset.active_id == "b"


def test_build_variant_set_rejects_unknown_active_id():
    with pytest.raises(ValueError, match="ghost"):
        build_variant_set("proj", [Path("a.s19")], active_id="ghost")


def test_build_variant_set_empty_project_has_no_active_variant():
    vset = build_variant_set("proj", [Path("tags.mac")])

    assert vset.variants == ()
    assert vset.active_id is None
