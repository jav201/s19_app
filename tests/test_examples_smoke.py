"""Functional smoke tests for every ``examples/`` case via the TUI service layer.

This file exercises the parser → service-layer → validation pipeline against
the on-disk example fixtures without launching the Textual UI. Each case is a
parametrized invocation so failures surface case-by-case in the pytest output.

Cases tested:
    - ``examples/case_NN_*`` (8 top-level cases).
    - ``examples/professional_validation/case_NN_*`` (7 nested cases).

For every case we verify:
    1. The primary image (S19 or HEX) loads and produces a non-trivial
       ``LoadedFile`` snapshot.
    2. If an ``.a2l`` is present, ``enrich_tags_and_render`` returns lists.
    3. ``build_validation_report`` returns a usable ``ValidationReport`` (or
       ``None`` for MAC-less + S19-less degenerate cases, which would already
       have been skipped).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

import pytest

from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.mac import parse_mac_file
from s19_app.tui.models import LoadedFile
from s19_app.tui.services.a2l_service import enrich_tags_and_render
from s19_app.tui.services.load_service import build_loaded_hex, build_loaded_s19
from s19_app.tui.services.validation_service import build_validation_report

EXAMPLES_ROOT = Path(__file__).resolve().parent.parent / "examples"
REPO_ROOT = EXAMPLES_ROOT.parent


# Case ids that take a long time in the smoke pipeline (~minutes vs ~seconds)
# and are marked @pytest.mark.slow so the CI default (`-m "not slow"`) skips
# them. Empty since batch-36 (US-060): the ~490s pv__case_06_large_nested_a2l
# duplicate was pruned; the retained 36 MB examples/case_06_large_nested_a2l
# now covers the large-A2L pipeline in the normal suite.
SLOW_CASE_IDS: set[str] = set()


def _discover_cases() -> list:
    """
    Discover every example case directory.

    Returns:
        list: ``pytest.param`` entries. ``case_id`` is unique across the
        top-level and ``professional_validation`` namespaces. Cases in
        ``SLOW_CASE_IDS`` carry the ``@pytest.mark.slow`` marker so the
        default test run skips them.
    """
    cases: list = []
    for entry in sorted(EXAMPLES_ROOT.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name == "professional_validation":
            for sub in sorted(entry.iterdir()):
                if sub.is_dir():
                    case_id = f"pv__{sub.name}"
                    marks = (pytest.mark.slow,) if case_id in SLOW_CASE_IDS else ()
                    cases.append(pytest.param(case_id, sub, marks=marks, id=case_id))
            continue
        case_id = entry.name
        cases.append(pytest.param(case_id, entry, id=case_id))
    return cases


def _pick_primary(case_dir: Path) -> Optional[Path]:
    """Pick the canonical S19/HEX image in ``case_dir`` (or ``None``)."""
    for candidate in ("firmware.s19", "firmware.hex", "prg.s19", "prg.hex"):
        path = case_dir / candidate
        if path.is_file():
            return path
    # Fall back to any *.s19 / *.hex
    for ext in (".s19", ".hex"):
        hits = sorted(p for p in case_dir.glob(f"*{ext}") if p.is_file())
        if hits:
            return hits[0]
    return None


def _pick_a2l(case_dir: Path) -> Optional[Path]:
    """Pick a representative ``.a2l`` in ``case_dir`` (or ``None``)."""
    for candidate in ("firmware.a2l",):
        path = case_dir / candidate
        if path.is_file():
            return path
    hits = sorted(p for p in case_dir.glob("*.a2l") if p.is_file())
    return hits[0] if hits else None


def _pick_mac(case_dir: Path) -> Optional[Path]:
    """Pick a representative ``.mac`` in ``case_dir`` (or ``None``)."""
    for candidate in ("firmware.mac",):
        path = case_dir / candidate
        if path.is_file():
            return path
    hits = sorted(p for p in case_dir.glob("*.mac") if p.is_file())
    return hits[0] if hits else None


_CASES = _discover_cases()


@pytest.mark.parametrize(
    ("case_id", "case_dir"),
    _CASES,
)
def test_case_loads_through_service_layer(case_id: str, case_dir: Path) -> None:
    """End-to-end smoke: load primary image, enrich A2L, build validation."""
    primary = _pick_primary(case_dir)
    if primary is None:
        pytest.skip(f"{case_id}: no S19/HEX image present")

    a2l_path = _pick_a2l(case_dir)
    a2l_data = parse_a2l_file(a2l_path) if a2l_path else None

    if primary.suffix.lower() == ".s19":
        loaded = build_loaded_s19(primary, S19File(str(primary)), a2l_path, a2l_data)
    else:
        loaded = build_loaded_hex(primary, IntelHexFile(str(primary)), a2l_path, a2l_data)

    assert isinstance(loaded, LoadedFile)
    # Either the loader produced ranges, or it deliberately surfaced errors —
    # both are valid snapshots, but a completely empty snapshot is a bug.
    assert loaded.mem_map or loaded.errors, (
        f"{case_id}: loader produced neither memory nor errors"
    )
    assert loaded.file_type in {"s19", "hex"}
    assert len(loaded.ranges) == len(loaded.range_validity), (
        f"{case_id}: range_validity out of sync with ranges"
    )

    # A2L service layer
    if a2l_data:
        rows, summary_lines = enrich_tags_and_render(a2l_data, loaded.mem_map)
        assert isinstance(rows, list)
        assert isinstance(summary_lines, list)

    # MAC records (optional)
    mac_path = _pick_mac(case_dir)
    mac_records: list[dict] = []
    if mac_path:
        mac_payload = parse_mac_file(mac_path)
        mac_records = list(mac_payload.get("records", []))

    # Validation service — always callable, even with empty MAC.
    report, issues, coverage_line = build_validation_report(
        records=mac_records,
        primary_file=loaded,
        a2l_data=a2l_data,
        a2l_enriched_tags=None,
        dedupe_issues=lambda items: items,
        overlapped_addresses=None,
    )
    assert report is not None, f"{case_id}: build_validation_report returned None for primary-backed case"
    assert isinstance(issues, list)
    assert coverage_line is None or "Coverage" in coverage_line, (
        f"{case_id}: coverage_line format unexpected"
    )


def test_at060a_fixtures_relocated_heavy_duplicate_pruned() -> None:
    """AT-060a (US-060): stress fixtures relocated, heavy duplicate pruned.

    One on-disk + service-layer node (C-18) covering all four observable
    outcomes of US-060:

    1. ``tmp/stress_smoke/`` is gone both on the filesystem and in the git
       index (no untracked orphan left behind — LLR-060.1).
    2. ``examples/case_07_stress_smoke/`` exists and its primary image loads
       through the real service layer to a NON-empty ``LoadedFile`` — content,
       not mere directory presence (C-10, C-12).
    3. the 54 MB ``professional_validation/case_06_large_nested_a2l`` slow
       duplicate is pruned (LLR-060.2, I-060-1-gated).
    4. the retained 36 MB ``case_06_large_nested_a2l/firmware.a2l`` is present
       (operator constraint D-1 — keep one large-A2L fixture).
    """
    # (1) tmp/stress_smoke/ absent on disk AND untracked in the git index.
    assert not (REPO_ROOT / "tmp" / "stress_smoke").exists(), (
        "tmp/stress_smoke/ must be removed after relocation"
    )
    tracked = subprocess.run(
        ["git", "ls-files", "tmp/stress_smoke"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert tracked == "", f"git still tracks tmp/stress_smoke: {tracked!r}"

    # (2) the relocated case exists and loads to a non-empty memory map.
    case07 = EXAMPLES_ROOT / "case_07_stress_smoke"
    assert case07.is_dir(), "examples/case_07_stress_smoke/ must exist"
    primary = _pick_primary(case07)
    assert primary is not None, "case_07_stress_smoke has no S19/HEX primary image"
    if primary.suffix.lower() == ".s19":
        loaded = build_loaded_s19(primary, S19File(str(primary)), None, None)
    else:
        loaded = build_loaded_hex(primary, IntelHexFile(str(primary)), None, None)
    assert isinstance(loaded, LoadedFile)
    assert loaded.mem_map, (
        "case_07_stress_smoke primary produced an empty memory map"
    )

    # (3) the 54 MB slow duplicate is pruned …
    assert not (
        EXAMPLES_ROOT / "professional_validation" / "case_06_large_nested_a2l"
    ).exists(), (
        "the 54 MB professional_validation/case_06_large_nested_a2l duplicate "
        "must be pruned"
    )
    # (4) … while the retained 36 MB large-A2L fixture remains.
    assert (
        EXAMPLES_ROOT / "case_06_large_nested_a2l" / "firmware.a2l"
    ).is_file(), (
        "the retained 36 MB examples/case_06_large_nested_a2l/firmware.a2l "
        "must be present"
    )


def test_tc323_discovery_and_coverage_map() -> None:
    """TC-323 (LLR-060.3): discovery + empty SLOW_CASE_IDS + coverage preserved.

    Asserts the slow set is now empty, the relocated case is auto-discovered,
    the pruned duplicate is no longer discovered, and the large-nested-A2L
    pipeline still has a covering case (now in the normal suite) — proving no
    coverage regression.
    """
    assert SLOW_CASE_IDS == set(), (
        "the only slow case was deleted; SLOW_CASE_IDS must be empty"
    )
    discovered_ids = {param.id for param in _discover_cases()}
    # the relocated stress case is picked up by dynamic discovery …
    assert "case_07_stress_smoke" in discovered_ids
    # … the pruned slow duplicate is no longer discovered …
    assert "pv__case_06_large_nested_a2l" not in discovered_ids
    # … and the large-nested-A2L pipeline is STILL covered by the retained
    # 36 MB top-level case (normal suite, every PR) — no coverage regression.
    assert "case_06_large_nested_a2l" in discovered_ids
