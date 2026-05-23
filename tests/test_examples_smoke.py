"""Functional smoke tests for every ``examples/`` case via the TUI service layer.

This file exercises the parser → service-layer → validation pipeline against
the on-disk example fixtures without launching the Textual UI. Each case is a
parametrized invocation so failures surface case-by-case in the pytest output.

Cases tested:
    - ``examples/case_NN_*`` (7 top-level cases).
    - ``examples/professional_validation/case_NN_*`` (8 nested cases).

For every case we verify:
    1. The primary image (S19 or HEX) loads and produces a non-trivial
       ``LoadedFile`` snapshot.
    2. If an ``.a2l`` is present, ``enrich_tags_and_render`` returns lists.
    3. ``build_validation_report`` returns a usable ``ValidationReport`` (or
       ``None`` for MAC-less + S19-less degenerate cases, which would already
       have been skipped).
"""

from __future__ import annotations

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


def _discover_cases() -> list[tuple[str, Path]]:
    """
    Discover every example case directory.

    Returns:
        list[tuple[str, Path]]: ``(case_id, case_dir)`` pairs. ``case_id`` is
        unique across the top-level and ``professional_validation`` namespaces.
    """
    cases: list[tuple[str, Path]] = []
    for entry in sorted(EXAMPLES_ROOT.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name == "professional_validation":
            for sub in sorted(entry.iterdir()):
                if sub.is_dir():
                    cases.append((f"pv__{sub.name}", sub))
            continue
        cases.append((entry.name, entry))
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
    ids=[c[0] for c in _CASES],
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
