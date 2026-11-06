"""Tests for the synthetic release-demo case generator.

Small and fast: every test generates the case at ``--size-mb 1`` into a
``tmp_path`` and drives the app's own loaders/validators directly (no TUI).

Dependencies:
    - ``tools/synth/make_release_case.py`` (imported via ``sys.path``)
    - the app's parser/validation layer (``s19_app``)
"""

from __future__ import annotations

import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
SEED = 20260001
SIZE_MB = 1.0

if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

from s19_app.core import S19File  # noqa: E402
from s19_app.hexfile import IntelHexFile  # noqa: E402
from s19_app.tui.a2l_extract import enrich_a2l_tags_with_values  # noqa: E402
from s19_app.tui.a2l_parse import parse_a2l_file  # noqa: E402
from s19_app.tui.a2l_validate import (  # noqa: E402
    validate_a2l_internal_issues,
    validate_a2l_tags,
)
from s19_app.tui.changes.check import run_check_document  # noqa: E402
from s19_app.tui.changes.io import parse_change_document  # noqa: E402
from s19_app.tui.mac import parse_mac_file  # noqa: E402
from s19_app.validation import validate_artifact_consistency  # noqa: E402

GENERATED_FILES = [
    "firmware.s19",
    "firmware.hex",
    "firmware_v2.s19",
    "firmware.a2l",
    "firmware.mac",
    "demo_patch.changes.json",
    "demo_check.chk.json",
    "demo_check_fails.chk.json",
    "firmware_issues.a2l",
    "firmware_issues.mac",
    "README.txt",
]


def _generate(case_dir: Path) -> dict[str, Path]:
    return gen.generate(case_dir, SEED, SIZE_MB)


def _load_clean(case_dir: Path):
    """Drive the app's loaders over the clean artifacts, return the snapshot."""
    s19 = S19File(str(case_dir / "firmware.s19"))
    mem = s19.get_memory_map()
    ranges = s19.get_memory_ranges()
    overlap = s19.get_overlap_addresses()
    a2l = parse_a2l_file(case_dir / "firmware.a2l")
    checks = validate_a2l_tags(enrich_a2l_tags_with_values(a2l, mem), mem)
    mac = parse_mac_file(case_dir / "firmware.mac")
    return s19, mem, ranges, overlap, a2l, checks, mac


@pytest.fixture(scope="module")
def case_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("synth_case")
    _generate(d)
    return d


def test_determinism(tmp_path: Path) -> None:
    """Same seed -> byte-identical files (including the new fault/check files)."""
    a = tmp_path / "run_a"
    b = tmp_path / "run_b"
    _generate(a)
    _generate(b)
    for name in GENERATED_FILES:
        assert (a / name).read_bytes() == (b / name).read_bytes(), name


def test_s19_loads_clean(case_dir: Path) -> None:
    """firmware.s19 re-parses through the app loader with zero issues."""
    s19 = S19File(str(case_dir / "firmware.s19"))
    assert s19.get_errors() == []
    assert s19.validate_all()
    assert s19.get_overlap_addresses() == []
    assert s19.get_out_of_order_records() == []
    assert s19.get_memory_map()


def test_hex_equals_s19(case_dir: Path) -> None:
    """firmware.hex is the same image as firmware.s19 (identical pair)."""
    s19 = S19File(str(case_dir / "firmware.s19"))
    hex_file = IntelHexFile(str(case_dir / "firmware.hex"))
    assert hex_file.get_errors() == []
    assert s19.get_memory_map() == hex_file.memory


def test_a2l_zero_issues(case_dir: Path) -> None:
    """A2L parses and validates with zero issues through the app's functions."""
    s19, mem, _ranges, _overlap, a2l, checks, _mac = _load_clean(case_dir)

    assert a2l["errors"] == []
    tags = a2l["tags"]
    assert sum(1 for t in tags if t["section"] == "CHARACTERISTIC") >= 300
    assert sum(1 for t in tags if t["section"] == "MEASUREMENT") >= 100

    assert all(t["schema_ok"] for t in checks)
    assert all(t["in_memory"] for t in checks if t["memory_checked"])
    assert not any(t.get("decode_error") for t in checks)
    assert not any(t.get("value_outside_limits") for t in checks)

    # Batch-101 Inc 11 (R-VAL-032.2): MOD_COMMON / MOD_PAR / AXIS_DESCR are ASAM
    # block names, so the clean demo's A2L raises no issue at all (base: 102
    # A2L_UNRECOGNIZED_BLOCK). `== []` replaces the former "all unrecognized"
    # assertion, which would pass vacuously on an empty list.
    issues = validate_a2l_internal_issues(a2l, tag_checks=checks)
    assert issues == [], [(issue.code, issue.message) for issue in issues[:5]]


def test_tab_verb_and_object_census(case_dir: Path) -> None:
    """COMPU_VTAB/TAB_VERB is decoded, and the array census is met in-image."""
    a2l = parse_a2l_file(case_dir / "firmware.a2l")

    # The app's table extractor reads COMPU_VTAB and records TAB_VERB as the
    # table kind; TAB_NOINTP / TAB_INTP COMPU_METHODs reference the tables.
    tabs = a2l["compu_tabs_by_name"]
    assert tabs["TBL_NOINTP"]["section"] == "COMPU_VTAB"
    assert tabs["TBL_NOINTP"]["kind"] == "TAB_VERB"
    methods = a2l["compu_methods_by_name"]
    assert methods["CM_TAB_NOINTP"]["conversion_type"] == "TAB_NOINTP"
    assert methods["CM_TAB_NOINTP"]["compu_tab_ref"] == "TBL_NOINTP"
    assert methods["CM_TAB_INTP"]["conversion_type"] == "TAB_INTP"
    assert methods["CM_TAB_INTP"]["compu_tab_ref"] == "TBL_INTP"

    kinds = Counter(
        t.get("char_type") for t in a2l["tags"] if t["section"] == "CHARACTERISTIC"
    )
    assert kinds["CURVE"] >= 10
    assert kinds["MAP"] >= 10
    assert kinds["VAL_BLK"] >= 5
    assert kinds["ASCII"] >= 2
    # Every CURVE/MAP carries an inline AXIS_DESCR and a derived byte span.
    for tag in a2l["tags"]:
        if tag.get("char_type") in ("CURVE", "MAP"):
            assert tag["axis_meta"], tag["name"]
            assert tag["length"] is not None, tag["name"]


def test_addresses_inside_image(case_dir: Path) -> None:
    """Every A2L span and every MAC address lies inside the image."""
    s19, mem, _ranges, _overlap, a2l, _checks, mac = _load_clean(case_dir)

    a2l_names = {t["name"] for t in a2l["tags"]}
    for tag in a2l["tags"]:
        addr = tag["address"]
        assert addr is not None, tag["name"]
        length = tag["length"]
        assert length is not None, tag["name"]
        assert all(addr + off in mem for off in range(length)), tag["name"]

    assert mac["diagnostics"] == []
    assert len(mac["records"]) == gen.MAC_LINE_COUNT
    for record in mac["records"]:
        assert record["parse_ok"]
        assert record["name"] in a2l_names
        assert record["address"] in mem


def test_v2_differs_only_where_intended(case_dir: Path) -> None:
    """firmware_v2.s19 differs only in the changed window + the extension."""
    v1 = S19File(str(case_dir / "firmware.s19")).get_memory_map()
    v2 = S19File(str(case_dir / "firmware_v2.s19")).get_memory_map()
    assert not S19File(str(case_dir / "firmware_v2.s19")).get_errors()

    only_v2 = set(v2) - set(v1)
    only_v1 = set(v1) - set(v2)
    changed = {a for a in set(v1) & set(v2) if v1[a] != v2[a]}

    regions = gen.compute_region_sizes(SIZE_MB)
    window_start, window_len = gen.compute_change_window(regions)
    extension_start, extension_len = gen.compute_extension(regions)

    assert only_v1 == set()
    assert only_v2 == set(range(extension_start, extension_start + extension_len))
    assert changed == set(range(window_start, window_start + window_len))


def test_change_documents_parse_clean(case_dir: Path) -> None:
    """The v2 change/check documents parse with zero issues; symbols resolve."""
    a2l = parse_a2l_file(case_dir / "firmware.a2l")
    change = parse_change_document(
        (case_dir / "demo_patch.changes.json").read_text(encoding="utf-8"),
        a2l_context=a2l,
    )
    check = parse_change_document(
        (case_dir / "demo_check.chk.json").read_text(encoding="utf-8"),
        a2l_context=a2l,
    )
    assert change.issues == []
    assert check.issues == []
    assert change.kind == "change"
    assert check.kind == "check"
    assert len(change.entries) == 7
    assert len(check.entries) == 3

    # Every entry kind the reader accepts is covered: bytes, string, and the
    # bytes+symbol (physical value by A2L tag name) form.
    assert {e.entry_type for e in change.entries} == {"bytes", "string"}
    symbols = [e.symbol for e in change.entries if e.symbol]
    assert len(symbols) == 2
    assert all(symbols)

    # All 7 patch entries address bytes inside the clean image.
    s19 = S19File(str(case_dir / "firmware.s19"))
    mem = s19.get_memory_map()
    for entry in change.entries:
        start, end = entry.addressed_range
        assert all(addr in mem for addr in range(start, end))


def test_check_documents_pass_and_fail(case_dir: Path) -> None:
    """demo_check passes every kind; demo_check_fails fails every kind."""
    _s19, mem, ranges, _overlap, a2l, checks, mac = _load_clean(case_dir)

    ok = parse_change_document(
        (case_dir / "demo_check.chk.json").read_text(encoding="utf-8"),
        a2l_context=a2l,
    )
    assert ok.issues == []
    ok_result = run_check_document(ok, mem, ranges, mac["records"], checks)
    assert ok_result.aggregates == {"passed": 3, "failed": 0, "uncheckable": 0}

    bad = parse_change_document(
        (case_dir / "demo_check_fails.chk.json").read_text(encoding="utf-8"),
        a2l_context=a2l,
    )
    assert bad.issues == []
    bad_result = run_check_document(bad, mem, ranges, mac["records"], checks)
    assert bad_result.aggregates == {"passed": 0, "failed": 3, "uncheckable": 0}


def test_a2l_issues_reported(case_dir: Path) -> None:
    """Each injected A2L fault is reported by the app's own validators."""
    _s19, mem, ranges, overlap, _a2l, _checks, mac = _load_clean(case_dir)
    ia2l = parse_a2l_file(case_dir / "firmware_issues.a2l")
    assert ia2l["errors"] == []

    ichecks = validate_a2l_tags(enrich_a2l_tags_with_values(ia2l, mem), mem)
    internal = Counter(
        i.code for i in validate_a2l_internal_issues(ia2l, tag_checks=ichecks)
    )
    # 1 duplicate symbol.
    assert internal["A2L_DUPLICATE_SYMBOL"] == 1

    report = validate_artifact_consistency(mac["records"], ichecks, ia2l, ranges, overlap)
    cross = Counter(i.code for i in report.issues)
    # 3 addresses outside the image + 2 spans crossing a region end.
    assert cross["CROSS_A2L_S19_OUT_OF_RANGE"] == 5

    by_name = {c["name"]: c for c in ichecks}
    for name in ("OUT_OF_RANGE_1", "OUT_OF_RANGE_2", "OUT_OF_RANGE_3",
                 "SPAN_OVER_1", "SPAN_OVER_2"):
        assert by_name[name]["in_memory"] is False, name
        assert by_name[name]["reason"] == "characteristic address not in S19", name
    # 1 missing COMPU_METHOD -> identity fallback, "compu method missing".
    assert by_name["MISSING_CM"]["conversion_status"] == "identity_fallback"
    assert by_name["MISSING_CM"]["conversion_error"] == "compu method missing"
    # 1 value outside its limits.
    assert by_name["LIMIT_BREAKER"]["value_outside_limits"] is True
    assert by_name["LIMIT_BREAKER"]["reason"] == "value outside limits"


def test_mac_issues_reported(case_dir: Path) -> None:
    """Each injected MAC fault is reported by the app's own validators."""
    _s19, _mem, ranges, overlap, a2l, checks, _mac = _load_clean(case_dir)
    imac = parse_mac_file(case_dir / "firmware_issues.mac")

    # 1 bad hex value + 1 line with no '=' are line-level parse diagnostics.
    assert len(imac["diagnostics"]) == 2
    assert any("invalid hex address" in d for d in imac["diagnostics"])
    assert any("expected one '=' separator" in d for d in imac["diagnostics"])

    report = validate_artifact_consistency(imac["records"], checks, a2l, ranges, overlap)
    codes = Counter(i.code for i in report.issues)
    assert codes["MAC_PARSE_ERROR"] == 2
    # 1 duplicate name (and its duplicate-address hard-conflict group).
    assert codes["MAC_DUPLICATE_NAME"] == 1
    assert codes["MAC_DUPLICATE_ADDRESS"] == 1
    # 3 addresses outside the image (each also a triple name/address mismatch).
    assert codes["CROSS_MAC_S19_OUT_OF_RANGE"] == 3
    assert codes["TRIPLE_NAME_ADDRESS_MISMATCH"] == 3
    # 3 names absent from the A2L.
    assert codes["CROSS_MAC_ONLY_SYMBOL"] == 3


def test_cli_entry_point(tmp_path: Path) -> None:
    """The console script runs end to end and writes the case."""
    out = tmp_path / "cli_case"
    result = subprocess.run(
        [
            sys.executable,
            str(SYNTH_DIR / "make_release_case.py"),
            "--out", str(out),
            "--seed", str(SEED),
            "--size-mb", "1",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr
    for name in GENERATED_FILES:
        assert (out / name).exists(), name
