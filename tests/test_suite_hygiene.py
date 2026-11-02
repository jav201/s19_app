"""Batch-101 Inc 2 — suite hygiene guard host (independent tester, stage E4).

One guard host for the increment's test-hygiene requirements (orchestrator
ruling O-1, addendum E3A-9 of the increment's E3 rulings).  The guard reads
only the approved design: ``.dev-flow/2026-11-01-batch-101/inc-2/01-requirements.md``
(48 rows), ``02-test-cases.md`` (81 cases), ``codewire/graph-inc2.md``
(interfaces I-1 .. I-9) and ``E3-rulings.md`` (round 1/2 rulings and the E4
addenda).  Nothing in this file imports code that the census scans; planted
sources are strings or files under ``tmp_path``; census functions of
``tests/support/suite_census.py`` are run on those strings and on the real
tree; the margin-property and summary cases run inner sessions through
``pytester.runpytest_subprocess``.

Rows guarded here: R-TST-001 .. 007, 010 .. 013, 015 .. 018, 020 .. 025,
030 .. 032 (static part), 040 .. 042, 043 .. 046, 050 .. 051, 080 .. 082,
plus the accepted E4 addenda E3S-1 (parallel lane prints no QC-TM text),
E3S-2 (committed-evidence redaction gate) and E3S-6 (workflow read as text
with the injection/trigger ratchet).  The gate-run, CI-run and E5-measured
cases (R-TST-008, 009, 014, 018/2, 023/2, 070 .. 072, 090, 091 and the
3-of-3 lane arms of R-TST-031/032) are not pytest nodes; they are owed to
the gate and CI evidence and are listed in the E4 tester notes.

On the base tree (main, before any Inc 2 code) every test in this module
fails for a behavioural reason: the census module of the guard
(``tests/support/suite_census.py``) does not exist, the new wait and margin
helpers of ``tests/support/timing.py`` do not exist, the shared waits accept
no ``timeout``, the marker, the conventions sentences, the workflow lanes
and the golden tokens are absent.  Evidence: ``.dev-flow/2026-11-01-batch-101/
evidence/inc-2/red-01-tester-base.txt``.
"""
from __future__ import annotations

import ast
import asyncio
import inspect
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as etree
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_ROOT = REPO_ROOT / "tests"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "tui-ci.yml"
CONVENTIONS_PATH = REPO_ROOT / "docs" / "engineering-rules.md"
EVIDENCE_ROOT = REPO_ROOT / ".dev-flow" / "2026-11-01-batch-101" / "evidence"

MARKER_LINE = (
    "@pytest.mark.serial_timing: serial_timing: a wall-clock timing arm; "
    "run apart and serially (-m serial_timing)"
)

PR_LANE_1 = 'pytest -v -rs -n auto --dist loadfile -m "not slow and not serial_timing"'
PR_LANE_2 = 'pytest -q -rs -m "serial_timing and not slow"'
PUSH_LANE_1 = 'pytest -v -rs -n auto --dist loadfile -m "not serial_timing"'
PUSH_LANE_2 = "pytest -q -rs -m serial_timing"

LANE_2_IF_PR = (
    "github.event_name == 'pull_request' && !cancelled() "
    "&& steps.install.outcome == 'success'"
)
LANE_2_IF_PUSH = (
    "github.event_name == 'push' && !cancelled() "
    "&& steps.install.outcome == 'success'"
)

XDIST_INSTALL_LINE = 'python -m pip install "pytest-xdist==3.8.0"'

CONVENTIONS_SECTION_TITLE = "Test timing, waits and oracles (batch-101 Inc 2)"

_CONVENTION_RULES = {
    "R-TST-030": (
        "An arm that checks the state a key press leaves while a real worker "
        "runs holds the worker at a forced slow step or records the state at "
        "the product hook; it never samples after the press."
    ),
    "R-TST-047": (
        "A timing arm stops its clock at a stamp the product emits (a commit "
        "handler, a painted line, an install callback), never when a poll "
        "notices."
    ),
    "R-TST-048": (
        "A margin under 20 % in the serial lane's QC-TM section is a gate "
        "finding; the finding gives the base tree's time beside it."
    ),
    "R-TST-052": (
        "A test that waits on a painted outcome collects the lines painted "
        "since its trigger (StatusLog.since(mark)) and asserts the one it "
        "needs; it never waits on the newest line alone."
    ),
    "R-TST-060": (
        "When an increment changes the order or the source of an observable, "
        "its gate greps tests/ for every node that asserts that observable "
        "and runs them, whatever module they sit in."
    ),
}

# The 31 static timing arms of the slice table (section 3), base set.
_BASE_STATIC_ARMS = frozenset(
    [
        "tests/test_a2l_alignment_sizing.py::test_at120_oversized_alignment_layout_clamps_to_none",
        "tests/test_a2l_alignment_sizing.py::test_tc149_dos_clamp_includes_padding",
        "tests/test_a2l_inline_axis_length.py::test_tc138_dos_clamp_pure_arithmetic",
        "tests/test_a2l_inline_axis_length.py::test_at111_oversized_axis_clamps_to_none",
        "tests/test_a2l_multiline_headers.py::test_at101_megabyte_unterminated_block_is_linear",
        "tests/test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second",
        "tests/test_b100_document.py::test_tc_b100_28_document_finding_is_kept_first_beside_a_full_batch",
        "tests/test_b100_document.py::test_tc_b100_30_classifier_outcome",
        "tests/test_b100_document.py::test_tc_b100_30_hostile_document_is_one_not_readable_under_one_second",
        "tests/test_b100_project_check.py::test_tc_b100_24_one_entry_over_the_cap_is_one_issue_fast",
        "tests/test_b100_project_check.py::test_tc_b100_24_assignments_75_by_1000_is_one_issue_fast",
        "tests/test_b100_project_check.py::test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second",
        "tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_each_name_is_checked_once_per_read",
        "tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_parent",
        "tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_entries_under_an_existing_folder_are_all_checked",
        "tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folder_ceiling",
        "tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_junction_loop_costs_one_failure",
        "tests/test_b100_project_check.py::test_tc_b100_61_r2_2_legitimate_manifest_inside_every_cap_is_checked_whole",
        "tests/test_b100_project_check.py::test_tc_b100_61_sec7_r2_2_one_serialize_checks_each_name_once",
        "tests/test_b100_project_check.py::test_tc_b100_61_files_at_the_cap_all_missing_are_bounded",
        "tests/test_b100_project_homes.py::test_tc_b100_31_junction_cycle_ends",
        "tests/test_b100_project_homes.py::test_tc_b100_31_entry_ceiling",
        "tests/test_b100_save_dialog.py::test_tc_b100_65_recompute_is_a_150ms_debounce",
        "tests/test_b100_save_dialog.py::test_tc_b100_65_session_decided_once_per_open_case06",
        "tests/test_b100_save_dialog.py::test_tc_b100_65_recompute_at_most_three_of_twenty_keystrokes",
        "tests/test_b100_save_dialog.py::test_tc_b100_65_emitting_4mib_image_recomputes_fast",
        "tests/test_b100_save_guards.py::test_tc_b100_05_merge_keeps_a_too_large_document_under_one_second",
        "tests/test_compare_engine.py::test_large_image_perf",
        "tests/test_tui_app.py::test_build_mac_view_cache_scales_under_load",
        "tests/test_tui_app.py::test_end_to_end_load_pipeline_under_budget",
        "tests/test_tui_app.py::test_stress_load_s19_then_a2l_then_mac",
    ]
)

_SAMPLED_PIN = frozenset(
    ["tests/test_b100_busy.py::test_at_b100_17_worker_load_of_an_8_mib_s19_by_keys"]
)

# The 7 report goldens that record the tool version (Definitions).
_GOLDENS_WITH_VERSION = [
    "tests/goldens/batch35/at054b-before-after-report.md",
    "tests/goldens/batch35/at054b-before-after-report.html",
    "tests/goldens/batch35/at055b-project-report.md",
    "tests/goldens/batch64/addendum-below-bound.md",
    "tests/goldens/batch74/producer-bound-positive-control.md",
    "tests/goldens/batch76/document-bound-preflight.md",
    "tests/goldens/batch99/at288-pre-move-report.bin",
]

# Sites a coarse taint would reach but the position/key-aware taint must not
# count as upper timing bounds (E3A-3).
_NOT_UPPER_BOUND_SITES = [
    "tests/test_b100_project_check.py:843",
    "tests/test_b100_project_check.py:981",
    "tests/test_b100_save_dialog.py:2331",
    "tests/test_b100_save_dialog.py:3493",
]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _norm_census_file_key(file_part: str) -> str:
    file_part = file_part.replace("\\", "/")
    root = str(REPO_ROOT).replace("\\", "/")
    if file_part.startswith(root + "/"):
        file_part = file_part[len(root) + 1 :]
    if file_part.startswith("./"):
        file_part = file_part[2:]
    if not file_part.startswith("tests/"):
        file_part = "tests/" + file_part
    return file_part


def _norm_arm_key(key: str) -> str:
    key = key.replace("\\", "/")
    file_part, sep, rest = key.partition("::")
    if not sep:
        return _norm_census_file_key(file_part)
    return f"{_norm_census_file_key(file_part)}::{rest}"


def _norm_site(site: str) -> str:
    file_part, sep, line = site.rpartition(":")
    if not sep:
        return site
    return f"{_norm_census_file_key(file_part)}:{line}"


def _has_serial_timing_mark(decorators, source: str) -> bool:
    for deco in decorators:
        node = deco.func if isinstance(deco, ast.Call) else deco
        if isinstance(node, ast.Attribute) and node.attr == "serial_timing":
            return True
    return False


def _pytestmark_refusals(body, source: str, where: str, refusals: list) -> None:
    for node in body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "pytestmark":
                segment = ast.get_source_segment(source, node) or ""
                if "serial_timing" in segment:
                    refusals.append(
                        f"{where} pytestmark carries serial_timing (refused): "
                        f"{segment.strip()[:80]}"
                    )


def _marked_set(tests_root: Path):
    """The marked set (E3A-16): marks read from the tests' own decorators.

    A module- or class-level ``pytestmark`` carrying the marker is refused
    and reported; it is never read as a mark.
    """
    marked = []
    refusals = []
    for path in sorted(tests_root.rglob("test_*.py")):
        rel = "tests/" + path.relative_to(tests_root).as_posix()
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        _pytestmark_refusals(tree.body, source, f"module {rel}", refusals)
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                if _has_serial_timing_mark(node.decorator_list, source):
                    marked.append(f"{rel}::{node.name}")
            elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                _pytestmark_refusals(
                    node.body, source, f"class {rel}::{node.name}", refusals
                )
                for item in node.body:
                    if (
                        isinstance(item, ast.FunctionDef)
                        and item.name.startswith("test_")
                        and _has_serial_timing_mark(item.decorator_list, source)
                    ):
                        marked.append(f"{rel}::{node.name}::{item.name}")
    return set(marked), refusals


def _marker_guard_lines(arms, sampled, marked) -> list:
    lines = []
    for nodeid in sorted((set(arms) | set(sampled)) - set(marked)):
        lines.append(f"timing arm without serial_timing: {nodeid}")
    for nodeid in sorted(set(marked) - set(arms) - set(sampled)):
        lines.append(f"serial_timing on a test that is not a timing arm: {nodeid}")
    return lines


def _unreported_sites(root: Path) -> list:
    from tests.support import suite_census

    try:
        return list(suite_census.unreported_upper_bounds(root))
    except TypeError:
        return list(suite_census.unreported_upper_bounds(root, suite_census.timing_arms(root)))


def _function_source(text: str, name: str) -> str:
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            segment = ast.get_source_segment(text, node)
            if segment is None:
                break
            return segment
    raise AssertionError(f"function {name} not found")


class _FakePilot:
    """Test double: ``pause`` returns at once and counts; ``press`` records."""

    def __init__(self) -> None:
        self.pauses = 0
        self.pressed: list = []

    async def pause(self, delay=None) -> None:
        self.pauses += 1

    async def press(self, key: str) -> None:
        self.pressed.append(key)


class _EmptyScreen:
    def query(self, selector):
        return []


class _StickyScreen:
    class _Widget:
        pass

    def query(self, selector):
        return [_StickyScreen._Widget()]


class _App:
    def __init__(self, screen) -> None:
        self.screen = screen


# ---------------------------------------------------------------------------
# R-TST-001 — the marker registration
# ---------------------------------------------------------------------------


def test_r_tst_001_serial_timing_marker_is_registered() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--markers", "-p", "no:cacheprovider"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    lines = [line.strip() for line in proc.stdout.splitlines()]
    assert MARKER_LINE in lines


# ---------------------------------------------------------------------------
# R-TST-002 (with R-TST-005/5) — every timing arm carries the marker
# ---------------------------------------------------------------------------


def test_r_tst_002_every_timing_arm_carries_serial_timing() -> None:
    from tests.support import suite_census

    assert set(suite_census.SAMPLED_TIMING_ARMS) == _SAMPLED_PIN
    arms = {_norm_arm_key(key) for key in suite_census.timing_arms(TESTS_ROOT)}
    lost = sorted(_BASE_STATIC_ARMS - arms)
    assert not lost, f"census lost base timing arms: {lost}"
    marked, refusals = _marked_set(TESTS_ROOT)
    assert not refusals, "\n".join(refusals)
    arm_set = arms | set(suite_census.SAMPLED_TIMING_ARMS)
    guard_lines = _marker_guard_lines(arm_set, set(), marked)
    assert not guard_lines, "\n".join(guard_lines)


def test_r_tst_002_2_parallel_lane_collection_prints_no_qc_tm_text() -> None:
    """E3S-1 guard case: collecting the parallel lane prints no QC-TM text."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-m",
            "not serial_timing",
            "-p",
            "no:cacheprovider",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=900,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output[-2000:]
    assert "QC-TM" not in output
    assert "Unknown pytest.mark.serial_timing" not in output


# ---------------------------------------------------------------------------
# R-TST-003 / R-TST-004 — the marker guard names both violation kinds
# ---------------------------------------------------------------------------

_PLANTED_UNMARKED_ARM = """import time


def test_x():
    t = time.perf_counter()
    work()
    assert time.perf_counter() - t < 1.0
"""

_PLANTED_MARKED_NON_ARM = """import pytest


@pytest.mark.serial_timing
def test_y():
    assert 1 + 1 == 2
"""


def test_r_tst_003_an_unmarked_timing_arm_is_named(tmp_path) -> None:
    from tests.support import suite_census

    planted = tmp_path / "test_unmarked_arm.py"
    planted.write_text(_PLANTED_UNMARKED_ARM, encoding="utf-8")
    arms = suite_census.timing_arms(tmp_path)
    keys = [key for key in arms if key.endswith("::test_x")]
    assert len(keys) == 1, f"planted arm not detected exactly once: {arms}"
    assert len(arms) == 1, f"unexpected extra arms: {arms}"
    marked, refusals = _marked_set(tmp_path)
    assert not refusals
    guard_lines = _marker_guard_lines(set(arms), set(), marked)
    assert guard_lines == [f"timing arm without serial_timing: {keys[0]}"]


def test_r_tst_004_a_marked_non_arm_is_named(tmp_path) -> None:
    from tests.support import suite_census

    planted = tmp_path / "test_marked_non_arm.py"
    planted.write_text(_PLANTED_MARKED_NON_ARM, encoding="utf-8")
    arms = suite_census.timing_arms(tmp_path)
    assert arms == {}, f"non-arm reported as arm: {arms}"
    marked, refusals = _marked_set(tmp_path)
    assert not refusals
    guard_lines = _marker_guard_lines(set(arms), set(), marked)
    keys = sorted(marked)
    assert len(keys) == 1
    assert guard_lines == [
        f"serial_timing on a test that is not a timing arm: {keys[0]}"
    ]


# ---------------------------------------------------------------------------
# R-TST-005 — the detector finds each planted timing-arm form
# ---------------------------------------------------------------------------

_FORM_SOURCES = {
    "form1": (
        "interval computed in the test",
        """import time


def test_a():
    start = time.perf_counter()
    f()
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0
""",
    ),
    "form2": (
        "interval asserted in a same-module helper",
        """from tests.support.timing import timing_bound


def _check(s):
    assert s["read"] < timing_bound(1.0)


def test_b():
    _check(scene())
""",
    ),
    "form3": (
        "interval returned by a nested function",
        """import time


def test_c():
    async def _s():
        msgs = []
        return msgs, time.perf_counter() - start

    msgs, elapsed = run_app(base, _s)
    assert elapsed < 5.0
""",
    ),
    "form4": (
        "a timing_bound operand",
        """from tests.support import timing
from tests.support.timing import timing_bound


def test_d():
    took = timing.probe()
    assert took < timing_bound(1.0)
""",
    ),
    "form5": (
        "hook-recorded stamp list",
        """import time


def test_e():
    stamps = []
    start = time.perf_counter()

    def wrapper():
        stamps.append(time.perf_counter())

    wrapper()
    took = stamps[0] - start
    assert took < 1.0
""",
    ),
    "form6": (
        "wrapped bound, interval from another module",
        None,  # written together with a planted support module
    ),
    "form7": (
        "clock under an import alias",
        """import time as _time


def test_g():
    t = _time.perf_counter()
    f()
    assert _time.perf_counter() - t < 2.0
""",
    ),
}

_FORM6_SUPPORT = """import time


def measure():
    start = time.perf_counter()
    return time.perf_counter() - start
"""

_FORM6_TEST = """import measure_mod
from tests.support.timing import report_margin
from tests.support.timing import timing_bound


def test_f():
    elapsed = measure_mod.measure()
    assert elapsed < report_margin("l", elapsed, timing_bound(1.0))
"""


@pytest.mark.parametrize(
    "form", ["form1", "form2", "form3", "form4", "form5", "form6", "form7"]
)
def test_r_tst_005_detector_finds_each_timing_arm_form(tmp_path, form) -> None:
    from tests.support import suite_census

    if form == "form6":
        (tmp_path / "measure_mod.py").write_text(_FORM6_SUPPORT, encoding="utf-8")
        (tmp_path / "test_form6.py").write_text(_FORM6_TEST, encoding="utf-8")
        test_name = "test_f"
    else:
        _, source = _FORM_SOURCES[form]
        (tmp_path / f"test_{form}.py").write_text(source, encoding="utf-8")
        test_name = {
            "form1": "test_a",
            "form2": "test_b",
            "form3": "test_c",
            "form4": "test_d",
            "form5": "test_e",
            "form7": "test_g",
        }[form]
    arms = suite_census.timing_arms(tmp_path)
    found = [key for key in arms if key.endswith(f"::{test_name}")]
    assert len(found) == 1, (
        f"{form} ({_FORM_SOURCES[form][0]}): planted arm not detected exactly "
        f"once in {arms}"
    )
    assert len(arms) == 1, f"{form}: unexpected extra arms: {arms}"


# ---------------------------------------------------------------------------
# R-TST-006 — intervals no ordering assert reads are not arms
# ---------------------------------------------------------------------------


def test_r_tst_006_detector_ignores_intervals_no_assert_reads() -> None:
    from tests.support import suite_census

    arms = {_norm_arm_key(key) for key in suite_census.timing_arms(TESTS_ROOT)}
    assert not [
        node for node in arms if node.startswith("tests/test_sync_evidence.py::")
    ], "clock intervals used as file times must not be timing arms"
    assert (
        "tests/test_b100_project_homes.py::test_tc_b100_31_copy_ceiling_2000_files"
        not in arms
    ), "a test that only prints its interval is not a timing arm"
    assert (
        "tests/test_b100_document.py::test_tc_b100_30_reopen_lists_the_recorded_document"
        not in arms
    ), "tuple-unpacking tests asserting no interval are not timing arms"
    assert (
        "tests/test_b100_document.py::test_tc_b100_30_hostile_document_is_one_not_readable_under_one_second"
        in arms
    )


# ---------------------------------------------------------------------------
# R-TST-007, 030, 047, 048, 052, 060 — the conventions sentences verbatim
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule_id", ["R-TST-007", "R-TST-030", "R-TST-047", "R-TST-048", "R-TST-052", "R-TST-060"]
)
def test_r_tst_007_conventions_hold_each_test_rule(rule_id) -> None:
    text = CONVENTIONS_PATH.read_text(encoding="utf-8")
    if rule_id == "R-TST-007":
        assert CONVENTIONS_SECTION_TITLE in text
        section = text.split(CONVENTIONS_SECTION_TITLE, 1)[1]
        section = section.split("\n#", 1)[0]
        parallel = 'pytest -n 8 -m "not serial_timing"'
        serial = "pytest -m serial_timing"
        assert parallel in section, "release gate parallel lane missing"
        assert serial in section, "release gate serial lane missing"
        assert section.index(parallel) < section.index(serial), "lanes out of order"
        assert "LAN Linux host" in section
    else:
        assert _CONVENTION_RULES[rule_id] in text, (
            f"{rule_id} sentence missing or edited in {CONVENTIONS_PATH.name}"
        )


# ---------------------------------------------------------------------------
# R-TST-010 .. 018 — the CI workflow, read as text (E3S-6 ratchet included)
# ---------------------------------------------------------------------------


def _workflow_jobs(text: str) -> dict:
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "jobs:")
    jobs = {}
    current = None
    for line in lines[start + 1 :]:
        if (
            line.startswith("  ")
            and not line.startswith("    ")
            and line.rstrip().endswith(":")
        ):
            current = line.strip()[:-1]
            jobs[current] = []
        elif current is not None:
            jobs[current].append(line)
    return jobs


def _job_steps(job_lines) -> list:
    steps = []
    current = None
    in_steps = False
    for line in job_lines:
        if line.strip() == "steps:" and line.startswith("    "):
            in_steps = True
            continue
        if not in_steps:
            continue
        if line.startswith("      - "):
            current = [line]
            steps.append(current)
        elif current is not None and (line.startswith("        ") or not line.strip()):
            current.append(line)
        elif current is not None:
            break
    return steps


def _step_value(step, field: str):
    prefix = field + ":"
    for line in step:
        stripped = line.strip()
        if stripped.startswith("- "):
            stripped = stripped[2:].strip()
        if stripped.startswith(prefix):
            return stripped.split(":", 1)[1].strip()
    return None


def _step_run(step):
    for i, line in enumerate(step):
        stripped = line.strip()
        if stripped.startswith("- "):
            stripped = stripped[2:].strip()
        if stripped.startswith("run:"):
            rest = stripped[4:].strip()
            if rest not in ("|", ">"):
                return rest
            block = []
            for more in step[i + 1 :]:
                if more.startswith("          "):
                    block.append(more.strip())
                elif not more.strip():
                    continue
                else:
                    break
            return "\n".join(block)
    return None


def _lane_steps(steps, marker: str) -> list:
    picked = [
        step
        for step in steps
        if (_step_value(step, "if") or "").startswith(
            f"github.event_name == '{marker}'"
        )
    ]
    return [step for step in picked if _step_run(step)]


def _assert_no_script_injection(steps) -> None:
    for step in steps:
        run = _step_run(step)
        if not run:
            continue
        assert "${{ github.event." not in run, f"event interpolation in a run line: {run}"
        assert "${{ github.head_ref" not in run, f"head_ref interpolation in a run line: {run}"


def _assert_no_unsafe_triggers(text: str) -> None:
    on_block = text.split("jobs:", 1)[0]
    assert "pull_request_target" not in on_block
    assert "workflow_run" not in on_block


def test_r_tst_010_pull_request_runs_two_lanes() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    jobs = _workflow_jobs(text)
    steps = _job_steps(jobs["tui-ci"])
    runs = [_step_run(step) for step in _lane_steps(steps, "pull_request")]
    assert runs == [PR_LANE_1, PR_LANE_2]
    _assert_no_script_injection(steps)
    _assert_no_unsafe_triggers(text)


def test_r_tst_011_push_runs_two_lanes() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    jobs = _workflow_jobs(text)
    steps = _job_steps(jobs["tui-ci"])
    runs = [_step_run(step) for step in _lane_steps(steps, "push")]
    assert runs == [PUSH_LANE_1, PUSH_LANE_2]
    _assert_no_script_injection(steps)


def test_r_tst_012_serial_lane_runs_after_a_red_lane() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    jobs = _workflow_jobs(text)
    steps = _job_steps(jobs["tui-ci"])
    by_run = {}
    for step in steps:
        run = _step_run(step)
        if run:
            by_run[run] = step
    lane2_ifs = [
        _step_value(by_run[command], "if") for command in (PR_LANE_2, PUSH_LANE_2)
    ]
    assert set(lane2_ifs) == {LANE_2_IF_PR, LANE_2_IF_PUSH}, lane2_ifs


def test_r_tst_013_014_ci_checks_out_full_history() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    jobs = _workflow_jobs(text)
    assert "snapshot" in jobs, "snapshot job must stay present"
    tui_steps = _job_steps(jobs["tui-ci"])
    checkouts = [
        step
        for step in tui_steps
        if (_step_value(step, "uses") or "").startswith("actions/checkout@")
    ]
    assert len(checkouts) == 1
    checkout_lines = "\n".join(checkouts[0])
    assert "fetch-depth: 0" in checkout_lines
    assert "persist-credentials: false" in checkout_lines  # E3S-3
    snap_steps = _job_steps(jobs["snapshot"])
    snap_checkouts = [
        step
        for step in snap_steps
        if (_step_value(step, "uses") or "").startswith("actions/checkout@")
    ]
    assert len(snap_checkouts) == 1
    assert "persist-credentials: false" in "\n".join(snap_checkouts[0])  # E3S-3


def test_r_tst_015_016_017_ci_time_limits() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    jobs = _workflow_jobs(text)
    tui_lines = jobs["tui-ci"]
    steps = _job_steps(tui_lines)
    by_run = {}
    for step in steps:
        run = _step_run(step)
        if run:
            by_run[run] = step
    for command in (PR_LANE_1, PR_LANE_2, PUSH_LANE_1, PUSH_LANE_2):
        assert command in by_run, f"missing lane step: {command}"
    assert _step_value(by_run[PUSH_LANE_1], "timeout-minutes") == "180"
    assert _step_value(by_run[PR_LANE_1], "timeout-minutes") == "120"
    assert _step_value(by_run[PUSH_LANE_2], "timeout-minutes") == "45"
    assert _step_value(by_run[PR_LANE_2], "timeout-minutes") == "30"
    job_level = [
        line.strip() for line in tui_lines if line.startswith("    timeout-minutes:")
    ]
    assert "timeout-minutes: 240" in job_level
    install_steps = [step for step in steps if _step_value(step, "id") == "install"]
    assert len(install_steps) == 1, "install step must carry id: install (E3A-13)"
    # Lane-2 fits after a lane-1 stop: install + lane 1 + lane 2 <= job limit.
    assert 3 + 180 + 45 <= 240
    assert 3 + 120 + 30 <= 240


def test_r_tst_018_ci_installs_pinned_xdist() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    jobs = _workflow_jobs(text)
    steps = _job_steps(jobs["tui-ci"])
    runs = "\n".join(run for run in (_step_run(step) for step in steps) if run)
    assert XDIST_INSTALL_LINE in runs


# ---------------------------------------------------------------------------
# R-TST-020 .. 022 — the one yielding, wall-clock-bounded wait
# ---------------------------------------------------------------------------


@pytest.mark.serial_timing
def test_r_tst_020_shared_wait_is_bounded_by_the_wall_clock() -> None:
    from tests.support import timing as timing_support

    pilot = _FakePilot()
    started = time.perf_counter()
    with pytest.raises(AssertionError) as excinfo:
        asyncio.run(
            timing_support.wait_until(pilot, lambda: False, "never", timeout=0.5)
        )
    elapsed = time.perf_counter() - started
    assert str(excinfo.value) == "never"
    assert elapsed >= 0.5
    assert elapsed < timing_support.report_margin(
        "R-TST-020 wall-clock bound", elapsed, 1.5
    )

    pilot = _FakePilot()
    flip = {"ready": False}

    def _predicate():
        return flip["ready"]

    async def _drive():
        await asyncio.sleep(0.2)
        flip["ready"] = True
        await timing_support.wait_until(pilot, _predicate, "late", timeout=60.0)

    started = time.perf_counter()
    asyncio.run(_drive())
    fast = time.perf_counter() - started
    assert fast < timing_support.report_margin("R-TST-020 fast return", fast, 0.4)


def _shape_range_loops(shape) -> int:
    for item in shape:
        if isinstance(item, int):
            return item
    raise AssertionError(f"no range-loop count in shape {shape!r}")


def _shape_failures(shape) -> list:
    for item in shape:
        if isinstance(item, (list, tuple)) and not isinstance(item, str):
            return list(item)
    raise AssertionError(f"no wait_until failure list in shape {shape!r}")


def test_r_tst_020_021_shared_helpers_delegate_to_the_one_wait() -> None:
    from tests.support import suite_census

    shapes = suite_census.shared_wait_bodies(TESTS_ROOT)
    by_func = {}
    for key, shape in shapes.items():
        func = key.replace("\\", "/").split("::")[-1]
        by_func.setdefault(func, []).append((key, shape))
    assert set(by_func) == {
        "settled",
        "wait_for",
        "read_load_result_panel",
        "dismiss_load_result_panel",
        "save_case01_project",
        "append_variant",
    }, f"census must cover exactly the 7 shared functions: {sorted(by_func)}"
    assert len(by_func["wait_for"]) == 2, "the two wait_for helpers must be separate"
    wait_until_calls = 0
    for func, entries in by_func.items():
        for key, shape in entries:
            assert _shape_range_loops(shape) == 0, (
                f"{key}: a range(...)-counted pause loop is left"
            )
            wait_until_calls += len(_shape_failures(shape))
    assert wait_until_calls == 9, f"expected 9 waits over the 7 functions, got {wait_until_calls}"
    assert len(_shape_failures(by_func["dismiss_load_result_panel"][0][1])) == 2
    assert len(_shape_failures(by_func["save_case01_project"][0][1])) == 2


def test_r_tst_021_shared_wait_yields_between_checks() -> None:
    from tests.support import timing as timing_support

    pilot = _FakePilot()
    checks = {"n": 0}

    def _predicate():
        checks["n"] += 1
        return False

    with pytest.raises(AssertionError, match="never"):
        asyncio.run(timing_support.wait_until(pilot, _predicate, "never", timeout=1.0))
    assert checks["n"] <= 21, (
        f"a yielding wait must run at most 21 checks over 1.0 s, got {checks['n']}"
    )


def test_r_tst_022_settled_pauses_before_its_first_check() -> None:
    from tests import b97_probes

    pilot = _FakePilot()
    seen = []

    def _predicate():
        if not seen:
            seen.append(pilot.pauses)
        return True

    asyncio.run(b97_probes.settled(pilot, _predicate, "row 2 back", timeout=5.0))
    assert seen and seen[0] >= 1, "settled must pause once before its first check"
    # The pause-first wait is also the wall-clock-bounded wait: the keyword-
    # only ``timeout`` of interface I-1/I-7 must be there (this row's bounded
    # wait is what R-TST-020 creates; without it the pause-first order is the
    # old unbounded count loop).
    timeout_param = inspect.signature(b97_probes.settled).parameters.get("timeout")
    assert timeout_param is not None
    assert timeout_param.kind is inspect.Parameter.KEYWORD_ONLY


def test_r_tst_023_shared_wait_signatures_are_kept() -> None:
    from tests import b97_probes
    from tests.support import b100_load_dialog
    from tests.support import b100_projects

    def _check_wait_signature(fn, positional, defaults, timeout_default=60.0):
        sig = inspect.signature(fn)
        params = list(sig.parameters.values())
        ordered = [
            p
            for p in params
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        assert [p.name for p in ordered] == positional, f"{fn.__name__}: {ordered}"
        for name, value in defaults.items():
            assert sig.parameters[name].default == value, (
                f"{fn.__name__}: default of {name} changed"
            )
        timeout = sig.parameters.get("timeout")
        assert timeout is not None and timeout.kind is inspect.Parameter.KEYWORD_ONLY, (
            f"{fn.__name__}: keyword-only timeout missing"
        )
        assert timeout.default == timeout_default

    _check_wait_signature(
        b97_probes.settled, ["pilot", "predicate", "description", "attempts"], {"attempts": 60}
    )
    _check_wait_signature(
        b100_load_dialog.wait_for,
        ["pilot", "predicate", "description", "attempts"],
        {"attempts": 400},
    )
    _check_wait_signature(
        b100_projects.wait_for,
        ["pilot", "predicate", "description", "attempts"],
        {"attempts": 400},
    )
    _check_wait_signature(
        b100_projects.read_load_result_panel, ["pilot", "app", "attempts"], {"attempts": 200}
    )
    _check_wait_signature(
        b100_projects.dismiss_load_result_panel,
        ["pilot", "app", "attempts"],
        {"attempts": 200},
    )
    sig = inspect.signature(b100_projects.save_case01_project)
    assert [
        p.name
        for p in sig.parameters.values()
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ] == ["base", "name", "files"]
    assert sig.parameters["name"].default == "P"
    sig = inspect.signature(b100_projects.append_variant)
    assert [
        p.name
        for p in sig.parameters.values()
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ] == ["base", "source", "name"]
    assert sig.parameters["name"].default == "P"


# ---------------------------------------------------------------------------
# R-TST-024 — the nine wait-failure texts (W1 .. W9)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", [f"W{i}" for i in range(1, 10)])
def test_r_tst_024_shared_wait_failure_texts(case, tmp_path) -> None:
    from tests.support import suite_census

    if case in {"W1", "W2", "W3", "W4", "W5", "W6"}:
        from tests import b97_probes
        from tests.support import b100_load_dialog
        from tests.support import b100_projects

        pilot = _FakePilot()
        if case == "W1":
            coro = b100_projects.wait_for(
                pilot, lambda: False, "the thing", timeout=0.2
            )
            expected = "timed out waiting for the thing"
        elif case == "W2":
            coro = b100_load_dialog.wait_for(
                pilot, lambda: False, "the Load dialog", timeout=0.2
            )
            expected = "timed out waiting for the Load dialog"
        elif case == "W3":
            coro = b97_probes.settled(pilot, lambda: False, "row 2 back", timeout=0.2)
            expected = "did not settle: row 2 back"
        elif case == "W4":
            coro = b100_projects.read_load_result_panel(
                pilot, _App(_EmptyScreen()), timeout=0.2
            )
            expected = "the Load-result panel was not painted"
        elif case == "W5":
            coro = b100_projects.dismiss_load_result_panel(
                pilot, _App(_EmptyScreen()), timeout=0.2
            )
            expected = "the Load-result panel did not open"
        else:  # W6
            coro = b100_projects.dismiss_load_result_panel(
                pilot, _App(_StickyScreen()), timeout=0.2
            )
            expected = "the Load-result panel did not close on esc"
        with pytest.raises(AssertionError) as excinfo:
            asyncio.run(coro)
        assert str(excinfo.value) == expected
        if case == "W5":
            assert pilot.pressed == [], "no escape may be pressed before the panel"
        if case == "W6":
            assert pilot.pressed == ["escape"]
        return

    # W7 .. W9 — static: the failure argument of each wait_until call.
    shapes = suite_census.shared_wait_bodies(TESTS_ROOT)
    by_func = {}
    for key, shape in shapes.items():
        func = key.replace("\\", "/").split("::")[-1]
        by_func.setdefault(func, []).append((key, shape))
    if case == "W7":
        failures = _shape_failures(by_func["save_case01_project"][0][1])
        assert len(failures) >= 1
        first = str(failures[0])
        assert "the load of " in first and "{item}" in first and "did not land" in first
    elif case == "W8":
        failures = _shape_failures(by_func["save_case01_project"][0][1])
        assert len(failures) >= 2
        second = str(failures[1])
        assert "Save project " in second and "{name}" in second and "did not land" in second
    else:  # W9
        failures = _shape_failures(by_func["append_variant"][0][1])
        assert len(failures) == 1
        text = str(failures[0])
        assert "the variant append of " in text
        assert "{source.name}" in text
        assert "{statuses}" in text


# ---------------------------------------------------------------------------
# R-TST-025 — the project-load clock stops at the install callback
# ---------------------------------------------------------------------------


def test_r_tst_025_load_project_clock_stops_at_the_install_callback(tmp_path) -> None:
    from tests.support import b100_projects as projects

    base = tmp_path / "app"
    projects.save_case01_project(base, files=("firmware.s19",))
    for _ in range(3):
        stamps = []

        async def scenario(app, pilot, log):
            real_install = app._install_prepared_project

            def recorder(prepared):
                real_install(prepared)
                stamps.append(time.perf_counter())

            app._install_prepared_project = recorder
            stamps.append(time.perf_counter())
            elapsed = await projects.load_project(pilot, app, "P")
            assert (
                app._install_prepared_project is recorder
            ), "the install wrapper must be restored (E3A-12)"
            return elapsed

        elapsed = projects.run_app(base, scenario)
        start, stamp = stamps
        assert abs(elapsed - (stamp - start)) <= 0.001, (
            f"returned interval {elapsed:.6f} s is not the install-return stamp "
            f"minus the start ({stamp - start:.6f} s)"
        )


# ---------------------------------------------------------------------------
# R-TST-031 / 032 — the post-press and dwell arms keep their forms (static)
# ---------------------------------------------------------------------------


def test_r_tst_031_032_post_press_and_dwell_arms_keep_their_forms() -> None:
    from tests.support import suite_census

    workers_text = (TESTS_ROOT / "test_b100_workers.py").read_text(encoding="utf-8")
    quit_body = _function_source(
        workers_text,
        "test_at_b100_18_quit_confirm_half_slow_save_as_leaves_no_partial_folder",
    )
    assert "held_save_scene" in quit_body
    assert 'Hold(monkeypatch, app_module, "place_into_workarea"' in workers_text, (
        "the quit-confirm arm must hold the save worker at a forced slow step"
    )
    parse_body = _function_source(
        workers_text, "test_at_b100_17_parse_half_case06_a2l_by_keys"
    )
    assert 'Spy(monkeypatch, S19TuiApp, "step_busy")' in parse_body, (
        "the parse arm must record states at the progress hook (step_busy)"
    )
    flow_text = (TESTS_ROOT / "test_b97_flow_execution.py").read_text(encoding="utf-8")
    dwell_body = _function_source(
        flow_text, "test_tc_b97_64_a_new_set_run_restarts_the_dwell"
    )
    assert "_fx_clock" in dwell_body, (
        "the dwell restart arm must read the injected dwell clock"
    )
    # These three arms keep no wall-clock bound: they stay in the parallel
    # lane.  If the census ever flags them, the marker guard would move them
    # to the serial lane against the design.
    arms = {_norm_arm_key(key) for key in suite_census.timing_arms(TESTS_ROOT)}
    for node in (
        "tests/test_b100_workers.py::test_at_b100_18_quit_confirm_half_slow_save_as_leaves_no_partial_folder",
        "tests/test_b100_workers.py::test_at_b100_17_parse_half_case06_a2l_by_keys",
        "tests/test_b97_flow_execution.py::test_tc_b97_64_a_new_set_run_restarts_the_dwell",
    ):
        assert node not in arms, f"{node} gained a wall-clock bound and left lane 1"


# ---------------------------------------------------------------------------
# R-TST-040 / 041 — every upper timing bound passes through the reporter
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_pending(monkeypatch):
    """E3A-11 / E3S-1: a fresh pending list, empty again at teardown."""
    from tests.support import timing as timing_support

    pending = []
    monkeypatch.setattr(timing_support, "_QC_TM_PENDING", pending)
    yield pending
    assert pending == [], "report_margin left records undrained"


def test_r_tst_040_report_margin_returns_the_bound(fresh_pending) -> None:
    from tests.support import timing as timing_support

    bound = timing_support.timing_bound(1.0)
    returned = timing_support.report_margin("x", 0.5, bound)
    assert returned is bound
    drained = []
    assert timing_support.qc_tm_drain(drained) == 1
    assert drained == [("qc_tm", "x|0.500|1.000|50.0")]


def test_r_tst_040_041_every_upper_timing_bound_is_reported(tmp_path) -> None:
    from tests.support import suite_census

    sites = {_norm_site(site) for site in _unreported_sites(TESTS_ROOT)}
    assert sites == set(), (
        "raw upper timing bounds: " + ", ".join(sorted(sites))
    )
    for forbidden in _NOT_UPPER_BOUND_SITES:
        assert forbidden not in sites, f"not an upper timing bound: {forbidden}"

    # Planted marked arm with four raw bounds: a float literal, an int
    # literal, a scaled timing_bound call and a module constant (R-TST-041).
    planted_lines = [
        "import time",
        "",
        "from tests.support.timing import timing_bound",
        "",
        "LIMIT = 1",
        "",
        "",
        "def test_raw_bounds_arm():",
        "    start = time.perf_counter()",
        "    work()",
        "    elapsed = time.perf_counter() - start",
        "    assert elapsed < 1.0",
        "    assert elapsed < 2",
        "    assert elapsed < timing_bound(1.0) * 2",
        "    assert elapsed < LIMIT",
    ]
    planted = tmp_path / "test_raw_bounds_planted.py"
    planted.write_text("\n".join(planted_lines) + "\n", encoding="utf-8")
    planted_sites = _unreported_sites(tmp_path)
    raw_lines = [
        i + 1
        for i, line in enumerate(planted_lines)
        if line.strip().startswith("assert elapsed <")
    ]
    assert len(planted_sites) == 4, f"expected 4 raw-bound sites: {planted_sites}"
    for number in raw_lines:
        assert any(
            site.endswith(f":{number}") and "test_raw_bounds_planted.py" in site
            for site in planted_sites
        ), f"planted raw bound at line {number} not reported: {planted_sites}"
    guard_lines = [f"timing bound without report_margin: {site}" for site in planted_sites]
    for line in guard_lines:
        assert re.fullmatch(
            r"timing bound without report_margin: .+:\d+", line
        ), f"guard text malformed: {line}"


# ---------------------------------------------------------------------------
# R-TST-042 .. 046 — the qc_tm property, the QC-TM section (inner runs)
# ---------------------------------------------------------------------------

_INNER_CONTEST = '''
import json
import os
import pathlib

try:
    from tests.support.timing import pytest_runtest_makereport
    from tests.support.timing import pytest_terminal_summary
except ImportError:  # hooks registered from the root conftest instead
    from tests.conftest import pytest_runtest_makereport
    from tests.conftest import pytest_terminal_summary


def pytest_runtest_logreport(report):
    probe_dir = pathlib.Path(os.environ["QC_TM_PROBE_DIR"])
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe = probe_dir / "reports.jsonl"
    with probe.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "nodeid": report.nodeid,
            "when": report.when,
            "outcome": report.outcome,
            "props": [list(pair) for pair in report.user_properties],
        }) + "\\n")
'''


def _inner_run(pytester, files, junit=False):
    pytester.makeconftest(_INNER_CONTEST)
    for name, source in files.items():
        (pytester.path / name).write_text(source, encoding="utf-8")
    previous_path = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + (previous_path or "")
    os.environ["QC_TM_PROBE_DIR"] = str(pytester.path)
    try:
        args = ["-p", "no:cacheprovider"]
        if junit:
            args.append("--junitxml=junit.xml")
        result = pytester.runpytest_subprocess(*args)
    finally:
        if previous_path is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = previous_path
        os.environ.pop("QC_TM_PROBE_DIR", None)
    return result


def _probe_records(pytester) -> list:
    probe = pytester.path / "reports.jsonl"
    return [json.loads(line) for line in probe.read_text(encoding="utf-8").splitlines()]


def _qc_tm_section(stdout: str) -> list:
    lines = stdout.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if "QC-TM timing margins" in line),
        None,
    )
    assert start is not None, "QC-TM timing margins section missing:\n" + stdout
    block = []
    for line in lines[start + 1 :]:
        if line.startswith("QC-TM:"):
            block.append(line)
            return block
        if line.strip():
            block.append(line)
    raise AssertionError("QC-TM count line missing:\n" + stdout)


def _qc_tm_rows(stdout: str):
    block = _qc_tm_section(stdout)
    return [line for line in block if "%" in line and " s / " in line], block[-1]


def test_r_tst_042_margin_report_is_a_test_property(pytester) -> None:
    result = _inner_run(
        pytester,
        {
            "test_margin_property.py": (
                "def test_arm():\n"
                "    from tests.support.timing import report_margin\n"
                "    assert report_margin('p', 0.85, 1.0) == 1.0\n"
            )
        },
        junit=True,
    )
    assert result.ret == 0, result.stdout.str()
    prop = ["qc_tm", "p|0.850|1.000|15.0"]
    records = _probe_records(pytester)
    phases = {
        record["when"]: record
        for record in records
        if record["nodeid"].endswith("::test_arm")
    }
    assert prop in phases["call"]["props"], phases
    assert prop in phases["teardown"]["props"], phases
    tree = etree.parse(str(pytester.path / "junit.xml"))
    values = [
        element.get("value")
        for element in tree.getroot().iter("property")
        if element.get("name") == "qc_tm"
    ]
    assert values == ["p|0.850|1.000|15.0"], values


_PLANTED_THREE_ARMS = '''\
def test_a():
    from tests.support.timing import report_margin
    assert report_margin("a", 0.6, 1.0) == 1.0


def test_b():
    from tests.support.timing import report_margin
    assert report_margin("b", 0.85, 1.0) == 1.0


def test_c():
    from tests.support.timing import report_margin
    assert report_margin("c", 0.75, 1.0) == 1.0
'''


def test_r_tst_043_045_qc_tm_section_rows_and_count(pytester) -> None:
    result = _inner_run(pytester, {"test_qc_tm_rows.py": _PLANTED_THREE_ARMS})
    assert result.ret == 0, result.stdout.str()
    rows, count_line = _qc_tm_rows(result.stdout.str())
    assert rows == [
        "LOW 15.0%  0.850 s / 1.000 s  b  test_qc_tm_rows.py::test_b",
        "25.0%  0.750 s / 1.000 s  c  test_qc_tm_rows.py::test_c",
        "40.0%  0.600 s / 1.000 s  a  test_qc_tm_rows.py::test_a",
    ], rows
    assert count_line == "QC-TM: 3 bounds, 1 under 20 % margin"


_PLANTED_TEARDOWN_ROW = '''\
import pytest


@pytest.fixture
def _boom():
    yield
    raise RuntimeError("teardown boom")


def test_arm(_boom):
    from tests.support.timing import report_margin
    assert report_margin("e", 0.85, 1.0) == 1.0
'''


def test_r_tst_043_2_teardown_error_report_gives_one_row(pytester) -> None:
    result = _inner_run(pytester, {"test_teardown_row.py": _PLANTED_TEARDOWN_ROW})
    assert result.ret != 0
    rows, count_line = _qc_tm_rows(result.stdout.str())
    arm_rows = [row for row in rows if row.endswith("test_teardown_row.py::test_arm")]
    assert len(arm_rows) == 1, rows
    assert arm_rows[0].startswith("LOW 15.0%"), arm_rows
    assert count_line == "QC-TM: 1 bounds, 1 under 20 % margin", count_line


_PLANTED_LOW_PREFIX = '''\
def test_b():
    from tests.support.timing import report_margin
    assert report_margin("b", 0.85, 1.0) == 1.0


def test_d():
    from tests.support.timing import report_margin
    assert report_margin("d", 0.8, 1.0) == 1.0
'''


def test_r_tst_044_low_margin_prefix(pytester) -> None:
    result = _inner_run(pytester, {"test_low_prefix.py": _PLANTED_LOW_PREFIX})
    assert result.ret == 0, result.stdout.str()
    rows, count_line = _qc_tm_rows(result.stdout.str())
    assert rows == [
        "LOW 15.0%  0.850 s / 1.000 s  b  test_low_prefix.py::test_b",
        "20.0%  0.800 s / 1.000 s  d  test_low_prefix.py::test_d",
    ], rows
    assert not rows[1].startswith("LOW ")
    assert count_line == "QC-TM: 2 bounds, 1 under 20 % margin"


_PLANTED_OVER_BOUND = '''\
def test_over():
    from tests.support.timing import report_margin
    assert 1.2 < report_margin("o", 1.2, 1.0)
'''


def test_r_tst_046_over_bound_arm_still_reports(pytester) -> None:
    result = _inner_run(pytester, {"test_over_bound.py": _PLANTED_OVER_BOUND})
    assert result.ret != 0, "the planted over-bound arm must fail"
    rows, count_line = _qc_tm_rows(result.stdout.str())
    assert rows == [
        "LOW -20.0%  1.200 s / 1.000 s  o  test_over_bound.py::test_over"
    ], rows
    assert count_line == "QC-TM: 1 bounds, 1 under 20 % margin"


# ---------------------------------------------------------------------------
# R-TST-050 / 051 — the status oracle reads every painted line; the ratchet
# ---------------------------------------------------------------------------


_NEWEST_GUARD_TEXT = (
    "newest-line wait added in {file}: {count} > baseline {base}; "
    "collect the painted lines with StatusLog.since(mark)"
)


def test_r_tst_050_status_log_keeps_every_painted_line(tmp_path) -> None:
    from tests.support import b100_projects as projects
    from tests.support import suite_census

    seen = {}

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        for i in range(1, 7):
            app.set_status(f"line {i}")
        seen["since"] = list(log.since(mark))
        seen["app_log_lines"] = len(list(app.log_lines))

    projects.run_app(tmp_path / "app", scenario)
    assert seen["since"] == [f"line {i}" for i in range(1, 7)], seen
    assert seen["app_log_lines"] == 4, seen
    # The QC-OR ratchet on the same tree: no file holds more newest-line
    # waits than its baseline (R-TST-051/1's pass state).
    baseline = {
        _norm_census_file_key(key): value
        for key, value in suite_census.NEWEST_LINE_BASELINE.items()
    }
    counts = suite_census.newest_line_waits(TESTS_ROOT)
    violations = [
        _NEWEST_GUARD_TEXT.format(
            file=_norm_census_file_key(file),
            count=count,
            base=baseline.get(_norm_census_file_key(file), 0),
        )
        for file, count in counts.items()
        if count > baseline.get(_norm_census_file_key(file), 0)
    ]
    assert not violations, "\n".join(violations)


_PLANTED_NEWEST_WAIT = '''

def _newest_status(app):
    return app.log_lines[-1]


def _planted_wait(pilot, app):
    _wait_for(pilot, lambda: "x" in _newest_status(app), "x")
'''

_PLANTED_READER_WAIT = '''

from tests.b97_probes import last_status
from tests.b97_probes import settled


def _planted_reader_wait(pilot, app):
    settled(pilot, lambda: "x" in last_status(app), "x")
'''


def test_r_tst_051_newest_line_waits_do_not_grow(tmp_path) -> None:
    from tests.support import suite_census

    baseline = {
        _norm_census_file_key(key): value
        for key, value in suite_census.NEWEST_LINE_BASELINE.items()
    }

    # One newest-line wait in a new file: 1 > baseline 0.
    case_new = tmp_path / "new_file"
    case_new.mkdir()
    (case_new / "test_newest_planted.py").write_text(
        _PLANTED_NEWEST_WAIT, encoding="utf-8"
    )
    counts = suite_census.newest_line_waits(case_new)
    assert counts, "planted newest-line wait not counted"
    key = next(iter(counts))
    assert key.endswith("test_newest_planted.py") and counts[key] == 1, counts
    assert _NEWEST_GUARD_TEXT.format(file=key, count=1, base=0) == (
        f"newest-line wait added in {key}: 1 > baseline 0; "
        "collect the painted lines with StatusLog.since(mark)"
    )

    # One more newest-line wait in a copy of a baselined file, and one more
    # through a support-module newest-line reader (E3A-6).
    pick = min(baseline, key=lambda name: baseline[name])
    source = (REPO_ROOT / pick).read_text(encoding="utf-8")

    case_extra = tmp_path / "baselined_extra"
    case_extra.mkdir()
    (case_extra / "test_baselined_copy.py").write_text(
        source + _PLANTED_NEWEST_WAIT, encoding="utf-8"
    )
    counts_extra = suite_census.newest_line_waits(case_extra)
    assert counts_extra, "planted baselined copy not counted"
    key_extra = next(iter(counts_extra))
    assert counts_extra[key_extra] == baseline[pick] + 1, (
        f"{key_extra}: expected {baseline[pick] + 1}, got {counts_extra[key_extra]}"
    )
    assert _NEWEST_GUARD_TEXT.format(
        file=key_extra, count=baseline[pick] + 1, base=baseline[pick]
    ) == (
        f"newest-line wait added in {key_extra}: {baseline[pick] + 1} "
        f"> baseline {baseline[pick]}; collect the painted lines with "
        "StatusLog.since(mark)"
    )

    case_reader = tmp_path / "reader_extra"
    case_reader.mkdir()
    (case_reader / "test_reader_copy.py").write_text(
        source + _PLANTED_READER_WAIT, encoding="utf-8"
    )
    counts_reader = suite_census.newest_line_waits(case_reader)
    assert counts_reader, "planted reader wait not counted"
    key_reader = next(iter(counts_reader))
    assert counts_reader[key_reader] == baseline[pick] + 1, (
        f"{key_reader}: expected {baseline[pick] + 1}, "
        f"got {counts_reader[key_reader]}"
    )


# ---------------------------------------------------------------------------
# E3S-2 — the committed-evidence redaction gate
# ---------------------------------------------------------------------------


_REDACTION_PATTERNS = [
    (
        "posix home path outside the runner image",
        re.compile(r"/home/(?!runner/)[A-Za-z0-9][A-Za-z0-9._-]*"),
    ),
    (
        "user-profile path",
        re.compile(r"[A-Za-z]:[\\/]Users[\\/][A-Za-z0-9][A-Za-z0-9._-]*"),
    ),
    (
        "lan address",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
        ),
    ),
]

_REDACTION_SUFFIXES = {".txt", ".md", ".log", ".json", ".jsonl", ".yml", ".yaml"}


def test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses() -> None:
    inc2_dir = EVIDENCE_ROOT / "inc-2"
    if not inc2_dir.is_dir():
        pytest.fail(
            "the increment's evidence folder is missing from this checkout; "
            "the redaction gate has nothing it is responsible for"
        )
    hits = []
    for path in sorted(EVIDENCE_ROOT.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _REDACTION_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for label, pattern in _REDACTION_PATTERNS:
            for match in pattern.finditer(text):
                hits.append(
                    f"{path.relative_to(REPO_ROOT).as_posix()}: {label}: {match.group(0)}"
                )
    assert not hits, "unredacted committed evidence:\n" + "\n".join(hits)


# ---------------------------------------------------------------------------
# R-TST-080 .. 082 — version-agnostic report goldens
# ---------------------------------------------------------------------------


def test_r_tst_080_report_goldens_hold_no_tool_version() -> None:
    goldens = TESTS_ROOT / "goldens"
    pinned = []
    for path in sorted(goldens.rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        if re.search(rb"Tool version: [0-9]", data):
            pinned.append(path.relative_to(REPO_ROOT).as_posix())
    assert not pinned, "goldens pin a tool version: " + ", ".join(pinned)
    for rel in _GOLDENS_WITH_VERSION:
        data = (REPO_ROOT / rel).read_bytes()
        assert b"Tool version: <TOOL-VERSION>" in data, (
            f"{rel} lost the tool-version token"
        )


def test_r_tst_081_golden_takes_the_package_version(monkeypatch) -> None:
    import s19_app.version

    from tests.conftest import canonical_report_bytes

    monkeypatch.setattr(s19_app.version, "__version__", "9.9.9")
    out = canonical_report_bytes(b"- Tool version: <TOOL-VERSION>\n")
    assert b"Tool version: 9.9.9" in out
    assert b"<TOOL-VERSION>" not in out


def test_r_tst_082_wrong_version_still_differs(monkeypatch) -> None:
    import s19_app.version

    from tests.conftest import canonical_report_bytes

    monkeypatch.setattr(s19_app.version, "__version__", "9.9.9")
    produced = canonical_report_bytes(b"- Tool version: 0.0.0\n")
    assert produced == b"- Tool version: 0.0.0\n", (
        "a produced report's own version must not be touched by the canonicalizer"
    )
    golden_side = canonical_report_bytes(b"- Tool version: <TOOL-VERSION>\n")
    assert golden_side == b"- Tool version: 9.9.9\n"
    assert produced != golden_side, (
        "a report printing another version must still differ from the golden"
    )
