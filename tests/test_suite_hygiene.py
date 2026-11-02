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
import io
import json
import os
import re
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as etree
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_ROOT = REPO_ROOT / "tests"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "tui-ci.yml"
CONVENTIONS_PATH = REPO_ROOT / "docs" / "engineering-rules.md"
BATCH_ROOT = REPO_ROOT / ".dev-flow" / "2026-11-01-batch-101"
EVIDENCE_ROOT = BATCH_ROOT / "evidence"

# Install budget before lane 1 starts (R-TST-016/017, note N-3).
_SETUP_MINUTES = 3

MARKER_LINE = (
    "@pytest.mark.serial_timing: a wall-clock timing arm; "
    "run apart and serially (-m serial_timing)"
)

PR_LANE_1 = 'pytest -v -rs -n auto -m "not slow and not serial_timing"'
PR_LANE_2 = 'pytest -q -rs -m "serial_timing and not slow"'
PUSH_LANE_1 = 'pytest -v -rs -n auto -m "not serial_timing"'
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

# The tree R-TST-040's base-tree counts are pinned to (01-requirements.md).
_BOUND_BASE_COMMIT = "b3bf42e"


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


def _margin_guard_lines(root: Path) -> list:
    """The margin guard's failure lines (R-TST-041), one per raw upper bound."""
    from tests.support import suite_census

    sites = suite_census.unreported_upper_bounds(root, suite_census.timing_arms(root))
    return [f"timing bound without report_margin: {_norm_site(site)}" for site in sites]


def _newest_guard_lines(root: Path, baseline: dict) -> list:
    """The newest-line guard's failure lines (R-TST-051), one per file above
    its baseline."""
    from tests.support import suite_census

    base = {_norm_census_file_key(key): value for key, value in baseline.items()}
    lines = []
    for file, count in sorted(suite_census.newest_line_waits(root).items()):
        key = _norm_census_file_key(file)
        if count > base.get(key, 0):
            lines.append(
                _NEWEST_GUARD_TEXT.format(file=key, count=count, base=base.get(key, 0))
            )
    return lines


def _git(*args):
    """The stdout bytes of a git command run in the repository, or None when
    git or the object is not available."""
    try:
        proc = subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, timeout=120
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def _merge_base_with_main():
    for ref in ("main", "origin/main"):
        out = _git("merge-base", "HEAD", ref)
        if out:
            return out.decode().strip()
    return None


def _extract_tests_tree(commit: str, dest: Path) -> Path:
    data = _git("archive", "--format=zip", commit, "tests")
    if data is None:
        pytest.skip(f"git history holding {commit} is not available in this checkout")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        archive.extractall(dest)
    return dest / "tests"


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
        "interval returned by a test support module function",
        """from tests.support import b100_projects as projects


async def test_f(pilot, app):
    elapsed = await projects.load_project(pilot, app, "P")
    assert elapsed < 1.0
""",
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

@pytest.mark.parametrize(
    "form", ["form1", "form2", "form3", "form4", "form5", "form6", "form7"]
)
def test_r_tst_005_detector_finds_each_timing_arm_form(tmp_path, form) -> None:
    from tests.support import suite_census

    _, source = _FORM_SOURCES[form]
    (tmp_path / f"test_{form}.py").write_text(source, encoding="utf-8")
    test_name = {
        "form1": "test_a",
        "form2": "test_b",
        "form3": "test_c",
        "form4": "test_d",
        "form5": "test_e",
        "form6": "test_f",
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


_SCRIPT_INJECTION = re.compile(r"\$\{\{\s*github\.(event\.|head_ref)")


def _script_injections(text: str) -> list:
    """Every run line, in every job, that interpolates event data (E3S-6)."""
    hits = []
    for job, lines in _workflow_jobs(text).items():
        for step in _job_steps(lines):
            run = _step_run(step)
            if run and _SCRIPT_INJECTION.search(run):
                hits.append(f"{job}: {run}")
    return hits


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
    assert _script_injections(text) == []
    _assert_no_unsafe_triggers(text)


_PLANTED_INJECTION_WORKFLOW = """on:
  push:
jobs:
  a:
    steps:
      - name: x
        run: echo ${{github.event.pull_request.title}}
  b:
    steps:
      - name: y
        run: echo ${{ github.head_ref }}
      - name: z
        run: echo ${{ matrix.os }}
"""


def test_r_tst_010_2_injection_ratchet_reads_every_run_line_of_every_job() -> None:
    """E5S-2: the ratchet matches without the space and in any job."""
    assert _script_injections(_PLANTED_INJECTION_WORKFLOW) == [
        "a: echo ${{github.event.pull_request.title}}",
        "b: echo ${{ github.head_ref }}",
    ]


def test_r_tst_011_push_runs_two_lanes() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    jobs = _workflow_jobs(text)
    steps = _job_steps(jobs["tui-ci"])
    runs = [_step_run(step) for step in _lane_steps(steps, "push")]
    assert runs == [PUSH_LANE_1, PUSH_LANE_2]
    assert _script_injections(text) == []


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


def test_r_tst_013_snapshot_job_changes_only_persist_credentials() -> None:
    """R-TST-013/1 (E5 F9): the snapshot checkout carries only
    persist-credentials: false (no fetch-depth), and the snapshot job differs
    from its base only by that setting."""
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    snap = _workflow_jobs(text)["snapshot"]
    checkouts = [
        step
        for step in _job_steps(snap)
        if (_step_value(step, "uses") or "").startswith("actions/checkout@")
    ]
    assert len(checkouts) == 1
    with_values = [line.strip() for line in checkouts[0] if line.startswith("          ")]
    assert with_values == ["persist-credentials: false"], with_values
    base = _merge_base_with_main()
    old = _git("show", f"{base}:.github/workflows/tui-ci.yml") if base else None
    if old is None:
        pytest.skip("the workflow's base version is not available in this checkout")
    base_snap = _workflow_jobs(old.decode("utf-8"))["snapshot"]

    def without_credentials_setting(lines):
        return [
            line.rstrip()
            for line in lines
            if line.strip() not in ("with:", "persist-credentials: false")
        ]

    assert without_credentials_setting(snap) == without_credentials_setting(base_snap)


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
    # R-TST-017: lane 2 still runs after a red or timed-out lane 1.
    assert _step_value(by_run[PR_LANE_2], "if") == LANE_2_IF_PR
    assert _step_value(by_run[PUSH_LANE_2], "if") == LANE_2_IF_PUSH
    job_level = [
        line.strip() for line in tui_lines if line.startswith("    timeout-minutes:")
    ]
    assert job_level == ["timeout-minutes: 240"], job_level
    install_steps = [step for step in steps if _step_value(step, "id") == "install"]
    assert len(install_steps) == 1, "install step must carry id: install (E3A-13)"
    # Lane 2 fits after a lane-1 stop: install + lane 1 + lane 2 <= job limit.
    job_limit = int(job_level[0].split(":", 1)[1])
    for lane_1, lane_2 in ((PUSH_LANE_1, PUSH_LANE_2), (PR_LANE_1, PR_LANE_2)):
        total = (
            _SETUP_MINUTES
            + int(_step_value(by_run[lane_1], "timeout-minutes"))
            + int(_step_value(by_run[lane_2], "timeout-minutes"))
        )
        assert total <= job_limit, (lane_1, total, job_limit)


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
    assert 'Hold(monkeypatch, app_module, "place_into_workarea"' in quit_body, (
        "the quit-confirm arm must hold the save worker at a forced slow step"
    )
    parse_body = _function_source(
        workers_text, "test_at_b100_17_parse_half_case06_a2l_by_keys"
    )
    assert "= app.step_busy" in parse_body and "app.step_busy = " in parse_body, (
        "the parse arm must record states at the progress hook (step_busy)"
    )
    flow_text = (TESTS_ROOT / "test_b97_flow_execution.py").read_text(encoding="utf-8")
    dwell_body = _function_source(
        flow_text, "test_tc_b97_64_a_new_set_run_restarts_the_dwell"
    )
    clock_patches = [
        node
        for node in ast.walk(ast.parse(dwell_body))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "setattr"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "_fx_clock"
    ]
    assert len(clock_patches) == 1, (
        "the dwell restart arm must patch the injected dwell clock (_fx_clock)"
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


def test_r_tst_040_2_report_margin_refuses_unsafe_labels(fresh_pending) -> None:
    """E3S-7 / E5S-3: a label holding the record separator or a control
    character is refused and nothing is recorded; a plain label round-trips
    through the drain and the QC-TM section."""
    from tests.support import timing as timing_support

    for label in ("a|b", "a\x1b[31m", "two\nlines"):
        with pytest.raises(ValueError):
            timing_support.report_margin(label, 0.5, 1.0)
    assert fresh_pending == []
    label = "TC-X case [p-1] (a/b)"
    returned = timing_support.report_margin(label, 0.85, 1.0)
    assert returned == 1.0
    drained = []
    assert timing_support.qc_tm_drain(drained) == 1
    assert drained == [("qc_tm", f"{label}|0.850|1.000|15.0")]
    assert timing_support.qc_tm_summary_lines([("tests/x.py::t", drained[0][1])]) == [
        "QC-TM timing margins",
        f"LOW 15.0%  0.850 s / 1.000 s  {label}  tests/x.py::t",
        "QC-TM: 1 bounds, 1 under 20 % margin",
    ]


class _WrapStrip(ast.NodeTransformer):
    """Undo a timing-arm wrap: report_margin(label, measured, bound) -> bound,
    and drop the serial_timing marker."""

    def visit_Call(self, node):
        self.generic_visit(node)
        func = node.func
        name = (
            func.id
            if isinstance(func, ast.Name)
            else func.attr if isinstance(func, ast.Attribute) else None
        )
        if name == "report_margin" and len(node.args) == 3 and not node.keywords:
            return node.args[2]
        return node

    def _strip_marker(self, node):
        self.generic_visit(node)
        node.decorator_list = [
            deco
            for deco in node.decorator_list
            if ast.unparse(deco) != "pytest.mark.serial_timing"
        ]
        return node

    visit_FunctionDef = _strip_marker
    visit_AsyncFunctionDef = _strip_marker


def _module_functions(tree) -> dict:
    functions = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[node.name] = node
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions[f"{node.name}.{item.name}"] = item
    return functions


def _wrap_marks(node) -> tuple:
    marked = any(
        ast.unparse(deco) == "pytest.mark.serial_timing" for deco in node.decorator_list
    )
    wraps = sum(
        1
        for sub in ast.walk(node)
        if isinstance(sub, ast.Call)
        and (
            (isinstance(sub.func, ast.Name) and sub.func.id == "report_margin")
            or (isinstance(sub.func, ast.Attribute) and sub.func.attr == "report_margin")
        )
    )
    return marked, wraps


def _wrap_drift(base_source: str, head_source: str) -> list:
    """Functions that gained a serial_timing marker or a report_margin wrap
    against the base and differ from it by anything else (R-TST-049)."""
    import copy

    base_functions = _module_functions(ast.parse(base_source))
    drift = []
    for name, head_node in _module_functions(ast.parse(head_source)).items():
        base_node = base_functions.get(name)
        if base_node is None:
            continue
        head_marked, head_wraps = _wrap_marks(head_node)
        base_marked, base_wraps = _wrap_marks(base_node)
        if not ((head_marked and not base_marked) or head_wraps > base_wraps):
            continue
        stripped_head = ast.dump(_WrapStrip().visit(copy.deepcopy(head_node)))
        stripped_base = ast.dump(_WrapStrip().visit(copy.deepcopy(base_node)))
        if stripped_head != stripped_base:
            drift.append(name)
    return drift


_WRAP_BASE = """def test_a():
    elapsed = measure()
    assert elapsed < 1.0
    assert result() == []
"""

_WRAP_CLEAN = """@pytest.mark.serial_timing
def test_a():
    elapsed = measure()
    assert elapsed < report_margin(
        "a", elapsed, 1.0
    )
    assert result() == []
"""

_WRAP_DROPPED_ORACLE = """@pytest.mark.serial_timing
def test_a():
    elapsed = measure()
    assert elapsed < report_margin("a", elapsed, 1.0)
"""


def test_r_tst_049_wrap_drift_detector_names_a_dropped_assertion() -> None:
    """E5 F10: a wrap that also drops an oracle assertion is named; a marker
    plus a reformatted wrap is not."""
    assert _wrap_drift(_WRAP_BASE, _WRAP_CLEAN) == []
    assert _wrap_drift(_WRAP_BASE, _WRAP_DROPPED_ORACLE) == ["test_a"]


def test_r_tst_049_wrapped_arms_change_nothing_else() -> None:
    """E5 F10: every function this branch wraps as a timing arm (against the
    merge-base with main) differs from its base only by the serial_timing
    marker and the report_margin wraps."""
    base = _merge_base_with_main()
    if base is None:
        pytest.skip("no merge-base with main in this checkout")
    drift = []
    for path in sorted(TESTS_ROOT.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "report_margin" not in text and "serial_timing" not in text:
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        old = _git("show", f"{base}:{rel}")
        if old is None:
            continue
        for name in _wrap_drift(old.decode("utf-8"), text):
            drift.append(
                f"wrapped timing arm changed beyond marker and report_margin: {rel}::{name}"
            )
    assert drift == [], "\n".join(drift)


def test_r_tst_040_041_every_upper_timing_bound_is_reported() -> None:
    lines = _margin_guard_lines(TESTS_ROOT)
    assert lines == [], "\n".join(lines)


def test_r_tst_040_1_base_tree_reports_its_37_bounds(tmp_path) -> None:
    """R-TST-040/1, 040/3, 040/4 base halves: the census of the b3bf42e tree
    reports exactly its 37 upper bounds, the 3 list-appended reads among them,
    and none of the count or lower-bound comparisons."""
    root = _extract_tests_tree(_BOUND_BASE_COMMIT, tmp_path)
    lines = _margin_guard_lines(root)
    sites = [line.rsplit(": ", 1)[1] for line in lines]
    assert len(sites) == 37, "\n".join(lines)
    for site in (
        "tests/test_b100_project_check.py:841",
        "tests/test_b100_project_check.py:978",
        "tests/test_b100_project_check.py:1350",
    ):
        assert site in sites, f"list-appended bound not reported: {site}"
    for site in (
        "tests/test_b100_project_check.py:843",
        "tests/test_b100_project_check.py:981",
        "tests/test_b100_save_dialog.py:2331",
        "tests/test_b100_save_dialog.py:3493",
    ):
        assert site not in sites, f"not an upper timing bound: {site}"
    # `0.1 <= q_delay <= 0.5`: only the upper half is a bound.
    assert sites.count("tests/test_b100_save_dialog.py:2335") == 1, sites


_PLANTED_RAW_BOUNDS = [
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


def test_r_tst_041_margin_guard_names_each_raw_bound(tmp_path) -> None:
    """R-TST-041/1, 041/2: a float literal, an int literal, a scaled
    timing_bound call and a module constant, each named by the guard."""
    root = tmp_path / "tests"
    root.mkdir()
    (root / "test_raw_bounds_planted.py").write_text(
        "\n".join(_PLANTED_RAW_BOUNDS) + "\n", encoding="utf-8"
    )
    assert _margin_guard_lines(root) == [
        "timing bound without report_margin: tests/test_raw_bounds_planted.py:12",
        "timing bound without report_margin: tests/test_raw_bounds_planted.py:13",
        "timing bound without report_margin: tests/test_raw_bounds_planted.py:14",
        "timing bound without report_margin: tests/test_raw_bounds_planted.py:15",
    ]


_PLANTED_POSITIONS = """import time


def _scene():
    start = time.perf_counter()
    rows = [1, 2]
    return rows, time.perf_counter() - start


def test_positions():
    rows, elapsed = _scene()
    assert len(rows) <= 5
    assert elapsed < 1.0
    start = time.perf_counter()
    scene = {"read": time.perf_counter() - start, "rows": 3}
    assert scene["rows"] <= 5
    assert scene["read"] < 1.0
    assert 0.1 <= elapsed
"""


def test_r_tst_040_3_counts_and_lower_bounds_are_not_bounds(tmp_path) -> None:
    """R-TST-040/3 (E3A-3): a count from the non-interval tuple position, a
    non-interval dict key and a lower bound are not upper timing bounds; the
    interval position and key beside them are."""
    root = tmp_path / "tests"
    root.mkdir()
    (root / "test_positions_planted.py").write_text(_PLANTED_POSITIONS, encoding="utf-8")
    assert _margin_guard_lines(root) == [
        "timing bound without report_margin: tests/test_positions_planted.py:13",
        "timing bound without report_margin: tests/test_positions_planted.py:17",
    ]


_PLANTED_APPENDED = """import time


def test_appended():
    timing = []
    t0 = time.perf_counter()
    timing.append(time.perf_counter() - t0)
    x = timing[0] if timing else None
    assert x < 1.0
"""


def test_r_tst_040_4_appended_and_conditional_reads_are_bounds(tmp_path) -> None:
    """R-TST-040/4 (N-1): an item of a list appended an interval, read through
    a conditional expression, is a timing arm and an upper timing bound."""
    from tests.support import suite_census

    root = tmp_path / "tests"
    root.mkdir()
    (root / "test_appended_planted.py").write_text(_PLANTED_APPENDED, encoding="utf-8")
    arms = [_norm_arm_key(key) for key in suite_census.timing_arms(root)]
    assert arms == ["tests/test_appended_planted.py::test_appended"], arms
    assert _margin_guard_lines(root) == [
        "timing bound without report_margin: tests/test_appended_planted.py:9",
    ]


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
    violations = _newest_guard_lines(TESTS_ROOT, suite_census.NEWEST_LINE_BASELINE)
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
    """R-TST-051/2-4: the guard's own text for a wait added in a new file, in a
    baselined file (planted under that file's own path, so its baseline n
    applies) and through a support-module newest-line reader."""
    from tests.support import suite_census

    baseline = suite_census.NEWEST_LINE_BASELINE
    pick = "tests/test_b100_reuse.py"
    n = baseline[pick]
    source = (REPO_ROOT / pick).read_text(encoding="utf-8")

    new_root = tmp_path / "new" / "tests"
    new_root.mkdir(parents=True)
    (new_root / "test_newest_planted.py").write_text(_PLANTED_NEWEST_WAIT, encoding="utf-8")
    assert _newest_guard_lines(new_root, baseline) == [
        "newest-line wait added in tests/test_newest_planted.py: 1 > baseline 0; "
        "collect the painted lines with StatusLog.since(mark)"
    ]

    extra_root = tmp_path / "extra" / "tests"
    extra_root.mkdir(parents=True)
    (extra_root / "test_b100_reuse.py").write_text(
        source + _PLANTED_NEWEST_WAIT, encoding="utf-8"
    )
    assert _newest_guard_lines(extra_root, baseline) == [
        f"newest-line wait added in {pick}: {n + 1} > baseline {n}; "
        "collect the painted lines with StatusLog.since(mark)"
    ]

    reader_root = tmp_path / "reader" / "tests"
    reader_root.mkdir(parents=True)
    (reader_root / "test_b100_reuse.py").write_text(
        source + _PLANTED_READER_WAIT, encoding="utf-8"
    )
    assert _newest_guard_lines(reader_root, baseline) == [
        f"newest-line wait added in {pick}: {n + 1} > baseline {n}; "
        "collect the painted lines with StatusLog.since(mark)"
    ]

    # The unchanged baselined file passes: the guard compares against n.
    same_root = tmp_path / "same" / "tests"
    same_root.mkdir(parents=True)
    (same_root / "test_b100_reuse.py").write_text(source, encoding="utf-8")
    assert _newest_guard_lines(same_root, baseline) == []


_PLANTED_ALL_LINE_READER = """

def painted_log(app):
    return [str(line) for line in app.log_lines]


def _correct_wait(pilot, app):
    wait_for(pilot, lambda: "Saved" in painted_log(app), "saved")


def _newest_wait(pilot, app):
    wait_for(pilot, lambda: "Saved" in painted_log(app)[-1], "saved")
"""


def test_r_tst_051_all_line_reader_counts_only_under_minus_one(tmp_path) -> None:
    """E5 F2: a wait that reads every painted line through an all-line reader
    is the form the rule asks for and counts 0; the same reader under [-1]
    reads only the newest line and counts 1."""
    from tests.support import suite_census

    root = tmp_path / "tests"
    root.mkdir()
    (root / "test_all_line_planted.py").write_text(_PLANTED_ALL_LINE_READER, encoding="utf-8")
    assert suite_census.newest_line_waits(root) == {"tests/test_all_line_planted.py": 1}


# ---------------------------------------------------------------------------
# E3S-2 — the committed-evidence redaction gate
# ---------------------------------------------------------------------------


# A value that only names the kind of thing (a placeholder), never a real one.
_PLACEHOLDER = re.compile(
    r"<[^<>\s]*>|user|host|name|share|account|server|\.\.\.|\u2026|", re.IGNORECASE
)

_REDACTION_PATTERNS = [
    (
        "posix home path outside the runner image",
        re.compile(r"/home/(?!runner/)(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"),
    ),
    (
        "user-profile path",
        re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"),
    ),
    (
        "unix-style user-profile path",
        re.compile(
            r"(?<![\w.:])/(?:mnt/[a-z]/|[a-z]/)?Users/(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
        ),
    ),
    ("pytest temp folder of an account", re.compile(r"pytest-of-(?P<name>[A-Za-z0-9._-]+)")),
    ("junit hostname attribute", re.compile(r'hostname="(?P<name>[A-Za-z0-9._-]*)"')),
    (
        "shell prompt user@host",
        re.compile(r"(?<![\w.-])(?P<name>[A-Za-z0-9._-]+@[A-Za-z0-9._-]+):[~/]"),
    ),
    (
        "unc host path",
        re.compile(r"(?:^|[\s'\"(=])\\\\(?P<name>[A-Za-z0-9-]+)\\[A-Za-z0-9$_.-]+"),
    ),
    (
        "lan address",
        re.compile(
            r"\b(?P<name>10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
        ),
    ),
]


def _is_placeholder(value: str) -> bool:
    return all(_PLACEHOLDER.fullmatch(part) for part in re.split(r"[@.]", value))


def _local_identity_names() -> set:
    """The account and host names of the machine running the suite, read at
    test time (never written into this file). The GitHub runner image's
    public account `runner` is left out: its home is the allowed
    /home/runner/ path and the word is common in the records."""
    names = set()
    for value in (
        os.environ.get("USERNAME"),
        os.environ.get("USER"),
        Path.home().name,
        socket.gethostname(),
        os.environ.get("COMPUTERNAME"),
        os.environ.get("HOSTNAME"),
    ):
        if value:
            short = value.split(".")[0]
            if len(short) >= 3 and short.lower() != "runner":
                names.add(short)
    return names


def _redaction_hits(root: Path, identity_names, skip=frozenset()) -> list:
    """`<file>: <form>: <match>` for each leak form in every text file under
    root (a file holding a NUL byte or not decoding as UTF-8 is binary)."""
    name_patterns = [
        re.compile(rf"(?<![A-Za-z0-9]){re.escape(name)}(?![A-Za-z0-9])", re.IGNORECASE)
        for name in sorted(identity_names)
    ]
    hits = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path in skip:
            continue
        data = path.read_bytes()
        if b"\x00" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(root).as_posix()
        for label, pattern in _REDACTION_PATTERNS:
            for match in pattern.finditer(text):
                if not _is_placeholder(match.group("name")):
                    hits.append(f"{rel}: {label}: {match.group(0).strip()}")
        for pattern in name_patterns:
            for match in pattern.finditer(text):
                hits.append(f"{rel}: local account or host name: {match.group(0)}")
    return hits


def _git_ignored(root: Path) -> frozenset:
    out = _git("ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", str(root))
    if not out:
        return frozenset()
    return frozenset(REPO_ROOT / name for name in out.decode("utf-8").split("\0") if name)


def test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses() -> None:
    """E3S-2 / E5S-1: every text file of the batch folder (records and
    evidence, not git-ignored) holds no home path, account or host name,
    junit host attribute, shell prompt, UNC host path or LAN address."""
    inc2_dir = EVIDENCE_ROOT / "inc-2"
    if not inc2_dir.is_dir():
        pytest.fail(
            "the increment's evidence folder is missing from this checkout; "
            "the redaction gate has nothing it is responsible for"
        )
    hits = _redaction_hits(BATCH_ROOT, _local_identity_names(), _git_ignored(BATCH_ROOT))
    assert not hits, "unredacted batch records or evidence:\n" + "\n".join(hits)


_PLANTED_LEAKS = {
    "posix home path outside the runner image": "cd /home/alice/work",
    "user-profile path": "C:\\Users\\alice\\proj",
    "unix-style user-profile path": "ls /mnt/c/Users/alice and /Users/bob",
    "pytest temp folder of an account": "/tmp/pytest-of-alice/pytest-3",
    "junit hostname attribute": '<testsuite hostname="build-box-7">',
    "shell prompt user@host": "alice@build-box-7:~$ pytest",
    "unc host path": "copied to \\\\fileserver01\\share",
    "lan address": "ssh to 192.168.7.20",
    "local account or host name": "probe-identity-xq7 ran it",
}


def test_r_tst_070_3_redaction_gate_names_each_leak_form(tmp_path) -> None:
    """E5S-1 negative control: one planted line per form, each named; the
    placeholder spellings of the records are not."""
    for index, (form, line) in enumerate(_PLANTED_LEAKS.items()):
        (tmp_path / f"leak{index}.xml").write_text(line + "\n", encoding="utf-8")
    (tmp_path / "clean.md").write_text(
        "<HOME>/Github and /home/runner/work, /tmp/pytest-of-<USER>/x, "
        'hostname="<host>", user@host:~$, \\\\HOST\\share, /Users/<name>\n',
        encoding="utf-8",
    )
    (tmp_path / "blob.bin").write_bytes(b"\x00/home/alice")
    hits = _redaction_hits(tmp_path, {"probe-identity-xq7"})
    named = {hit.split(": ")[1] for hit in hits}
    assert named == set(_PLANTED_LEAKS), hits
    assert not [hit for hit in hits if hit.startswith(("clean.md", "blob.bin"))], hits


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
