from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import sys
import traceback

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from redaction import redact

INC = Path(__file__).resolve().parents[1]
ROOT = INC.parents[2]


def rows(text: str) -> list[list[str]]:
    return [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in text.splitlines()
        if line.startswith("| R-A2L-REFRESH.")
    ]


def main(fault: str | None = None) -> None:
    req = (INC / "01-requirements.md").read_text(encoding="utf-8")
    cases = (INC / "02-test-cases.md").read_text(encoding="utf-8")
    slice_text = (INC / "E1-slice.md").read_text(encoding="utf-8")
    rulings = (INC / "E1-rulings.md").read_text(encoding="utf-8")

    requirements = rows(req)
    expected_ids = [
        f"R-A2L-REFRESH.{number:03d}" if fault != "initial" else f"R-A2L-REFRESH.{number}"
        for number in range(39, 49)
    ]
    assert [row[0] for row in requirements] == expected_ids
    for row in requirements:
        assert len(row) == 7, row
        identifier, form, sentence, threshold, control, stories, status = row
        assert form in {"U", "When", "While", "If", "Where"}
        assert sentence.count("shall") == 1
        subject = sentence if fault == "case" else sentence.lower()
        assert "the system shall" in subject
        assert sentence.endswith(".") and ". " not in sentence
        assert re.search(r"\b\d+/\d+\b", threshold)
        assert "RED" in control
        assert "US-" in stories
        assert status == "new"
    assert "5/5 routes" in requirements[0][3]
    for row in requirements[1:4]:
        assert row[1] == "When"
        for expected in ("45 s", "60 s", "E1 host", "responsive"):
            assert expected in row[2]
        for expected in ("parse", "50 ms", "100 ms", "61 s"):
            assert expected in row[3] or expected in row[4]
    assert "2/2 project shapes" in requirements[2][3]
    for index, expected in ((4, "4/4 routes"), (6, "3/3"), (8, "6/6"), (9, "12/12")):
        assert expected in requirements[index][3], requirements[index][0]
    same_path = requirements[8]
    assert "changed artifact's generation strictly increases" in same_path[3]
    assert "unchanged source content/bytes remain byte-identical" in same_path[3]
    assert "may increment an unchanged artifact's generation" in same_path[3]
    assert "unchanged artifact generation is unchanged" not in same_path[3]
    print("REQUIREMENTS count=10 EARS=10 thresholds=10 negative_controls=10 total_budgets=3 same_path_content_generation=resolved adverse_thresholds=4/4,3/3,6/6,12/12")

    ledger_source = rows(cases)
    ledger = ledger_source if fault == "ledger" else [row for row in ledger_source if len(row) == 5]
    assert len(ledger) == 39
    counts = Counter(row[0].split("/")[0] for row in ledger)
    expected_counts = dict(zip(expected_ids, (5, 1, 2, 1, 4, 3, 3, 2, 6, 12)))
    assert counts == expected_counts, counts
    assert len({row[0] for row in ledger}) == 39
    assert len({row[1] for row in ledger}) == 39
    case_ids = {row[0] for row in ledger}
    new_cases = {
        "R-A2L-REFRESH.039/5",
        "R-A2L-REFRESH.041/2",
        "R-A2L-REFRESH.043/4",
        "R-A2L-REFRESH.045/3",
        "R-A2L-REFRESH.047/5",
        "R-A2L-REFRESH.047/6",
        *(f"R-A2L-REFRESH.048/{number}" for number in range(7, 13)),
    }
    assert new_cases <= case_ids
    assert all(len(row) == 5 and row[4] == "full" for row in ledger)
    assert all("tests/test_alp_inc3_" in row[3] and "::test_" in row[3] for row in ledger)
    assert "| Result |" not in cases and "not_run" not in cases and "| verified" not in cases
    assert "19 normal, 4 performance and 16 robustness" in cases
    assert "distinct **collected node id**" in cases
    assert "distinct planned on-disk node" not in cases
    same_path_cases = {row[0]: row[2] for row in ledger if row[0].startswith("R-A2L-REFRESH.047/")}
    assert "A2L generation is unchanged" not in same_path_cases["R-A2L-REFRESH.047/1"]
    for case_id in ("R-A2L-REFRESH.047/2", "R-A2L-REFRESH.047/3", "R-A2L-REFRESH.047/5", "R-A2L-REFRESH.047/6"):
        assert "byte-identical" in same_path_cases[case_id]
        assert "may increment" in same_path_cases[case_id]
    print(f"CASES count=39 classes=19_normal,4_performance,16_robustness per_requirement={dict(counts)} results=absent")

    for path in (
        "s19_app/tui/app/file_load.py",
        "s19_app/tui/app/project_load.py",
        "s19_app/tui/app/loaded_state.py",
        "s19_app/tui/app/shared.py",
    ):
        assert (ROOT / path).is_file() and path in slice_text
    assert "**13**" in slice_text and "4 SOURCE files of at most 4" in slice_text
    assert "12 existing changed + 1 new" in slice_text
    assert "39 distinct collected parameter node ids" in slice_text
    premise_text = (INC / "evidence-e1/premise-census.txt").read_text(encoding="utf-8")
    assert "planned_changed_SOURCE=4" in premise_text
    l1_row = next(line for line in slice_text.splitlines() if line.startswith("| L1 |"))
    assert ".041" in l1_row and ".042" not in l1_row
    assert "A2L-only branch" in slice_text and "without calling L1" in slice_text
    print("SLICE source_files=4 implementation_nodes=13 L1_mapping=041_only_for_image_project")

    lint = json.loads((INC / "codewire/baseline-lint.json").read_text(encoding="utf-8"))
    assert lint["unread"] == []
    baseline_names = {node["name"] for node in lint["nodes"]}
    changed_functions = {
        "FileLoadMixin.load_from_path",
        "FileLoadMixin._load_workarea_file",
        "FileLoadMixin._parse_loaded_file",
        "FileLoadMixin._prepare_load_payload",
        "FileLoadMixin._start_load_worker",
        "ProjectLoadMixin._handle_load_project",
        "ProjectLoadMixin._prepare_project_load",
        "ProjectLoadMixin._install_prepared_project",
        "LoadedStateMixin._apply_prepared_load",
    }
    context_functions = {
        "ProjectLoadMixin._reset_project_session",
        "A2lViewMixin._replace_current_a2l",
        "enrich_tags_and_render",
    }
    assert baseline_names == changed_functions | context_functions
    assert changed_functions.isdisjoint(context_functions)
    assert "9 planned-change functions" in slice_text and "3 unchanged context functions" in slice_text
    marks = json.loads((INC / "codewire/baseline-marks.json").read_text(encoding="utf-8"))
    assert len(marks["placed"]) == 12 and marks["missing"] == [] and marks["conflicts"] == []
    report = (INC / "codewire/baseline-extract/diff-report.md").read_text(encoding="utf-8")
    assert "Findings: 0 (0 drift, 0 info)" in report
    assert "Files that failed to parse: 0" in report
    assert not (INC / "codewire/.throwaway").exists()
    print("CODEWIRE baseline=9_changed_functions+3_context=12 marks=12 unread=0 findings=0 parse_failures=0")

    for number in range(1, 7):
        assert len(re.findall(rf"^P{number:02d} TRUE ", premise_text, re.M)) == 1
    assert "ROUTE_REFERENCE_CENSUS" in premise_text and "python_files=498" in premise_text
    assert "CENSUS_CONTROL TRUE known_present=1 known_absent=0" in premise_text
    for name in ("initial", "second", "route"):
        red = (INC / f"evidence-e1/premise-census-{name}-red.txt").read_text(encoding="utf-8")
        assert "Traceback (most recent call last)" in red and "AssertionError" in red
    print("PREMISES P01_P06=TRUE census_source=132 census_source_and_tests=498 red_controls=3")

    fixture = (INC / "evidence-e1/case06-probe.txt").read_text(encoding="utf-8")
    for expected in ("size_bytes=37742888", "tags=220040", "distinct_names=220040", "errors=0"):
        assert expected in fixture
    assert "s19_app.__file__=<repo>" in fixture and "path=<repo>" in fixture
    path_red = (INC / "evidence-e1/case06-probe-path-red.txt").read_text(encoding="utf-8")
    assert "Traceback (most recent call last)" in path_red and "ModuleNotFoundError" in path_red
    assert "subsequent Qwen retries failed" in rulings
    assert "DeepSeek audited this packet through `pi`" in rulings
    print("FIXTURE case06=220040_tags paths=redacted QWEN=initial_and_retries_failed DEEPSEEK=pi_audit")

    trace = (INC / "evidence-e1/trace-check.txt").read_text(encoding="utf-8")
    assert "2 US, 10 active requirements" in trace
    assert "checks run: US, CASE, TEST, SLICE, EVID, 11 gap(s)" in trace
    assert len(re.findall(r"^TEST   R-A2L-REFRESH\.", trace, re.M)) == 10
    assert len(re.findall(r"^EVID   ", trace, re.M)) == 1
    assert not re.search(r"^(US|CASE|SLICE)   ", trace, re.M)
    print("TRACE US_CASE_SLICE=gaps_0 TEST=gaps_10_planned EVID=gaps_1_future_E5")

    stage = (INC / "evidence-e3/stage-invariant.txt").read_text(encoding="utf-8")
    assert "SYNC P5=true await=0 yield=0" in stage
    assert "SYNC L1=true await=0 yield=0" in stage
    assert "runtime_generation_writers=UI_only STAGE_RACE=unreachable rollback=none" in stage
    assert "BLOCKER none" in stage
    integrated = (INC / "codewire/graph-inc3.md").read_text(encoding="utf-8")
    assert "STAGE_RACE)" not in integrated
    print("STAGE_INVARIANT synchronous_UI=true runtime_writers=UI_only stage_race=removed rollback=none")

    assert redact(f"{ROOT}\\s19_app", ROOT).startswith("<repo>")
    assert redact(str(Path.home() / "probe"), ROOT).startswith("<home>")
    for path in INC.rglob("*"):
        if path.is_file() and path.suffix in {".md", ".py", ".txt", ".json"}:
            text = path.read_text(encoding="utf-8")
            assert str(ROOT) not in text and ROOT.as_posix() not in text, path
            assert not re.search(r"(?i)\b[A-Z]:[\\/]+Users[\\/]+", text), path
            assert not re.search(r"(?i)/(?:home|Users)/[^/\s\"']+", text), path
    print("REDACTION known_root_and_home_controls=true personal_paths=0")
    print("E1_STRUCTURE PASS; no product behavior, test result or performance claim validated")


if __name__ == "__main__":
    fault = None
    if len(sys.argv) > 1:
        if len(sys.argv) != 2 or not sys.argv[1].startswith("--red-case="):
            raise SystemExit("usage: validate_e1.py [--red-case=initial|case|ledger]")
        fault = sys.argv[1].split("=", 1)[1]
        if fault not in {"initial", "case", "ledger"}:
            raise SystemExit("unknown RED case")
    try:
        main(fault)
    except Exception:
        print(redact(traceback.format_exc(), ROOT), end="")
        raise SystemExit(1)
