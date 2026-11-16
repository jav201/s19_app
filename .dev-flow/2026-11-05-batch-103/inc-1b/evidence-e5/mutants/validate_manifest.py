#!/usr/bin/env python3
"""Static and collection-only validation for the Inc 1b E5 mutant manifest."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import importlib.util

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("e5_run_mutants", HERE / "run_mutants.py")
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
INC = HERE.parent.parent
PLAN = INC / "E5-mutant-plan.md"
BASELINE = "287b9dc3c5e18614ea50a053ef183d80dac59dfc"
GROUP_COUNTS = {"GA": 16, "GT": 8, "GQ": 15, "GC": 21, "GN": 9, "GW": 4}
V = "tests/test_b103_copy_views.py"
TAIL = "tests/test_b103_clipboard_tail.py"
CORRECTED = {
    "GA-A04": [
        f"{V}::test_r_copy_4_full_row_names[R-COPY.4/1]",
        f"{V}::test_r_copy_4_full_row_names[R-COPY.4/3]",
    ],
    "GA-A06": [
        f"{V}::test_r_copy_4_full_row_names[R-COPY.4/1]",
        f"{V}::test_r_copy_4_full_row_names[R-COPY.4/3]",
    ],
    "GA-A14": [
        f"{V}::test_r_copy_15_right_click_clears_selection[R-COPY.15/1]",
        f"{V}::test_r_copy_15_right_click_clears_selection[R-COPY.15/2]",
        f"{V}::test_r_copy_15_right_click_clears_selection[R-COPY.15/3]",
    ],
    "GT-T03": [
        f"{V}::test_r_copy_21_valid_right_click_highlights_without_selection[R-COPY.21/1]",
        f"{V}::test_r_copy_21_valid_right_click_highlights_without_selection[R-COPY.21/2]",
    ],
    "GT-T04": [
        f"{V}::test_r_copy_22_right_click_does_not_jump_hex[R-COPY.22/1]",
        f"{V}::test_r_copy_22_right_click_does_not_jump_hex[R-COPY.22/2]",
    ],
    "GT-T08": [
        f"{V}::test_r_copy_4_full_row_names[R-COPY.4/1]",
        f"{V}::test_r_copy_4_full_row_names[R-COPY.4/2]",
        f"{V}::test_r_copy_4_full_row_names[R-COPY.4/3]",
    ],
    "GC-C01": [
        f"{V}::test_r_copy_1_ctrl_c_writes_each_view[R-COPY.1/{index}]"
        for index in range(1, 7)
    ],
    "GC-C03": [
        f"{V}::test_r_copy_10_one_osc52_request[R-COPY.10/{index}]"
        for index in range(1, 4)
    ],
}


def original_plan(repo: Path) -> str:
    relative = ".dev-flow/2026-11-05-batch-103/inc-1b/E5-mutant-plan.md"
    completed = subprocess.run(
        ["git", "-C", str(repo), "show", f"{BASELINE}:{relative}"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout


def validate_data(
    data: dict,
    repo: Path,
    plan_text: str | None = None,
    original_text: str | None = None,
    collected: set[str] | None = None,
) -> tuple[list[str], dict]:
    errors: list[str] = []
    mutants = data.get("mutants", [])
    by_id = {m.get("id"): m for m in mutants}
    if len(by_id) != len(mutants):
        errors.append("duplicate mutant IDs")
    if data.get("baseline_commit") != BASELINE:
        errors.append("baseline_commit mismatch")
    if data.get("product_aliases") != {
        "app.py": "s19_app/tui/app.py",
        "os_clipboard_input.py": "s19_app/tui/os_clipboard_input.py",
    }:
        errors.append("product aliases mismatch")
    actual_group_counts = {group: sum(m.get("group") == group for m in mutants) for group in GROUP_COUNTS}
    if actual_group_counts != GROUP_COUNTS:
        errors.append(f"group counts mismatch: {actual_group_counts}")
    if len(mutants) != 73:
        errors.append(f"mutant count {len(mutants)} != 73")
    expected_blocked = {"GC-C14", "GW-W01", "GW-W02", "GW-W03", "GW-W04"}
    actual_blocked = {m["id"] for m in mutants if not m.get("runnable", True)}
    if actual_blocked != expected_blocked:
        errors.append(f"blocked set mismatch: {sorted(actual_blocked)}")
    for mutant in mutants:
        mutant_id = mutant.get("id", "<missing>")
        expected_baseline = "W" if mutant.get("group") == "GW" else "L"
        if mutant.get("baseline") != expected_baseline:
            errors.append(f"{mutant_id}: baseline mismatch")
        if mutant.get("source") not in set(data.get("product_aliases", {}).values()):
            errors.append(f"{mutant_id}: unexpanded or unauthorized product path")
        if not mutant.get("tests"):
            errors.append(f"{mutant_id}: empty test set")
        for node in mutant.get("tests", []):
            if not node.startswith("tests/") or "::" not in node:
                errors.append(f"{mutant_id}: unexpanded test alias {node}")
        source = repo / mutant.get("source", "")
        try:
            original_bytes = source.read_bytes()
            text = original_bytes.decode("utf-8")
            count = text.count(mutant["old"])
            if count != 1:
                errors.append(f"{mutant_id}: anchor count={count}, required=1")
            else:
                changed = text.replace(mutant["old"], mutant["new"], 1).encode("utf-8")
                if changed == original_bytes:
                    errors.append(f"{mutant_id}: replacement is a no-op")
                restored = original_bytes
                if hashlib.sha256(restored).hexdigest() != hashlib.sha256(original_bytes).hexdigest():
                    errors.append(f"{mutant_id}: in-memory restore failed")
        except (OSError, KeyError, UnicodeError) as exc:
            errors.append(f"{mutant_id}: anchor read failed: {exc}")
    corrected_nodes = [node for nodes in CORRECTED.values() for node in nodes]
    if len(corrected_nodes) != 23 or len(set(corrected_nodes)) != 19:
        errors.append(
            f"corrected oracle counts={(len(corrected_nodes), len(set(corrected_nodes)))}, "
            "required=(23 expansions, 19 distinct)"
        )
    for mutant_id, expected_nodes in CORRECTED.items():
        actual = by_id.get(mutant_id, {}).get("tests", [])
        missing = [node for node in expected_nodes if node not in actual]
        if missing:
            errors.append(f"{mutant_id}: missing corrected selectors {missing}")
    all_tests = [node for m in mutants for node in m.get("tests", [])]
    all_functions = {node.split("[")[0] for node in all_tests}
    if len(all_tests) != 132:
        errors.append(f"expanded test reference count={len(all_tests)}, expected=132")
    if len(all_functions) != 58:
        errors.append(f"distinct test function count={len(all_functions)}, expected=58")
    if collected is not None:
        missing_nodes = sorted(set(all_tests) - collected)
        if missing_nodes:
            errors.append(f"pytest collection missing {len(missing_nodes)} selected nodes: {missing_nodes}")
        if len(collected) != data["baseline_linux"]["collected"]:
            errors.append(f"collected={len(collected)}, expected={data['baseline_linux']['collected']}")
        missing_skips = sorted(set(data["baseline_linux"]["skipped_nodes"]) - collected)
        if missing_skips:
            errors.append(f"declared skip nodes absent from collection: {missing_skips}")
    baseline = data.get("baseline_linux", {})
    if (baseline.get("passed"), baseline.get("skipped"), baseline.get("collected")) != (123, 19, 142):
        errors.append("Linux baseline counts mismatch")
    if len(set(baseline.get("skipped_nodes", []))) != 19:
        errors.append("Linux baseline must declare 19 distinct skip nodes")
    if plan_text is not None:
        if BASELINE not in plan_text or "e8f8e3d1" in plan_text or "25563883" in plan_text:
            errors.append("plan baseline is not exclusively the pinned HEAD")
        for mutant_id, expected_nodes in CORRECTED.items():
            rows = [line for line in plan_text.splitlines() if line.startswith(f"| {mutant_id} |")]
            if len(rows) != 1:
                errors.append(f"{mutant_id}: plan row count={len(rows)}")
                continue
            for node in expected_nodes:
                if node not in rows[0]:
                    errors.append(f"{mutant_id}: plan lacks full node {node}")
        table_lines = [line for line in plan_text.splitlines() if line.startswith("| G")]
        app_aliases = sum(len(re.findall(r"`app\.py(?::[^`]*)?`", line)) for line in table_lines)
        tail_aliases = sum(len(re.findall(r"`os_clipboard_input\.py(?::[^`]*)?`", line)) for line in table_lines)
        if (app_aliases, tail_aliases) != (40, 22):
            errors.append(f"abbreviated product routes={(app_aliases, tail_aliases)}, expected=(40, 22)")
        q10_rows = [line for line in table_lines if line.startswith("| GQ-Q10 |")]
        if len(q10_rows) != 1 or "después de `(\"g\", \"focus_goto\", \"Go-to\"),`" not in q10_rows[0] or "antes de `(\"q\", \"help_quit\", \"Quit\"),`" not in q10_rows[0]:
            errors.append("GQ-Q10 insertion position is not explicit")
    if original_text is not None:
        original_functions = set(re.findall(r"(?:V|Tail|Q|AT|tests/test_b103_[a-z_]+\.py)::([A-Za-z0-9_]+)", original_text))
        original_functions.update(
            {
                "test_r_copy_25_1_view_and_row_nul_fail_closed",
                "test_r_copy_25_2_every_direct_box_route_nul_fail_closed",
                "test_r_copy_25_3_nul_only_after_cap_is_allowed",
                # 287b9dc3 rebase: GC-C20 adds this transport oracle on purpose.
                "test_e5_powershell_preserves_lf_and_emits_bom_free_readers",
            }
        )
        manifest_functions = {node.rsplit("::", 1)[1].split("[")[0] for node in all_tests}
        if manifest_functions != original_functions:
            errors.append(
                f"test function scope changed: added={sorted(manifest_functions-original_functions)} "
                f"removed={sorted(original_functions-manifest_functions)}"
            )
    counts = {
        "mutants": len(mutants),
        "groups": actual_group_counts,
        "linux": sum(m.get("baseline") == "L" for m in mutants),
        "winci": sum(m.get("baseline") == "W" for m in mutants),
        "linux_runnable": sum(m.get("baseline") == "L" and m.get("runnable", True) for m in mutants),
        "blocked": len(actual_blocked),
        "corrected_rows": len(CORRECTED),
        "corrected_parameterized_nodes": len(corrected_nodes),
        "corrected_distinct_nodes": len(set(corrected_nodes)),
        "expanded_test_references": len(all_tests),
        "distinct_test_nodes": len(set(all_tests)),
        "distinct_test_functions": len(all_functions),
        "collected_nodes": len(collected) if collected is not None else None,
        "abbreviated_product_routes": {"app.py": 40, "os_clipboard_input.py": 22},
    }
    return errors, counts


def negative_controls(data: dict, repo: Path) -> dict:
    outcomes = {}
    bad_anchor = copy.deepcopy(data)
    bad_anchor["mutants"][0]["old"] = "DEFINITELY-NOT-PRESENT\n"
    errors, _ = validate_data(bad_anchor, repo)
    outcomes["zero_anchor_is_rejected"] = any("anchor count=0" in error for error in errors)
    bad_selector = copy.deepcopy(data)
    bad_selector["mutants"][3]["tests"] = bad_selector["mutants"][3]["tests"][:-3]
    errors, _ = validate_data(bad_selector, repo)
    outcomes["missing_23rd_style_selector_is_rejected"] = any("GA-A04: missing corrected selectors" in error for error in errors)
    bad_baseline = copy.deepcopy(data)
    bad_baseline["baseline_commit"] = "25563883f24ad96ee52881628bb06d56b4e0c597"
    errors, _ = validate_data(bad_baseline, repo)
    outcomes["wrong_baseline_is_rejected"] = "baseline_commit mismatch" in errors
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--collect", action="store_true", help="pytest collection only; execute zero tests")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        print("This validation must run on Linux", file=sys.stderr)
        return 2
    repo = args.repo_root.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    data = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    ast.parse((HERE / "run_mutants.py").read_text(encoding="utf-8"))
    ast.parse((HERE / "validate_manifest.py").read_text(encoding="utf-8"))
    actual_head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()
    collection = None
    collection_result = None
    if args.collect:
        collection_result = runner.collect_nodes(repo, output / "collection", 300, data["test_files"])
        collection = set(collection_result["collected_nodes"])
    errors, counts = validate_data(
        data,
        repo,
        PLAN.read_text(encoding="utf-8"),
        original_plan(repo),
        collection,
    )
    if actual_head != BASELINE:
        errors.append(f"repo HEAD={actual_head}, expected={BASELINE}")
    if collection_result is not None and (collection_result["returncode"] != 0 or collection_result["timeout"]):
        errors.append(f"pytest collection failed: exit={collection_result['returncode']} timeout={collection_result['timeout']}")
    controls = negative_controls(data, repo)
    if not all(controls.values()):
        errors.append(f"validator negative controls failed: {controls}")
    report = {
        "scope": "static anchors plus pytest collection only; zero product tests and zero mutants executed",
        "baseline_commit": BASELINE,
        "actual_head": actual_head,
        "manifest_sha256": runner.sha256_file(HERE / "manifest.json"),
        "runner_sha256": runner.sha256_file(HERE / "run_mutants.py"),
        "validator_sha256": runner.sha256_file(Path(__file__).resolve()),
        "counts": counts,
        "negative_controls": controls,
        "collection": collection_result,
        "errors": errors,
        "verdict": "PASS" if not errors else "FAIL",
    }
    runner.write_json(output / "static-validation.json", report)
    print(json.dumps({"verdict": report["verdict"], "counts": counts, "negative_controls": controls, "errors": errors}, ensure_ascii=False))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
