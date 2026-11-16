"""Independently reconcile M9b results with raw JUnit and render the record."""

import copy
import datetime
import json
import os
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path.home() / "work" / "zq-m9b"
OUT = ROOT / "out"
EXPECTED_COMMIT = "2e80b0d68370c0d4c3eebbc5cf6e325b712769d0"
EXPECTED = {
    "G01": (("N-94a", "R-PE-BENCH.94", 1), ("N-102", "R-PE-BENCH.102", 2)),
    "G02": (("N-94b", "R-PE-BENCH.94", 1),),
    "G03": (("N-95a", "R-PE-BENCH.95", 1),),
    "G04": (("N-95b", "R-PE-BENCH.95", 1),),
    "G05": (("N-96a", "R-PE-BENCH.96", 1),),
    "G06": (("N-96b", "R-PE-BENCH.96", 1),),
    "G07": (("N-97a", "R-PE-BENCH.97", 1),),
    "G08": (("N-97b", "R-PE-BENCH.97", 1),),
    "G09": (("N-98a", "R-PE-BENCH.98", 2),),
    "G10": (("N-98b", "R-PE-BENCH.98", 1), ("N-99", "R-PE-BENCH.99", 1)),
    "G11": (("N-100a", "R-PE-BENCH.100", 3),),
    "G12": (("N-100b", "R-PE-BENCH.100", 3),),
    "G13": (("N-101a", "R-PE-BENCH.101", 6),),
    "G14": (("N-101b", "R-PE-BENCH.101", 2),),
    "G15": (("N-103", "R-PE-BENCH.103", 2),),
    "G16": (("N-104", "R-PE-BENCH.104", 2),),
    "G17": (("N-105", "R-PE-BENCH.105", 3),),
    "G18": (("N-106", "R-PE-BENCH.106", 2),),
    "G19": (("I-CHAIN-98", "R-PE-BENCH.98", 1), ("I-CHAIN-99", "R-PE-BENCH.99", 1)),
    "G20": (("I-TOKEN-DROP", "R-PE-BENCH.106", 1),),
    "G21": (("I-NO-INCREMENT", "R-PE-BENCH.106", 1),),
    "G22": (("I-LATER-RAISE", "R-PE-BENCH.98/2", 1),),
    "G23": (("I-PANEL-GONE", "R-PE-BENCH.98/2", 1),),
}
VALID = {"KILLED", "CRASH", "SURVIVED", "BAD"}
SURVIVOR_ANALYSIS = {
    "N-95b": "show_page appends summary jobs directly to _page (bench_sheet.py:594-598), bypassing the mutated _enqueue; the busy timer stays paused, so the selected node cannot observe the roster mutation.",
}
CRASH_ANALYSIS = {
    "N-97b": "Textual raises WorkerDeclarationError while importing the mutant because thread=False is invalid on this synchronous worker; no test executed.",
    "I-LATER-RAISE": "Deleting the complete except block leaves try without except/finally, so Python raises SyntaxError at import; no test executed.",
}


def junit_node(case):
    return case.attrib.get("classname", "").replace(".", "/") + ".py::" + case.attrib.get("name", "")


def actual_arm(case, baseline=False):
    failures = list(case.findall("failure"))
    errors = list(case.findall("error"))
    skipped = list(case.findall("skipped"))
    if errors:
        return "FAIL" if baseline else "CRASH"
    if failures:
        if baseline:
            return "FAIL"
        text = "\n".join((item.text or "") + "\n" + item.attrib.get("message", "") for item in failures)
        return "KILLED" if re.search(r"(^|\n)\s*(E\s+)?(AssertionError|Failed)(:|\n|$)", text) else "CRASH"
    if skipped:
        return "FAIL" if baseline else "CRASH"
    return "PASS" if baseline else "SURVIVED"


def aggregate(arms):
    verdicts = [arm["verdict"] for arm in arms]
    if "BAD" in verdicts:
        return "BAD"
    if "CRASH" in verdicts:
        return "CRASH"
    if "KILLED" in verdicts:
        return "KILLED"
    return "SURVIVED"


def reconcile(payload, check_xml=True):
    errors = []
    if payload.get("commit") != EXPECTED_COMMIT:
        errors.append("wrong source commit")
    results = payload.get("results", [])
    by_group = {item.get("group"): item for item in results}
    if len(by_group) != len(results):
        errors.append("duplicate group result")
    if set(by_group) != set(EXPECTED):
        errors.append(f"group census mismatch: {sorted(by_group)}")
    for group_id, expected_controls in EXPECTED.items():
        result = by_group.get(group_id)
        if result is None:
            continue
        expected_arm_count = sum(item[2] for item in expected_controls)
        if result.get("expected_arms") != expected_arm_count:
            errors.append(f"{group_id}: declared arm count mismatch")
        if len(result.get("nodes", [])) != expected_arm_count:
            errors.append(f"{group_id}: node union count mismatch")
        controls = result.get("controls", [])
        actual_signature = tuple((c.get("id"), c.get("requirement"), len(c.get("arms", []))) for c in controls)
        if actual_signature != expected_controls:
            errors.append(f"{group_id}: control/requirement/arm signature mismatch: {actual_signature}")
        baseline = result.get("baseline")
        mutant = result.get("mutant")
        baseline_arms = baseline.get("arms") if baseline else None
        baseline_invalid = baseline is not None and (
            baseline.get("rc") != 0
            or not isinstance(baseline_arms, dict)
            or len(baseline_arms) != expected_arm_count
            or any(arm.get("verdict") != "PASS" for arm in baseline_arms.values())
        )
        if baseline_invalid:
            if not controls or any(c.get("verdict") != "BAD" for c in controls):
                errors.append(f"{group_id}: invalid baseline did not produce BAD controls")
            if mutant is not None or result.get("mutation_receipts"):
                errors.append(f"{group_id}: invalid baseline nevertheless applied/ran a mutant")
            preflight = baseline.get("preflight", {})
            if not preflight or float(preflight.get("load_one", 99)) >= 1.0:
                errors.append(f"{group_id}/baseline: quiet-host predicate failed")
            if preflight.get("other_test_jobs") != 0:
                errors.append(f"{group_id}/baseline: concurrent test job predicate failed")
            transcript = OUT / baseline.get("transcript", "absent")
            if not transcript.exists() or transcript.stat().st_size == 0:
                errors.append(f"{group_id}/baseline: invalid-baseline transcript absent or empty")
            elif f"EXIT_CODE {baseline.get('rc')}" not in transcript.read_text(encoding="utf-8"):
                errors.append(f"{group_id}/baseline: transcript exit code mismatch")
            if check_xml:
                path = ROOT / "groups" / group_id / "baseline.xml"
                if path.exists():
                    try:
                        cases = list(ET.parse(path).getroot().iter("testcase"))
                    except (OSError, ET.ParseError) as exc:
                        errors.append(f"{group_id}/baseline: raw XML unreadable: {exc}")
                    else:
                        nodes = [junit_node(case) for case in cases]
                        if len(nodes) != expected_arm_count or set(nodes) != set(result["nodes"]):
                            errors.append(f"{group_id}/baseline: invalid baseline selection mismatch")
                        for node, case in zip(nodes, cases):
                            actual = actual_arm(case, baseline=True)
                            reported = baseline_arms.get(node, {}).get("verdict") if isinstance(baseline_arms, dict) else None
                            if actual != reported:
                                errors.append(f"{group_id}/{node}: invalid baseline {reported} != raw XML {actual}")
                elif baseline.get("rc") == 0:
                    errors.append(f"{group_id}/baseline: green claim without raw XML")
            continue
        if baseline is None or mutant is None:
            errors.append(f"{group_id}: baseline or mutant phase absent")
            continue
        if baseline.get("rc") != 0 or baseline.get("error"):
            errors.append(f"{group_id}: baseline not green")
        baseline_arms = baseline.get("arms", {})
        if len(baseline_arms) != expected_arm_count or any(
            arm.get("verdict") != "PASS" for arm in baseline_arms.values()
        ):
            errors.append(f"{group_id}: incomplete baseline PASS census")
        for phase, run in (("baseline", baseline), ("mutant", mutant)):
            preflight = run.get("preflight", {})
            if not preflight or float(preflight.get("load_one", 99)) >= 1.0:
                errors.append(f"{group_id}/{phase}: quiet-host predicate failed")
            if preflight.get("other_test_jobs") != 0:
                errors.append(f"{group_id}/{phase}: concurrent test job predicate failed")
            transcript = OUT / run.get("transcript", "absent")
            if not transcript.exists() or transcript.stat().st_size == 0:
                errors.append(f"{group_id}/{phase}: transcript absent or empty")
            elif f"EXIT_CODE {run.get('rc')}" not in transcript.read_text(encoding="utf-8"):
                errors.append(f"{group_id}/{phase}: transcript exit code mismatch")
        receipts = result.get("mutation_receipts", {})
        if not receipts or sum(sum(counts) for counts in receipts.values()) < 1:
            errors.append(f"{group_id}: zero-applied mutation")
        xml_cases = {}
        if check_xml:
            for phase in ("baseline", "mutant"):
                path = ROOT / "groups" / group_id / f"{phase}.xml"
                try:
                    cases = list(ET.parse(path).getroot().iter("testcase"))
                except (OSError, ET.ParseError) as exc:
                    crash_without_xml = (
                        phase == "mutant"
                        and mutant.get("rc") != 0
                        and all(
                            arm.get("verdict") == "CRASH"
                            for control in controls
                            for arm in control.get("arms", [])
                        )
                    )
                    if not crash_without_xml:
                        errors.append(f"{group_id}/{phase}: raw XML unreadable: {exc}")
                    continue
                nodes = [junit_node(case) for case in cases]
                if len(nodes) != expected_arm_count or set(nodes) != set(result["nodes"]):
                    errors.append(f"{group_id}/{phase}: raw XML selection mismatch")
                if len(nodes) != len(set(nodes)):
                    errors.append(f"{group_id}/{phase}: duplicate raw XML node")
                xml_cases[phase] = dict(zip(nodes, cases))
        for control_result in controls:
            for arm in control_result.get("arms", []):
                if arm.get("verdict") not in VALID:
                    errors.append(f"{group_id}/{control_result.get('id')}: invalid arm verdict")
                if arm.get("node") not in result.get("nodes", []):
                    errors.append(f"{group_id}/{control_result.get('id')}: arm outside group union")
                if check_xml and arm.get("node") in xml_cases.get("mutant", {}):
                    actual = actual_arm(xml_cases["mutant"][arm["node"]])
                    if actual != arm["verdict"]:
                        errors.append(
                            f"{group_id}/{arm['node']}: reported {arm['verdict']} != raw XML {actual}"
                        )
                if check_xml and arm.get("node") in xml_cases.get("baseline", {}):
                    actual = actual_arm(xml_cases["baseline"][arm["node"]], baseline=True)
                    if actual != "PASS":
                        errors.append(f"{group_id}/{arm['node']}: raw baseline is {actual}")
            if control_result.get("arms") and control_result.get("verdict") != aggregate(control_result["arms"]):
                errors.append(f"{group_id}/{control_result.get('id')}: control aggregate mismatch")
    return errors


def short_node(node):
    for prefix, alias in (
        ("tests/test_b103_inc9b_w.py::", "W::"),
        ("tests/test_b103_inc9b_s.py::", "S::"),
        ("tests/test_b103_inc9b_at.py::", "AT::"),
    ):
        if node.startswith(prefix):
            return alias + node[len(prefix):]
    return node


def transcript_summary(group_id, phase="mutant"):
    path = OUT / f"{group_id}-{phase}.txt"
    lines = path.read_text(encoding="utf-8").splitlines()
    for line in reversed(lines):
        if re.search(r"\b(passed|failed|errors?|skipped)\b", line) and " in " in line:
            return line.strip("= ")
    exit_lines = [line for line in lines if line.startswith("EXIT_CODE ")]
    return exit_lines[-1] if exit_lines else "see transcript and per-arm summary"


def render(payload):
    results = payload["results"]
    controls = [c for result in results for c in result["controls"]]
    counts = {verdict: sum(c["verdict"] == verdict for c in controls) for verdict in sorted(VALID)}
    arm_counts = {
        verdict: sum(arm["verdict"] == verdict for c in controls for arm in c["arms"])
        for verdict in sorted(VALID)
    }
    loads = [
        run["preflight"]["load_one"]
        for result in results
        for run in (result.get("baseline"), result.get("mutant"))
        if run is not None
    ]
    run_date = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()
    lines = [
        "# Inc 9b E4 - mechanical mutant run (M9b)",
        "",
        f"Run record: `{run_date}`; source `b103-inc9b` at `{EXPECTED_COMMIT}`.",
        "Population: 26 runnable controls in 23 fresh-copy groups, 43 resolved node arms; three declared coverage holes are MISSING, not run and not scored as kills or survivors.",
        "",
        "## Method and harness proof",
        "",
        "- Every group used a newly extracted copy of the exact source archive under `~/work/zq-m9b/groups/`; no real worktree was mutated. A mutant was scored only after its full node union resolved to the required arm count and passed on the unmutated copy; an invalid baseline is BAD and applies no mutant.",
        "- Exact old-expression anchors matched once per edit; zero or multiple matches were application failures. Mutation receipts are in `results.json`; `anchor-check.txt` covers all 23 groups before execution.",
        "- Pytest used the isolated HT-02/HT-03 environment, `PYTHONDONTWRITEBYTECODE=1`, `timeout 300`, `-n 0`, no cache provider, and an import-location probe at the head of every transcript. Every baseline and mutant preflight required one-minute load < 1.0 and zero other test/Q9b jobs.",
        f"- Recorded pre-run one-minute loads ranged from {min(loads):.2f} to {max(loads):.2f}. No loaded-host verdict was accepted. Host cleanup used only recorded PID/SID values; `host_m9b.sh` builds its verification pattern at runtime.",
        "- Per-arm verdicts were parsed from JUnit, never inferred from a process exit code. `selftest.txt` proves rejection of zero application and empty selection, plus KILLED/CRASH/SURVIVED classification on synthetic known-answer inputs.",
        "- `validation.txt` independently reconciles the 23-group/26-control/43-arm census, GREEN baselines, quiet preflight, mutation receipts, control aggregates, and every reported arm against raw JUnit. Its deliberately corrupted result and empty-census controls are rejected.",
        "",
        "Test aliases: `W` = `tests/test_b103_inc9b_w.py`; `S` = `tests/test_b103_inc9b_s.py`; `AT` = `tests/test_b103_inc9b_at.py`. Evidence paths below are relative to `inc-9b/`.",
        "",
        "## Control table",
        "",
        "| control id | requirement | mutation (file:line, one line) | tests run | verdict | evidence line |",
        "|---|---|---|---|---|---|",
    ]
    for result in results:
        for control_result in result["controls"]:
            tests = "<br>".join(f"`{short_node(node)}`" for node in control_result["nodes"])
            phase = "mutant" if result.get("mutant") is not None else "baseline"
            suffix = "per-arm `summary.tsv`" if phase == "mutant" else "baseline invalid; mutation not applied"
            evidence = (
                f"`evidence-e4/mutants/{result['group']}-{phase}.txt` — "
                f"{transcript_summary(result['group'], phase)}; {suffix}"
            )
            lines.append(
                f"| {control_result['id']} | {control_result['requirement']} | {control_result['mutation']} "
                f"| {tests} | {control_result['verdict']} | {evidence} |"
            )
    for missing in payload["missing"]:
        lines.append(
            f"| {missing['id']} | {missing['requirement']} | Declared copy-only mutation not applied; no discriminating node "
            f"| none — declared HOLD | MISSING | {missing['reason']} |"
        )
    lines.extend([
        "",
        "## Score",
        "",
        f"- Runnable controls: **{counts['KILLED']} KILLED / 26** ({counts['KILLED'] / 26 * 100:.1f}%), "
        f"{counts['SURVIVED']} SURVIVED, {counts['CRASH']} CRASH, {counts['BAD']} BAD.",
        f"- Resolved node arms: **43 total** — "
        + ", ".join(f"{arm_counts[v]} {v}" for v in ("KILLED", "SURVIVED", "CRASH", "BAD"))
        + ". A control with a killing arm and another green arm remains KILLED at control level; every green arm stays visible below.",
        "- Three MISSING controls are excluded from the kill denominator: I-APPLY-SYNC, I-LOAD-SYNC, I-MOUNT-ONCE.",
        "",
        "## Per-arm verdicts",
        "",
        "The machine-readable ledger is `evidence-e4/mutants/summary.tsv`; the same verdicts are enumerated here.",
        "",
        "| group | control | resolved node | verdict |",
        "|---|---|---|---|",
    ])
    for result in results:
        for control_result in result["controls"]:
            for arm in control_result["arms"]:
                lines.append(
                    f"| {result['group']} | {control_result['id']} | `{short_node(arm['node'])}` | {arm['verdict']} |"
                )
    survivors = [c for c in controls if c["verdict"] == "SURVIVED"]
    surviving_arms = [
        (result["group"], c, arm)
        for result in results
        for c in result["controls"]
        for arm in c["arms"]
        if arm["verdict"] == "SURVIVED"
    ]
    lines.extend(["", "## Survivors and missing coverage", ""])
    if not surviving_arms:
        lines.append("No surviving control or surviving resolved arm.")
    else:
        for control_result in survivors:
            analysis = SURVIVOR_ANALYSIS.get(
                control_result["id"],
                f"the selected node set stayed GREEN after {control_result['mutation']}; those assertions do not discriminate this mutation.",
            )
            lines.append(
                f"- **{control_result['id']} ({control_result['requirement']}) SURVIVED:** {analysis}"
            )
        for group_id, control_result, arm in surviving_arms:
            if control_result["verdict"] != "SURVIVED":
                if control_result["id"] == "N-101a" and "101_5" in arm["node"]:
                    analysis = "the stale generation is dropped in _job_done (bench_sheet.py:254-266) before RecordStageRequested; none of the three mutated refusal/result cleanup paths executes, although sibling arms kill the control."
                else:
                    analysis = f"this node stayed GREEN although a sibling arm killed the control; it provides no discrimination for {control_result['mutation']}."
                lines.append(
                    f"- **{control_result['id']} surviving arm {short_node(arm['node'])}:** {analysis}"
                )
    for missing in payload["missing"]:
        lines.append(f"- **{missing['id']} MISSING:** {missing['reason']}")
    lines.extend(["", "## CRASH and BAD outcomes", ""])
    exceptional = [
        (result, control_result)
        for result in results
        for control_result in result["controls"]
        if control_result["verdict"] in ("CRASH", "BAD")
    ]
    if not exceptional:
        lines.append("None.")
    for result, control_result in exceptional:
        details = sorted({arm["detail"] for arm in control_result["arms"]})
        if control_result["verdict"] == "CRASH":
            analysis = CRASH_ANALYSIS.get(control_result["id"], "; ".join(details))
        elif result["group"] in ("G10", "G19"):
            analysis = "The two-node baseline union timed out at 300 seconds after one completed arm in both the initial fresh copy and the low-load fresh retry; no mutant was applied, so this is neither a kill nor a survivor."
        else:
            analysis = "; ".join(details)
        lines.append(
            f"- **{control_result['id']} {control_result['verdict']}:** "
            f"{analysis} See `{result['group']}-mutant.txt` when present; otherwise the invalid-baseline transcript and `retries.txt`."
        )
    lines.extend([
        "",
        "## Evidence and limits",
        "",
        "- `anchor-check.txt`, `selftest.txt`, `validation.txt`, `results.json`, `summary.tsv`, `DONE`, every executed-phase transcript, and preserved first-attempt/retry records are stored byte-for-byte under `evidence-e4/mutants/` (`-text` inherited from the batch rule).",
        "- The mutation, driver, host, retry, and independent validator/render scripts make the execution and PID/SID-scoped cleanup auditable. `cleanup.txt` confirms both recorded drivers had exited and `~/work/zq-m9b` was removed by the explicit created-path list in `host_m9b.sh`.",
        "- An initial archive transfer was rejected as empty before anchor checks or test execution. Its scratch was explicitly deleted and re-created; no result from that attempt is included.",
        "- Timing nodes were used only as mutation oracles on a quiet host. This record does not change any timing bound or make a separate performance decision.",
        "",
    ])
    return "\n".join(lines)


def main():
    payload = json.loads((OUT / "results.json").read_text(encoding="utf-8"))
    errors = reconcile(payload)
    corrupted = copy.deepcopy(payload)
    first = corrupted["results"][0]["controls"][0]
    first["arms"][0]["verdict"] = "SURVIVED"
    first["verdict"] = "SURVIVED"
    negative_errors = reconcile(corrupted, check_xml=True)
    empty_errors = reconcile({"commit": EXPECTED_COMMIT, "results": []}, check_xml=False)
    if not negative_errors or not empty_errors:
        errors.append("validator negative control failed")
    validation_lines = [
        f"DATE {datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()}",
        f"GROUPS {len(payload.get('results', []))}",
        f"CONTROLS {sum(len(r['controls']) for r in payload.get('results', []))}",
        f"ARMS {sum(len(c['arms']) for r in payload.get('results', []) for c in r['controls'])}",
        f"CORRUPTED_RESULT_REJECTIONS {len(negative_errors)}",
        f"EMPTY_CENSUS_REJECTIONS {len(empty_errors)}",
    ]
    if errors:
        validation_lines.append("VALIDATION FAIL")
        validation_lines.extend(f"ERROR {error}" for error in errors)
    else:
        validation_lines.append("VALIDATION PASS")
        validation_lines.append("CORRUPTED_RESULT_CONTROL REJECTED")
        validation_lines.append("EMPTY_CENSUS_CONTROL REJECTED")
    (OUT / "validation.txt").write_text("\n".join(validation_lines) + "\n", encoding="utf-8", newline="\n")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    (OUT / "E4-mutants.md").write_text(render(payload), encoding="utf-8", newline="\n")
    print("VALIDATION PASS; E4-mutants.md rendered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
