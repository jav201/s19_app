#!/usr/bin/env python3
"""Mechanical, isolated Linux runner for the Inc 1b E5 mutant manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "manifest.json"
VERDICTS = ("KILLED", "SURVIVED", "CRASH", "BAD")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def require_linux() -> None:
    if sys.platform != "linux":
        raise RuntimeError("This runner is Linux-only; no probe or test may run on this PC")


def require_empty_work_dir(path: Path) -> None:
    if path.exists() and any(path.iterdir()):
        raise RuntimeError(f"Work directory must be new or empty: {path}")
    path.mkdir(parents=True, exist_ok=True)


def isolated_env(state: Path) -> dict[str, str]:
    home = state / "state"
    tmp = state / "tmp"
    for directory in (home, tmp):
        directory.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "PYTHONPATH", "PYTHONSTARTUP"):
        env.pop(name, None)
    env.update(
        {
            "HOME": str(home),
            "TMPDIR": str(tmp),
            "XDG_CONFIG_HOME": str(home / "config"),
            "XDG_DATA_HOME": str(home / "data"),
            "XDG_CACHE_HOME": str(home / "cache"),
            "XDG_RUNTIME_DIR": str(home / "runtime"),
            "LOCALAPPDATA": str(home / "local"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    for name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "LOCALAPPDATA"):
        Path(env[name]).mkdir(parents=True, exist_ok=True)
    return env


def pytest_command(tree: Path, junit: Path, nodes: list[str], import_product: bool) -> list[str]:
    if import_product:
        launcher = (
            "import sys; sys.path.insert(0, sys.argv.pop(1)); "
            "import s19_app; print('s19_app.__file__=' + s19_app.__file__, flush=True); "
            "import pytest; raise SystemExit(pytest.main(sys.argv[1:]))"
        )
    else:
        launcher = (
            "import sys; sys.path.insert(0, sys.argv.pop(1)); "
            "import pytest; raise SystemExit(pytest.main(sys.argv[1:]))"
        )
    return [
        sys.executable,
        "-I",
        "-B",
        "-c",
        launcher,
        str(tree),
        "-q",
        "-p",
        "no:cacheprovider",
        f"--junitxml={junit}",
        *nodes,
    ]


def run_process(
    command: list[str],
    cwd: Path,
    env: dict[str, str],
    transcript: Path,
    timeout: int,
) -> dict:
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    timed_out = False
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGTERM)
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate()
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_bytes(output)
    return {
        "returncode": process.returncode,
        "timeout": timed_out,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "transcript": str(transcript),
        "command": command,
    }


def junit_cases(junit: Path) -> dict[str, str]:
    if not junit.is_file():
        return {}
    root = ET.parse(junit).getroot()
    cases: dict[str, str] = {}
    for case in root.iter("testcase"):
        classname = case.attrib.get("classname", "").replace(".", "/")
        name = case.attrib.get("name", "")
        if not classname or not name:
            raise RuntimeError(f"JUnit testcase lacks classname/name in {junit}")
        node = f"{classname}.py::{name}"
        if node in cases:
            raise RuntimeError(f"Duplicate JUnit node {node}")
        if case.find("skipped") is not None:
            status = "skipped"
        elif case.find("error") is not None:
            status = "error"
        elif case.find("failure") is not None:
            status = "failed"
        else:
            status = "passed"
        cases[node] = status
    return cases


def run_pytest(
    tree: Path,
    nodes: list[str],
    output: Path,
    timeout: int,
    import_product: bool = True,
) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    junit = output / "junit.xml"
    command = pytest_command(tree, junit, nodes, import_product)
    result = run_process(
        command,
        tree,
        isolated_env(output / "environment"),
        output / "pytest.txt",
        timeout,
    )
    try:
        cases = junit_cases(junit)
        parse_error = None
    except (ET.ParseError, RuntimeError) as exc:
        cases = {}
        parse_error = str(exc)
    result.update(
        {
            "nodes": cases,
            "parse_error": parse_error,
            "counts": {
                status: list(cases.values()).count(status)
                for status in ("passed", "failed", "error", "skipped")
            },
        }
    )
    return result


def collect_nodes(tree: Path, output: Path, timeout: int, files: list[str]) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    launcher = (
        "import sys; sys.path.insert(0, sys.argv.pop(1)); "
        "import s19_app; print('s19_app.__file__=' + s19_app.__file__, flush=True); "
        "import pytest; raise SystemExit(pytest.main(sys.argv[1:]))"
    )
    command = [
        sys.executable,
        "-I",
        "-B",
        "-c",
        launcher,
        str(tree),
        "--collect-only",
        "-q",
        "-p",
        "no:cacheprovider",
        *files,
    ]
    result = run_process(
        command,
        tree,
        isolated_env(output / "environment"),
        output / "collect.txt",
        timeout,
    )
    lines = (output / "collect.txt").read_text(encoding="utf-8").splitlines()
    nodes = [line.strip() for line in lines if line.startswith("tests/") and "::" in line]
    result["collected_nodes"] = nodes
    return result


def classify_target(result: dict, expected_nodes: list[str], phase: str) -> tuple[str, str]:
    expected = set(expected_nodes)
    actual = set(result["nodes"])
    counts = result["counts"]
    if phase == "pre" or phase == "restore":
        if (
            result["returncode"] == 0
            and not result["timeout"]
            and result["parse_error"] is None
            and actual == expected
            and counts["passed"] == len(expected)
            and counts["failed"] == counts["error"] == counts["skipped"] == 0
        ):
            return "SURVIVED", f"{phase} target is green"
        return "BAD", f"{phase} target is not a complete green oracle: {counts}"
    if result["timeout"]:
        return "CRASH", "external timeout; never a bare-timeout kill"
    if result["parse_error"] is not None:
        return "CRASH", result["parse_error"]
    if actual != expected:
        return "CRASH", f"post-mutant collection changed: expected={len(expected)} actual={len(actual)}"
    if counts["skipped"]:
        return "BAD", "a selected node skipped; a skip is not a kill"
    if counts["error"]:
        return "CRASH", "test error, not an assertion kill"
    if result["returncode"] == 1 and counts["failed"] and counts["failed"] + counts["passed"] == len(expected):
        return "KILLED", "assertion failure in the complete selected node set"
    if result["returncode"] == 0 and counts["passed"] == len(expected):
        return "SURVIVED", "all selected nodes passed"
    if result["returncode"] in (2, 3, 4, 5) or result["returncode"] < 0:
        return "CRASH", f"pytest crash/interruption after a valid pre-run, exit={result['returncode']}"
    return "BAD", f"unclassifiable pytest result exit={result['returncode']} counts={counts}"


def safe_source(tree: Path, relative: str) -> Path:
    root = tree.resolve()
    path = (root / relative).resolve()
    if path != root and root not in path.parents:
        raise RuntimeError(f"Source escapes isolated tree: {relative}")
    return path


def apply_one(tree: Path, mutant: dict) -> dict:
    path = safe_source(tree, mutant["source"])
    original_bytes = path.read_bytes()
    text = original_bytes.decode("utf-8")
    count = text.count(mutant["old"])
    result = {
        "source": mutant["source"],
        "source_sha256_before": sha256_bytes(original_bytes),
        "applied_count": 0,
        "original_bytes": original_bytes,
    }
    if count != 1:
        result["reason"] = f"anchor count={count}, required exactly 1; no bytes written"
        return result
    if mutant["old"] == mutant["new"]:
        result["reason"] = "old and new are identical; no bytes written"
        return result
    mutated_text = text.replace(mutant["old"], mutant["new"], 1)
    mutated_bytes = mutated_text.encode("utf-8")
    if mutated_bytes == original_bytes:
        result["reason"] = "replacement did not change bytes; no bytes written"
        return result
    path.write_bytes(mutated_bytes)
    result.update(
        {
            "applied_count": 1,
            "source_sha256_mutated": sha256_file(path),
            "reason": "exactly one replacement applied",
        }
    )
    return result


def bytecode_files(tree: Path) -> set[str]:
    return {
        str(path.relative_to(tree))
        for path in tree.rglob("*")
        if path.is_file() and (path.suffix in (".pyc", ".pyo") or "__pycache__" in path.parts)
    }


def restore_source(tree: Path, mutant: dict, applied: dict) -> dict:
    path = safe_source(tree, mutant["source"])
    path.write_bytes(applied["original_bytes"])
    restored_hash = sha256_file(path)
    return {
        "source_sha256_restored": restored_hash,
        "restore_ok": restored_hash == applied["source_sha256_before"],
    }


def environment_record(manifest: dict) -> dict:
    code = (
        "import importlib.metadata as m, json, platform, sys; "
        "print(json.dumps({'python': sys.version, 'executable': sys.executable, "
        "'platform': platform.platform(), "
        "'pytest': m.version('pytest'), 'textual': m.version('textual')}))"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    record = json.loads(completed.stdout)
    record.update(
        {
            "baseline_commit": manifest["baseline_commit"],
            "manifest_sha256": sha256_file(MANIFEST_PATH),
            "bytecode_disabled": True,
            "display_unset": True,
            "wayland_display_unset": True,
        }
    )
    return record


def git(command: list[str], cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *command],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
    )


def prepare_pristine(source_repo: Path, group_dir: Path, commit: str) -> Path:
    actual = git(["rev-parse", "HEAD"], source_repo).stdout.strip()
    if actual != commit:
        raise RuntimeError(f"Source HEAD {actual} != pinned baseline {commit}")
    git(["diff", "--quiet"], source_repo)
    git(["diff", "--cached", "--quiet"], source_repo)
    pristine = group_dir / "pristine"
    git(
        ["clone", "--shared", "--no-hardlinks", "--no-checkout", str(source_repo), str(pristine)],
        group_dir,
        timeout=300,
    )
    git(["checkout", "--detach", commit], pristine, timeout=300)
    if git(["rev-parse", "HEAD"], pristine).stdout.strip() != commit:
        raise RuntimeError("Pristine checkout hash mismatch")
    git(["diff", "--quiet"], pristine)
    git(["diff", "--cached", "--quiet"], pristine)
    return pristine


def run_group_baseline(
    pristine: Path,
    group_dir: Path,
    manifest: dict,
    timeout: int,
) -> dict:
    expected = manifest["baseline_linux"]
    output = group_dir / "baseline-evidence"
    # Tracked .pyc files exist in the repo; only bytecode created by the run counts.
    before_bytecode = bytecode_files(pristine)
    collected = collect_nodes(pristine, output / "collection", min(timeout, 300), manifest["test_files"])
    result = run_pytest(pristine, manifest["test_files"], output / "run", timeout)
    counts = result["counts"]
    actual_nodes = set(result["nodes"])
    collected_nodes = set(collected["collected_nodes"])
    skipped = {node for node, status in result["nodes"].items() if status == "skipped"}
    expected_skipped = set(expected["skipped_nodes"])
    checks = {
        "collection_exit_zero": collected["returncode"] == 0 and not collected["timeout"],
        "collected_count": len(collected_nodes) == expected["collected"],
        "junit_matches_collection": actual_nodes == collected_nodes,
        "passed_count": counts["passed"] == expected["passed"],
        "skipped_count": counts["skipped"] == expected["skipped"],
        "failed_zero": counts["failed"] == 0,
        "errors_zero": counts["error"] == 0,
        "exact_skip_nodes": skipped == expected_skipped,
        "pytest_exit_zero": result["returncode"] == 0 and not result["timeout"],
        "junit_parse": result["parse_error"] is None,
        "no_new_bytecode": not (bytecode_files(pristine) - before_bytecode),
    }
    report = {
        "group": group_dir.name,
        "environment": environment_record(manifest),
        "checks": checks,
        "counts": counts,
        "collected_count": len(collected_nodes),
        "skipped_nodes": sorted(skipped),
        "collection": collected,
        "run": result,
        "verdict": "PASS" if all(checks.values()) else "BAD",
    }
    write_json(group_dir / "baseline.json", report)
    return report


def run_mutant(
    pristine: Path,
    mutant: dict,
    destination: Path,
    timeout: int,
) -> dict:
    tree = destination / "tree"
    shutil.copytree(pristine, tree, symlinks=True)
    before_bytecode = bytecode_files(tree)
    result = {
        "id": mutant["id"],
        "group": mutant["group"],
        "baseline_commit": load_manifest()["baseline_commit"],
        "tests": mutant["tests"],
        "verdict": "BAD",
        "reason": "not attempted",
        "bytecode_disabled": True,
    }
    applied = None
    try:
        pre = run_pytest(tree, mutant["tests"], destination / "pre", timeout)
        pre_verdict, pre_reason = classify_target(pre, mutant["tests"], "pre")
        result["pre"] = pre
        if pre_verdict == "BAD":
            result["reason"] = pre_reason
            return result
        applied = apply_one(tree, mutant)
        result.update({key: value for key, value in applied.items() if key != "original_bytes"})
        if applied["applied_count"] != 1:
            result["reason"] = applied["reason"]
            return result
        post = run_pytest(tree, mutant["tests"], destination / "post", timeout)
        verdict, reason = classify_target(post, mutant["tests"], "post")
        result.update({"post": post, "verdict": verdict, "reason": reason})
    except Exception as exc:
        result.update({"verdict": "BAD", "reason": f"harness exception: {type(exc).__name__}: {exc}"})
    finally:
        if applied is not None and applied["applied_count"] == 1:
            try:
                restored = restore_source(tree, mutant, applied)
                result.update(restored)
                after_bytecode = bytecode_files(tree)
                result["new_bytecode"] = sorted(after_bytecode - before_bytecode)
                result["no_new_bytecode"] = not result["new_bytecode"]
                restore_run = run_pytest(tree, mutant["tests"], destination / "restored", timeout)
                restore_verdict, restore_reason = classify_target(restore_run, mutant["tests"], "restore")
                result["restored_run"] = restore_run
                result["restored_target_green"] = restore_verdict != "BAD"
                git(["diff", "--quiet"], tree)
                git(["diff", "--cached", "--quiet"], tree)
                result["tracked_tree_clean"] = True
                if not restored["restore_ok"] or result["new_bytecode"] or restore_verdict == "BAD":
                    result["verdict"] = "BAD"
                    result["reason"] = f"restore validation failed: {restore_reason}"
            except Exception as exc:
                result["verdict"] = "BAD"
                result["reason"] = f"restore exception: {type(exc).__name__}: {exc}"
        write_json(destination / "result.json", result)
    return result


def blocked_result(mutant: dict, manifest: dict) -> dict:
    return {
        "id": mutant["id"],
        "group": mutant["group"],
        "baseline_commit": manifest["baseline_commit"],
        "tests": mutant["tests"],
        "applied_count": 0,
        "verdict": "BAD",
        "reason": mutant.get("blocked_reason", "not runnable by the Linux runner"),
    }


def command_run(args: argparse.Namespace) -> int:
    require_linux()
    manifest = load_manifest()
    work = args.work_dir.resolve()
    require_empty_work_dir(work)
    by_id = {mutant["id"]: mutant for mutant in manifest["mutants"]}
    requested_groups = None
    if args.groups:
        if not (args.all or args.baseline_only):
            raise RuntimeError("--groups requires --all or --baseline-only")
        requested_groups = args.groups.split(",")
        unknown_groups = sorted(set(requested_groups) - set(manifest["baseline_linux"]["groups"]))
        if unknown_groups:
            raise RuntimeError(f"Unknown L groups: {unknown_groups}")
    if args.only:
        requested = args.only.split(",")
        unknown = sorted(set(requested) - set(by_id))
        if unknown:
            raise RuntimeError(f"Unknown mutant IDs: {unknown}")
        if len(set(requested)) != len(requested):
            raise RuntimeError("Duplicate mutant IDs in --only")
        selected = [by_id[mutant_id] for mutant_id in requested]
    elif args.all or args.baseline_only:
        selected = [m for m in manifest["mutants"] if m["baseline"] == "L"]
        if requested_groups is not None:
            selected = [m for m in selected if m["group"] in requested_groups]
    else:
        raise RuntimeError("Choose --all, --baseline-only or --only explicitly")
    if not selected:
        raise RuntimeError("Empty mutant selection is BAD")
    immediate = [] if args.baseline_only else [m for m in selected if m["baseline"] != "L" or not m.get("runnable", True)]
    runnable = [m for m in selected if m["baseline"] == "L" and m.get("runnable", True)]
    results = []
    for mutant in immediate:
        result = blocked_result(mutant, manifest)
        results.append(result)
        write_json(work / mutant["group"] / mutant["id"] / "result.json", result)
    groups = sorted({m["group"] for m in runnable})
    baseline_reports = []
    if not args.baseline_only:
        for group in groups:
            group_dir = work / group
            group_dir.mkdir(parents=True, exist_ok=True)
            pristine = prepare_pristine(args.source_repo.resolve(), group_dir, manifest["baseline_commit"])
            baseline = run_group_baseline(pristine, group_dir, manifest, args.baseline_timeout)
            baseline_reports.append({"group": group, "verdict": baseline["verdict"]})
            if baseline["verdict"] != "PASS":
                for mutant in (m for m in runnable if m["group"] == group):
                    result = blocked_result(mutant, manifest)
                    result["reason"] = "group baseline BAD; mutant never applied"
                    results.append(result)
                    write_json(group_dir / mutant["id"] / "result.json", result)
                continue
            for mutant in (m for m in runnable if m["group"] == group):
                result = run_mutant(pristine, mutant, group_dir / mutant["id"], args.timeout)
                results.append(result)
    else:
        for group in groups:
            group_dir = work / group
            group_dir.mkdir(parents=True, exist_ok=True)
            pristine = prepare_pristine(args.source_repo.resolve(), group_dir, manifest["baseline_commit"])
            baseline = run_group_baseline(pristine, group_dir, manifest, args.baseline_timeout)
            baseline_reports.append({"group": group, "verdict": baseline["verdict"]})
    counts = {verdict: sum(r["verdict"] == verdict for r in results) for verdict in VERDICTS}
    summary = {
        "baseline_commit": manifest["baseline_commit"],
        "manifest_sha256": sha256_file(MANIFEST_PATH),
        "baseline_only": args.baseline_only,
        "baselines": baseline_reports,
        "selected_count": len(runnable) if args.baseline_only else len(selected),
        "executed_mutants": sum("post" in result for result in results),
        "blocked_count": len(immediate),
        "verdicts": counts,
        "results": results,
    }
    write_json(work / "summary.json", summary)
    print(json.dumps({"baselines": baseline_reports, "verdicts": counts, "blocked": len(immediate)}))
    return 1 if counts["BAD"] or any(b["verdict"] != "PASS" for b in baseline_reports) else 0


def fixture_attempt(root: Path, name: str, new_source: str, expected_verdict: str, timeout: int) -> dict:
    tree = root / name / "tree"
    tree.mkdir(parents=True)
    (tree / "sample.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tree / "test_sample.py").write_text(
        "import sample\n\ndef test_value():\n    assert sample.VALUE == 1\n",
        encoding="utf-8",
    )
    mutant = {
        "id": f"HARNESS-{name}",
        "source": "sample.py",
        "old": "VALUE = 1\n",
        "new": new_source,
        "tests": ["test_sample.py::test_value"],
    }
    destination = root / name
    before_bytecode = bytecode_files(tree)
    result = {"expected_verdict": expected_verdict}
    pre = run_pytest(tree, mutant["tests"], destination / "pre", timeout, import_product=False)
    pre_verdict, pre_reason = classify_target(pre, mutant["tests"], "pre")
    if pre_verdict == "BAD":
        raise RuntimeError(f"Fixture {name} pre-test failed: {pre_reason}")
    applied = apply_one(tree, mutant)
    try:
        if applied["applied_count"] != 1:
            raise RuntimeError(applied["reason"])
        post = run_pytest(tree, mutant["tests"], destination / "post", timeout, import_product=False)
        verdict, reason = classify_target(post, mutant["tests"], "post")
        result.update(
            {
                "actual_verdict": verdict,
                "reason": reason,
                "applied_count": applied["applied_count"],
                "counts": post["counts"],
            }
        )
    finally:
        restored = restore_source(tree, mutant, applied)
        result.update(restored)
        restored_run = run_pytest(tree, mutant["tests"], destination / "restored", timeout, import_product=False)
        restored_verdict, restored_reason = classify_target(restored_run, mutant["tests"], "restore")
        result["restored_target_green"] = restored_verdict != "BAD"
        result["no_new_bytecode"] = not (bytecode_files(tree) - before_bytecode)
        if restored_verdict == "BAD":
            raise RuntimeError(f"Fixture {name} restore test failed: {restored_reason}")
    return result


def command_self_test(args: argparse.Namespace) -> int:
    require_linux()
    root = args.work_dir.resolve()
    require_empty_work_dir(root)
    cases = [
        ("killed", "VALUE = 2\n", "KILLED"),
        ("survived", "VALUE = 1\n# no behavior change\n", "SURVIVED"),
        ("crash", "VALUE = (\n", "CRASH"),
    ]
    results = [fixture_attempt(root, name, source, verdict, args.timeout) for name, source, verdict in cases]
    bad_tree = root / "bad" / "tree"
    bad_tree.mkdir(parents=True)
    (bad_tree / "sample.py").write_text("VALUE = 1\n", encoding="utf-8")
    bad_applied = apply_one(
        bad_tree,
        {"source": "sample.py", "old": "MISSING = 1\n", "new": "MISSING = 2\n"},
    )
    results.append(
        {
            "expected_verdict": "BAD",
            "actual_verdict": "BAD" if bad_applied["applied_count"] == 0 else "BAD_HARNESS",
            "applied_count": bad_applied["applied_count"],
            "reason": bad_applied["reason"],
            "restore_ok": sha256_file(bad_tree / "sample.py") == bad_applied["source_sha256_before"],
        }
    )
    checks = {
        "all_verdicts_observed": {r["actual_verdict"] for r in results} == set(VERDICTS),
        "expected_verdicts": all(r["actual_verdict"] == r["expected_verdict"] for r in results),
        "known_bad_killed": results[0]["actual_verdict"] == "KILLED",
        "zero_apply_bad": results[-1]["applied_count"] == 0,
        "all_restored": all(r.get("restore_ok") is True for r in results),
        "no_new_bytecode": all(r.get("no_new_bytecode", True) for r in results),
    }
    report = {
        "scope": "disposable toy fixtures only; zero product mutants executed",
        "checks": checks,
        "results": results,
        "verdict": "PASS" if all(checks.values()) else "FAIL",
    }
    write_json(root / "self-test.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["verdict"] == "PASS" else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run selected product mutants in fresh isolated Linux copies")
    run.add_argument("--source-repo", type=Path, required=True)
    run.add_argument("--work-dir", type=Path, required=True)
    selection = run.add_mutually_exclusive_group()
    selection.add_argument("--all", action="store_true")
    selection.add_argument("--baseline-only", action="store_true")
    selection.add_argument("--only", help="comma-separated mutant IDs")
    run.add_argument("--groups", help="optional comma-separated L groups with --all/--baseline-only")
    run.add_argument("--timeout", type=int, default=180)
    run.add_argument("--baseline-timeout", type=int, default=2400)
    run.set_defaults(func=command_run)
    self_test = sub.add_parser("self-test", help="exercise all four verdicts on toy fixtures only")
    self_test.add_argument("--work-dir", type=Path, required=True)
    self_test.add_argument("--timeout", type=int, default=60)
    self_test.set_defaults(func=command_self_test)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        print(f"BAD: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
