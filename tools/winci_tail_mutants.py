#!/usr/bin/env python3
"""Run the two Inc 1b GW tail mutants on an isolated GitHub Windows runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.support.b103_artifact_safety import (  # noqa: E402
    SafetyAudit,
    _decoded_views,
    _scan_text,
)

MANIFEST_PATH = (
    ROOT
    / ".dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/mutants/manifest.json"
)
CLOSURE_COMMIT = "caae1bf9a0b97266731753fc9dc0a38f3762f222"
ALLOWED_IDS = ("GW-W01", "GW-W02")
VERDICTS = ("KILLED", "SURVIVED", "CRASH", "BAD")
TIMEOUT_SIGNATURES = (
    "fixture predicate not satisfied before timeout",
    "timeoutexpired",
    "timed out",
)
INFRA_SIGNATURES = (
    "os clipboard not isolated",
    "clipboard probe",
    "winci clipboard unavailable",
)


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


def selected_mutants(requested: str) -> list[dict]:
    ids = requested.split(",")
    if not ids or len(set(ids)) != len(ids) or any(item not in ALLOWED_IDS for item in ids):
        raise RuntimeError("Select each of GW-W01 and/or GW-W02 at most once")
    by_id = {mutant["id"]: mutant for mutant in load_manifest()["mutants"]}
    return [by_id[item] for item in ids]


def require_hosted_windows() -> None:
    if sys.platform != "win32":
        raise RuntimeError("This runner is Windows-only; dynamic tests are forbidden off WinCI")
    if os.environ.get("GITHUB_ACTIONS", "").lower() != "true":
        raise RuntimeError("GITHUB_ACTIONS must be true")
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("RUNNER_ENVIRONMENT must be github-hosted")


def require_empty_output(path: Path) -> None:
    if path.exists() and any(path.iterdir()):
        raise RuntimeError(f"Output directory must be new or empty: {path}")
    path.mkdir(parents=True, exist_ok=True)


def git_quiet(*arguments: str) -> None:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(f"git {' '.join(arguments)} exited {completed.returncode}")


def require_pinned_tree() -> None:
    git_quiet("diff", "--quiet")
    git_quiet("diff", "--cached", "--quiet")
    git_quiet("cat-file", "-e", f"{CLOSURE_COMMIT}^{{commit}}")
    git_quiet("diff", "--quiet", CLOSURE_COMMIT, "--", "s19_app", "tests")


def bytecode_files(tree: Path) -> set[str]:
    return {
        str(path.relative_to(tree))
        for path in tree.rglob("*")
        if path.is_file() and (path.suffix in (".pyc", ".pyo") or "__pycache__" in path.parts)
    }


def isolated_env(state: Path) -> dict[str, str]:
    home = state / "home"
    temp = state / "temp"
    for directory in (home, temp):
        directory.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    for name in ("PYTHONPATH", "PYTHONSTARTUP", "PYTEST_ADDOPTS"):
        env.pop(name, None)
    env.update(
        {
            "HOME": str(home),
            "TEMP": str(temp),
            "TMP": str(temp),
            "LOCALAPPDATA": str(home / "local"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    Path(env["LOCALAPPDATA"]).mkdir(parents=True, exist_ok=True)
    return env


def redact_command(command: list[str], output: Path) -> list[str]:
    replacements = ((str(ROOT), "<repo>"), (str(output), "<evidence>"))
    rendered = []
    for argument in command:
        value = str(argument)
        for original, replacement in replacements:
            value = value.replace(original, replacement)
        rendered.append(value)
    return rendered


def run_process(
    command: list[str],
    env: dict[str, str],
    transcript: Path,
    output: Path,
    timeout: int,
) -> dict:
    started = time.monotonic()
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        creationflags=creationflags,
    )
    timed_out = False
    taskkill_returncode = None
    try:
        data, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        killed = subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        taskkill_returncode = killed.returncode
        try:
            data, _ = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            data, _ = process.communicate()
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_bytes(data)
    return {
        "returncode": process.returncode,
        "timeout": timed_out,
        "taskkill_returncode": taskkill_returncode,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "transcript": str(transcript.relative_to(output)),
        "command": redact_command(command, output),
    }


def timings(case: ET.Element) -> list[dict]:
    records = []
    for prop in case.findall("./properties/property"):
        if prop.attrib.get("name") != "qc_tm":
            continue
        value = prop.attrib.get("value", "")
        try:
            label, measured, bound, margin = value.rsplit("|", 3)
            records.append(
                {
                    "label": label,
                    "measured": float(measured),
                    "bound": float(bound),
                    "margin": float(margin),
                }
            )
        except (ValueError, TypeError):
            raise RuntimeError("Malformed qc_tm JUnit property") from None
    return records


def failure_text(case: ET.Element) -> str:
    pieces = []
    for tag in ("failure", "error", "skipped"):
        element = case.find(tag)
        if element is not None:
            pieces.extend((element.attrib.get("message", ""), element.text or ""))
    return "\n".join(pieces)


def mechanisms(mutant_id: str, text: str, timing_rows: list[dict]) -> list[str]:
    lowered = text.lower()
    found = []
    if mutant_id == "GW-W01":
        signatures = (
            ("writer_ui_thread", "responsive writer ran on the ui thread"),
            ("tick_bound", "responsive writer exceeded its tick bound"),
            ("too_few_ticks", "responsive writer control recorded too few ticks"),
        )
    else:
        signatures = (
            ("double_writer", "held copy did not perform exactly one writer call"),
            ("writer_incomplete", "responsive writer did not run to completion"),
        )
    for name, signature in signatures:
        if signature in lowered:
            found.append(name)
    if mutant_id == "GW-W02" and any(
        row["label"] == "r_paste_13_101_row" and row["margin"] < 0
        for row in timing_rows
    ):
        found.append("warning_bound")
    if not found and text:
        found.append("other_assertion")
    return found


def junit_cases(junit: Path, mutant_id: str) -> tuple[dict[str, str], dict[str, dict]]:
    if not junit.is_file():
        return {}, {}
    root = ET.parse(junit).getroot()
    statuses: dict[str, str] = {}
    details: dict[str, dict] = {}
    for case in root.iter("testcase"):
        classname = case.attrib.get("classname", "").replace(".", "/")
        name = case.attrib.get("name", "")
        if not classname or not name:
            raise RuntimeError("JUnit testcase lacks classname/name")
        node = f"{classname}.py::{name}"
        if node in statuses:
            raise RuntimeError(f"Duplicate JUnit node {node}")
        if case.find("skipped") is not None:
            status = "skipped"
        elif case.find("error") is not None:
            status = "error"
        elif case.find("failure") is not None:
            status = "failed"
        else:
            status = "passed"
        text = failure_text(case)
        timing_rows = timings(case)
        statuses[node] = status
        details[node] = {
            "status": status,
            "mechanisms": mechanisms(mutant_id, text, timing_rows),
            "qc_tm": timing_rows,
            "timeout_signature": any(item in text.lower() for item in TIMEOUT_SIGNATURES),
            "infra_signature": any(item in text.lower() for item in INFRA_SIGNATURES),
        }
    return statuses, details


def run_pytest(mutant: dict, output: Path, timeout: int) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    before_bytecode = bytecode_files(ROOT)
    junit = output / "junit.xml"
    launcher = (
        "import sys; sys.stdout.reconfigure(encoding='utf-8'); "
        "sys.stderr.reconfigure(encoding='utf-8'); "
        "sys.path.insert(0, sys.argv.pop(1)); "
        "import s19_app; print('s19_app.__file__=' + s19_app.__file__, flush=True); "
        "import pytest; raise SystemExit(pytest.main(sys.argv[1:]))"
    )
    command = [
        sys.executable,
        "-I",
        "-B",
        "-c",
        launcher,
        str(ROOT),
        "-q",
        "-p",
        "no:cacheprovider",
        f"--junitxml={junit}",
        *mutant["tests"],
    ]
    result = run_process(
        command,
        isolated_env(output / "environment"),
        output / "pytest.txt",
        output,
        timeout,
    )
    try:
        cases, details = junit_cases(junit, mutant["id"])
        parse_error = None
    except (ET.ParseError, RuntimeError, ValueError) as exc:
        cases, details = {}, {}
        parse_error = f"{type(exc).__name__}"
    new_bytecode = sorted(bytecode_files(ROOT) - before_bytecode)
    result.update(
        {
            "expected_nodes": mutant["tests"],
            "nodes": cases,
            "node_details": details,
            "parse_error": parse_error,
            "new_bytecode": new_bytecode,
            "counts": {
                status: list(cases.values()).count(status)
                for status in ("passed", "failed", "error", "skipped")
            },
        }
    )
    return result


def classify_target(result: dict, phase: str) -> tuple[str, str]:
    expected = set(result["expected_nodes"])
    actual = set(result["nodes"])
    counts = result["counts"]
    if phase in ("pre", "post-restore"):
        if (
            result["returncode"] == 0
            and not result["timeout"]
            and result["parse_error"] is None
            and actual == expected
            and counts["passed"] == len(expected)
            and counts["failed"] == counts["error"] == counts["skipped"] == 0
            and not result["new_bytecode"]
        ):
            return "PASS", f"{phase}: every selected node passed without skip"
        return "BAD", f"{phase}: selected nodes were not a complete green oracle"
    if result["timeout"]:
        return "CRASH", "external timeout; never a kill"
    if result["parse_error"] is not None:
        return "CRASH", f"JUnit parse failure: {result['parse_error']}"
    if actual != expected:
        return "CRASH", "post-mutant collection/selection changed"
    if counts["skipped"]:
        return "BAD", "a selected node skipped; a skip is not a kill"
    if counts["error"]:
        return "CRASH", "test error; an error is not an assertion kill"
    details = result["node_details"].values()
    if any(row["timeout_signature"] for row in details):
        return "CRASH", "test timeout signature; a timeout is not a kill"
    if any(row["infra_signature"] for row in details):
        return "CRASH", "clipboard infrastructure failure; not a kill"
    if result["new_bytecode"]:
        return "BAD", "new bytecode invalidated the attempt"
    if (
        result["returncode"] == 1
        and counts["failed"]
        and counts["failed"] + counts["passed"] == len(expected)
    ):
        return "KILLED", "assertion failure with no errors, skips or timeouts"
    if result["returncode"] == 0 and counts["passed"] == len(expected):
        return "SURVIVED", "every selected node passed"
    if result["returncode"] in (2, 3, 4, 5) or result["returncode"] < 0:
        return "CRASH", f"pytest collection/crash/interruption exit={result['returncode']}"
    return "BAD", f"unclassifiable pytest exit={result['returncode']}"


def apply_one(mutant: dict, path: Path | None = None) -> dict:
    path = ROOT / mutant["source"] if path is None else path
    original_bytes = path.read_bytes()
    crlf_count = original_bytes.count(b"\r\n")
    bare_lf_count = original_bytes.count(b"\n") - crlf_count
    newline = "\r\n" if crlf_count else "\n"
    result = {
        "source": mutant["source"],
        "source_sha256_before": sha256_bytes(original_bytes),
        "source_newline": "CRLF" if crlf_count else "LF",
        "applied_count": 0,
        "original_bytes": original_bytes,
    }
    if crlf_count and (bare_lf_count or original_bytes.count(b"\r") != crlf_count):
        result["reason"] = "mixed newlines refused; no bytes written"
        return result
    text = original_bytes.decode("utf-8").replace("\r\n", "\n")
    count = text.count(mutant["old"])
    if count != 1:
        result["reason"] = f"anchor count={count}; required exactly 1; no bytes written"
        return result
    if mutant["old"] == mutant["new"]:
        result["reason"] = "old and new are identical; no bytes written"
        return result
    mutated_text = text.replace(mutant["old"], mutant["new"], 1)
    mutated_bytes = mutated_text.replace("\n", newline).encode("utf-8")
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


def restore_source(path: Path, original: bytes) -> dict:
    path.write_bytes(original)
    restored = sha256_file(path)
    return {
        "source_sha256_restored": restored,
        "restore_ok": restored == sha256_bytes(original),
    }


def public_mutation(applied: dict) -> dict:
    return {key: value for key, value in applied.items() if key != "original_bytes"}


def run_mutant(mutant: dict, destination: Path, timeout: int) -> dict:
    result = {
        "id": mutant["id"],
        "group": mutant["group"],
        "manifest_baseline_commit": load_manifest()["baseline_commit"],
        "closure_commit": CLOSURE_COMMIT,
        "lane_head": os.environ.get("GITHUB_SHA"),
        "tests": mutant["tests"],
        "verdict": "BAD",
        "reason": "not attempted",
        "bytecode_disabled": True,
    }
    before_bytecode = bytecode_files(ROOT)
    applied = None
    try:
        pre = run_pytest(mutant, destination / "pre", timeout)
        result["pre"] = pre
        pre_verdict, pre_reason = classify_target(pre, "pre")
        result["pre_verdict"] = pre_verdict
        if pre_verdict != "PASS":
            result["reason"] = pre_reason
            write_json(destination / "result.json", result)
            return result
        applied = apply_one(mutant)
        result.update(public_mutation(applied))
        if applied["applied_count"] != 1:
            result["reason"] = applied["reason"]
        else:
            post = run_pytest(mutant, destination / "post", timeout)
            verdict, reason = classify_target(post, "post")
            result.update({"post": post, "verdict": verdict, "reason": reason})
    except Exception as exc:
        result.update(
            {"verdict": "BAD", "reason": f"harness exception: {type(exc).__name__}"}
        )
    finally:
        if applied is not None:
            try:
                if applied["applied_count"] == 1:
                    result.update(
                        restore_source(ROOT / mutant["source"], applied["original_bytes"])
                    )
                else:
                    result["restore_ok"] = (
                        sha256_file(ROOT / mutant["source"])
                        == applied["source_sha256_before"]
                    )
                restored = run_pytest(mutant, destination / "post-restore", timeout)
                restored_verdict, restored_reason = classify_target(restored, "post-restore")
                result["post_restore"] = restored
                result["post_restore_verdict"] = restored_verdict
                result["post_restore_target_green"] = restored_verdict == "PASS"
                result["new_bytecode"] = sorted(bytecode_files(ROOT) - before_bytecode)
                result["no_new_bytecode"] = not result["new_bytecode"]
                require_pinned_tree()
                result["pinned_tree_restored"] = True
                restore_checks = (
                    result["restore_ok"],
                    result["post_restore_target_green"],
                    result["no_new_bytecode"],
                )
                if not all(restore_checks):
                    result["verdict"] = "BAD"
                    result["reason"] = f"restore validation failed: {restored_reason}"
            except Exception as exc:
                result.update(
                    {
                        "verdict": "BAD",
                        "reason": f"restore exception: {type(exc).__name__}",
                    }
                )
        write_json(destination / "result.json", result)
    return result


def synthetic_result(
    directory: Path,
    name: str,
    statuses: list[str],
    returncode: int,
    *,
    timeout: bool = False,
    malformed: bool = False,
    message: str = "synthetic known-bad control",
    mutant_id: str = "GW-W01",
) -> dict:
    expected = [f"tests/test_b103_clipboard_tail.py::case_{index}" for index in range(len(statuses))]
    junit = directory / f"{name}.xml"
    if malformed:
        junit.write_text("<testsuite>", encoding="utf-8")
    else:
        suite = ET.Element("testsuite")
        for index, status in enumerate(statuses):
            case = ET.SubElement(
                suite,
                "testcase",
                {"classname": "tests.test_b103_clipboard_tail", "name": f"case_{index}"},
            )
            if status != "passed":
                tag = {"failed": "failure", "error": "error", "skipped": "skipped"}[status]
                ET.SubElement(case, tag, {"message": message})
        ET.ElementTree(suite).write(junit, encoding="utf-8", xml_declaration=True)
    try:
        nodes, details = junit_cases(junit, mutant_id)
        parse_error = None
    except (ET.ParseError, RuntimeError, ValueError) as exc:
        nodes, details = {}, {}
        parse_error = type(exc).__name__
    return {
        "expected_nodes": expected,
        "nodes": nodes,
        "node_details": details,
        "parse_error": parse_error,
        "new_bytecode": [],
        "returncode": returncode,
        "timeout": timeout,
        "counts": {
            status: statuses.count(status)
            for status in ("passed", "failed", "error", "skipped")
        },
    }


def scan_tree(root: Path) -> SafetyAudit:
    audit = SafetyAudit()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "artifact-safety.json":
            continue
        label = str(path.relative_to(root))
        try:
            data = path.read_bytes()
        except OSError as exc:
            audit.violations.append(f"ARTIFACT_UNREADABLE artifact={label} error={type(exc).__name__}")
            continue
        audit.files += 1
        audit.bytes += len(data)
        if not data:
            audit.violations.append(f"ARTIFACT_EMPTY artifact={label}")
        for view in _decoded_views(data):
            _scan_text(label, view, audit)
        if path.suffix == ".xml":
            try:
                ET.fromstring(data)
            except (ET.ParseError, ValueError) as exc:
                audit.violations.append(f"JUNIT_XML_UNREADABLE artifact={label} error={type(exc).__name__}")
    return audit


def command_self_test(output: Path) -> int:
    require_empty_output(output)
    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(dir=output) as temporary:
        temp = Path(temporary)

        def record(name: str, function) -> None:
            try:
                checks[name] = bool(function())
            except Exception:
                checks[name] = False

        mutants = selected_mutants("GW-W01,GW-W02")
        source = ROOT / mutants[0]["source"]

        def mutation_round_trips() -> bool:
            temporary_source = temp / "source.py"
            temporary_source.write_bytes(source.read_bytes())
            original = temporary_source.read_bytes()
            for mutant in mutants:
                applied = apply_one(mutant, temporary_source)
                if applied["applied_count"] != 1 or temporary_source.read_bytes() == original:
                    return False
                restored = restore_source(temporary_source, applied["original_bytes"])
                if not restored["restore_ok"] or temporary_source.read_bytes() != original:
                    return False
            return True

        record("mutation_round_trips_and_one_at_a_time", mutation_round_trips)

        def reject_bad_anchors() -> bool:
            original = source.read_bytes()
            for bad in (b"anchor absent\n", original + original):
                temporary_source = temp / "bad-anchor.py"
                temporary_source.write_bytes(bad)
                applied = apply_one(mutants[0], temporary_source)
                if applied["applied_count"] != 0 or temporary_source.read_bytes() != bad:
                    return False
            return True

        record("zero_and_duplicate_anchors_rejected", reject_bad_anchors)

        def bytecode_known_bad() -> bool:
            cache = temp / "__pycache__"
            cache.mkdir()
            (cache / "bad.pyc").write_bytes(b"bad")
            return bool(bytecode_files(temp))

        record("bytecode_detector_known_bad", bytecode_known_bad)

        classifications = (
            ("known_bad_assertion_is_killed", "post", ["passed", "failed"], 1, False, False, "KILLED"),
            ("known_bad_survivor", "post", ["passed", "passed"], 0, False, False, "SURVIVED"),
            ("known_bad_error_is_crash", "post", ["error"], 1, False, False, "CRASH"),
            ("known_bad_skip_is_bad", "post", ["skipped"], 0, False, False, "BAD"),
            ("known_bad_timeout_is_crash", "post", ["failed"], 1, True, False, "CRASH"),
            ("known_bad_collection_is_crash", "post", [], 4, False, False, "CRASH"),
            ("known_bad_malformed_junit_is_crash", "post", ["passed"], 0, False, True, "CRASH"),
            ("known_bad_baseline_skip_is_bad", "pre", ["skipped"], 0, False, False, "BAD"),
            ("known_good_baseline", "pre", ["passed", "passed"], 0, False, False, "PASS"),
            ("known_good_restore", "post-restore", ["passed"], 0, False, False, "PASS"),
        )
        for name, phase, statuses, returncode, timed_out, malformed, expected in classifications:
            record(
                name,
                lambda phase=phase, statuses=statuses, returncode=returncode, timed_out=timed_out, malformed=malformed, expected=expected: classify_target(
                    synthetic_result(temp, "case", statuses, returncode, timeout=timed_out, malformed=malformed),
                    phase,
                )[0]
                == expected,
            )

        record(
            "known_bad_internal_timeout_is_crash",
            lambda: classify_target(
                synthetic_result(
                    temp,
                    "internal-timeout",
                    ["failed"],
                    1,
                    message="fixture predicate not satisfied before timeout",
                ),
                "post",
            )[0]
            == "CRASH",
        )
        record(
            "known_bad_infra_is_crash",
            lambda: classify_target(
                synthetic_result(
                    temp,
                    "infra",
                    ["failed"],
                    1,
                    message="OS clipboard not isolated",
                ),
                "post",
            )[0]
            == "CRASH",
        )
        record(
            "w01_mechanism_known_bad",
            lambda: "writer_ui_thread"
            in synthetic_result(
                temp,
                "w01-mechanism",
                ["failed"],
                1,
                message="responsive writer ran on the UI thread",
            )["node_details"]["tests/test_b103_clipboard_tail.py::case_0"]["mechanisms"],
        )
        record(
            "w02_mechanism_known_bad",
            lambda: "double_writer"
            in synthetic_result(
                temp,
                "w02-mechanism",
                ["failed"],
                1,
                message="held copy did not perform exactly one writer call",
                mutant_id="GW-W02",
            )["node_details"]["tests/test_b103_clipboard_tail.py::case_0"]["mechanisms"],
        )

        def safety_known_bad() -> bool:
            bad = temp / "known-bad.txt"
            bad.write_text('SEED-OS-1b\napi_key="not-a-real-credential"\n', encoding="utf-8")
            audit = SafetyAudit()
            data = bad.read_bytes()
            for view in _decoded_views(data):
                _scan_text("known-bad", view, audit)
            return any("CONTROL_CANARY" in item for item in audit.violations) and any(
                "CREDENTIAL" in item for item in audit.violations
            )

        record("artifact_scanner_known_bad", safety_known_bad)
    report = {
        "schema_version": 1,
        "lane": "winci-tail",
        "closure_commit": CLOSURE_COMMIT,
        "checks": checks,
        "check_count": len(checks),
        "verdict": "PASS" if checks and all(checks.values()) else "FAIL",
    }
    write_json(output / "self-tests.json", report)
    return 0 if report["verdict"] == "PASS" else 1


def environment_record() -> dict:
    code = (
        "import importlib.metadata as m, json, platform, sys; "
        "print(json.dumps({'python': sys.version, 'platform': platform.platform(), "
        "'pytest': m.version('pytest'), 'textual': m.version('textual')}))"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    record = json.loads(completed.stdout)
    record.update(
        {
            "closure_commit": CLOSURE_COMMIT,
            "lane_head": os.environ.get("GITHUB_SHA"),
            "manifest_sha256": sha256_file(MANIFEST_PATH),
            "bytecode_disabled": True,
            "pytest_cache": "no:cacheprovider",
            "stdin": "DEVNULL",
        }
    )
    return record


def command_run(output: Path, requested: str, timeout: int) -> int:
    require_hosted_windows()
    require_pinned_tree()
    self_test_path = output / "self-tests.json"
    self_test = json.loads(self_test_path.read_text(encoding="utf-8"))
    if self_test.get("verdict") != "PASS" or not self_test.get("checks") or not all(
        self_test["checks"].values()
    ):
        raise RuntimeError("Self-tests must pass before any dynamic baseline is trusted")
    mutants = selected_mutants(requested)
    write_json(output / "environment.json", environment_record())
    results = [
        run_mutant(mutant, output / mutant["id"], timeout)
        for mutant in mutants
    ]
    counts = {verdict: sum(row["verdict"] == verdict for row in results) for verdict in VERDICTS}
    summary = {
        "schema_version": 1,
        "lane": "winci-tail",
        "closure_commit": CLOSURE_COMMIT,
        "lane_head": os.environ.get("GITHUB_SHA"),
        "selected": [row["id"] for row in results],
        "counts": counts,
        "results": [
            {
                "id": row["id"],
                "verdict": row["verdict"],
                "reason": row["reason"],
                "applied_count": row.get("applied_count", 0),
                "pre_verdict": row.get("pre_verdict"),
                "post_restore_verdict": row.get("post_restore_verdict"),
                "restore_ok": row.get("restore_ok", False),
                "no_new_bytecode": row.get("no_new_bytecode", False),
            }
            for row in results
        ],
        "verdict": "PASS" if len(results) == len(mutants) and all(row["verdict"] == "KILLED" for row in results) else "FAIL",
    }
    write_json(output / "summary.json", summary)
    require_pinned_tree()
    return 0 if summary["verdict"] == "PASS" else 1


def command_scan(output: Path) -> int:
    audit = scan_tree(output)
    report = {
        "schema_version": 1,
        "files": audit.files,
        "bytes": audit.bytes,
        "violations": audit.violations,
        "verdict": "PASS" if not audit.violations else "FAIL",
    }
    write_json(output / "artifact-safety.json", report)
    safety_audit = SafetyAudit()
    data = (output / "artifact-safety.json").read_bytes()
    for view in _decoded_views(data):
        _scan_text("artifact-safety.json", view, safety_audit)
    if safety_audit.violations:
        return 1
    print(f"ARTIFACT_SAFETY files={audit.files} bytes={audit.bytes} verdict={report['verdict']}")
    return 0 if report["verdict"] == "PASS" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--scan", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mutants", default="GW-W01,GW-W02")
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args(argv)
    output = args.output.resolve()
    if args.self_test:
        return command_self_test(output)
    if args.run:
        return command_run(output, args.mutants, args.timeout)
    return command_scan(output)


if __name__ == "__main__":
    raise SystemExit(main())
