from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_COMMIT = "caae1bf9a0b97266731753fc9dc0a38f3762f222"
SOURCE = Path("s19_app/tui/os_clipboard_input.py")
TARGET = "tests/test_b103_copy_paste_matrix.py::test_copy_paste_acceptance_cell[AT-I1b-1/2-T1-P2]"
PROBE = "tests/test_b103_clipboard_windows.py::test_runner_clipboard_probe"
TEST_TIMEOUT_S = 240
MUTANTS = {
    "GW-W03": {
        "old": "            first_line = event.text.splitlines()[0]\n",
        "new": "            first_line = event.text\n",
        "mechanism": "Expose the complete multiline OS artifact instead of its first line.",
    },
    "GW-W04": {
        "old": "            else:\n                event.text = _strip_paste_controls(first_line, multiline=False)\n",
        "new": "            else:\n                event.text = _strip_paste_controls(first_line, multiline=False)\n                super()._on_paste(event)\n",
        "mechanism": "Invoke the stock paste handler once inside the override so stock dispatch duplicates it.",
    },
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def bytecode_snapshot(root: Path = ROOT) -> dict[str, str]:
    return {
        str(path.relative_to(root)): sha256(path.read_bytes())
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".pyc", ".pyo"}
    }


def target_parts(selector: str) -> tuple[str, str]:
    module, name = selector.rsplit("::", 1)
    return module.replace("/", ".").removesuffix(".py"), name


def junit_failure_type(element: ET.Element) -> str:
    declared = element.get("type")
    if declared:
        return declared
    message = element.get("message") or ""
    if re.match(r"^AssertionError(?:\s|:|$)", message):
        return "AssertionError"
    return ""


def parse_junit(path: Path, selector: str) -> dict:
    result = {
        "path": str(path),
        "parse_error": None,
        "tests": 0,
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "target_matches": 0,
        "target_outcome": None,
        "failure_types": [],
    }
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError, ValueError) as exc:
        result["parse_error"] = type(exc).__name__
        return result
    classname, target_name = target_parts(selector)
    cases = list(root.iter("testcase"))
    result["tests"] = len(cases)
    for case in cases:
        failure = case.find("failure")
        error = case.find("error")
        skipped = case.find("skipped")
        if skipped is not None:
            outcome = "skipped"
            result["skipped"] += 1
        elif error is not None:
            outcome = "error"
            result["errors"] += 1
        elif failure is not None:
            outcome = "failed"
            result["failed"] += 1
        else:
            outcome = "passed"
            result["passed"] += 1
        if case.get("classname") == classname and case.get("name") == target_name:
            result["target_matches"] += 1
            result["target_outcome"] = outcome
            if failure is not None:
                result["failure_types"].append(junit_failure_type(failure))
            if error is not None:
                result["failure_types"].append(junit_failure_type(error))
    return result


def clean_pass(phase: dict) -> bool:
    junit = phase["junit"]
    return bool(
        not phase["timed_out"]
        and phase["exit_code"] == 0
        and junit["parse_error"] is None
        and junit["tests"] == 1
        and junit["target_matches"] == 1
        and junit["target_outcome"] == "passed"
        and junit["passed"] == 1
        and junit["failed"] == 0
        and junit["errors"] == 0
        and junit["skipped"] == 0
    )


def classify_post(phase: dict) -> tuple[str, str]:
    if phase["timed_out"]:
        return "CRASH", "external_timeout"
    junit = phase["junit"]
    if junit["parse_error"] is not None:
        return "CRASH", "junit_unreadable"
    if junit["skipped"]:
        return "BAD", "skip_is_not_a_kill"
    if junit["errors"]:
        return "CRASH", "junit_error"
    if junit["tests"] != 1 or junit["target_matches"] != 1:
        if phase["exit_code"] in {2, 4}:
            return "CRASH", "collection_failure"
        return "BAD", "invalid_selection"
    outcome = junit["target_outcome"]
    if outcome == "failed":
        failure_types = junit["failure_types"]
        if phase["exit_code"] == 1 and failure_types and all(
            value.split(".")[-1] == "AssertionError" for value in failure_types
        ):
            return "KILLED", "target_assertion_failed"
        return "BAD", "non_assertion_failure"
    if outcome == "passed" and phase["exit_code"] == 0:
        return "SURVIVED", "target_passed"
    return "CRASH", "unexpected_pytest_exit"


def run_pytest(selector: str, stem: Path, timeout_s: int = TEST_TIMEOUT_S) -> dict:
    stem.parent.mkdir(parents=True, exist_ok=True)
    log_path = stem.with_suffix(".log")
    junit_path = stem.with_suffix(".xml")
    display_command = [
        "python",
        "-B",
        "-m",
        "pytest",
        "-v",
        "-rs",
        "-p",
        "no:cacheprovider",
        "--junitxml",
        str(junit_path),
        selector,
    ]
    command = [sys.executable, *display_command[1:]]
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTEST_ADDOPTS", None)
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        creationflags=creationflags,
    )
    timed_out = False
    timeout_kill_exit = None
    try:
        output, _ = process.communicate(timeout=timeout_s)
        exit_code = process.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "nt":
            killed = subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            timeout_kill_exit = killed.returncode
        else:
            process.kill()
        output, _ = process.communicate()
        exit_code = 124
    log_path.write_bytes(output or b"")
    return {
        "selector": selector,
        "command": display_command,
        "stdin": "DEVNULL",
        "environment": {"PYTHONDONTWRITEBYTECODE": "1", "PYTEST_ADDOPTS": "removed"},
        "timeout_seconds": timeout_s,
        "timed_out": timed_out,
        "timeout_kill_exit": timeout_kill_exit,
        "exit_code": exit_code,
        "process_returncode": process.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "log": str(log_path),
        "junit": parse_junit(junit_path, selector),
    }


def replace_once(path: Path, old: str, new: str, expected_sha256: str | None = None) -> dict:
    original = path.read_bytes()
    original_sha256 = sha256(original)
    if expected_sha256 is not None and original_sha256 != expected_sha256:
        return {
            "applied_count": 0,
            "original_sha256": original_sha256,
            "error": "original_hash_mismatch",
        }
    text = original.decode("utf-8")
    actual_old = old
    actual_new = new
    newline_style = "LF"
    count = text.count(actual_old)
    if count == 0:
        actual_old = old.replace("\n", "\r\n")
        actual_new = new.replace("\n", "\r\n")
        newline_style = "CRLF"
        count = text.count(actual_old)
    result = {
        "applied_count": count,
        "original_sha256": original_sha256,
        "newline_style": newline_style,
        "error": None,
    }
    if count != 1:
        result["error"] = "anchor_count_must_be_one"
        return result
    mutated = text.replace(actual_old, actual_new, 1).encode("utf-8")
    path.write_bytes(mutated)
    written = path.read_bytes()
    result["mutated_sha256"] = sha256(written)
    if written != mutated or written == original:
        result["error"] = "mutated_bytes_not_verified"
    return result


def git_clean_against_base() -> bool:
    paths = [
        SOURCE,
        Path("tests/test_b103_copy_paste_matrix.py"),
        Path("tests/test_b103_clipboard_windows.py"),
        Path("tests/support/b103_clipboard.py"),
        Path("examples/case_00_public"),
    ]
    command = ["git", "diff", "--quiet", BASE_COMMIT, "--", *map(str, paths)]
    return subprocess.run(command, cwd=ROOT, check=False).returncode == 0


def synthetic_junit(path: Path, outcome: str, failure_type: str | None = "AssertionError") -> None:
    classname, name = target_parts(TARGET)
    child = ""
    if outcome == "failed":
        if failure_type is None:
            child = '<failure message="AssertionError: known-bad">known-bad</failure>'
        else:
            child = f'<failure type="{failure_type}">known-bad</failure>'
    elif outcome == "error":
        child = '<error type="RuntimeError">known-bad</error>'
    elif outcome == "skipped":
        child = '<skipped message="known-bad"/>'
    path.write_text(
        f'<testsuite><testcase classname="{classname}" name="{name}">{child}</testcase></testsuite>',
        encoding="utf-8",
    )


def run_self_tests(output: Path) -> list[dict]:
    controls: list[dict] = []

    def record(name: str, passed: bool, observed: object) -> None:
        controls.append({"name": name, "passed": passed, "observed": observed})

    with tempfile.TemporaryDirectory(prefix="e5-paste-self-test-") as temporary:
        root = Path(temporary)
        for outcome, exit_code, expected in [
            ("passed", 0, "SURVIVED"),
            ("failed", 1, "KILLED"),
            ("error", 1, "CRASH"),
            ("skipped", 0, "BAD"),
        ]:
            junit_path = root / f"{outcome}.xml"
            synthetic_junit(junit_path, outcome)
            verdict, reason = classify_post(
                {"timed_out": False, "exit_code": exit_code, "junit": parse_junit(junit_path, TARGET)}
            )
            record(f"junit_{outcome}", verdict == expected, {"verdict": verdict, "reason": reason})
        junit_path = root / "assertion-message.xml"
        synthetic_junit(junit_path, "failed", None)
        verdict, reason = classify_post(
            {"timed_out": False, "exit_code": 1, "junit": parse_junit(junit_path, TARGET)}
        )
        record(
            "junit_assertion_message_without_type",
            verdict == "KILLED",
            {"verdict": verdict, "reason": reason},
        )
        junit_path = root / "non-assert.xml"
        synthetic_junit(junit_path, "failed", "Failed")
        verdict, reason = classify_post(
            {"timed_out": False, "exit_code": 1, "junit": parse_junit(junit_path, TARGET)}
        )
        record("non_assertion_is_not_kill", verdict == "BAD", {"verdict": verdict, "reason": reason})
        verdict, reason = classify_post(
            {"timed_out": True, "exit_code": 124, "junit": parse_junit(root / "passed.xml", TARGET)}
        )
        record("timeout_is_not_kill", verdict == "CRASH", {"verdict": verdict, "reason": reason})

        mutant_file = root / "mutant.txt"
        mutant_file.write_bytes(b"alpha\nbeta\n")
        applied = replace_once(mutant_file, "beta\n", "gamma\n")
        record("single_anchor_applied", applied["applied_count"] == 1 and mutant_file.read_bytes() == b"alpha\ngamma\n", applied)
        mutant_file.write_bytes(b"alpha\r\nbeta\r\n")
        crlf = replace_once(mutant_file, "beta\n", "gamma\n")
        record(
            "crlf_anchor_applied_without_newline_conversion",
            crlf["applied_count"] == 1
            and crlf["newline_style"] == "CRLF"
            and mutant_file.read_bytes() == b"alpha\r\ngamma\r\n",
            crlf,
        )
        mutant_file.write_bytes(b"beta\nbeta\n")
        duplicate = replace_once(mutant_file, "beta\n", "gamma\n")
        record("duplicate_anchor_rejected", duplicate["applied_count"] == 2 and mutant_file.read_bytes() == b"beta\nbeta\n", duplicate)
        missing = replace_once(mutant_file, "missing\n", "gamma\n")
        record("missing_anchor_rejected", missing["applied_count"] == 0 and mutant_file.read_bytes() == b"beta\nbeta\n", missing)

        original = b"restore-me\n"
        mutant_file.write_bytes(original)
        expected_hash = sha256(original)
        mutant_file.write_bytes(b"known-bad\n")
        restored_badly = sha256(mutant_file.read_bytes()) == expected_hash
        mutant_file.write_bytes(original)
        restored = sha256(mutant_file.read_bytes()) == expected_hash
        record("restore_hash_known_bad_and_good", not restored_badly and restored, {"bad_detected": not restored_badly, "restore_verified": restored})

        before = bytecode_snapshot(root)
        (root / "known-bad.pyc").write_bytes(b"not-real-bytecode")
        after = bytecode_snapshot(root)
        record("new_bytecode_detected", before != after, {"before": len(before), "after": len(after)})
        (root / "known-bad.pyc").unlink()

        counts: dict[str, int] = {}
        redacted = redact_bytes(b"C:\\Users\\known-bad\\file SEED-1b", counts)
        record(
            "redaction_known_bad",
            b"known-bad" not in redacted and b"SEED-1b" not in redacted and counts.get("control_canary", 0) >= 1,
            counts,
        )
    write_json(output / "self-tests.json", {"passed": all(c["passed"] for c in controls), "controls": controls})
    return controls


def redact_bytes(data: bytes, counts: dict[str, int]) -> bytes:
    from tests.support.b103_artifact_safety import CONTROL_CANARIES, _forms

    for values in CONTROL_CANARIES.values():
        for value in values:
            for form in sorted(_forms(value), key=len, reverse=True):
                encoded = form.encode("utf-8", errors="surrogatepass")
                occurrences = data.count(encoded)
                if occurrences:
                    data = data.replace(encoded, b"[REDACTED_CONTROL_CANARY]")
                    counts["control_canary"] = counts.get("control_canary", 0) + occurrences
    for variable in ("GITHUB_WORKSPACE", "RUNNER_TEMP", "USERPROFILE"):
        value = os.environ.get(variable)
        if not value:
            continue
        forms = {value, value.replace("\\", "/"), value.replace("/", "\\")}
        forms.update(form.replace("\\", "\\\\") for form in tuple(forms))
        for form in sorted(forms, key=len, reverse=True):
            encoded = form.encode("utf-8")
            occurrences = data.count(encoded)
            if occurrences:
                data = data.replace(encoded, f"[CI_{variable}]".encode("ascii"))
                counts["ci_path"] = counts.get("ci_path", 0) + occurrences
    path_patterns = [
        rb"(?i)\b[A-Z]:[\\/]+(?:Users|Documents and Settings)[\\/]+[^\\/\s<>\"']+",
        rb"(?i)/mnt/[a-z]/users/[^/\s<>\"']+",
        rb"(?i)/(?:home|root)/[^/\s<>\"']+",
        rb"(?i)/users/[^/\s<>\"']+",
    ]
    for pattern in path_patterns:
        data, count = re.subn(pattern, b"[REDACTED_USER_ROOT]", data)
        counts["personal_path"] = counts.get("personal_path", 0) + count
    credential_patterns = [
        rb"(?i)\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
        rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        rb"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        rb"(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]{8,}",
        rb"(?i)[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@",
    ]
    for pattern in credential_patterns:
        data, count = re.subn(pattern, b"[REDACTED_CREDENTIAL]", data)
        counts["credential"] = counts.get("credential", 0) + count
    data, count = re.subn(rb"(?i)\bb103-probe-[0-9a-f]{32}\b", b"[REDACTED_PROBE_NONCE]", data)
    counts["probe_nonce"] = counts.get("probe_nonce", 0) + count
    return data


def redact_artifacts(output: Path) -> dict:
    counts: dict[str, int] = {}
    files = []
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.suffix not in {".json", ".xml", ".log", ".txt"}:
            continue
        before = path.read_bytes()
        after = redact_bytes(before, counts)
        if after != before:
            path.write_bytes(after)
        files.append(str(path.relative_to(output)))
    report = {"files": files, "redactions": counts}
    write_json(output / "redactions.json", report)
    return report


def audit_artifacts(output: Path) -> dict:
    from tests.support.b103_artifact_safety import (
        SafetyAudit,
        _decoded_views,
        _scan_text,
        audit_artifacts as audit_pair,
    )

    violations: list[str] = []
    files = 0
    byte_count = 0
    xml_paths = sorted(output.rglob("*.xml"))
    for junit in xml_paths:
        transcript = junit.with_suffix(".log")
        audit = audit_pair(transcript, junit)
        files += audit.files
        byte_count += audit.bytes
        violations.extend(f"{junit.relative_to(output)}:{item}" for item in audit.violations)
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.suffix != ".json" or path.name == "artifact-safety.json":
            continue
        data = path.read_bytes()
        audit = SafetyAudit()
        for view in _decoded_views(data):
            _scan_text(str(path.relative_to(output)), view, audit)
        files += 1
        byte_count += len(data)
        violations.extend(audit.violations)
    if not xml_paths:
        violations.append("NO_JUNIT_ARTIFACTS")
    report = {"files": files, "bytes": byte_count, "violations": violations, "passed": not violations}
    write_json(output / "artifact-safety.json", report)
    return report


def run_mutant(mutant_id: str, output: Path) -> dict:
    source_path = ROOT / SOURCE
    original = source_path.read_bytes()
    original_sha256 = sha256(original)
    before_bytecode = bytecode_snapshot()
    mutant_dir = output / mutant_id
    result = {
        "id": mutant_id,
        "source": str(SOURCE),
        "selector": TARGET,
        "mechanism": MUTANTS[mutant_id]["mechanism"],
        "original_sha256": original_sha256,
        "os_artifact": {
            "reader": "tests.support.b103_clipboard.other_program_read",
            "transport": "separate system PowerShell process; exact independent OS value feeds events.Paste",
            "payload_archived": False,
        },
        "oracle": 'target_widget.value == expected.split("\\n", 1)[0]',
        "phases": {},
    }
    result["phases"]["pre_probe"] = run_pytest(PROBE, mutant_dir / "pre-probe")
    result["phases"]["pre"] = run_pytest(TARGET, mutant_dir / "pre")
    baseline_valid = clean_pass(result["phases"]["pre_probe"]) and clean_pass(result["phases"]["pre"])
    result["baseline_valid"] = baseline_valid
    if not baseline_valid:
        result["verdict"] = "BAD"
        result["reason"] = "probe_or_baseline_not_clean_pass"
        result["restore"] = {
            "restored_sha256": sha256(source_path.read_bytes()),
            "match": sha256(source_path.read_bytes()) == original_sha256,
        }
        write_json(mutant_dir / "result.json", result)
        return result

    try:
        mutation = replace_once(
            source_path,
            MUTANTS[mutant_id]["old"],
            MUTANTS[mutant_id]["new"],
            expected_sha256=original_sha256,
        )
        result["mutation"] = mutation
        if mutation["applied_count"] == 1 and mutation["error"] is None:
            result["phases"]["post"] = run_pytest(TARGET, mutant_dir / "post")
    finally:
        source_path.write_bytes(original)
    restored_sha256 = sha256(source_path.read_bytes())
    result["restore"] = {
        "original_sha256": original_sha256,
        "restored_sha256": restored_sha256,
        "match": restored_sha256 == original_sha256,
        "git_diff_quiet": subprocess.run(
            ["git", "diff", "--quiet", "--", str(SOURCE)], cwd=ROOT, check=False
        ).returncode == 0,
    }
    result["phases"]["post_restore"] = run_pytest(TARGET, mutant_dir / "post-restore")
    result["post_restore_valid"] = clean_pass(result["phases"]["post_restore"])
    result["bytecode_unchanged"] = before_bytecode == bytecode_snapshot()
    if "post" in result["phases"]:
        verdict, reason = classify_post(result["phases"]["post"])
    else:
        verdict, reason = "BAD", "mutation_not_applied_exactly_once"
    gates = {
        "baseline_valid": baseline_valid,
        "applied_once": result["mutation"]["applied_count"] == 1 and result["mutation"]["error"] is None,
        "restore_hash": result["restore"]["match"],
        "restore_git_clean": result["restore"]["git_diff_quiet"],
        "post_restore_passed": result["post_restore_valid"],
        "bytecode_unchanged": result["bytecode_unchanged"],
    }
    result["gates"] = gates
    if not all(gates.values()):
        verdict = "BAD"
        reason = "integrity_gate_failed:" + ",".join(name for name, passed in gates.items() if not passed)
    result["verdict"] = verdict
    result["reason"] = reason
    write_json(mutant_dir / "result.json", result)
    return result


def execute(output: Path) -> int:
    output.mkdir(parents=True, exist_ok=True)
    controls = run_self_tests(output)
    summary = {
        "lane": "PASTE",
        "base_commit": BASE_COMMIT,
        "head_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "platform": platform.platform(),
        "python": sys.version,
        "textual": importlib.metadata.version("textual"),
        "selector": TARGET,
        "test_timeout_seconds": TEST_TIMEOUT_S,
        "self_tests_passed": all(control["passed"] for control in controls),
        "mutants": {},
    }
    write_json(output / "summary.json", summary)
    if not summary["self_tests_passed"]:
        summary["status"] = "BAD"
        summary["reason"] = "self_test_failure"
        write_json(output / "summary.json", summary)
        return 2
    isolated = (
        sys.platform == "win32"
        and os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    )
    summary["isolated_winci"] = isolated
    summary["base_closure_clean"] = git_clean_against_base()
    if not isolated or not summary["base_closure_clean"]:
        summary["status"] = "BAD"
        summary["reason"] = "isolation_or_base_closure"
        write_json(output / "summary.json", summary)
        return 2
    for mutant_id in MUTANTS:
        result = run_mutant(mutant_id, output)
        summary["mutants"][mutant_id] = {
            "verdict": result["verdict"],
            "reason": result["reason"],
            "post_exit_code": result["phases"].get("post", {}).get("exit_code"),
            "post_restore_exit_code": result["phases"].get("post_restore", {}).get("exit_code"),
            "result": str(Path(mutant_id) / "result.json"),
        }
        summary["status"] = "COMPLETE" if all(
            item["verdict"] != "BAD" for item in summary["mutants"].values()
        ) else "BAD"
        write_json(output / "summary.json", summary)
    return 0 if summary["status"] == "COMPLETE" else 2


def publish(output: Path) -> int:
    redact_artifacts(output)
    report = audit_artifacts(output)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("execute", "publish"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "execute":
        return execute(args.output)
    return publish(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
