from __future__ import annotations

import base64
import contextlib
import io
import ntpath
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))

from tests.support import b103_clipboard as support
from tests.support import b103_winci_gate as gate
import tests.test_b103_copy_paste_matrix as matrix

FAILURES = []
SYSTEM_POWERSHELL = (
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)
MATRIX_CLASS = "tests.test_b103_copy_paste_matrix"


def check(name, function) -> None:
    try:
        function()
    except Exception as exc:
        FAILURES.append(name)
        print(f"FAIL {name} error={type(exc).__name__}")
    else:
        print(f"PASS {name}")


def completed(argv, stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def isolated_patches():
    return (
        patch.object(support, "host_platform", lambda: "win32"),
        patch.object(support, "_system_powershell_path", lambda: SYSTEM_POWERSHELL),
        patch.object(support, "require_isolated_clipboard", lambda kind: None),
    )


def external_write_is_exact_and_self_verified() -> None:
    payload = "L1\r\nL2😀\n\n" + ("x" * 70000) + "\n"
    clipboard = {"value": None}
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        command = argv[-1]
        if "[Windows.Clipboard]::SetText($text)" in command:
            encoded = kwargs["input"]
            clipboard["value"] = base64.b64decode(encoded).decode(
                "utf-16-le", "surrogatepass"
            )
            assert "FromBase64String" in command
            assert "ReadToEnd" in command
            assert "Set-Clipboard" not in command
            return completed(argv)
        assert "Get-Clipboard" in command
        assert "[Text.UTF8Encoding]::new($false)" in command
        assert "[Console]::Out.Write" in command
        stdout = base64.b64encode(
            clipboard["value"].encode("utf-8")
        ).decode("ascii")
        return completed(argv, stdout=stdout)

    host, resolver, isolation = isolated_patches()
    with host, resolver, isolation, patch.object(
        support.subprocess, "run", fake_run
    ), patch.object(
        support, "_own_write", side_effect=AssertionError("in-process write")
    ), patch.object(
        support, "own_read", side_effect=AssertionError("in-process read")
    ):
        support.other_program_write(payload)

    assert len(calls) == 2
    for argv, kwargs in calls:
        assert argv[0] == SYSTEM_POWERSHELL
        assert ntpath.isabs(argv[0])
        assert kwargs["shell"] is False
        assert payload not in " ".join(argv)
    assert calls[0][1]["input"] != payload
    assert calls[1][1]["stdin"] == subprocess.DEVNULL


def mismatch_diagnostics_hold_only_metadata() -> None:
    secret = "EXPECTED-CLIPBOARD-SECRET"
    other = "UNEXPECTED-CLIPBOARD-SECRET"
    calls = 0

    def fake_run(argv, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return completed(argv)
        stdout = base64.b64encode(other.encode("utf-8")).decode("ascii")
        return completed(argv, stdout=stdout)

    host, resolver, isolation = isolated_patches()
    with host, resolver, isolation, patch.object(support.subprocess, "run", fake_run):
        try:
            support.other_program_write(secret)
        except AssertionError as exc:
            message = str(exc)
        else:
            raise AssertionError("mismatch was not rejected")
    assert secret not in message and other not in message
    assert "expected_chars=" in message and "actual_chars=" in message


def probe_returns_no_clipboard_content() -> None:
    nonce_bytes = bytes(range(16))
    nonce = "b103-probe-" + nonce_bytes.hex()
    secret = "PRIVATE-CLIPBOARD-CONTENT"
    with patch.object(support, "require_isolated_clipboard", lambda kind: None), patch.object(
        support.os, "urandom", lambda size: nonce_bytes
    ), patch.object(support, "_own_write", lambda text: True), patch.object(
        support, "other_program_read", lambda: secret
    ):
        usable, metadata = support._probe_once()
    assert not usable
    assert nonce not in metadata and secret not in metadata
    assert "expected_chars=" in metadata and "actual_chars=" in metadata

    with patch.object(support, "require_isolated_clipboard", lambda kind: None), patch.object(
        support.os, "urandom", lambda size: nonce_bytes
    ), patch.object(support, "_own_write", lambda text: True), patch.object(
        support, "other_program_read", lambda: nonce
    ):
        usable, metadata = support._probe_once()
    assert usable and nonce not in metadata

    with patch.object(support, "require_isolated_clipboard", lambda kind: None), patch.object(
        support.os, "urandom", lambda size: nonce_bytes
    ), patch.object(support, "_own_write", lambda text: True), patch.object(
        support, "other_program_read", side_effect=AssertionError(secret)
    ):
        usable, metadata = support._probe_once()
    assert not usable and secret not in metadata and nonce not in metadata


def other_program_helpers_guard_before_process() -> None:
    for helper, args in (
        (support.other_program_read, ()),
        (support.other_program_write, ("seed",)),
    ):
        events = []

        def blocked(kind):
            events.append("guard")
            raise RuntimeError("not isolated")

        with patch.object(support, "host_platform", lambda: "win32"), patch.object(
            support, "require_isolated_clipboard", blocked
        ), patch.object(
            support, "_system_powershell_path", side_effect=AssertionError("resolver")
        ), patch.object(
            support.subprocess, "run", side_effect=AssertionError("process")
        ):
            try:
                helper(*args)
            except RuntimeError:
                pass
            else:
                raise AssertionError("non-isolated helper did not fail")
        assert events == ["guard"]


def bom_is_not_relaxed_away() -> None:
    def fake_run(argv, **kwargs):
        stdout = "\ufeff" + base64.b64encode(b"value").decode("ascii")
        return completed(argv, stdout=stdout)

    host, resolver, isolation = isolated_patches()
    with host, resolver, isolation, patch.object(support.subprocess, "run", fake_run):
        try:
            support.other_program_read()
        except AssertionError as exc:
            assert "not Base64 UTF-8" in str(exc)
        else:
            raise AssertionError("BOM was silently accepted")


def write_junit(path: Path, cases, *, at_nodes=28) -> None:
    suite = ET.Element("testsuite")
    failures = errors = skipped = 0
    for index in range(at_nodes):
        cases.insert(
            0,
            (
                MATRIX_CLASS,
                f"test_copy_paste_acceptance_cell[AT-I1b-{index + 1}]",
                "passed",
                "",
            ),
        )
    for classname, name, outcome, reason in cases:
        case = ET.SubElement(suite, "testcase", classname=classname, name=name)
        if outcome == "skipped":
            skipped += 1
            ET.SubElement(case, "skipped", message=reason)
        elif outcome in ("failure", "error"):
            if outcome == "failure":
                failures += 1
            else:
                errors += 1
            ET.SubElement(case, outcome, message="redacted fixture")
    suite.attrib.update(
        tests=str(len(cases)),
        failures=str(failures),
        errors=str(errors),
        skipped=str(skipped),
    )
    document = ET.Element("testsuites", name="pytest tests")
    document.append(suite)
    ET.ElementTree(document).write(path, encoding="utf-8", xml_declaration=True)


def run_gate(path: Path, pytest_exit=0):
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        result = gate.main(
            ["--junit-xml", str(path), "--pytest-exit", str(pytest_exit)]
        )
    return result, stdout.getvalue()


def gate_contract() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        clean = [
            ("tests.test_b103_clipboard_tail", "linux_arm", "skipped", "Linux failing-writer arm"),
            (MATRIX_CLASS, gate.MANUAL_TEST, "skipped", "AT-I1b-8 manual not_run"),
        ]
        report = root / "clean.xml"
        write_junit(report, clean)
        result, output = run_gate(report)
        assert result == 0 and "at_nodes=28" in output
        assert output.count("ALLOWED_SKIP") == 2

        report = root / "skip.xml"
        write_junit(
            report,
            [("tests.example", "infra", "skipped", "runner clipboard unusable: SECRET")],
        )
        result, output = run_gate(report)
        assert result == 1 and "DISALLOWED_SKIP" in output and "SECRET" not in output

        report = root / "wrong-manual.xml"
        write_junit(
            report,
            [("tests.example", "not_manual", "skipped", "AT-I1b-8 manual")],
        )
        result, _ = run_gate(report)
        assert result == 1

        for outcome in ("failure", "error"):
            report = root / f"{outcome}.xml"
            write_junit(report, [("tests.example", outcome, outcome, "")])
            result, output = run_gate(report)
            assert result == 1 and outcome.upper() in output

        report = root / "exit.xml"
        write_junit(report, [])
        result, output = run_gate(report, pytest_exit=7)
        assert result == 7 and "pytest_exit=7 gate_exit=7" in output

        report = root / "census.xml"
        write_junit(report, [], at_nodes=27)
        result, output = run_gate(report)
        assert result == 1 and "AT_CENSUS" in output


def matrix_and_workflow_contract() -> None:
    assert len(matrix.AT_CELLS) == 28
    assert len({cell.id for cell in matrix.AT_CELLS}) == 28
    assert not hasattr(matrix, "_run_powershell")
    source = (ROOT / "tests" / "test_b103_copy_paste_matrix.py").read_text(
        encoding="utf-8"
    )
    assert "def _seed_os_clipboard() -> None:\n    other_program_write(SEED)" in source
    workflow = (ROOT / ".github" / "workflows" / "clipboard-windows.yml").read_text(
        encoding="utf-8"
    )
    assert '--junitxml="$junit"' in workflow
    assert workflow.index("$pytestExit = $LASTEXITCODE") < workflow.index(
        "b103_winci_gate.py"
    )
    assert workflow.count("Tee-Object") >= 2
    assert "exit $gateExit" in workflow
    assert "if: always()" in workflow
    assert "actions/upload-artifact@v4" in workflow


check("external_write_is_exact_and_self_verified", external_write_is_exact_and_self_verified)
check("mismatch_diagnostics_hold_only_metadata", mismatch_diagnostics_hold_only_metadata)
check("probe_returns_no_clipboard_content", probe_returns_no_clipboard_content)
check("other_program_helpers_guard_before_process", other_program_helpers_guard_before_process)
check("bom_is_not_relaxed_away", bom_is_not_relaxed_away)
check("gate_contract", gate_contract)
check("matrix_and_workflow_contract", matrix_and_workflow_contract)
print(f"CONTRACT_FAILURES={len(FAILURES)}")
raise SystemExit(1 if FAILURES else 0)
