"""Linux-safe E5 negative controls for clipboard disclosure and isolation.

The outer pytest child is deliberately RED. Its transcript and JUnit must
never disclose the known-bad canary. OS clipboard and process boundaries are
mocked in every direct control; this module is not one of the six WinCI files.
"""

from __future__ import annotations

import base64
import ctypes
import logging
import os
import subprocess
import sys
import xml.etree.ElementTree as etree
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import test_b103_clipboard_tail as tail
from tests import test_b103_clipboard_windows as windows
from tests.support import b103_clipboard as support


CANARY = '<&>"\\\nΩ-E5-KNOWN-BAD-0123456789'


class _GuardDenied(RuntimeError):
    pass


class _BoundaryTouched(RuntimeError):
    pass


def _assert_no_canary(surface: str, label: str) -> None:
    forms = windows._disclosure_forms(CANARY)
    hits = [name for name, needle in forms.items() if needle and needle in surface]
    assert not hits, (
        f"{label}: known-bad disclosure; forms={hits}; surface_chars={len(surface)}"
    )


def _real_probe_mismatch(monkeypatch: pytest.MonkeyPatch) -> object:
    monkeypatch.setattr(support, "require_isolated_clipboard", lambda *_: None)
    monkeypatch.setattr(support.os, "urandom", lambda size: b"\x5a" * size)
    monkeypatch.setattr(support, "_own_write", lambda _text: True)
    monkeypatch.setattr(support, "other_program_read", lambda: CANARY)
    usable, detail = support._probe_once()
    assert not usable
    assert isinstance(detail, support._ProbeDetail)
    assert detail.stage == "round-trip-mismatch"
    return detail


def test_e5_probe_classification_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = _real_probe_mismatch(monkeypatch)
    detail = support._ProbeDetail(
        CANARY,
        stage=real.stage,
        expected_chars=real.metadata["expected_chars"],
        actual_chars=real.metadata["actual_chars"],
    )
    metadata = windows._probe_failure_metadata(detail)
    assert metadata.startswith("stage=round-trip-mismatch,"), (
        "probe mismatch was not classified as round-trip-mismatch"
    )
    _assert_no_canary(metadata, "probe metadata")


def _record_with(channel: str, text: str) -> logging.LogRecord:
    if channel == "exception":
        try:
            raise ValueError(text)
        except ValueError:
            return logging.LogRecord(
                "known-bad",
                logging.ERROR,
                __file__,
                1,
                "exception record",
                (),
                sys.exc_info(),
            )
    return logging.LogRecord(
        "known-bad",
        logging.ERROR,
        __file__,
        1,
        "%s" if channel == "message" else "stack record",
        (text,) if channel == "message" else (),
        None,
        sinfo=text if channel == "stack" else None,
    )


def test_e5_windows_log_oracle_covers_complete_records_and_derived_forms() -> None:
    forms = windows._disclosure_forms(CANARY)
    assert {"full", "prefix", "repr", "escape", "xml"} <= set(forms)
    for channel in ("message", "exception", "stack"):
        for form_name, text in forms.items():
            record = _record_with(channel, text)
            with pytest.raises(AssertionError) as caught:
                windows._assert_log_excludes([record], CANARY, "known-bad log")
            _assert_no_canary(str(caught.value), f"assert message {channel}/{form_name}")


def test_e5_tail_log_oracle_covers_complete_records_and_derived_forms() -> None:
    forms = windows._disclosure_forms(CANARY)
    for channel in ("message", "exception", "stack"):
        for form_name, text in forms.items():
            record = _record_with(channel, text)
            records = [
                (record.name, record.levelname, windows._formatted_log_entry(record))
            ]
            with pytest.raises(AssertionError) as caught:
                tail._no_secret(records, CANARY)
            _assert_no_canary(
                str(caught.value), f"tail assert message {channel}/{form_name}"
            )


class _ApiBoundary:
    def __init__(self) -> None:
        self.calls = []

    def __getattr__(self, name: str):
        def called(*args, **kwargs):
            self.calls.append(name)
            raise _BoundaryTouched(f"OS API boundary reached: {name}")

        return called


def test_e5_intrinsic_guards_precede_clipboard_and_process_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32 = _ApiBoundary()
    kernel32 = _ApiBoundary()
    process_calls = []
    guard_calls = []

    def deny(kind: str) -> None:
        guard_calls.append(kind)
        raise _GuardDenied("injected non-isolated host")

    def forbid_process(*args, **kwargs):
        process_calls.append(args)
        raise _BoundaryTouched("process boundary reached")

    monkeypatch.setattr(support, "require_isolated_clipboard", deny)
    monkeypatch.setattr(support, "_require_windows", lambda: None)
    monkeypatch.setattr(support, "_system_powershell_path", lambda: r"C:\Safe\powershell.exe")
    monkeypatch.setattr(subprocess, "run", forbid_process)
    monkeypatch.setattr(subprocess, "Popen", forbid_process)
    monkeypatch.setattr(
        ctypes,
        "windll",
        SimpleNamespace(user32=user32, kernel32=kernel32),
        raising=False,
    )

    calls = (
        ("windows nontext", lambda: windows._write_nontext_clipboard("bitmap")),
        ("windows holder", lambda: windows._hold_clipboard(0.1)),
        ("windows open probe", windows._open_clipboard_probe),
        ("windows empty text", windows._write_empty_unicode_text),
        ("windows unterminated", lambda: windows._own_write_no_terminator("x")),
        ("support launcher", lambda: support._run_system_powershell("Get-Clipboard")),
        ("support own write", lambda: support._own_write("x")),
        ("support own read", support.own_read),
        ("support sequence", support.clipboard_sequence_number),
    )
    for label, call in calls:
        before = len(guard_calls)
        try:
            call()
        except _GuardDenied:
            pass
        else:
            raise AssertionError(f"helper lacked intrinsic isolation guard: {label}")
        assert len(guard_calls) == before + 1, f"guard count changed unexpectedly: {label}"
        assert user32.calls == [], f"user32 was reached before the guard: {label}"
        assert kernel32.calls == [], f"kernel32 was reached before the guard: {label}"
        assert process_calls == [], f"process was reached before the guard: {label}"


def _install_binary_powershell(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, str], list[tuple[list, dict]]]:
    monkeypatch.setattr(support, "_require_windows", lambda: None)
    monkeypatch.setattr(support, "require_isolated_clipboard", lambda *_: None)
    monkeypatch.setattr(support, "_system_powershell_path", lambda: r"C:\Safe\powershell.exe")
    state = {"text": ""}
    calls = []

    def fake_run(argv, **kwargs):
        assert kwargs.get("capture_output") is True
        assert kwargs.get("text", False) is False
        assert kwargs.get("universal_newlines", False) is False
        assert "newline" not in kwargs
        assert kwargs.get("encoding") is None
        assert kwargs.get("errors") is None
        calls.append((list(argv), dict(kwargs)))
        if "input" in kwargs:
            assert isinstance(kwargs["input"], bytes)
            state["text"] = base64.b64decode(
                kwargs["input"], validate=True
            ).decode("utf-16-le", "surrogatepass")
            stdout = b""
        else:
            assert kwargs.get("stdin") == subprocess.DEVNULL
            stdout = base64.b64encode(state["text"].encode("utf-8"))
        return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(support.subprocess, "run", fake_run)
    return state, calls


def test_e5_external_seed_transport_preserves_unicode_cr_lf_and_final_lf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, calls = _install_binary_powershell(monkeypatch)
    for payload in (
        "SEED-Ω-🙂",
        "SEED-CR\rX",
        "SEED-CRLF\r\nX",
        "SEED-LF\nX",
        "SEED-FINAL-LF\n",
    ):
        first_call = len(calls)
        support.other_program_write(payload)
        assert state["text"] == payload, "external seed writer changed payload shape"
        assert support.other_program_read() == payload, "external seed reader changed payload shape"
        for argv, kwargs in calls[first_call:]:
            assert payload not in str(argv), "seed payload appeared in process argv"
            if "input" in kwargs:
                raw = payload.encode("utf-16-le", "surrogatepass")
                assert raw not in kwargs["input"], "seed payload bypassed Base64 transport"


def test_e5_external_seed_writer_loads_presentation_core_before_set_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _state, calls = _install_binary_powershell(monkeypatch)
    support.other_program_write("SEED-ASSEMBLY")
    write_calls = [(argv, kwargs) for argv, kwargs in calls if "input" in kwargs]
    assert len(write_calls) == 1
    argv, _kwargs = write_calls[0]
    command = argv[-1]
    assembly = command.index("Add-Type -AssemblyName PresentationCore")
    set_text = command.index("[Windows.Clipboard]::SetText($text)")
    assert assembly < set_text
    assert "System.Windows.Forms" not in command


_KNOWN_BAD_SOURCE = r'''
import logging
from types import SimpleNamespace

from s19_app.tui import os_clipboard_input as product
from tests import test_b103_clipboard_tail as tail
from tests import test_b103_clipboard_windows as windows
from tests.support import b103_clipboard as support

CANARY = None


def _allow_mocked_windows(monkeypatch):
    monkeypatch.setattr(support, "_require_windows", lambda: None)
    monkeypatch.setattr(support, "require_isolated_clipboard", lambda *args, **kwargs: None)


def test_probe_mismatch(monkeypatch):
    _allow_mocked_windows(monkeypatch)
    monkeypatch.setattr(support.os, "urandom", lambda size: b"\x5a" * size)
    monkeypatch.setattr(support, "_own_write", lambda _text: True)
    monkeypatch.setattr(support, "other_program_read", lambda: CANARY)
    usable, real = support._probe_once()
    assert not usable and isinstance(real, support._ProbeDetail)
    detail = support._ProbeDetail(
        CANARY,
        stage=real.stage,
        expected_chars=real.metadata["expected_chars"],
        actual_chars=real.metadata["actual_chars"],
    )
    monkeypatch.setattr(support, "clipboard_probe", lambda: (False, detail))
    windows.test_runner_clipboard_probe()


def test_round_trip_mismatch(monkeypatch):
    _allow_mocked_windows(monkeypatch)
    monkeypatch.setattr(
        support,
        "_run_system_powershell",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
    )
    monkeypatch.setattr(support, "other_program_read", lambda: CANARY + "-wrong")
    support.other_program_write(CANARY)


def _inject_process_exception(monkeypatch):
    _allow_mocked_windows(monkeypatch)
    monkeypatch.setattr(support, "_system_powershell_path", lambda: r"C:\Safe\powershell.exe")

    def fail(*args, **kwargs):
        raise OSError(CANARY)

    monkeypatch.setattr(support.subprocess, "run", fail)


def test_read_exception_chaining(monkeypatch):
    _inject_process_exception(monkeypatch)
    support.other_program_read()


def test_write_exception_chaining(monkeypatch):
    _inject_process_exception(monkeypatch)
    support.other_program_write(CANARY)


def _capture_log(channel, form="full"):
    text = windows._disclosure_forms(CANARY)[form]
    logger = logging.getLogger("s19_app")
    previous_level = logger.level
    previous_propagate = logger.propagate
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    records = support.install_log_capture()
    removed = []
    for handler in list(logger.handlers):
        if getattr(handler, "records", None) is not records:
            removed.append(handler)
            logger.removeHandler(handler)
    try:
        if channel == "message":
            logger.error("known-bad message: %s", text)
        elif channel == "exception":
            try:
                raise ValueError(text)
            except ValueError:
                logger.exception("known-bad exception record")
        else:
            record = logging.LogRecord(
                "s19_app",
                logging.ERROR,
                __file__,
                1,
                "known-bad stack record",
                (),
                None,
                sinfo="frame\n" + text,
            )
            logger.handle(record)
    finally:
        support.remove_log_capture(records)
        for handler in removed:
            logger.addHandler(handler)
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate
    return records


def _known_bad_log(channel, form="full"):
    records = _capture_log(channel, form)
    checks = (
        lambda: tail._no_secret(records, CANARY),
        lambda: windows._assert_log_excludes(records, CANARY, "known-bad outer"),
    )
    detected = []
    for check in checks:
        try:
            check()
        except AssertionError:
            detected.append(True)
        else:
            detected.append(False)
    assert all(detected), (
        f"known-bad log detector missed {channel}/{form}; "
        f"detections={len([x for x in detected if x])}"
    )
    raise AssertionError(f"known-bad log detected: {channel}/{form}")


def test_log_message():
    _known_bad_log("message")


def test_log_exception():
    _known_bad_log("exception")


def test_log_stack():
    _known_bad_log("stack")


def test_log_xml():
    _known_bad_log("message", "xml")


def test_counts_run_arms(monkeypatch):
    obs = {
        "counts": {
            "override": 0,
            "tail": 0,
            "base": 0,
            "writer": 0,
            "helper": 0,
            "process": 0,
        },
        "osc": [CANARY],
        "osc_requests": [CANARY],
        "payload": CANARY,
    }

    def bad_arm():
        tail._counts(obs, override=1, tail=1, base=1, writer=1, osc=1, helper=1)

    tail._run_arms(monkeypatch, [("known-bad-counts", bad_arm)])


def _hostile_case(tmp_path, monkeypatch, broken):
    program = r"C:\Safe\WindowsPowerShell\v1.0\powershell.exe"
    system_directory = r"C:\Safe"
    records = []
    if broken == "log-xml":
        records = [
            ("s19_app", "ERROR", windows._disclosure_forms(CANARY)["xml"])
        ]

    def observation(_tmp_path, _monkeypatch, payload):
        argv = [program, "-NonInteractive", *product._POWERSHELL_WRITE_COMMAND]
        kwargs = {
            "shell": False,
            "cwd": system_directory,
            "input": payload.encode("utf-8", errors="replace"),
        }
        counts = {
            "override": 1,
            "tail": 1,
            "base": 1,
            "writer": 1,
            "helper": 1,
            "process": 1,
        }
        if broken == "cardinality":
            counts["process"] = 2
        elif broken == "argv":
            argv[0] = CANARY
        elif broken == "cwd":
            kwargs["cwd"] = CANARY
        elif broken == "input":
            kwargs["input"] = (payload + "-wrong").encode("utf-8", errors="replace")
        processes = [(list(argv), dict(kwargs)) for _ in range(counts["process"])]
        return {
            "counts": counts,
            "app": payload,
            "os": payload,
            "base_payloads": [payload],
            "override_payloads": [payload],
            "tail_payloads": [payload],
            "writer_payloads": [payload],
            "writer_threads": [1],
            "helper_payloads": [payload],
            "osc": [payload],
            "osc_requests": [{"request": "known-bad"}],
            "processes": processes,
            "notices": [(product._copy_notice_text(payload), "information", 6.0)],
            "transport": "linux-simulated-powershell",
            "expected": payload,
        }

    patches = (
        (tail, "HOSTILE_NAME", CANARY),
        (tail, "sys", SimpleNamespace(platform="linux")),
        (product, "_system_powershell", lambda: program),
        (product, "_system_directory", lambda: system_directory),
        (tail, "_powershell_transport_observation", observation),
        (tail, "_with_logs", lambda observe: (observe(), records)),
    )
    previous = [(owner, name, getattr(owner, name)) for owner, name, _ in patches]
    try:
        for owner, name, value in patches:
            setattr(owner, name, value)
        tail.test_r_tui_043_13_102_hostile_exact_payload_transport_and_logs(tmp_path, monkeypatch)
    finally:
        for owner, name, value in reversed(previous):
            setattr(owner, name, value)


def test_hostile_cardinality(tmp_path, monkeypatch):
    _hostile_case(tmp_path, monkeypatch, "cardinality")


def test_hostile_argv(tmp_path, monkeypatch):
    _hostile_case(tmp_path, monkeypatch, "argv")


def test_hostile_cwd(tmp_path, monkeypatch):
    _hostile_case(tmp_path, monkeypatch, "cwd")


def test_hostile_input(tmp_path, monkeypatch):
    _hostile_case(tmp_path, monkeypatch, "input")


def test_hostile_log_xml(tmp_path, monkeypatch):
    _hostile_case(tmp_path, monkeypatch, "log-xml")
'''


_EXPECTED_KNOWN_BAD = {
    "test_probe_mismatch",
    "test_round_trip_mismatch",
    "test_read_exception_chaining",
    "test_write_exception_chaining",
    "test_log_message",
    "test_log_exception",
    "test_log_stack",
    "test_log_xml",
    "test_counts_run_arms",
    "test_hostile_cardinality",
    "test_hostile_argv",
    "test_hostile_cwd",
    "test_hostile_input",
    "test_hostile_log_xml",
}


def _junit_surface(root: etree.Element) -> str:
    values = []
    for element in root.iter():
        values.extend((element.tag, element.text or "", element.tail or ""))
        for key, value in element.attrib.items():
            values.extend((key, value))
    return "\n".join(values)


def test_e5_outer_known_bad_child_is_red_without_transcript_or_junit_disclosure(
    pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _KNOWN_BAD_SOURCE.replace("CANARY = None", f"CANARY = {CANARY!r}", 1)
    (pytester.path / "test_known_bad.py").write_text(source, encoding="utf-8")
    repo = Path(__file__).resolve().parents[1]
    previous = os.environ.get("PYTHONPATH")
    monkeypatch.setenv("PYTHONPATH", str(repo) + os.pathsep + (previous or ""))
    result = pytester.runpytest_subprocess(
        "-p",
        "no:cacheprovider",
        "-o",
        "addopts=",
        "--tb=short",
        "--junitxml=junit.xml",
        "test_known_bad.py",
    )
    assert result.ret != 0, "known-bad pytest child unexpectedly exited successfully"

    junit_raw = (pytester.path / "junit.xml").read_text(encoding="utf-8")
    root = etree.fromstring(junit_raw)
    cases = list(root.iter("testcase"))
    failed = {
        case.attrib.get("name", "")
        for case in cases
        if case.find("failure") is not None
    }
    errors = [case for case in cases if case.find("error") is not None]
    assert len(cases) == len(_EXPECTED_KNOWN_BAD), (
        f"known-bad child collection count changed: {len(cases)}"
    )
    assert failed == _EXPECTED_KNOWN_BAD, (
        f"known-bad child failed-node census changed: count={len(failed)}"
    )
    assert not errors, f"known-bad child produced {len(errors)} errors instead of failures"

    stdout = result.stdout.str()
    stderr = result.stderr.str()
    for label, surface in (
        ("stdout", stdout),
        ("stderr", stderr),
        ("JUnit raw", junit_raw),
        ("JUnit parsed", _junit_surface(root)),
    ):
        _assert_no_canary(surface, label)

    safe_markers = (
        "stage=round-trip-mismatch",
        "round-trip mismatch",
        "system PowerShell invocation failed",
        "known-bad log detected: message/full",
        "known-bad log detected: exception/full",
        "known-bad log detected: stack/full",
        "known-bad log detected: message/xml",
        "clipboard arm failures: hostile-no-final-lf, hostile-final-lf, unicode, cr, crlf",
        "clipboard arm failures: hostile-no-final-lf, hostile-final-lf",
    )
    combined = stdout + "\n" + junit_raw
    for index, marker in enumerate(safe_markers):
        assert marker in combined, f"known-bad child missed expected safe marker {index}"
