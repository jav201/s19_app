"""Static, non-importing contract checks for the legacy Windows clipboard tests."""

from __future__ import annotations

import ast
import sys
from pathlib import Path


def function_source(tree: ast.AST, source: str, name: str) -> str:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(source, node) or ""
    return ""


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: contract_probe.py PATH", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    holder = function_source(tree, source, "_hold_clipboard")
    reap = function_source(tree, source, "_reap_holder")
    release = function_source(tree, source, "_release_clipboard")
    decoy = function_source(tree, source, "test_r_paste_16_3_decoy_powershell_never_runs")
    probe = function_source(tree, source, "test_runner_clipboard_probe")

    checks = {
        "holder_uses_kernel32_sleep": "kernel32.Sleep(20)" in holder and "user32.Sleep" not in holder,
        "holder_declares_cleanup": "user32.CloseClipboard()" in holder and "user32.DestroyWindow(hwnd)" in holder,
        "readiness_has_timeout": "ready_lines.get(timeout=5.0)" in holder and "reader.join(timeout=1.0)" in holder,
        "readiness_checks_liveness": "clipboard holder exited after HOLDING" in holder and "clipboard holder did not stay alive" in holder,
        "reap_has_bounded_wait_and_closes_stream": "proc.wait(timeout=3.0)" in reap and "proc.stdout.close()" in reap,
        "release_joins_and_verifies_reap": all(
            token in release
            for token in (
                'state["release"].set()',
                'state["supervisor"].join(timeout=5.0)',
                "clipboard holder supervisor did not finish",
                "clipboard holder process is still running",
            )
        ),
        "all_held_callers_release_and_join": (
            source.count('_held["release"].set()') == 0
            and source.count("_release_clipboard(_held)") == 13
        ),
        "decoy_is_a_real_executable_in_cwd_and_path": all(
            token in decoy
            for token in (
                "csc.exe",
                "powershell.exe",
                "shutil.copyfile",
                "monkeypatch.chdir",
                '"PATH"',
                "B103_DECOY_MARKER",
            )
        ),
        "decoy_forces_real_read_and_write_rescues": all(
            token in decoy
            for token in (
                "mod._STRATEGIES",
                "mod._read_via_powershell",
                "mod._WRITE_STRATEGIES",
                "mod._write_via_powershell",
            )
        ),
        "decoy_requires_nonempty_system_only_starts_and_no_marker": all(
            token in decoy
            for token in (
                "assert started",
                "non-system PowerShell",
                "marker.exists()",
            )
        ),
        "probe_failure_does_not_print_raw_result": (
            "runner clipboard unusable: {result}" not in probe
            and "_probe_failure_metadata" in probe
        ),
        "wait_failure_reports_shapes_not_content": (
            "expected!r" not in source
            and "got {_box(widget)!r}" not in source
            and "_content_shape" in function_source(tree, source, "_wait_for_box")
        ),
        "log_assertions_do_not_print_messages": (
            ", messages" not in source
            and function_source(tree, source, "_assert_log_excludes") != ""
        ),
        "content_comparisons_use_redacting_helper": source.count("_assert_content_equal(") >= 25,
        "no_raw_holder_ready_output": "ready.strip()!r" not in holder and "ready!r" not in holder,
    }

    failed = [name for name, passed in checks.items() if not passed]
    for name, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'} {name}")
    print(f"summary total={len(checks)} passed={len(checks) - len(failed)} failed={len(failed)}")
    print(f"test_function_count={sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_') for node in ast.walk(tree))}")
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
