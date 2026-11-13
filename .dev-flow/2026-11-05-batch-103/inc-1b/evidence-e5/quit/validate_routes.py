from __future__ import annotations

import ast
import base64
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

EXPECTED_WINCI = (
    ("R-COPY.16/1", "test_r_copy_16_1_button_and_materialized_empty_selection"),
    ("R-COPY.16/2", "test_r_copy_16_2_no_widget_focused"),
    ("R-COPY.16/3", "test_r_copy_16_3_highlighted_table_row_is_not_selection"),
    ("R-COPY.16/4", "test_r_copy_16_4_empty_single_line_input"),
    ("R-COPY.16/5", "test_r_copy_16_5_empty_json_selection"),
    ("R-COPY.16/6", "test_r_copy_16_6_multiline_text_without_selection"),
    ("R-COPY.20/1", "test_r_copy_20_1_help_modal_blocks_quit_even_with_empty_selection"),
    ("R-COPY.20/2", "test_r_copy_20_2_load_dialog_stays_top"),
    ("R-COPY.20/3", "test_r_copy_20_3_existing_copy_quit_stays_single"),
)


def _has_winci_seed(node: ast.AST) -> bool:
    return any(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "_run"
        and any(
            keyword.arg == "winci_seed"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in call.keywords
        )
        for call in ast.walk(node)
    )


def _expect_failure(label, function):
    try:
        function()
    except pytest.skip.Exception as exc:
        raise AssertionError(f"{label}: infrastructure failure became skip") from exc
    except (pytest.fail.Exception, AssertionError) as exc:
        return exc
    raise AssertionError(f"{label}: infrastructure failure did not fail")


def _load_module(test_path: Path):
    spec = importlib.util.spec_from_file_location("b103_quit_route_audit", test_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _static_audit(tree: ast.AST) -> None:
    tests = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    }
    assert len(tests) == 28, len(tests)
    expected = {name for _, name in EXPECTED_WINCI}
    seeded = {name for name, node in tests.items() if _has_winci_seed(node)}
    assert seeded == expected, sorted(seeded ^ expected)
    assert len(EXPECTED_WINCI) == 9

    skips = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "pytest"
        and node.func.attr == "skip"
    ]
    assert skips == [], skips

    for name in expected - {"test_r_copy_20_3_existing_copy_quit_stays_single"}:
        assert name in tests
    for name in (
        "test_r_copy_20_1_help_modal_blocks_quit_even_with_empty_selection",
        "test_r_copy_20_2_load_dialog_stays_top",
    ):
        observations = sum(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "_assert_no_copy_effects"
            for call in ast.walk(tests[name])
        )
        assert observations == 3, (name, observations)
    assert any(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "_close_and_assert_unchanged"
        for call in ast.walk(tests["test_r_copy_20_3_existing_copy_quit_stays_single"])
    )


def _dynamic_audit(module) -> None:
    payload = "Ñ€\rL1\r\nL2 漢\n"
    encoded_payload = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    completed = SimpleNamespace(returncode=0, stdout=encoded_payload + "\r\n", stderr="")
    with (
        patch.object(module, "require_isolated_clipboard"),
        patch.object(module, "_winci_powershell_path", return_value="unused-in-probe"),
        patch.object(module.subprocess, "run", return_value=completed) as run,
    ):
        assert module._read_os_clipboard_exact() == payload
        assert run.call_count == 1
        assert run.call_args.kwargs["shell"] is False
        assert run.call_args.kwargs["check"] is False
        script = run.call_args.args[0][-1]
        assert "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);" in script
        assert "[Console]::OutputEncoding=[Text.Encoding]::UTF8" not in script

    for label, completed in (
        ("bom", SimpleNamespace(returncode=0, stdout="\ufeff" + encoded_payload, stderr="")),
        ("invalid-base64", SimpleNamespace(returncode=0, stdout="not-base64", stderr="")),
        ("powershell-exit", SimpleNamespace(returncode=1, stdout="", stderr="simulated")),
    ):
        with (
            patch.object(module, "require_isolated_clipboard"),
            patch.object(module, "_winci_powershell_path", return_value="unused-in-probe"),
            patch.object(module.subprocess, "run", return_value=completed),
        ):
            _expect_failure(label, module._read_os_clipboard_exact)

    with (
        patch.object(module, "require_isolated_clipboard"),
        patch.object(module, "_winci_powershell_path", return_value="unused-in-probe"),
        patch.object(module.subprocess, "run", side_effect=OSError("simulated")),
    ):
        _expect_failure("powershell-os-error", module._read_os_clipboard_exact)

    with (
        patch.object(module, "require_isolated_clipboard", side_effect=AssertionError("not isolated")),
        patch.object(module.subprocess, "run") as run,
    ):
        _expect_failure("outside-isolation", lambda: module._separate_powershell("unused"))
        assert run.call_count == 0

    from s19_app.tui import os_clipboard_input as os_clipboard

    with patch.object(os_clipboard, "_system_powershell", return_value=None):
        _expect_failure("missing-powershell", module._winci_powershell_path)

    monkeypatch = pytest.MonkeyPatch()
    try:
        with (
            patch.object(module.sys, "platform", "win32"),
            patch.object(module, "require_isolated_clipboard"),
            patch.object(module, "clipboard_probe", return_value=(False, "CLIPBOARD-SECRET")),
        ):
            error = _expect_failure("probe", lambda: module.clipboard.__wrapped__(monkeypatch))
            assert "CLIPBOARD-SECRET" not in str(error)
    finally:
        monkeypatch.undo()

    monkeypatch = pytest.MonkeyPatch()
    try:
        with (
            patch.object(module.sys, "platform", "win32"),
            patch.object(module, "require_isolated_clipboard"),
            patch.object(module, "clipboard_probe", side_effect=pytest.skip.Exception("simulated")),
        ):
            _expect_failure("probe-skip", lambda: module.clipboard.__wrapped__(monkeypatch))
    finally:
        monkeypatch.undo()

    encoded_seed = base64.b64encode(module.SEED.encode("utf-8")).decode("ascii")
    results = [
        SimpleNamespace(returncode=0, stdout="", stderr=""),
        SimpleNamespace(returncode=0, stdout=encoded_seed + "\r\n", stderr=""),
    ]
    with (
        patch.object(module, "require_isolated_clipboard"),
        patch.object(module, "_winci_powershell_path", return_value="unused-in-probe"),
        patch.object(module.subprocess, "run", side_effect=results) as run,
    ):
        module._seed_os_clipboard()
        assert run.call_count == 2
        seed_script = run.call_args_list[0].args[0][-1]
        read_script = run.call_args_list[1].args[0][-1]
        assert "Set-Clipboard -Value $text" in seed_script
        assert encoded_seed in seed_script
        assert "Get-Clipboard -Raw" in read_script
        for call in run.call_args_list:
            assert call.args[0][0] == "unused-in-probe"
            assert call.kwargs["shell"] is False
            assert call.kwargs["check"] is False


def main() -> None:
    test_path = Path(sys.argv[1]).resolve()
    tree = ast.parse(test_path.read_text(encoding="utf-8"))
    _static_audit(tree)
    module = _load_module(test_path)
    _dynamic_audit(module)

    print("ROUTE_AUDIT PASS: 28 Linux nodes; exactly 9 explicit WinCI seed routes")
    for route, name in EXPECTED_WINCI:
        print(f"ROUTE PASS {route}: {name}; WinCI=not_run")
    print("MODAL_CLOSURE_AUDIT PASS: .20/1-2 have 3 observations; .20/3 closes with n")
    print("EXACT_READER_SIMULATED PASS: UTF8Encoding(false); Unicode/CR/LF/final LF preserved")
    print("INFRASTRUCTURE_AUDIT PASS: probe/seed/read/isolation errors fail, never skip")
    print("EXTERNAL_SEED_SIMULATED PASS: distinct Set-Clipboard and Get-Clipboard processes")
    print("WINCI not_run: no real Windows clipboard or PowerShell was used")


if __name__ == "__main__":
    main()
