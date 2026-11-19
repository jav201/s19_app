# U-DLG — R-DLG.2: Escape in the seven dialogs that ignore it (DeepSeek v4-pro, product code)

Appended after `frontB/FB-common.md` and `units2/TA2-common.md` (its apply_recite/lint sections do not apply: this unit writes no row and no `Traces:` line). Tree 2a8ab75f.

## Fixed diagnosis (read at 2a8ab75f)
- Canon R-DLG.2 (`REQUIREMENTS.md:3744`): "When the operator presses Escape in a dialog while none of its dropdown lists is open, the system shall do what the dialog's Cancel or Close button does." F2a flagged it UNIMPLEMENTED: batch-101 Inc 12 fixed only the Reports dialog and routed the rest to BL-I12-5 (`.dev-flow/BACKLOG-CODE.md:1864`; `.dev-flow/2026-11-01-batch-101/inc-12/E1-rulings.md:17`, `:76`).
- Seven `ModalScreen`s in `s19_app/tui/screens.py` have no `escape` binding (every other dialog has one, e.g. `ChangeSetJsonScreen` `:762` + `action_cancel` `:793-795`, `LoadGuardScreen` `screens_directionb/shared.py:624`):
  | class | lines | `def __init__` | Cancel/Close branch in `on_button_pressed` | what that branch does |
  |---|---|---|---|---|
  | `EntryJsonScreen` | 798-876 | :851 | :870-872 `entry_json_cancel` | `dismiss(None)` |
  | `SaveFlowScreen` | 1407-1475 | :1425 | :1466-1468 `flow_save_cancel` | `dismiss(None)` |
  | `LoadFlowScreen` | 1476-1581 | :1494 | :1522-1524 `flow_load_cancel` | `dismiss(None)` |
  | `ConfirmDiscardScreen` | 2186-2228 | :2200 | :2225-2226 `flow_discard_cancel` | `dismiss(False)` |
  | `SelectVariantScreen` | 2321-2406 | :2334 | :2381-2384 `variant_cancel` | log `SelectVariantScreen dismissed by cancel.`, `dismiss(None)` |
  | `ConfirmWriteScreen` | 3448-3535 | :3491 | :3531-3533 `confirm_write_cancel` | log `ConfirmWriteScreen cancelled.`, `dismiss(ConfirmWriteResult(False, self._crc_saveback_width))` |
  | `OperationsScreen` | 3536-4340 | :3609 | :3759-3762 `operations_close` | log `OperationsScreen dismissed by close.`, `dismiss(None)` |
- None of the seven has a dropdown (`Select`), so R-DLG.15 (an open dropdown keeps its own Escape) does not arise. The fix is the approved pattern of batch-101 Inc 12 ruling D-7 A (a plain, non-priority screen binding that does what Close does).

## Files (exactly 3)
`s19_app/tui/screens.py`, `tests/test_b101_reach_and_reports_escape.py` (append only), `REQUIREMENTS.md` (7 cells of CTX-DIALOG).

## Steps (append to `../REPORT.md` after each)
1. Header; N0 (`--collect-only -q tests`).
2. **Tests first.** Append the code block below to the end of `tests/test_b101_reach_and_reports_escape.py`. Run the new nodes on the unchanged product: expect 7 + 1 RED (`did not settle: <Class> closes by escape`), and the `button` half of each case passing. Paste the summary. If `OperationsScreen(...)` with the synthetic `LoadedFile` fails to compose, STOP that case and report (fallback, only with the orchestrator's OK: open it as `tests/test_tui_crc_surface.py:113` `_open_crc_screen` does, after a real load).
3. **Product.** In each of the seven classes: (a) insert directly above its `    def __init__` line: a `#:` comment line `#: Escape does what Cancel does (R-DLG.2; the ChangeSetJsonScreen idiom).` (for Operations: `… what Close does …`), the line `    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]` (Operations: `    BINDINGS = [Binding("escape", "close_operations", "Close", show=False)]`) and one empty line; (b) insert directly above its `    def on_button_pressed` line a method `def action_cancel(self) -> None:` (Operations: `def action_close_operations(self) -> None:`) whose docstring is `"""Escape and the Cancel button share this path (R-DLG.2)."""` (Operations: `Close button`) and whose body is exactly the "what that branch does" column, followed by one empty line; (c) replace the body of the Cancel/Close branch with `self.action_cancel()` (Operations: `self.action_close_operations()`), keeping its `return` where it had one. Nothing else changes (`Binding` is imported at `:14`).
4. **Canon context.** In CTX-DIALOG (`REQUIREMENTS.md:3400-3413`) change the last cell `no` to `yes` on exactly these 7 lines: `Select variant (project '<name>'):`, `Save flow as:`, `Load flow:`, `Discard unsaved flow edits?`, `Edit entry JSON:`, `Write the computed CRC(s) into a new …`, `Operations:`. Nothing else (the line `project has no` at :3418 is the Reports focus note: leave it).
5. Run the new nodes -> 8 passed. Run the existing nodes of the file whose names start `test_r_dlg_2_` -> unchanged GREEN.
6. **Negative control (R-DLG.2):** in a copy delete the `BINDINGS` line of `SaveFlowScreen` -> `test_r_dlg_2_13_escape_does_what_cancel_does[SaveFlowScreen]` and `test_r_dlg_2_14_escape_in_save_flow_saves_nothing` RED, the other 6 cases GREEN.
7. After: N0 + 8. End per TA2-common.

## Code to append to `tests/test_b101_reach_and_reports_escape.py`
```python


# --------------------------------------------------------------------------- #
# R-DLG.2 in the seven dialogs that ignored Escape (BL-I12-5, batch-103 fix round)
# --------------------------------------------------------------------------- #
_SEVEN_DIALOGS = [
    "EntryJsonScreen",
    "SaveFlowScreen",
    "LoadFlowScreen",
    "ConfirmDiscardScreen",
    "SelectVariantScreen",
    "ConfirmWriteScreen",
    "OperationsScreen",
]


def _seven_dialogs(tmp_path: Path) -> dict:
    """name -> (factory, id of its Cancel or Close button, the result that button gives)."""
    from s19_app.tui.models import LoadedFile
    from s19_app.tui.screens import (
        ConfirmDiscardScreen,
        ConfirmWriteResult,
        ConfirmWriteScreen,
        EntryJsonScreen,
        LoadFlowScreen,
        OperationsScreen,
        SaveFlowScreen,
        SelectVariantScreen,
    )

    loaded = LoadedFile(
        path=Path("firmware.s19"),
        file_type="s19",
        mem_map={0x1000: 0x12},
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1004)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_records=[],
        mac_diagnostics=[],
    )
    return {
        "EntryJsonScreen": (lambda: EntryJsonScreen('{"type": "bytes"}'), "entry_json_cancel", None),
        "SaveFlowScreen": (lambda: SaveFlowScreen("flow", existing=[]), "flow_save_cancel", None),
        "LoadFlowScreen": (lambda: LoadFlowScreen(["nightly"], tmp_path), "flow_load_cancel", None),
        "ConfirmDiscardScreen": (lambda: ConfirmDiscardScreen("nightly"), "flow_discard_cancel", False),
        "SelectVariantScreen": (
            lambda: SelectVariantScreen("proj1", [("v1", "v1"), ("v2", "v2")], 0),
            "variant_cancel",
            None,
        ),
        "ConfirmWriteScreen": (ConfirmWriteScreen, "confirm_write_cancel", ConfirmWriteResult(False, 32)),
        "OperationsScreen": (lambda: OperationsScreen([("crc", "CRC")], loaded), "operations_close", None),
    }


async def _dismiss_with(app, pilot, screen, how: str, button_id: str) -> list:
    from textual.widgets import Button

    results: list = []
    kind = type(screen)
    app.push_screen(screen, callback=results.append)
    await settled(pilot, lambda: isinstance(app.screen, kind), f"{kind.__name__} opens", timeout=CLOSE_WAIT_S)
    await settle(pilot)
    if how == "escape":
        await pilot.press("escape")
    else:
        app.screen.query_one(f"#{button_id}", Button).press()
    await settled(
        pilot,
        lambda: not any(isinstance(s, kind) for s in app.screen_stack),
        f"{kind.__name__} closes by {how}; stack {_stack(app)}",
        timeout=CLOSE_WAIT_S,
    )
    await settle(pilot)
    return results


@pytest.mark.parametrize("name", _SEVEN_DIALOGS)
def test_r_dlg_2_13_escape_does_what_cancel_does(tmp_path: Path, name: str) -> None:
    """R-DLG.2/13 (verification): in each dialog that ignored Escape (CTX-DIALOG
    "Esc today: no", BL-I12-5), Escape closes the dialog with exactly the result its
    Cancel or Close button gives, and that is the result the button always gave
    (the callers read None or False as "nothing changes").

    Mutant: drop one dialog's escape binding -> that case never closes -> RED.
    """
    factory, button_id, expected = _seven_dialogs(tmp_path)[name]

    async def scenario(app, pilot) -> None:
        by_button = await _dismiss_with(app, pilot, factory(), "button", button_id)
        by_escape = await _dismiss_with(app, pilot, factory(), "escape", button_id)
        assert by_button == [expected], by_button
        assert by_escape == [expected], by_escape

    _run(tmp_path, scenario)


def test_r_dlg_2_14_escape_in_save_flow_saves_nothing(tmp_path: Path) -> None:
    """R-DLG.2/14 (validation, black box): in the Flow Builder of an open project the
    operator adds a block, presses Save, then Escape in the Save flow dialog: the
    dialog closes, no flow file is written and the flow stays unsaved.

    Mutant: as R-DLG.2/13 -> RED (the dialog stays open).
    """
    from textual.widgets import Button, Static

    from s19_app.tui.screens import SaveFlowScreen

    async def scenario(app, pilot) -> None:
        make_project(app, "proj1")
        project = await load_project(app, "proj1")
        await open_flow_builder(app, pilot)
        app.query_one("#flow_ref", Input).value = "prg.s19"
        app.query_one("#flow_add", Button).press()
        await settle(pilot)
        app.query_one("#flow_save", Button).press()
        await settled(pilot, lambda: isinstance(app.screen, SaveFlowScreen), "Save flow opens", timeout=CLOSE_WAIT_S)
        await settle(pilot)
        await pilot.press("escape")
        await settled(
            pilot,
            lambda: not any(isinstance(s, SaveFlowScreen) for s in app.screen_stack),
            f"Save flow closes on Escape; stack {_stack(app)}",
            timeout=CLOSE_WAIT_S,
        )
        await settle(pilot)
        flows = project / "flows"
        written = sorted(p.name for p in flows.glob("*.json")) if flows.is_dir() else []
        assert written == [], written
        strip = app.query_one("#flow_name_strip", Static).render().plain
        assert "· unsaved" in strip, strip

    _run(tmp_path, scenario)
```

## For the checker
Laws on the unit tree: no new RED. Regression files (they construct these dialogs): `tests/test_tui_flow_persistence_ui.py`, `tests/test_tui_variants.py`, `tests/test_tui_crc_surface.py`, `tests/test_b100_load_question.py`, `tests/test_tui_patch_editor_v2.py`, `tests/test_tui_operations_view.py`: same result as on 2a8ab75f. Diff of `screens.py`: per class only the comment, the `BINDINGS` line, one action method and the one-line branch body.
