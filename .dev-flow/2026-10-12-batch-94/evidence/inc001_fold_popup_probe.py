"""inc001 FOLD-ROUND probe — ONE dirty Load raises exactly ONE LoadGuardScreen
and the popup stack drains empty after the answer (both arms).

Companion to the fix-round ``_review-b94/probe_double_popup.py`` (which proved
the duplicate push: two LoadGuardScreen instances stacked). Re-run after the
fold round's F1 product edit (app.py: the verbatim duplicate
``_answer`` + ``push_screen`` block deleted).

Evidence: ``inc001_fold_popup_probe.txt`` (tee of this run).
"""
import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from textual.widgets import Button, Input

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import LoadGuardScreen, PatchEditorPanel

VALID_ONE = """{
  "format": "s19app-changeset",
  "version": "2.0",
  "kind": "change",
  "encoding": "utf-8",
  "value_mode": "text",
  "entries": [
    {"type": "bytes", "address": "0x100", "bytes": "DE AD BE EF"}
  ]
}"""


async def one_arm(answer_button: str) -> dict:
    tmp = Path(tempfile.mkdtemp())
    app = S19TuiApp(base_dir=tmp)
    patches = tmp / ".s19tool" / "workarea" / "patches"
    patches.mkdir(parents=True, exist_ok=True)
    (patches / "target.json").write_text(VALID_ONE, encoding="utf-8")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        await pilot.press("6")
        await pilot.pause()
        service = app._change_service
        service.add_entry("0x100", "", "DE AD BE EF")
        panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
        panel.refresh_entries(service.rows(None), mem_map=None)
        await pilot.pause()
        app.query_one("#patch_entry_address_input", Input).value = "0x200"
        app.query_one("#patch_entry_bytes_input", Input).value = "DE AD BE EF"
        await pilot.pause()
        app.query_one("#patch_entry_add_button", Button).focus()
        await pilot.press("enter")
        await pilot.pause()
        assert panel._dirty, "precondition: panel dirty"
        app.query_one("#patch_doc_path_input", Input).value = str(
            patches / "target.json"
        )
        # ONE single Load activation.
        app.query_one("#patch_doc_load_button", Button).focus()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.pause()
        stack_before = [s.__class__.__name__ for s in app.screen_stack]
        guards_before = sum(
            isinstance(s, LoadGuardScreen) for s in app.screen_stack
        )
        # Answer the guard popup.
        app.screen.query_one(answer_button, Button).press()
        await pilot.pause()
        await pilot.pause()
        stack_after = [s.__class__.__name__ for s in app.screen_stack]
        guards_after = sum(
            isinstance(s, LoadGuardScreen) for s in app.screen_stack
        )
        return {
            "stack_before": stack_before,
            "guards_before": guards_before,
            "stack_after": stack_after,
            "guards_after": guards_after,
            "dirty_after": panel._dirty,
            "rows_after": app.query_one("#patch_doc_entries_table").row_count,
        }


async def main() -> None:
    accept = await one_arm("#load_guard_accept")
    cancel = await one_arm("#load_guard_cancel")

    print(f"ACCEPT arm: {accept['stack_before']} -> {accept['stack_after']}")
    print(f"  LoadGuardScreen count before answer: {accept['guards_before']}")
    print(f"  LoadGuardScreen count after answer:  {accept['guards_after']}")
    print(f"  dirty after: {accept['dirty_after']} (expect False)")
    print(f"  rows after:  {accept['rows_after']} (expect 1 = target loaded)")
    print(f"CANCEL arm: {cancel['stack_before']} -> {cancel['stack_after']}")
    print(f"  LoadGuardScreen count before answer: {cancel['guards_before']}")
    print(f"  LoadGuardScreen count after answer:  {cancel['guards_after']}")
    print(f"  dirty after: {cancel['dirty_after']} (expect True)")
    print(f"  rows after:  {cancel['rows_after']} (expect 2 = edits kept)")

    ok = (
        accept["guards_before"] == 1
        and accept["guards_after"] == 0
        and accept["dirty_after"] is False
        and accept["rows_after"] == 1
        and cancel["guards_before"] == 1
        and cancel["guards_after"] == 0
        and cancel["dirty_after"] is True
        and cancel["rows_after"] == 2
    )
    print("PROBE:", "PASS — exactly one popup, stack drains empty (both arms)"
          if ok else "FAIL — see arms above")
    if not ok:
        sys.exit(1)


asyncio.run(main())
