"""Thread U5: Check Editor and CRC Designer — the results shown vs what was computed.

Check Editor (key `=`): a memory row 0x8000007C size 4 on case_01, Validate, then a
Patch Editor apply of DE AD BE EF at the same address (not saved), Validate again,
then Write .chk.json; and a row outside the image.
CRC Designer (key `0`): coverage preview before/after a load, and over a range with
no image bytes.
"""
from ucommon import *  # noqa: F403


def plain(w):
    try:
        r = w.render(); return str(getattr(r, "plain", r))
    except Exception as exc:  # noqa: BLE001
        return f"<{exc}>"


async def main():
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 60)) as pilot:
        await settle(app, pilot)
        p("== U5.0 CRC Designer before any load: `0`")
        await pilot.press("0"); await settle(app, pilot, 3)
        p("   active screen key =", app._active_screen_key, "| coverage preview =", plain(app.query_one("#crc_coverage_preview"))[:200].replace("\n", " / "))
        app._load_path_from_user_input(EX / "case_00_public" / "prg.s19"); await settle(app, pilot); take(app)
        p("== U5.1 after loading prg.s19 (no field changed)")
        p("   coverage preview =", plain(app.query_one("#crc_coverage_preview"))[:300].replace("\n", " / "))
        p("   coverage window  =", plain(app.query_one("#crc_coverage_window"))[:300].replace("\n", " / "))
        p("   ranges field     =", app.query_one("#crc_coverage_ranges").value)
        p("== U5.2 ranges field set to 20000-30000 (no bytes of prg.s19 there)")
        app.query_one("#crc_coverage_ranges").value = "20000-30000"; await settle(app, pilot, 3)
        p("   coverage preview =", plain(app.query_one("#crc_coverage_preview"))[:400].replace("\n", " / "))
        p("   warnings         =", plain(app.query_one("#crc_warnings"))[:300].replace("\n", " / "))
        p("== U5.3 load case_01 firmware.s19 over it (ranges field unchanged)")
        app._load_path_from_user_input(C1 / "firmware.s19"); await settle(app, pilot); take(app)
        app.query_one("#crc_coverage_ranges").value = "80000000-80000080"; await settle(app, pilot, 3)
        before = plain(app.query_one("#crc_coverage_preview"))
        p("   coverage preview (case_01, 80000000-80000080) =", before[:300].replace("\n", " / "))
        app._load_path_from_user_input(C2 / "firmware.s19"); await settle(app, pilot); take(app)
        after = plain(app.query_one("#crc_coverage_preview"))
        p("   coverage preview after loading case_02, no field touched =", after[:300].replace("\n", " / "))
        p("   identical text after a different image? =", before == after)
        from s19_app.tui.crc_designer_view import CrcDesignerPanel
        cp = app.query_one(CrcDesignerPanel); cp._recompute(); await pilot.pause()
        p("   after a forced _recompute =", plain(app.query_one("#crc_coverage_preview"))[:300].replace("\n", " / "))

        p("== U5.4 Check Editor `=`; reload case_01")
        app._load_path_from_user_input(C1 / "firmware.s19"); await settle(app, pilot); take(app)
        await pilot.press("equals_sign"); await settle(app, pilot, 3)
        p("   active screen key =", app._active_screen_key, "| focused =", type(app.focused).__name__ if app.focused else None, getattr(app.focused, "id", None))
        from s19_app.tui.screens_directionb import CheckEditorPanel
        cpanel = app.query_one(CheckEditorPanel)
        btns = {b.id: plain(b) for b in cpanel.query("Button")}
        p("   buttons =", {k: v for k, v in btns.items() if k and k.startswith("check_")})
        cpanel.query_one("#check_mem_address_input").value = "0x8000007C"
        cpanel.query_one("#check_mem_size_input").value = "4"
        cpanel.query_one("#check_mem_add_button").press(); await settle(app, pilot, 3)
        p("   check_status =", plain(cpanel.query_one("#check_status")))
        cpanel.query_one("#check_validate_button").press(); await settle(app, pilot, 4)
        p("   [validate, clean image] recorded =", take(app))
        f = app.current_file
        p("   image @0x8000007C =", " ".join(f"{f.mem_map[0x8000007C + i]:02X}" for i in range(4)))
        p("== U5.5 Patch Editor apply DE AD BE EF @0x8000007C (not saved), back to Check Editor, Validate + Write")
        from s19_app.tui.screens_directionb import PatchEditorPanel as P
        app.on_patch_editor_panel_action_requested(P.ActionRequested("add_entry", address_text="0x8000007C", bytes_text="DE AD BE EF"))
        app.on_patch_editor_panel_action_requested(P.ActionRequested("apply_doc"))
        take(app)
        p("   image @0x8000007C =", " ".join(f"{f.mem_map[0x8000007C + i]:02X}" for i in range(4)))
        cpanel.query_one("#check_validate_button").press(); await settle(app, pilot, 4)
        p("   [validate, patched unsaved image] recorded =", take(app))
        cpanel.query_one("#check_file_name_input").value = "spec.chk.json"
        cpanel.query_one("#check_write_button").press(); await settle(app, pilot, 4)
        p("   [write] recorded =", take(app))
        hits = list(base.rglob("spec.chk.json"))
        for h in hits:
            p("   written", h.relative_to(base), "=", h.read_text()[:300].replace("\n", " "))
        p("== U5.6 a row outside the image (0x90000000), Validate")
        cpanel.query_one("#check_mem_address_input").value = "0x90000000"
        cpanel.query_one("#check_mem_size_input").value = "2"
        cpanel.query_one("#check_mem_add_button").press(); await settle(app, pilot, 3)
        p("   check_status =", plain(cpanel.query_one("#check_status")))
        cpanel.query_one("#check_validate_button").press(); await settle(app, pilot, 4)
        p("   recorded =", take(app))
        p("== U5.7 Bytes field vs paste grammar: same text '11 22'")
        from s19_app.tui.services.change_service import parse_new_bytes
        p("   Bytes field parse_new_bytes('11 22') =", [f"{b:02X}" for b in parse_new_bytes("11 22")],
          "| parse_new_bytes('10 1A 08') =", [f"{b:02X}" for b in parse_new_bytes("10 1A 08")])
        doc = '{"format":"s19app-changeset","version":"2.0","kind":"change","encoding":"utf-8","value_mode":"text","entries":[{"type":"bytes","address":"0x8000007C","bytes":"11 22"}]}'
        res = app._change_service.load_text(doc)
        p("   paste JSON bytes '11 22' -> ok =", res.ok, "entries =", [(hex(e.address), " ".join(f"{b:02X}" for b in e.encoded_bytes)) for e in app._change_service.document.entries])


run(main)
