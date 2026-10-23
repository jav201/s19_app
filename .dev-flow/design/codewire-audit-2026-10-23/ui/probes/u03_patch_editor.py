"""Thread U3: Patch Editor add -> apply -> decline -> undo -> add -> apply -> save-back -> Save.

Data: case_01 firmware.s19, address 0x8000007C (inside the image). Buttons are
activated with Button.press() (the same Pressed message a click posts; the
widget may sit outside the 160x50 viewport). Keys: `6` (rail), ctrl+z.
"""
from ucommon import *  # noqa: F403

ADDR = 0x8000007C


def table_rows(app):
    from textual.widgets import DataTable
    try:
        t = app.query_one("#patch_doc_entries_table", DataTable)
    except Exception as exc:  # noqa: BLE001
        return f"<{exc}>"
    rows = []
    for rk in t.rows:
        rows.append(" | ".join(str(getattr(c, "plain", c)) for c in t.get_row(rk)))
    return rows


def mem_at(app, a, n=4):
    f = app.current_file
    return " ".join(f"{f.mem_map.get(a + i, -1):02X}" if f.mem_map.get(a + i) is not None else "--" for i in range(n)) if f else None


def mini_s19_at(path, a, n=4):
    """Independent read of S1/S2/S3 records only."""
    out = {}
    for line in Path(path).read_text().splitlines():
        if not line or line[0] != "S" or line[1] not in "123":
            continue
        al = {"1": 2, "2": 3, "3": 4}[line[1]]
        raw = bytes.fromhex(line[2:])
        addr = int.from_bytes(raw[1:1 + al], "big")
        for i, b in enumerate(raw[1 + al:-1]):
            out[addr + i] = b
    return " ".join(f"{out[a + i]:02X}" if a + i in out else "--" for i in range(n))


async def main():
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=SIZE) as pilot:
        await settle(app, pilot)
        app._load_path_from_user_input(C1 / "firmware.s19"); await settle(app, pilot); take(app)
        await pilot.press("6"); await settle(app, pilot, 3)

        def show(tag):
            p(f"   [{tag}] recorded =", take(app))
            p(f"   [{tag}] table =", table_rows(app))
            p(f"   [{tag}] tally =", q_text(app, "#patch_doc_tally"), "| history =", q_text(app, "#patch_history_strip")[:120])
            p(f"   [{tag}] image @0x8000007C =", mem_at(app, ADDR), "| status_text =", q_text(app, "#status_text"), "| context =", q_text(app, "#status_context"))
            p(f"   [{tag}] card =", q_text(app, "#patch_before_after_card")[:200].replace("\n", " / "))
            sb = app.query_one("#patch_saveback_row")
            p(f"   [{tag}] save-back row hidden = {sb.has_class('hidden')}; undo enabled = {not app.query_one('#patch_undo_button').disabled}")

        async def press(bid):
            app.query_one("#" + bid).press(); await settle(app, pilot, 4)

        p("== U3.0 on Patch Editor; focused =", type(app.focused).__name__ if app.focused else None, getattr(app.focused, "id", None))
        app.query_one("#patch_entry_address_input").value = "0x8000007C"
        app.query_one("#patch_entry_bytes_input").value = "DE AD BE EF"
        p("== U3.1 Add"); await press("patch_entry_add_button"); show("add")
        p("== U3.2 Apply loaded changes"); await press("patch_doc_apply_button"); show("apply")
        p("   save-back name prefill =", app.query_one("#patch_saveback_name_input").value)
        p("== U3.3 Decline save-back"); await press("patch_saveback_decline_button"); show("decline")
        p("== U3.4 ctrl+z (undo)"); await pilot.press("ctrl+z"); await settle(app, pilot, 3); show("undo")
        p("== U3.5 Apply again with the empty document"); await press("patch_doc_apply_button"); show("apply-empty")
        app.query_one("#patch_entry_address_input").value = "0x80000080"
        app.query_one("#patch_entry_bytes_input").value = "01 02"
        p("== U3.6 Add 0x80000080 01 02 + Apply"); await press("patch_entry_add_button"); await press("patch_doc_apply_button"); show("apply2")
        p("== U3.7 Confirm save-back with the default name"); await press("patch_saveback_confirm_button"); show("saveback")
        saved = sorted(app.workarea.glob("*.s19"))
        p("   files written in workarea root =", [x.name for x in saved])
        for sp in saved:
            p(f"   independent read of {sp.name} @0x8000007C = {mini_s19_at(sp, ADDR)}  (source case_01 = {mini_s19_at(C1 / 'firmware.s19', ADDR)})")
        p("== U3.8 Patch 'Save' button (save_doc)"); await press("patch_doc_save_button"); show("save_doc")
        p("   patches dir =", sorted(x.name for x in (app.workarea / "patches").iterdir()))
        p("== U3.9 Load another file over the patched, unsaved image (case_02)")
        app.query_one("#patch_entry_address_input").value = "0x8000007C"
        app.query_one("#patch_entry_bytes_input").value = "11 22"
        await press("patch_entry_add_button"); await press("patch_doc_apply_button"); await press("patch_saveback_decline_button"); take(app)
        p("   before load: image @0x8000007C =", mem_at(app, ADDR))
        app._load_path_from_user_input(C2 / "firmware.s19"); await settle(app, pilot)
        show("load-over")
        p("   screen after load =", type(app.screen).__name__)


run(main)
