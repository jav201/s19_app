"""T2 threads: Patch Editor apply -> undo -> apply -> save-back (16 and 32 bytes/line) -> verify.

Data: case_02 (README patch targets: 0x80010080 "DE AD BE EF", 0x80010005 "05182025").
"""
import shutil

from cwh import C2, new_base, mini_s19, out, run_app, load_path, patch_action, settle


def test_t2a_apply_undo_apply_saveback():
    base = new_base()
    src = base / "src"
    src.mkdir()
    shutil.copyfile(C2 / "firmware.s19", src / "firmware.s19")

    async def body(app, pilot):
        from s19_app.tui.screens_directionb import PatchEditorPanel as P
        await load_path(app, pilot, src / "firmware.s19")
        f = app.current_file
        out("T2a-load", file=f.path.name, at_0x80010080=hex(f.mem_map[0x80010080]), s0=f.source_s0_header)
        patch_action(app, "add_entry", address_text="0x80010080", bytes_text="DE AD BE EF")
        patch_action(app, "apply_doc")
        out("T2a-apply1", status=app._probe_status[-1], at_0x80010080=hex(f.mem_map[0x80010080]))
        # the body of action_patch_undo after its screen gate (app.py:3615): the service undo + refresh
        app._change_service.undo()
        app._change_service.undo()
        await settle(app, pilot)
        out("T2a-undo", entries=len(app._change_service.document.entries), at_0x80010080=hex(f.mem_map[0x80010080]))
        patch_action(app, "add_entry", address_text="0x80010005", bytes_text="30 35 31 38 32 30 32 35")
        patch_action(app, "apply_doc")
        out("T2a-apply2", status=app._probe_status[-1],
            summary=[(hex(e.address_start), e.disposition) for e in app._change_service.last_summary.entries])
        # save-back at 16 bytes/line, then at 32 with a new name
        app.on_patch_editor_panel_save_back_decision(P.SaveBackDecision("p16.s19", bytes_per_line=16))
        await settle(app, pilot)
        v = app._change_service.last_summary.verify_result
        out("T2a-save16", status=app._probe_status[-2:], verify=getattr(v, "status", v))
        app.on_patch_editor_panel_save_back_decision(P.SaveBackDecision("p32.s19", bytes_per_line=32))
        await settle(app, pilot)
        for name in ("p16.s19", "p32.s19"):
            p = app.workarea / name
            mem, errs, meta = mini_s19(p)
            first = p.read_text().splitlines()[0]
            out("T2a-file", file=name, first=first, s0=meta["s0"], term=meta["term"],
                at_0x80010080=hex(mem.get(0x80010080, -1)), at_0x80010005=bytes(mem.get(0x80010005 + i, 0) for i in range(8)).hex(' '),
                phantom_0x0=bytes(mem.get(i, 0) for i in range(4)))

    run_app(body, base)


def test_t2b_bytes_field_hex_dump():
    """T2b: the Bytes field (placeholder "DE AD BE EF") with a hex dump of the case_02 README text
    "05182025" and a mixed dump."""
    from s19_app.tui.services.change_service import parse_new_bytes
    for text in ("30 35 31 38 32 30 32 35", "DE AD 10 20", "0F 10 1F 20"):
        out("T2b", text=text, parsed=" ".join(f"{b:02X}" for b in parse_new_bytes(text)))
