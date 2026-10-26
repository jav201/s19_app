"""Probe: black-box AT-B99-09 flow through the Load dialog at both widths."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from textual.widgets import Button, DataTable, Input

from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from tests.b97_probes import painted_rows, settled

ROOT = Path(__file__).resolve().parents[4]
CORPUS = ROOT / "tests" / "fixtures" / "synth"

_UNDECODABLE_EXTRA = (
    '    /begin COMPU_METHOD RAT_FUNC_NOROOT "%6.2" RAT_FUNC "%6.2" ""\n'
    "      COEFFS 1 0 1 0 0 1\n"
    "    /end COMPU_METHOD\n"
    '    /begin CHARACTERISTIC NO_ROOT_SYM "no real inverse at raw 0"\n'
    "      VALUE 0x200A RL_U16_NO_BO 0 RAT_FUNC_NOROOT 0 100\n"
    "    /end CHARACTERISTIC\n"
    '    /begin CHARACTERISTIC OUTSIDE_SYM "parked outside the image"\n'
    "      VALUE 0x9000 RL_U16_NO_BO 0 RAT_FUNC_DIV_10 0 100\n"
    "    /end CHARACTERISTIC\n"
)


def _pair(tmp: Path):
    a2l_text = (CORPUS / "synth_a2l.a2l").read_text(encoding="utf-8")
    anchor = "    /begin GROUP GRP_SYNTH_B99"
    a2l_text = a2l_text.replace(anchor, _UNDECODABLE_EXTRA + anchor)
    a2l_path = tmp / "case.a2l"
    a2l_path.write_text(a2l_text, encoding="utf-8")
    mem_map = {0x2000 + i: b for i, b in enumerate(bytes.fromhex("1011012C000200010F0000000032"))}
    s19_path = tmp / "case.s19"
    s19_path.write_text(
        emit_s19_from_mem_map(mem_map, [(0x2000, 0x200E)]), encoding="ascii"
    )
    return s19_path, a2l_path


async def _load_via_dialog(app, pilot, path: Path, wait_for) -> None:
    await pilot.press("l")
    await pilot.pause()
    screen = app.screen
    screen.query_one("#load_path", Input).value = str(path)
    await pilot.pause()
    screen.query_one("#load_ok", Button).press()
    await settled(pilot, wait_for, f"{path.name} loaded", attempts=200)


async def run(tmp: Path, size) -> None:
    s19_path, a2l_path = _pair(tmp)
    app = S19TuiApp(base_dir=tmp)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await _load_via_dialog(app, pilot, s19_path, lambda: app.current_file is not None)
        print("S19 loaded:", app.current_file is not None)
        await _load_via_dialog(
            app,
            pilot,
            a2l_path,
            lambda: "case.a2l" in str(app.query_one("#loaded_panel").query(".loaded-detail")[2].render()),
        )
        print("A2L loaded")
        await pilot.press("escape")
        await pilot.pause()
        await pilot.press("2")
        await settled(pilot, lambda: "A2L Explorer" in "\n".join("".join(seg.text for seg in s) for s in app.screen._compositor.render_strips()), "a2l footer painted")
        table0 = app.query_one("#a2l_tags_list", DataTable)
        table0.focus()
        await pilot.pause()
        for downs in range(8):
            screen_text = "\n".join("".join(seg.text for seg in s) for s in app.screen._compositor.render_strips())
            hits = [ln for ln in screen_text.splitlines() if any(tok in ln for tok in ("SYM", "30.0", "4113", "n/a", "40.0"))]
            print(f"=== focused, after {downs} downs ===")
            for ln in hits:
                print(repr(ln))
            await pilot.press("down")
            await pilot.pause()
        return
        table = app.query_one("#a2l_tags_list", DataTable)
        rows = painted_rows(app, table)
        print(f"--- painted table rows at {size} ---")
        for r in rows:
            if r.strip():
                print(repr(r))
        # modal
        table.focus()
        await pilot.pause()
        for _ in range(6):
            await pilot.press("down")
            await pilot.pause()
        await pilot.press("d")
        await settled(pilot, lambda: "Scalar value" in "\n".join(painted_rows(app, app.screen)), "modal painted")
        screen_text = "\n".join("".join(seg.text for seg in s) for s in app.screen._compositor.render_strips())
        print("--- modal lines ---")
        for line in screen_text.splitlines():
            if "Scalar value" in line or "rat_func" in line or "n/a" in line:
                print(repr(line))
        await pilot.press("escape")
        await pilot.pause()


if __name__ == "__main__":
    import shutil, tempfile

    for size in ((80, 24),):
        d = tempfile.mkdtemp()
        asyncio.run(run(Path(d), size))
