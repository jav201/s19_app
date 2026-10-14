"""Throwaway smoke probe for the Inc-002 fb_a panel (not part of the suite)."""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
os.chdir(Path(__file__).resolve().parents[3])

from s19_app.tui.app import S19TuiApp
from s19_app.tui.flow_screens import FlowBuilderPanel


def _s19(data_addr: int, data: bytes) -> str:
    lines = ["S00600004844521B"]
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        addr = data_addr + i
        count = len(chunk) + 3
        body = bytes([count, (addr >> 8) & 0xFF, addr & 0xFF]) + chunk
        cks = (~(sum(body) & 0xFF)) & 0xFF
        lines.append("S1" + body.hex().upper() + f"{cks:02X}")
    lines.append("S9030000FC")
    return "\n".join(lines) + "\n"


def _patch_json(addr: int, value: int) -> str:
    import json

    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "entries": [
                {"op": "write", "address": hex(addr), "bytes": [value]},
            ],
        }
    )


async def main() -> None:
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    project = tmp / ".s19tool" / "workarea" / "proj"
    project.mkdir(parents=True)
    (project / "prg.s19").write_text(_s19(0x1000, bytes([0x11] * 32)), encoding="utf-8")
    (project / "base.s19").write_text(_s19(0x1000, bytes([0x11] * 32)), encoding="utf-8")
    (project / "hotfix.json").write_text(_patch_json(0x1002, 0xEE), encoding="utf-8")

    app = S19TuiApp(base_dir=tmp)
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        app.current_project_dir = project
        await pilot.press("8")
        await pilot.pause()
        panel = app.query_one("#flow_panel", FlowBuilderPanel)

        # Empty canvas first.
        empty = app.query_one("#flow_canvas")
        plain = empty.render().plain
        assert "empty canvas" in plain, plain[:200]
        assert "┌" in plain and "┐" in plain

        # Add source + patch + write-out through the REAL controls.
        app.query_one("#flow_ref").value = "prg.s19"
        app.query_one("#flow_add").press()
        await pilot.pause()
        app.query_one("#flow_ref").value = "hotfix.json"
        kind_sel = app.query_one("#flow_kind")
        kind_sel.value = "patch"
        await pilot.pause()
        app.query_one("#flow_add").press()
        await pilot.pause()
        app.query_one("#flow_ref").value = "out.s19"
        kind_sel.value = "write_out"
        await pilot.pause()
        app.query_one("#flow_add").press()
        await pilot.pause()

        canvas = app.query_one("#flow_canvas").render().plain
        assert "PATCH" in canvas and "hotfix.json" in canvas, canvas
        assert "prg.s19" in canvas, canvas
        assert "┤" in canvas and "├" in canvas, canvas  # stubs
        assert "└" in canvas and "┐" in canvas, canvas  # cable bends
        assert "·" in canvas, canvas  # grid dots
        assert all(len(l) <= 88 for l in canvas.splitlines())
        print("canvas ok; first 14 lines:")
        for ln in canvas.splitlines()[:14]:
            print("|" + ln)

        # A2B wiring: refused both-external, accepted flow+file.
        kind_sel.value = "a2b"
        await pilot.pause()
        assert app.query_one("#flow_ref_a").display is True
        app.query_one("#flow_ref_a").value = "base.s19"
        app.query_one("#flow_ref_b").value = "#nope"
        app.query_one("#flow_add").press()
        await pilot.pause()
        notice = app.query_one("#flow_wiring_notice")
        assert notice.display is True and "refused" in notice.render().plain
        app.query_one("#flow_ref_a").value = "#2"  # patch output
        app.query_one("#flow_ref_b").value = "base.s19"
        app.query_one("#flow_add").press()
        await pilot.pause()
        assert len(panel._blocks) == 4
        assert notice.display is False
        canvas = app.query_one("#flow_canvas").render().plain
        assert "A2B-DIFF" in canvas and "#2.out" in canvas, canvas

        # Run the whole flow through the real Run button.
        app.query_one("#flow_run").press()
        for _ in range(40):
            await pilot.pause()
        result_plain = "\n".join(
            w.render().plain for w in app.query("#flow_result Static")
        )
        assert "CLEAN" in result_plain, result_plain
        out = project / "out.s19"
        assert out.exists(), result_plain
        print("run ok; result tail:")
        for ln in result_plain.splitlines()[-12:]:
            print("|" + ln)

        # Report file with provenance lines.
        reports = sorted((project / "reports").glob("*flow-a2b*.md"))
        assert reports, list((project / "reports").glob("*"))
        text = reports[-1].read_text(encoding="utf-8")
        prov = [l for l in text.splitlines() if l.startswith("- Image")]
        print("provenance lines:")
        for l in prov:
            print("|" + l)
        assert any("[flow]" in l and "block 2 (patch).out" in l for l in prov), prov
        assert any("[external]" in l and "base.s19" in l for l in prov), prov
    print("SMOKE OK")


asyncio.run(main())
