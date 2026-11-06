"""Inc 5 E1 confirmation pilot (batch-101). Headless; run from the worktree root.

Scenario D4  : CRC Designer coverage after an in-place change apply (Inc 13 D-4).
Scenario D4b : the same apply posted while the CRC Designer is displayed.
Scenario CHK : Check Editor write / reload / validate on case 08 (F-26, F-27,
               D9-11, R-CHKED-010 on a signature change).
Prints one transcript; no file outside the run folder is written.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import zlib
from pathlib import Path

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "synth"))

import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)

import make_release_case as gen  # noqa: E402
from s19_app.tui import crc_designer_view  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.crc_designer_view import CrcDesignerPanel  # noqa: E402
from s19_app.tui.screens_directionb import CheckEditorPanel, PatchEditorPanel  # noqa: E402
from tests.support.b100_projects import StatusLog  # noqa: E402
from tests.support.timing import wait_until  # noqa: E402
from tests.test_b101_symbol_reads import attach_a2l, pick_by_keys, settle, show_screen  # noqa: E402

RUN = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/i5e1/run")
COUNT = [0]
_orig = CrcDesignerPanel._recompute


def _counted(self, *a, **k):
    COUNT[0] += 1
    return _orig(self, *a, **k)


CrcDesignerPanel._recompute = _counted


def s1(addr: int, data: bytes) -> str:
    body = bytes([len(data) + 3, addr >> 8, addr & 0xFF]) + data
    return "S1" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


def write_fixture(path: Path) -> None:
    lines = [
        "S0030000FC",
        s1(0x8000, bytes(range(8))),
        s1(0x8010, bytes(range(0x10, 0x18))),
        "S9030000FC",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def concat_crc(mem: dict) -> int:
    data = bytes(mem[a] for a in range(0x8000, 0x8008)) + bytes(
        mem[a] for a in range(0x8010, 0x8018)
    )
    return zlib.crc32(data)


def preview(app) -> str:
    from textual.widgets import Static

    return str(app.query_one("#crc_coverage_preview", Static).content)


async def d4(base: Path, designer_shown_at_apply: bool) -> dict:
    base.mkdir(parents=True, exist_ok=True)
    img = base / "fixture.s19"
    write_fixture(img)
    patches = base / "workarea" / "patches"
    out: dict = {"scenario": "D4b" if designer_shown_at_apply else "D4"}
    app = S19TuiApp(base_dir=base)
    log = StatusLog(app)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        app.load_selected_file(img)
        await wait_until(pilot, lambda: app.current_file is not None, "image load")
        await pilot.press("0")
        await wait_until(
            pilot,
            lambda: preview(app).startswith("Active policy"),
            lambda: f"designer preview: {preview(app)!r}",
            pause_first=True,
        )
        await pilot.pause(0.4)
        mem = app.current_file.mem_map
        out["ranges"] = [f"0x{a:X}-0x{b:X}" for a, b in app.current_file.ranges]
        out["preview_before_apply"] = preview(app)
        out["oracle_before"] = f"0x{concat_crc(mem):08X}"
        patches = app._patches_dir()
        patches.mkdir(parents=True, exist_ok=True)
        doc = patches / "d4.changes.json"
        doc.write_text(
            json.dumps(
                {
                    "format": "s19app-changeset",
                    "version": "2.0",
                    "kind": "change",
                    "encoding": "utf-8",
                    "value_mode": "text",
                    "entries": [{"type": "bytes", "address": "0x8003", "bytes": "AA"}],
                }
            ),
            encoding="utf-8",
        )
        if not designer_shown_at_apply:
            await pilot.press("6")
            await settle(pilot)
        panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
        mark = len(log.messages)
        panel.post_message(PatchEditorPanel.ActionRequested("load_doc", path_text=str(doc)))
        await settle(pilot)
        panel.post_message(PatchEditorPanel.ActionRequested("apply_doc"))
        await wait_until(
            pilot,
            lambda: any(m.startswith("Apply:") for m in log.since(mark)),
            lambda: f"apply status: {log.since(mark)!r}",
        )
        out["status_lines"] = list(log.since(mark))
        out["byte_0x8003_after"] = f"0x{mem[0x8003]:02X}"
        out["same_mem_map_object"] = app.current_file.mem_map is mem
        before = COUNT[0]
        if not designer_shown_at_apply:
            await pilot.press("0")
        await pilot.pause(0.6)
        await settle(pilot)
        out["recomputes_after_apply"] = COUNT[0] - before
        out["preview_after_apply"] = preview(app)
        out["oracle_after"] = f"0x{concat_crc(mem):08X}"
        shown = [ln for ln in out["preview_after_apply"].splitlines() if ln.startswith("concat:")]
        out["designer_concat_after"] = shown[0].split()[-1] if shown else None
        out["designer_matches_post_apply_bytes"] = out["designer_concat_after"] == out["oracle_after"]
    return out


async def chk(base: Path) -> dict:
    from textual.widgets import Button, Input, Static

    base.mkdir(parents=True, exist_ok=True)
    case = base / "case08"
    gen.generate(case, 20260001, 1.0)
    out: dict = {"scenario": "CHK"}
    app = S19TuiApp(base_dir=base / "app")
    (base / "app").mkdir(exist_ok=True)
    log = StatusLog(app)

    def head() -> str:
        return str(app.query_one("#check_fields_lines", Static).render()).split("\n")[0]

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        app.load_selected_file(case / "firmware.s19")
        await wait_until(pilot, lambda: app.current_file is not None, "image load")
        await attach_a2l(pilot, app, case)
        await show_screen(pilot, app, "equals_sign", "#check_spec_file_select")
        mem = app.current_file.mem_map
        tags = [t for t in app._compute_a2l_enriched_tags() if isinstance(t.get("address"), int)]
        keys: dict = {}
        for t in tags:
            k = (t["address"], int(t.get("byte_size") or 1))
            keys.setdefault(k, []).append(t["name"])
        shared = {k: v for k, v in keys.items() if len(v) > 1}
        out["measurable_params"] = len(tags)
        out["params_sharing_address_and_size"] = sum(len(v) for v in shared.values())
        same_addr: dict = {}
        for t in tags:
            same_addr.setdefault(t["address"], set()).add(t["name"])
        out["params_sharing_address_any_size"] = sum(len(v) for v in same_addr.values() if len(v) > 1)

        def in_image(t) -> bool:
            size = int(t.get("byte_size") or 1)
            return all((t["address"] + i) in mem for i in range(size))

        picks = [
            t["name"]
            for t in tags
            if in_image(t) and len(keys[(t["address"], int(t.get("byte_size") or 1))]) == 1
        ][:2]
        panel = app.query_one("#check_editor_panel", CheckEditorPanel)
        panel._picker.include_names(picks)
        await settle(pilot)
        mem_addr = max(mem) - 3
        app.query_one("#check_mem_address_input", Input).value = f"0x{mem_addr:08X}"
        app.query_one("#check_mem_label_input", Input).value = "SERIAL"
        app.query_one("#check_mem_size_input", Input).value = "4"
        app.query_one("#check_mem_add_button", Button).press()
        await settle(pilot)
        out["picked"] = list(panel._picked_params)
        out["head_before_write"] = head()
        app.query_one("#check_file_name_input", Input).value = "pilot_fields.chk.json"
        mark = len(log.messages)
        app.query_one("#check_write_button", Button).press()
        await wait_until(
            pilot,
            lambda: any(m.startswith("Check Editor: wrote") for m in log.since(mark)),
            lambda: f"write: {log.since(mark)!r}",
        )
        await settle(pilot)
        out["write_status"] = [m for m in log.since(mark) if m.startswith("Check Editor")]
        out["F26_head_after_write"] = head()
        out["F26_picks_after_write"] = list(panel._picked_params)
        written = json.loads((app._patches_dir() / "pilot_fields.chk.json").read_text(encoding="utf-8"))
        out["written_entries"] = written["entries"]
        # R-CHKED-010 on a signature change: re-attach the same A2L, leave, return.
        await pilot.press("1")
        await settle(pilot)
        await attach_a2l(pilot, app, case)
        await show_screen(pilot, app, "equals_sign", "#check_spec_file_select")
        out["R010_picks_after_same_a2l_reattached_and_return"] = list(panel._picked_params)
        # D9-11: change one byte of the first picked parameter in the image.
        first = picks[0]
        address = next(t["address"] for t in tags if t["name"] == first)
        old = mem[address]
        mem[address] = old ^ 0xFF
        out["image_byte_changed"] = f"{first} @ 0x{address:08X}: 0x{old:02X} -> 0x{mem[address]:02X}"
        mark = len(log.messages)
        await pick_by_keys(pilot, app, "#check_spec_file_select", "pilot_fields.chk.json")
        await wait_until(
            pilot,
            lambda: any(m.startswith("Check Editor: loaded") for m in log.since(mark)),
            lambda: f"load: {log.since(mark)!r}",
        )
        await settle(pilot)
        out["load_status"] = [m for m in log.since(mark) if m.startswith("Check Editor")]
        out["F27_head_after_reload"] = head()
        out["F27_picks_after_reload"] = list(panel._picked_params)
        out["F27_memory_rows_after_reload"] = [
            (f"0x{a:08X}", label, size) for a, label, size in panel._memory_rows
        ]
        mark = len(log.messages)
        app.query_one("#check_validate_button", Button).press()
        await wait_until(
            pilot,
            lambda: any(m.startswith("Checks:") for m in log.since(mark)),
            lambda: f"validate: {log.since(mark)!r}",
        )
        out["D9_11_validate_status"] = [m for m in log.since(mark) if m.startswith("Checks:")]
        out["D9_11_expected_if_spec_bytes_kept"] = "Checks: 2 passed, 1 failed, 0 uncheckable"
    return out


def main() -> None:
    if RUN.exists():
        shutil.rmtree(RUN)
    RUN.mkdir(parents=True)
    os.environ.pop("NO_COLOR", None)
    for name, coro in (
        ("D4", lambda: d4(RUN / "d4", False)),
        ("D4b", lambda: d4(RUN / "d4b", True)),
        ("CHK", lambda: chk(RUN / "chk")),
    ):
        try:
            result = asyncio.run(coro())
        except Exception as exc:  # report, keep going
            result = {"scenario": name, "error": f"{type(exc).__name__}: {exc}"}
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
