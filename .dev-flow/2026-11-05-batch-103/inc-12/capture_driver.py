"""Inc 12 E5 capture driver (batch-103): the REAL app on a scratch work area.

Run by ``capture_windows.ps1`` under ``python -I -B`` in a fresh Windows
Terminal window; the wrapper passes the checkout, the scenario, the scratch
``--base`` and an optional sidecar ``--report`` path. This file inserts the
checkout at ``sys.path[0]`` itself (``-I`` ignores ``PYTHONPATH``), so the app
under test is always the tree the wrapper names, never the driver's own
environment. The app is built on ``--base`` (the wrapper's scratch dir, removed
by the wrapper after the capture) and driven through the same
loading/rail/cursor/scroll handlers a keyboard user reaches, to one stable A2L
Explorer surface per scenario. The app keeps running until the wrapper closes
the window; the drive task only reaches the surface and then returns.

Scenarios (see ``02-test-cases.md`` AT-B103-I12-2):

  synmap           The synthetic SYNMAP of Inc 11 (MAP + S19 image), row 0.
  page64           The synthetic PAGE64(48) page (64-bit address, LENGTH
                   1048576), unscrolled.
  synmap-midscroll SYNMAP scrolled part-way right (the E3A-05 pane-edge
                   capture).
  v171             The tracked ``examples/case_00_public/ASAP2_Demo_V171.a2l``,
                   unscrolled (its ASAM.M.SCALAR rows lead the page).
  v171-nameline    V171 with the cursor on the first row whose card shows a
                   DISPLAY_IDENTIFIER (the Name-line capture, R-TUI-042a.8).
  curve            A tracked file holding a CURVE with no length, selected at
                   capture time with the ``corr2-e3c2-bytesize.py`` criterion
                   (Inc 11 E3S-18: the tags whose Raw/Physical cells go blank).

Synthetic text only is written for the SYNMAP / PAGE64 fixtures. Tracked files
are read from the checkout and their names/counts go into the sidecar report;
no file text, corpus text or clipboard content is copied into any record, and
no clipboard is touched (``markup=False`` widgets; the filter inputs are never
focused). The recent-files store and HOME/XDG/LOCALAPPDATA are isolated by the
wrapper, not here.

    python -I -B capture_driver.py --root <checkout> --scenario <name> \
        --base <scratch-dir> [--report <sidecar.txt>]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Argument parsing happens before the checkout import so ``--root`` can be
# inserted at sys.path[0].
# ---------------------------------------------------------------------------
_SCENARIOS = (
    "synmap",
    "page64",
    "synmap-midscroll",
    "v171",
    "v171-nameline",
    "curve",
)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", required=True, type=Path, help="checkout under test")
    parser.add_argument("--scenario", required=True, choices=_SCENARIOS)
    parser.add_argument("--base", required=True, type=Path, help="scratch work area")
    parser.add_argument("--report", type=Path, default=None, help="sidecar summary path")
    return parser.parse_args(argv)


def main() -> int:
    args = _parse_args(sys.argv[1:])
    root = args.root.resolve()
    sys.path.insert(0, str(root))  # the checkout, before any s19_app import

    # Deferred imports so everything resolves from the checkout (and so a
    # syntax-only ``python -m py_compile`` never needs the checkout present).
    from textual.widgets import DataTable

    from s19_app.tui.a2l import enrich_a2l_tags_with_values, parse_a2l_file
    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.changes.io import emit_s19_from_mem_map

    base = args.base.resolve()
    base.mkdir(parents=True, exist_ok=True)
    os.chdir(base)

    # Synthetic fixture builders (the Inc 11 / Inc 12 probe shapes, inline so
    # the driver stays self-contained and writes no imported record text).
    ADDR = 0x1C2D3E00
    ADDR64 = 0x1C2D3E004026
    NX, NY = 87, 13
    MAP_LEN = 2 + 2 + NX * NY * 2  # 2266

    HEAD = (
        "ASAP2_VERSION 1 71\n"
        "/begin PROJECT PSYN \"\"\n"
        "/begin MODULE MSYN \"\"\n"
        "/begin MOD_COMMON \"\"\n"
        "BYTE_ORDER MSB_LAST\n"
        "/end MOD_COMMON\n"
        "/begin COMPU_METHOD CM_SYN \"\" IDENTICAL \"%.0\" \"\"\n"
        "/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT RL_SYN_MAP\n"
        "NO_AXIS_PTS_X 1 UWORD\n"
        "NO_AXIS_PTS_Y 2 UWORD\n"
        "FNC_VALUES 3 UWORD COLUMN_DIR DIRECT\n"
        "/end RECORD_LAYOUT\n"
    )
    TAIL = "/end MODULE\n/end PROJECT\n"

    def map_block(name: str) -> str:
        return (
            f"/begin CHARACTERISTIC {name} \"synthetic map\"\n"
            f"  MAP 0x{ADDR:08X} RL_SYN_MAP 4095 CM_SYN 0 4095\n"
            "  /begin AXIS_DESCR\n"
            f"    FIX_AXIS NO_INPUT_QUANTITY CM_SYN {NX} 0 {NX - 1}\n"
            f"    FIX_AXIS_PAR 0 1 {NX}\n"
            "  /end AXIS_DESCR\n"
            "  /begin AXIS_DESCR\n"
            f"    FIX_AXIS NO_INPUT_QUANTITY CM_SYN {NY} 0 {NY - 1}\n"
            f"    FIX_AXIS_PAR 0 1 {NY}\n"
            "  /end AXIS_DESCR\n"
            "/end CHARACTERISTIC\n"
        )

    def name_of(prefix: str, n: int) -> str:
        return (prefix + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" * 4)[:n]

    def meas(name: str, addr: int, dtype: str = "UWORD", length: int | None = None) -> str:
        hexdig = max(8, len(f"{addr:X}"))
        extra = f"  LENGTH {length}\n" if length is not None else ""
        return (
            f'/begin MEASUREMENT {name} "synthetic"\n  {dtype} CM_SYN 0 0 0 65535\n'
            f"  ECU_ADDRESS 0x{addr:0{hexdig}X}\n{extra}/end MEASUREMENT\n"
        )

    def page_syn() -> str:
        return HEAD + map_block("SYN_MAP_W") + TAIL

    def page64(n: int) -> str:
        body = (
            map_block(name_of("SYN_MAP_", n))
            + meas(name_of("SYN_V64_", n), ADDR64)
            + meas(name_of("SYN_BIG_", n), 0x1000, "UBYTE", 1048576)
        )
        return HEAD + body + TAIL

    def synthetic_image() -> str:
        mem_map = {ADDR + i: (i * 7) & 0xFF for i in range(MAP_LEN)}
        return emit_s19_from_mem_map(mem_map, [(ADDR, ADDR + MAP_LEN)])

    # -----------------------------------------------------------------------
    # Tracked-file selection for the CURVE-without-length scenario: the
    # ``corr2-e3c2-bytesize.py`` criterion is "a tag with no length whose
    # enriched size Inc 11's E3S-18 removes". After Inc 11 the enriched
    # ``byte_size`` of a length-less tag is None, so the surviving, version-
    # independent form is "CURVE with no length" (char_type == "CURVE" and
    # ``length is None``). The file with the most such CURVEs is chosen and
    # its name + counts are written to the sidecar report.
    # -----------------------------------------------------------------------
    def select_curve_file() -> tuple[Path, int, dict[str, int]]:
        probe = subprocess.run(
            ["git", "-C", str(root), "grep", "-l", "CURVE", "--", "*.a2l"],
            capture_output=True,
            text=True,
        )
        rel_files = [ln for ln in probe.stdout.splitlines() if ln.strip()]
        if probe.returncode not in (0, 1) or not rel_files:
            # Fallback: every tracked A2L, filtered by a cheap literal scan.
            listed = subprocess.run(
                ["git", "-C", str(root), "ls-files", "*.a2l"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.split()
            rel_files = [
                rel for rel in listed if "CURVE" in (root / rel).read_text(encoding="utf-8", errors="replace")
            ]
        per_file: dict[str, int] = {}
        best_rel, best_count = "", 0
        for rel in rel_files:
            data = parse_a2l_file(root / rel)
            count = 0
            for tag in enrich_a2l_tags_with_values(data, {}):
                if tag.get("char_type") == "CURVE" and tag.get("length") is None:
                    count += 1
            if count:
                per_file[rel] = count
            if count > best_count:
                best_rel, best_count = rel, count
        if not best_rel:
            raise SystemExit("no tracked A2L file holds a CURVE with no length")
        return root / best_rel, best_count, per_file

    v171_path = root / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l"
    image_path = root / "examples" / "case_00_public" / "prg.s19"
    curve_path: Path | None = None
    curve_counts: dict[str, int] = {}
    if args.scenario == "curve":
        curve_path, _curve_count, curve_counts = select_curve_file()

    fixture_a2l = base / "fixture.a2l"
    fixture_s19 = base / "fixture.s19"

    report_lines: list[str] = [
        f"scenario={args.scenario}",
    ]

    class CaptureApp(S19TuiApp):
        # Textual resolves a relative CSS_PATH against the subclass's own file;
        # point it back at the app's stylesheet in the checkout under test.
        CSS_PATH = str(root / "s19_app" / "tui" / "styles.tcss")

        def __init__(self) -> None:
            super().__init__(base_dir=base)
            self._ready = asyncio.Event()

        def on_mount(self) -> None:
            super().on_mount()
            self._drive_task = asyncio.create_task(self._drive())

        async def _settle(self, seconds: float = 0.5) -> None:
            await asyncio.sleep(seconds)

        async def _wait_for(self, predicate, timeout: float = 30.0) -> bool:
            deadline = time.perf_counter() + timeout
            while time.perf_counter() < deadline:
                if predicate():
                    return True
                await asyncio.sleep(0.05)
            return False

        async def _show_explorer(self) -> DataTable:
            self.action_show_screen("a2l")
            await self._settle(0.6)
            table = self.query_one("#a2l_tags_list", DataTable)
            table.focus()
            if table.row_count:
                table.move_cursor(row=0)
            await self._settle(0.4)
            return table

        def _first_display_id_row(self) -> int:
            for index, tag in enumerate(self._a2l_filtered_tags):
                if tag.get("display_identifier"):
                    return index
            return 0

        def _first_curve_without_length(self) -> int:
            for index, tag in enumerate(self._a2l_filtered_tags):
                if tag.get("char_type") == "CURVE" and tag.get("length") is None:
                    return index
            return -1

        async def _drive(self) -> None:
            error: str | None = None
            try:
                await self._settle(0.3)
                if args.scenario in ("synmap", "page64", "synmap-midscroll"):
                    a2l_text = page_syn() if args.scenario != "page64" else page64(48)
                    fixture_a2l.write_text(a2l_text, encoding="utf-8")
                    fixture_s19.write_text(synthetic_image(), encoding="ascii")
                    self.load_selected_file(fixture_s19)
                    await self._wait_for(
                        lambda: self.current_file is not None
                        and self.current_file.path.name == fixture_s19.name
                    )
                    self.load_a2l_from_path(fixture_a2l)
                    report_lines.append(f"synthetic_fixture={args.scenario}")
                elif args.scenario == "curve":
                    assert curve_path is not None
                    self.load_selected_file(image_path)
                    await self._wait_for(
                        lambda: self.current_file is not None
                        and self.current_file.path.name == image_path.name
                    )
                    self.load_a2l_from_path(curve_path)
                    report_lines.append(f"selected_file={curve_path.relative_to(root)}")
                    report_lines.append(f"curve_without_length_selected={_curve_count}")
                    report_lines.append(
                        "curve_without_length_per_file=" + json.dumps(curve_counts, sort_keys=True)
                    )
                else:  # v171, v171-nameline
                    self.load_selected_file(image_path)
                    await self._wait_for(
                        lambda: self.current_file is not None
                        and self.current_file.path.name == image_path.name
                    )
                    self.load_a2l_from_path(v171_path)
                    report_lines.append("tracked_file=examples/case_00_public/ASAP2_Demo_V171.a2l")
                await self.workers.wait_for_complete()
                await self._settle(0.6)
                table = await self._show_explorer()
                report_lines.append(f"tags={len(self._a2l_filtered_tags)}")
                report_lines.append(f"table_rows={table.row_count}")
                if args.scenario == "synmap-midscroll":
                    target = max(0, int(table.max_scroll_x) // 2)
                    table.scroll_to(x=target, animate=False)
                    report_lines.append(f"scroll_x={target}/{int(table.max_scroll_x)}")
                    await self._settle(0.4)
                elif args.scenario == "v171-nameline":
                    row = self._first_display_id_row()
                    if table.row_count:
                        table.move_cursor(row=row)
                    report_lines.append(f"cursor_row={row}")
                    await self._settle(0.4)
                elif args.scenario == "curve":
                    idx = self._first_curve_without_length()
                    if idx >= 0:
                        page_size = self._clamp_viewer_page_size(self.a2l_tags_page_size)
                        start = (idx // page_size) * page_size
                        self._a2l_window_start = start
                        self.update_a2l_tags_view(self._a2l_filtered_tags)
                        await self._settle(0.5)
                        table = self.query_one("#a2l_tags_list", DataTable)
                        if table.row_count:
                            table.move_cursor(row=idx - start)
                        report_lines.append(
                            f"curve_without_length_row={idx} "
                            f"(page {idx // page_size + 1}, in-page row {idx - start})"
                        )
                    await self._settle(0.4)
                report_lines.append("surface=ready")
            except BaseException as exc:  # noqa: BLE001 - keep the app alive, report it
                error = f"{type(exc).__name__}: {exc}"
                report_lines.append(f"surface=error {error}")
                sys.stderr.write(f"capture drive failed: {error}\n")
            finally:
                if args.report is not None:
                    try:
                        args.report.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
                    except OSError:
                        pass
                self._ready.set()

    app = CaptureApp()
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
