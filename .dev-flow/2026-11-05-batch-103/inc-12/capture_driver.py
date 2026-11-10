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
  curve            The tracked ``examples/case_00_public/software_a.a2l``
                   (pinned) with a deterministic 64-byte synthetic image at
                   the first length-less CURVE's address (parsed from the A2L,
                   never recorded). Its 151 CURVE-without-length tags lead the
                   page; ``--expect-raw`` asserts the selected CURVE's
                   Raw/Physical cells are present or blank.

Synthetic text only is written for the SYNMAP / PAGE64 fixtures. Tracked files
are read from the checkout and their names/counts go into the sidecar report;
no file text, corpus text or clipboard content is copied into any record, and
no clipboard is touched (``markup=False`` widgets; the filter inputs are never
focused). The recent-files store and HOME/XDG/LOCALAPPDATA are isolated by the
wrapper, not here.

    python -I -B capture_driver.py --root <checkout> --scenario <name> \
        --base <scratch-dir> --expect-raw present|blank [--report <sidecar.txt>]
"""
from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
import time
import traceback
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

# The CURVE scenario is pinned to this tracked file (repo-relative, so the
# same path resolves under both -Root and -BeforeRoot). The executed e07
# selection evidence counts exactly 151 CURVE tags with no length in it.
_CURVE_FILE_REL = ("examples", "case_00_public", "software_a.a2l")
_REQUIRED_CURVE_COUNT = 151
#: Deterministic synthetic image size (bytes) placed at the first length-less
#: CURVE's address for the curve scenario. The address is parsed from the
#: tracked A2L and never recorded in the sidecar.
_CURVE_SYNTHETIC_BYTES = 64

# A safety-net matcher for any absolute path a redacted message may still hold
# (Windows drive letter or a leading slash). Anchors are replaced exactly first.
_ABS_PATH_RE = re.compile(r"(?:[A-Za-z]:[\\/][^\s'\"]*|/(?:[^\s'\"]*[/\\])?[^\s'\"]*)")


def _redact_frame_path(path: Path, root: Path, base: Path) -> str:
    """Reduce a frame filename to a repo-relative or basename label."""
    resolved = path.resolve()
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        pass
    try:
        return resolved.relative_to(base).as_posix()
    except ValueError:
        pass
    return path.name


def _redacted_traceback(root: Path, base: Path) -> list[str]:
    """Frame locations only (file, line, function) - never source text or
    absolute paths. Returns empty when there is no active exception."""
    tb = sys.exc_info()[2]
    if tb is None:
        return []
    lines: list[str] = []
    for frame in traceback.extract_tb(tb):
        label = _redact_frame_path(Path(frame.filename), root, base)
        lines.append(f'  File "{label}", line {frame.lineno}, in {frame.name}')
    return lines


def _redact_message(msg: str, root: Path, base: Path) -> str:
    """Replace every absolute path an exception message may echo with a
    repo-relative or basename label, so no personal path reaches the
    sidecar or console."""
    text = msg
    for anchor in (root, base, base.parent):
        text = text.replace(str(anchor), _anchor_label(anchor, root, base))
    text = _ABS_PATH_RE.sub(lambda m: Path(m.group(0)).name, text)
    return text


def _anchor_label(anchor: Path, root: Path, base: Path) -> str:
    if anchor == root:
        return "<checkout>"
    if anchor == base:
        return "<scratch>"
    return anchor.name


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", required=True, type=Path, help="checkout under test")
    parser.add_argument("--scenario", required=True, choices=_SCENARIOS)
    parser.add_argument("--base", required=True, type=Path, help="scratch work area")
    parser.add_argument(
        "--expect-raw",
        required=True,
        choices=("present", "blank"),
        help="expected Raw/Physical state of the selected CURVE (curve scenario)",
    )
    parser.add_argument("--report", type=Path, default=None, help="sidecar summary path")
    return parser.parse_args(argv)


def main() -> int:
    args = _parse_args(sys.argv[1:])
    root = args.root.resolve()
    sys.path.insert(0, str(root))  # the checkout, before any s19_app import

    # Deferred imports so everything resolves from the checkout (and so a
    # syntax-only ``python -m py_compile`` never needs the checkout present).
    from textual.widgets import DataTable

    from s19_app.tui.a2l import parse_a2l_file
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

    def meas(name: str, addr: int, dtype: str | None = "UWORD", length: int | None = None) -> str:
        hexdig = max(8, len(f"{addr:X}"))
        extra = f"  LENGTH {length}\n" if length is not None else ""
        header = f"  {dtype} CM_SYN 0 0 0 65535\n" if dtype is not None else ""
        return (
            f'/begin MEASUREMENT {name} "synthetic"\n{header}'
            f"  ECU_ADDRESS 0x{addr:0{hexdig}X}\n{extra}/end MEASUREMENT\n"
        )

    def page_syn() -> str:
        return HEAD + map_block("SYN_MAP_W") + TAIL

    def page64(n: int) -> str:
        body = (
            map_block(name_of("SYN_MAP_", n))
            + meas(name_of("SYN_V64_", n), ADDR64)
            + meas(name_of("SYN_BIG_", n), 0x1000, None, 1048576)
        )
        return HEAD + body + TAIL

    def synthetic_image() -> str:
        mem_map = {ADDR + i: (i * 7) & 0xFF for i in range(MAP_LEN)}
        return emit_s19_from_mem_map(mem_map, [(ADDR, ADDR + MAP_LEN)])

    v171_path = root / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l"
    image_path = root / "examples" / "case_00_public" / "prg.s19"
    # Pinned (no dynamic selection): the same repo-relative file under both
    # -Root and -BeforeRoot, whose 151 CURVE-without-length tags the executed
    # e07 selection evidence requires.
    curve_path = root.joinpath(*_CURVE_FILE_REL)

    def curve_synthetic_image() -> str:
        """Deterministic 64-byte S19 image at the first length-less CURVE's
        address, parsed from the tracked A2L. The CURVE name and address are
        consumed here and never reach the report."""
        parsed = parse_a2l_file(curve_path)
        address: int | None = None
        for tag in parsed.get("tags", []):
            if tag.get("char_type") == "CURVE" and tag.get("length") is None:
                address = tag.get("address")
                break
        if not isinstance(address, int) or address < 0:
            raise AssertionError(
                "software_a.a2l has no CURVE tag with no length and an address"
            )
        mem_map = {
            address + offset: (offset * 7) & 0xFF
            for offset in range(_CURVE_SYNTHETIC_BYTES)
        }
        return emit_s19_from_mem_map(
            mem_map, [(address, address + _CURVE_SYNTHETIC_BYTES)]
        )

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
            self._capture_ready = asyncio.Event()

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

        def _image_loaded(self, name: str) -> bool:
            """True once the just-launched image load installed ``current_file``."""
            return (
                self.current_file is not None
                and self.current_file.path.name == name
            )

        def _a2l_ready(self) -> bool:
            """True once the A2L attach installed data and computed the enriched tags."""
            return (
                self.current_a2l_data is not None
                and self._a2l_enriched_key is not None
                and bool(self._a2l_enriched_tags)
            )

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
            return -1

        def _curve_without_length_count(self) -> int:
            """Count the CURVE tags with no length in the enriched tag list."""
            return sum(
                1
                for tag in self._a2l_enriched_tags
                if tag.get("char_type") == "CURVE" and tag.get("length") is None
            )

        def _first_curve_without_length(self) -> int:
            for index, tag in enumerate(self._a2l_filtered_tags):
                if tag.get("char_type") == "CURVE" and tag.get("length") is None:
                    return index
            return -1

        async def _drive(self) -> None:
            try:
                await self._settle(0.3)
                if args.scenario in ("synmap", "page64", "synmap-midscroll"):
                    a2l_text = page_syn() if args.scenario != "page64" else page64(48)
                    fixture_a2l.write_text(a2l_text, encoding="utf-8")
                    fixture_s19.write_text(synthetic_image(), encoding="ascii")
                    self.load_selected_file(fixture_s19)
                    if not await self._wait_for(
                        lambda: self._image_loaded(fixture_s19.name)
                    ):
                        raise TimeoutError("image load did not finish before A2L attach")
                    # ``load_selected_file`` applies synchronously but defers the
                    # sections -> hex -> a2l refresh chain on ``call_later``; let
                    # that chain drain so the A2L attach never races it.
                    await self._settle(0.4)
                    self.load_a2l_from_path(fixture_a2l)
                    report_lines.append(f"synthetic_fixture={args.scenario}")
                elif args.scenario == "curve":
                    fixture_s19.write_text(curve_synthetic_image(), encoding="ascii")
                    self.load_selected_file(fixture_s19)
                    if not await self._wait_for(
                        lambda: self._image_loaded(fixture_s19.name)
                    ):
                        raise TimeoutError("image load did not finish before A2L attach")
                    await self._settle(0.4)
                    self.load_a2l_from_path(curve_path)
                    report_lines.append("selected_file=" + "/".join(_CURVE_FILE_REL))
                else:  # v171, v171-nameline
                    self.load_selected_file(image_path)
                    if not await self._wait_for(
                        lambda: self._image_loaded(image_path.name)
                    ):
                        raise TimeoutError("image load did not finish before A2L attach")
                    await self._settle(0.4)
                    self.load_a2l_from_path(v171_path)
                    report_lines.append("tracked_file=examples/case_00_public/ASAP2_Demo_V171.a2l")
                # A2L attach runs on its own worker; wait on the installed
                # state (data + enriched tags/key), never on the global worker
                # manager, whose ``wait_for_complete`` raises ``WorkerCancelled``
                # if any unrelated worker was cancelled.
                if not await self._wait_for(self._a2l_ready):
                    raise TimeoutError(
                        "A2L load did not finish: "
                        f"current_a2l_data={'set' if self.current_a2l_data else 'unset'} "
                        f"enriched_key={'set' if self._a2l_enriched_key else 'unset'} "
                        f"tags={len(self._a2l_enriched_tags)}"
                    )
                if args.scenario == "curve":
                    curve_count = self._curve_without_length_count()
                    report_lines.append(f"curve_without_length_selected={curve_count}")
                    if curve_count != _REQUIRED_CURVE_COUNT:
                        raise AssertionError(
                            f"software_a.a2l has {curve_count} CURVE tags with no "
                            f"length, expected {_REQUIRED_CURVE_COUNT}"
                        )
                await self._settle(0.6)
                table = await self._show_explorer()
                report_lines.append(f"tags={len(self._a2l_filtered_tags)}")
                report_lines.append(f"table_rows={table.row_count}")
                if args.scenario == "synmap-midscroll":
                    max_scroll_x = int(table.max_scroll_x)
                    if max_scroll_x <= 0:
                        raise AssertionError(
                            f"mid-scroll surface has no horizontal scroll "
                            f"(max_scroll_x={max_scroll_x})"
                        )
                    target = min(25, max_scroll_x)
                    if target <= 0:
                        raise AssertionError(
                            f"mid-scroll target is not positive (target={target})"
                        )
                    table.scroll_to(x=target, animate=False)
                    report_lines.append(f"scroll_x={target}/{max_scroll_x}")
                    await self._settle(0.4)
                elif args.scenario == "v171-nameline":
                    row = self._first_display_id_row()
                    if row < 0 or row >= len(self._a2l_filtered_tags):
                        raise AssertionError(
                            "Name-line: no A2L tag holds a display_identifier"
                        )
                    if not self._a2l_filtered_tags[row].get("display_identifier"):
                        raise AssertionError(
                            f"Name-line row {row} has no display_identifier"
                        )
                    if table.row_count:
                        table.move_cursor(row=row)
                    report_lines.append(f"cursor_row={row}")
                    await self._settle(0.4)
                elif args.scenario == "curve":
                    idx = self._first_curve_without_length()
                    if idx < 0:
                        raise AssertionError(
                            "no CURVE tag with no length found in software_a.a2l"
                        )
                    page_size = self._clamp_viewer_page_size(self.a2l_tags_page_size)
                    start = (idx // page_size) * page_size
                    self._a2l_window_start = start
                    self.update_a2l_tags_view(self._a2l_filtered_tags)
                    await self._settle(0.5)
                    table = self.query_one("#a2l_tags_list", DataTable)
                    in_page = idx - start
                    if in_page >= table.row_count:
                        raise AssertionError(
                            f"CURVE row {idx} not placed in-page "
                            f"(in-page row {in_page} of {table.row_count} rows)"
                        )
                    if table.row_count:
                        table.move_cursor(row=in_page)
                    report_lines.append(
                        f"curve_without_length_row={idx} "
                        f"(page {idx // page_size + 1}, in-page row {in_page})"
                    )
                    await self._settle(0.4)
                    # Raw/Physical discrimination: assert the selected enriched
                    # CURVE matches the expected state without ever recording a
                    # value. Both cells must agree (both present, or both blank);
                    # a half-populated row is a failure, not a pass.
                    selected = self._a2l_filtered_tags[idx]
                    raw_present = selected.get("raw_value") is not None
                    physical_present = selected.get("physical_value") is not None
                    if args.expect_raw == "present":
                        if not raw_present or not physical_present:
                            raise AssertionError(
                                "expected present Raw/Physical for the selected "
                                "CURVE but observed blank"
                            )
                        observed = "present"
                    else:
                        if raw_present or physical_present:
                            raise AssertionError(
                                "expected blank Raw/Physical for the selected "
                                "CURVE but observed present"
                            )
                        observed = "blank"
                    report_lines.append(
                        f"expect_raw={args.expect_raw} observed_raw={observed}"
                    )
                report_lines.append("surface=ready")
            except BaseException as exc:  # noqa: BLE001 - keep the app alive, report it
                error = _redact_message(f"{type(exc).__name__}: {exc}", root, base)
                frames = _redacted_traceback(root, base)
                report_lines.append(f"surface=error {error}")
                for frame_line in frames:
                    report_lines.append(f"traceback: {frame_line}")
                sys.stderr.write(f"capture drive failed: {error}\n")
                for frame_line in frames:
                    sys.stderr.write(frame_line + "\n")
            finally:
                if args.report is not None:
                    try:
                        args.report.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
                    except OSError:
                        pass
                self._capture_ready.set()

    app = CaptureApp()
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
