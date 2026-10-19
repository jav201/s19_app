"""Batch-94 Inc-002 — the fb_a Flow Builder through the shipped surface.

AT-B94-15 · AT-B94-16 · AT-B94-17 · AT-B94-18 (black-box, C-18: one on-disk
node per AT) + TC-B94-20 (fb_a composition census). The B2 move is observed
by construction: the panel is imported from its NEW address
(``s19_app.tui.flow_screens``) and driven through ``S19TuiApp`` routing.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from textual.widgets import Button, Input, Select, Static

from s19_app.core import S19File
from s19_app.tui.app import S19TuiApp
from s19_app.tui.flow_screens import FlowBuilderPanel
from s19_app.tui.services import flow_persistence_service as fps
from s19_app.tui.services.flow_model import (
    BLOCK_A2B,
    BLOCK_CRC,
    BLOCK_PATCH,
)
from s19_app.tui.services.load_service import build_loaded_s19

#: Minimal CLEAN S19 — 01 02 03 04 at 0x1000 (checksum-verified).
_S19 = "S107100001020304DE\nS9030000FC\n"


def _make_project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    """Create ``<tmp>/.s19tool/workarea/<name>/`` holding the given files."""
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


def _patch_json() -> str:
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [
                {"type": "bytes", "address": "0x1001", "bytes": "AA"},
            ],
        }
    )


def _project(tmp_path: Path) -> Path:
    return _make_project(
        tmp_path,
        {
            "prg.s19": _S19,
            "base.s19": _S19,
            "hotfix.json": _patch_json(),
        },
    )


def _reload(path: Path) -> dict[int, int]:
    return build_loaded_s19(path, S19File(str(path)), None, None).mem_map


#: The batch-77 hostile payload family, re-derived locally (the hostile_map
#: idiom — a wrong class would produce a wrong expectation and a wrong result
#: that agree).
_SENTINEL = "b77hostilemark"
_HOSTILE_SYMBOL = (
    _SENTINEL + "\x1b[31m" + "_evil[red]" + "\x9b1m" + "\x9d8;;u\x07" + "\x00\x7f"
)
#: A Windows-legal hostile file name (NTFS rejects the control bytes) for the
#: run-through-report arm.
_HOSTILE_FILE_NAME = _SENTINEL + "_evil[red].s19"


def _control_bytes(text: str) -> list[int]:
    # The C0/C1 hostile class MINUS the line-break structure of a multi-line
    # painted surface (the batch-77 projector excludes the line-break class
    # the same way when the surface is a document).
    return [
        ord(c)
        for c in text
        if (ord(c) < 0x20 and c not in (chr(10), chr(9))) or 0x7F <= ord(c) < 0xA0
    ]


async def _show_flow(app: S19TuiApp, pilot, project: Path) -> None:
    app.current_project_dir = project
    await pilot.press("8")
    await pilot.pause()



async def _wait_prefill(app: S19TuiApp, pilot, expected: str) -> None:
    """Wait for SaveFlowScreen's on_mount prefill to land BEFORE typing (the
    load-flaky settle family — screens.py prefills the input on mount; a
    typed value that lands first is overwritten)."""
    for _ in range(25):
        await pilot.pause()
        if app.screen.query_one("#flow_save_name", Input).value == expected:
            return
    raise AssertionError(f"save-name prefill {expected!r} did not land")

def _add_ref_block(app: S19TuiApp, kind: str, ref: str) -> None:
    app.query_one("#flow_kind", Select).value = kind
    app.query_one("#flow_ref", Input).value = ref
    app.query_one("#flow_add", Button).press()


def _painted_static(app: S19TuiApp, selector: str) -> "tuple[str, object]":
    """The widget's PAINTED plain text + spans (C-32 — not a pre-layout attr)."""
    widget = app.query_one(selector, Static)
    rendered = widget.render()
    return rendered.plain, rendered.spans


# --------------------------------------------------------------------------- #
# AT-B94-15 — fb_a surface; a wired patch run writes the patched image
# --------------------------------------------------------------------------- #


def test_at_b94_15_fb_a_surface_and_wired_patch_run(tmp_path: Path) -> None:
    """AT-B94-15 (HLR-013, black-box): the palette exposes patch/CRC/A2B-diff;
    placed blocks carry typed in/out stubs; >=1 cable run renders at 120x30
    inside the boxed 96x18 workspace; a patch block wired to an S19 image and
    a patch JSON, run through the shipped surface, writes the patched image.
    """
    project = _project(tmp_path)

    async def _drive() -> "tuple[list[str], str, tuple[int, int], int]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _show_flow(app, pilot, project)
            palette_kinds = [
                button.id.removeprefix("flow_palette_")
                for button in app.query("#flow_palette Button")
            ]
            empty_canvas, _ = _painted_static(app, "#flow_canvas")
            assert "(empty canvas" in empty_canvas

            _add_ref_block(app, "source", "prg.s19")
            await pilot.pause()
            _add_ref_block(app, "patch", "hotfix.json")
            await pilot.pause()
            _add_ref_block(app, "write_out", "out.s19")
            await pilot.pause()

            canvas, _ = _painted_static(app, "#flow_canvas")
            screen = app.query_one("#screen_flow")
            canvas_region = app.query_one("#flow_canvas").region
            app.query_one("#flow_run", Button).press()
            for _ in range(30):
                await pilot.pause()
            return (
                palette_kinds,
                canvas,
                (screen.region.width, screen.region.height),
                canvas_region.width,
            )

    palette_kinds, canvas, screen_box, canvas_width = asyncio.run(_drive())

    # Palette exposes exactly the three fb_a placeable types.
    assert sorted(palette_kinds) == sorted([BLOCK_PATCH, BLOCK_CRC, BLOCK_A2B])
    # Box-drawn blocks with typed stubs and >=1 cable run (fb_a geometry).
    assert "PATCH" in canvas and "WRITE-OUT" in canvas
    assert "prg.s19" in canvas  # SOURCE chip
    assert "┌" in canvas and "┐" in canvas and "└" in canvas  # framed canvas + bends
    assert "┤" in canvas and "├" in canvas  # typed in/out stubs
    assert "─" in canvas and "│" in canvas  # the cable run
    assert "·" in canvas  # grid dots
    assert all(len(line) <= 88 for line in canvas.splitlines())
    # The boxed budget: the screen is the measured 96x18 at 120x30 and the
    # canvas paints inside it (C-23 measured, C-32 painted oracle).
    assert screen_box == (96, 18), screen_box
    assert canvas_width <= 96
    # The wired run wrote the patched image: 100% of the declared addresses.
    mem_map = _reload(project / "out.s19")
    assert mem_map[0x1000] == 0x01
    assert mem_map[0x1001] == 0xAA
    assert mem_map[0x1002] == 0x03


# --------------------------------------------------------------------------- #
# AT-B94-16 — A2B wiring: flow-output-or-file, >=1 from this flow, provenance
# --------------------------------------------------------------------------- #


def test_at_b94_16_a2b_wiring_rule_and_report_provenance(tmp_path: Path) -> None:
    """AT-B94-16 (HLR-014, black-box): each A2B input binds to a flow output
    or a file; a both-external pair is refused AT WIRING time (the refusal is
    visible, the block is never added, and a run produces 0 reports); the
    accepted flow+file binding's report states each input's provenance."""
    project = _project(tmp_path)

    async def _drive() -> "tuple[str, int, str, list[str]]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _show_flow(app, pilot, project)
            panel = app.query_one("#flow_panel", FlowBuilderPanel)

            _add_ref_block(app, "source", "prg.s19")
            await pilot.pause()
            _add_ref_block(app, "patch", "hotfix.json")
            await pilot.pause()

            # Refused wiring: both inputs external.
            app.query_one("#flow_palette_a2b", Button).press()
            await pilot.pause()
            assert app.query_one("#flow_ref_a").display is True
            assert app.query_one("#flow_ref", Input).display is False
            app.query_one("#flow_ref_a", Input).value = "base.s19"
            app.query_one("#flow_ref_b", Input).value = "prg.s19"
            app.query_one("#flow_add", Button).press()
            await pilot.pause()
            refused_notice = app.query_one("#flow_wiring_notice", Static)
            refused_blocks = len(panel._blocks)
            refused_visible = refused_notice.display
            refused_text = refused_notice.render().plain

            # Accepted wiring: one flow output (#2 = the patch) + one file.
            app.query_one("#flow_ref_a", Input).value = "#2"
            app.query_one("#flow_ref_b", Input).value = "base.s19"
            app.query_one("#flow_add", Button).press()
            await pilot.pause()
            accepted_blocks = len(panel._blocks)
            notice_hidden = not app.query_one("#flow_wiring_notice", Static).display
            canvas, _ = _painted_static(app, "#flow_canvas")

            app.query_one("#flow_run", Button).press()
            for _ in range(30):
                await pilot.pause()
            reports = sorted((project / "reports").glob("*flow-a2b*.md"))
            provenance = []
            if reports:
                provenance = [
                    ln
                    for ln in reports[-1].read_text(encoding="utf-8").splitlines()
                    if ln.startswith("- Image A:") or ln.startswith("- Image B:")
                ]
            return (
                refused_text,
                refused_blocks + (1000 if refused_visible else 0),
                canvas,
                provenance if notice_hidden and accepted_blocks == 3 else [],
            )

    refused_text, refused_state, canvas, provenance = asyncio.run(_drive())

    assert "refused" in refused_text
    assert refused_state == 1002  # 2 blocks kept + the notice was visible
    assert "#2.out" in canvas  # the accepted flow binding paints on the canvas
    assert len(provenance) == 2, provenance
    assert any("[flow]" in ln and "block 2 (patch).out" in ln for ln in provenance)
    assert any("[external]" in ln and "base.s19" in ln for ln in provenance)


# --------------------------------------------------------------------------- #
# AT-B94-17 — template save -> import listing -> import reconstructs; dedup
# --------------------------------------------------------------------------- #


def test_at_b94_17_template_save_listing_import_and_dedup(tmp_path: Path) -> None:
    """AT-B94-17 (HLR-015, black-box): saving a built flow names it; the name
    appears in the Flow Execution import listing (``list_saved_flows`` — the
    surface Inc-003's import consumes); importing reconstructs the flow
    (block count + kinds); a second same-name save dedup-suffixes instead of
    clobbering."""
    project = _project(tmp_path)

    async def _drive() -> "tuple[list[str], list[str], str]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _show_flow(app, pilot, project)
            panel = app.query_one("#flow_panel", FlowBuilderPanel)
            _add_ref_block(app, "source", "prg.s19")
            await pilot.pause()
            _add_ref_block(app, "patch", "hotfix.json")
            await pilot.pause()

            # Save "chain1" through the real button + modal.
            app.query_one("#flow_save", Button).press()
            await _wait_prefill(app, pilot, "flow")
            app.screen.query_one("#flow_save_name", Input).value = "chain1"
            app.screen.query_one("#flow_save_ok", Button).press()
            for _ in range(5):
                await pilot.pause()
            saved_kinds = [b.kind for b in panel._blocks]
            strip, _ = _painted_static(app, "#flow_name_strip")

            # Second save under the SAME name (a write-out variant flow).
            _add_ref_block(app, "write_out", "out.s19")
            await pilot.pause()
            app.query_one("#flow_save", Button).press()
            await _wait_prefill(app, pilot, "chain1")
            app.screen.query_one("#flow_save_name", Input).value = "chain1"
            app.screen.query_one("#flow_save_ok", Button).press()
            for _ in range(5):
                await pilot.pause()
            return saved_kinds, [b.kind for b in panel._blocks], strip

    saved_kinds, dedup_kinds, strip = asyncio.run(_drive())

    assert saved_kinds == ["source", "patch"]
    assert "chain1" in strip and "✓" in strip
    # The import listing (Flow Execution's surface) carries BOTH templates.
    assert fps.list_saved_flows(project) == ["chain1", "chain1_2"]
    # The dedup-suffix: the first template is intact, the second is its own.
    first, first_findings = fps.load_flow_json(
        project / "flows" / "chain1.json", project
    )
    second, second_findings = fps.load_flow_json(
        project / "flows" / "chain1_2.json", project
    )
    assert first_findings == [] and second_findings == []
    assert [b.kind for b in first.blocks] == saved_kinds
    assert [b.kind for b in second.blocks] == dedup_kinds == [
        "source",
        "patch",
        "write_out",
    ]


# --------------------------------------------------------------------------- #
# AT-B94-18 — hostile file-derived names render literally (C-17)
# --------------------------------------------------------------------------- #


def test_at_b94_18_hostile_names_render_literally(tmp_path: Path) -> None:
    """AT-B94-18 (HLR-016, black-box, C-17): the batch-77 hostile payload in a
    bound file name renders literally on the canvas (sentinel visible, markup
    literal, 0 control bytes) and a Windows-legal hostile name reaches the
    emitted report with the sentinel visible, the Mode-A label escaped and 0
    control bytes. Two app sessions: the full payload never runs (its file
    does not exist), the report arm uses the legal on-disk name."""
    project = _make_project(
        tmp_path,
        {"prg.s19": _S19, _HOSTILE_FILE_NAME: _S19, "hotfix.json": _patch_json()},
    )

    async def _drive_canvas() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _show_flow(app, pilot, project)
            _add_ref_block(app, "source", "prg.s19")
            await pilot.pause()
            # The full hostile payload (control bytes + markup) as the file
            # input — refused bindings never paint, so pair it with a legal
            # flow output to make the wiring stick. Never run.
            app.query_one("#flow_palette_a2b", Button).press()
            await pilot.pause()
            app.query_one("#flow_ref_a", Input).value = "#1"
            app.query_one("#flow_ref_b", Input).value = _HOSTILE_SYMBOL
            app.query_one("#flow_add", Button).press()
            await pilot.pause()
            canvas, _spans = _painted_static(app, "#flow_canvas")
            return canvas

    async def _drive_report() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _show_flow(app, pilot, project)
            _add_ref_block(app, "source", "prg.s19")
            await pilot.pause()
            app.query_one("#flow_palette_a2b", Button).press()
            await pilot.pause()
            app.query_one("#flow_ref_a", Input).value = "#1"
            app.query_one("#flow_ref_b", Input).value = _HOSTILE_FILE_NAME
            app.query_one("#flow_add", Button).press()
            await pilot.pause()
            app.query_one("#flow_run", Button).press()
            for _ in range(30):
                await pilot.pause()
            reports = sorted((project / "reports").glob("*flow-a2b*.md"))
            assert reports, "the runnable hostile-name arm must emit a report"
            return reports[-1].read_bytes().decode("utf-8")

    canvas = asyncio.run(_drive_canvas())
    report_text = asyncio.run(_drive_report())

    # Canvas: sentinel visible, brackets literal, 0 control bytes. (The canvas
    # legitimately carries STYLE spans — box-art colours — so the markup
    # census is the AST scan in test_tc_042_10, not a span emptiness check.)
    assert _SENTINEL in canvas
    assert "_evil[red]" in canvas  # literal brackets, never parsed
    assert _control_bytes(canvas) == []
    # Report: sentinel visible, the Mode-A label escaped, 0 control bytes
    # (over the newline-normalized bytes — the CRLF convention is the
    # producer's own).
    assert _SENTINEL in report_text
    image_lines = [
        ln for ln in report_text.splitlines() if ln.startswith("- Image B:")
    ]
    assert len(image_lines) == 1
    label_part = image_lines[0].split(" [external]")[0]
    assert "[red]" not in label_part and "\\[red\\]" in label_part
    normalized = report_text.replace("\r\n", "\n")
    assert _control_bytes(normalized) == []


# --------------------------------------------------------------------------- #
# TC-B94-20 — fb_a composition census
# --------------------------------------------------------------------------- #


def test_tc_b94_20_fb_a_composition_census(tmp_path: Path) -> None:
    """TC-B94-20 (LLR-013.1, white-box census): the reworked panel composes
    exactly ONE palette rail (carrying the three placeable types), ONE framed
    canvas; a source + two box blocks render >=1 cable run with typed stubs
    inside the boxed 96x18 at 120x30; the empty canvas renders the fb_a empty
    state; the panel also composes at the 80x24 floor (C-29 overflow scrolls,
    no exception)."""
    project = _project(tmp_path)

    async def _drive(size: "tuple[int, int]") -> "tuple[int, int, int, str, int]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await _show_flow(app, pilot, project)
            palette_count = len(app.query("#flow_palette"))  # one rail…
            palette_buttons = len(app.query("#flow_palette Button"))
            canvas_count = len(app.query("#flow_canvas"))
            if size == (120, 30):
                empty_canvas, _ = _painted_static(app, "#flow_canvas")
                assert "(empty canvas" in empty_canvas
            _add_ref_block(app, "source", "prg.s19")
            await pilot.pause()
            _add_ref_block(app, "patch", "hotfix.json")
            await pilot.pause()
            _add_ref_block(app, "write_out", "out.s19")
            await pilot.pause()
            canvas, _ = _painted_static(app, "#flow_canvas")
            return (
                palette_count,
                palette_buttons,
                canvas_count,
                canvas,
                app.query_one("#flow_canvas").region.width,
            )

    palette_count, palette_buttons, canvas_count, canvas, canvas_width = asyncio.run(
        _drive((120, 30))
    )
    assert palette_count == 1  # one palette rail…
    assert palette_buttons == 3  # …carrying the three placeable types
    assert canvas_count == 1  # …one framed canvas
    assert len(FlowBuilderPanel._PALETTE_TYPES) == 3  # 3 placeable types
    assert {kind for *_rest, kind in FlowBuilderPanel._PALETTE_TYPES} == {
        BLOCK_PATCH,
        BLOCK_CRC,
        BLOCK_A2B,
    }
    # The source chip + two box blocks render >=1 cable run with typed stubs,
    # inside the boxed budget.
    assert "┤" in canvas and "├" in canvas
    assert "└" in canvas and "┘" in canvas  # the bend glyphs of a cable run
    assert canvas_width <= 96
    assert all(len(line) <= 88 for line in canvas.splitlines())
    # The 80x24 floor composes and paints without exception (run_test raises
    # on mount/paint errors).
    small_palette, small_buttons, small_canvas, small_text, _ = asyncio.run(
        _drive((80, 24))
    )
    assert small_palette == 1 and small_buttons == 3 and small_canvas == 1
    assert "PATCH" in small_text
